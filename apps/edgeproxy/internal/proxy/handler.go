package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/cache"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/router"
)

type cacheFillLocker interface {
	Lock(string) func()
}

type routeRuntime struct {
	cfg                *config.RouteConfig
	pool               *upstreamPool
	cache              *cache.Cache
	fills              cacheFillLocker
	forwardedForHeader string
}

type handlerLifecycle struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type Handler struct {
	mu      sync.RWMutex
	logger  *slog.Logger
	router  *router.Router
	metrics *metrics.Registry
	logs    *accesslog.Store
	routes  map[string]*routeRuntime
	clients *clientResolver
	life    *handlerLifecycle

	tunnelMu         sync.Mutex
	tunnels          map[*activeProtocolTunnel]struct{}
	tunnelsClosed    bool
	tunnelWG         sync.WaitGroup
	healthProbeSlots chan struct{}
}

func NewHandler(cfg config.Config, logger *slog.Logger, registry *metrics.Registry, logStore *accesslog.Store) (*Handler, error) {
	h := &Handler{logger: logger, metrics: registry, logs: logStore, tunnels: make(map[*activeProtocolTunnel]struct{}), healthProbeSlots: make(chan struct{}, maxConcurrentHealthChecksGlobal)}
	state, err := h.buildState(cfg)
	if err != nil {
		return nil, err
	}
	h.router, h.routes, h.clients, h.life = state.router, state.routes, state.clients, state.life
	return h, nil
}

type handlerState struct {
	router  *router.Router
	routes  map[string]*routeRuntime
	clients *clientResolver
	life    *handlerLifecycle
}

func (h *Handler) buildState(cfg config.Config) (handlerState, error) {
	clients, err := newClientResolver(cfg.Server.TrustedProxyCIDRs, cfg.Server.ForwardedForHeader)
	if err != nil {
		return handlerState{}, fmt.Errorf("configure trusted proxies: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	life := &handlerLifecycle{cancel: cancel}
	state := handlerState{router: router.New(cfg.Routes), routes: make(map[string]*routeRuntime), clients: clients, life: life}
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		pool, err := newUpstreamPool(*route)
		if err != nil {
			cancel()
			life.wg.Wait()
			return handlerState{}, err
		}
		runtime := &routeRuntime{cfg: route, pool: pool, fills: cache.NewKeyLocker(), forwardedForHeader: clients.header}
		if route.Cache.Enabled {
			runtime.cache = cache.New(route.Cache.MaxEntries, route.Cache.MaxBytes)
		}
		state.routes[route.Name] = runtime
		if route.HealthCheck.Enabled {
			life.wg.Add(1)
			go func(rt *routeRuntime) {
				defer life.wg.Done()
				rt.pool.runHealthChecks(ctx, rt.cfg.HealthCheck, h.healthProbeSlots, func(change healthChange) {
					h.recordHealthChange(rt.cfg.Name, change)
				})
			}(runtime)
		}
	}
	return state, nil
}

// Reload validates and prepares a complete data-plane generation before
// atomically publishing it. Existing requests continue on the previous
// generation while new requests immediately use the new route table.
func (h *Handler) Reload(cfg config.Config) error {
	state, err := h.buildState(cfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	oldRoutes, oldLife := h.routes, h.life
	h.router, h.routes, h.clients, h.life = state.router, state.routes, state.clients, state.life
	h.mu.Unlock()
	closeHandlerState(oldRoutes, oldLife)
	return nil
}

func (h *Handler) Close() {
	h.closeProtocolTunnels()
	h.mu.Lock()
	routes, life := h.routes, h.life
	h.routes = map[string]*routeRuntime{}
	h.life = nil
	h.mu.Unlock()
	closeHandlerState(routes, life)
}

type activeProtocolTunnel struct {
	client  io.Closer
	backend io.Closer
	once    sync.Once
}

func (t *activeProtocolTunnel) Close() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		_ = t.client.Close()
		_ = t.backend.Close()
	})
}

func (h *Handler) registerProtocolTunnel(client, backend io.Closer) (*activeProtocolTunnel, bool) {
	tunnel := &activeProtocolTunnel{client: client, backend: backend}
	h.tunnelMu.Lock()
	defer h.tunnelMu.Unlock()
	if h.tunnelsClosed {
		tunnel.Close()
		return nil, false
	}
	h.tunnels[tunnel] = struct{}{}
	h.tunnelWG.Add(1)
	return tunnel, true
}

func (h *Handler) unregisterProtocolTunnel(tunnel *activeProtocolTunnel) {
	if tunnel == nil {
		return
	}
	h.tunnelMu.Lock()
	if _, ok := h.tunnels[tunnel]; ok {
		delete(h.tunnels, tunnel)
		h.tunnelWG.Done()
	}
	h.tunnelMu.Unlock()
}

func (h *Handler) closeProtocolTunnels() {
	h.tunnelMu.Lock()
	if h.tunnelsClosed {
		h.tunnelMu.Unlock()
		h.tunnelWG.Wait()
		return
	}
	h.tunnelsClosed = true
	tunnels := make([]*activeProtocolTunnel, 0, len(h.tunnels))
	for tunnel := range h.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	h.tunnelMu.Unlock()
	for _, tunnel := range tunnels {
		tunnel.Close()
	}
	h.tunnelWG.Wait()
}

func closeHandlerState(routes map[string]*routeRuntime, life *handlerLifecycle) {
	if life != nil && life.cancel != nil {
		life.cancel()
		life.wg.Wait()
	}
	for _, route := range routes {
		route.pool.closeIdleConnections()
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	started := time.Now()
	h.mu.RLock()
	clients, routeTable, routeMap := h.clients, h.router, h.routes
	h.mu.RUnlock()
	operationalProbe := trustedOperationalProbe(req, clients)
	// The marker is edge-internal control metadata. Never forward a client copy
	// to an Origin, regardless of whether the directly connected peer was trusted.
	req.Header.Del(internalProbeHeader)
	if operationalProbe {
		// Operational data-plane probes must exercise the route and Origin path
		// without reading from or mutating the application cache.
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Pragma", "no-cache")
		req = withOperationalProbe(req)
	}
	req = withResolvedClientIP(req, clients.Resolve(req))
	match, ok := routeTable.Match(req)
	if !ok {
		http.Error(w, "no route configured for this host and path", http.StatusNotFound)
		return
	}
	rt := routeMap[match.Route.Name]
	id := requestID(req)
	w.Header().Set("X-Request-ID", id)

	bytesIn := uint64(0)
	var streamedBody *countingReadCloser
	if req.ContentLength > 0 {
		bytesIn = uint64(req.ContentLength)
	} else if req.ContentLength < 0 && req.Body != nil && req.Body != http.NoBody {
		streamedBody = &countingReadCloser{ReadCloser: req.Body}
		req.Body = streamedBody
	}
	var finish func(metrics.RequestObservation)
	if !operationalProbe {
		finish = h.metrics.Begin(rt.cfg.Name, req.Method)
	}
	rw := &responseCapture{ResponseWriter: w}
	result := requestResult{cacheStatus: "BYPASS"}
	defer func() {
		if streamedBody != nil {
			bytesIn = streamedBody.BytesRead()
		}
		bytesIn = saturatingAddUint64(bytesIn, result.tunnelBytesIn)
		bytesOut := saturatingAddUint64(uint64(maxInt64(rw.bytes, 0)), result.tunnelBytesOut)
		canceled := result.clientCanceled
		status := rw.status
		if status == 0 && !canceled {
			status = http.StatusOK
		}
		duration := time.Since(started)
		if result.responseDuration > 0 {
			duration = result.responseDuration
		}
		if finish != nil {
			finish(metrics.RequestObservation{
				Status:      status,
				Canceled:    canceled,
				BytesIn:     bytesIn,
				BytesOut:    bytesOut,
				Duration:    duration,
				ProxyError:  result.proxyError,
				Retries:     result.retries,
				CacheStatus: result.cacheStatus,
			})
		}
		if operationalProbe {
			return
		}

		level := "INFO"
		message := "client request completed"
		if canceled {
			message = "client request canceled"
		} else if status >= 500 || result.proxyError {
			level = "ERROR"
		} else if status >= 400 {
			level = "WARN"
		}
		if h.logs != nil {
			h.logs.Append(accesslog.Entry{
				Level:              level,
				Event:              "request_completed",
				Message:            message,
				RequestID:          id,
				ClientIP:           clientIP(req),
				Method:             req.Method,
				Host:               req.Host,
				Path:               req.URL.EscapedPath(),
				Query:              sanitizedQuery(req),
				Route:              rt.cfg.Name,
				Status:             status,
				BytesIn:            bytesIn,
				BytesOut:           bytesOut,
				DurationMS:         durationMS(duration),
				CacheStatus:        result.cacheStatus,
				Upstream:           result.upstream,
				UpstreamStatus:     result.upstreamStatus,
				UpstreamDurationMS: durationMS(result.upstreamDuration),
				UpstreamCalls:      result.upstreamCalls,
				Retries:            result.retries,
				ProxyError:         result.proxyError,
				Canceled:           canceled,
				Error:              result.errorMessage,
				UserAgent:          req.UserAgent(),
				Tags:               []string{"access", "proxy"},
			})
		}

		h.logger.Log(context.Background(), parseLogLevel(level), "request",
			"request_id", id,
			"client_ip", clientIP(req),
			"method", req.Method,
			"host", req.Host,
			"path", req.URL.EscapedPath(),
			"query", sanitizedQuery(req),
			"route", rt.cfg.Name,
			"status", status,
			"bytes_in", bytesIn,
			"bytes_out", bytesOut,
			"duration_ms", durationMS(duration),
			"upstream", result.upstream,
			"upstream_status", result.upstreamStatus,
			"upstream_calls", result.upstreamCalls,
			"upstream_duration_ms", durationMS(result.upstreamDuration),
			"cache", result.cacheStatus,
			"retries", result.retries,
			"proxy_error", result.proxyError,
			"canceled", canceled,
		)
	}()

	result = h.handleRoute(rw, req, rt, id, started)
}

type requestResult struct {
	cacheStatus      string
	upstream         string
	upstreamStatus   int
	upstreamDuration time.Duration
	upstreamCalls    uint64
	retries          uint64
	tunnelBytesIn    uint64
	tunnelBytesOut   uint64
	responseDuration time.Duration
	proxyError       bool
	clientCanceled   bool
	errorMessage     string
}

func (h *Handler) handleRoute(w http.ResponseWriter, req *http.Request, rt *routeRuntime, id string, started time.Time) requestResult {
	if hasProtocolUpgrade(req.Header) {
		if _, err := protocolUpgrade(req.Header); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return requestResult{cacheStatus: "BYPASS", errorMessage: err.Error()}
		}
	}
	// A trusted synthetic connectivity probe must reach a real Origin, but it is
	// not application traffic. Bypass cache lookup, fill serialization, and cache
	// population explicitly rather than relying only on request cache headers.
	if isOperationalProbe(req) {
		return h.fetchAndServe(w, req, rt, id, nil, "BYPASS", false, started)
	}
	lookup, store, _ := requestCacheMode(req, rt.cfg.Cache)
	if !lookup && !store {
		return h.fetchAndServe(w, req, rt, id, nil, "BYPASS", false, started)
	}

	key := cacheKey(req, rt.cfg.Cache)
	now := time.Now()
	var stale *cache.Entry
	if lookup {
		entry, fresh, isStale := rt.cache.Get(key, now)
		allowed := requestAllowsCachedEntry(req, entry, now)
		if fresh && allowed {
			result := requestResult{cacheStatus: "HIT"}
			if err := serveCacheEntry(w, req, entry, "HIT", now); err != nil {
				h.recordResponseCopyError(&result, req, rt.cfg.Name, id, err)
			}
			return result
		}
		if isStale && allowed {
			stale = &entry
		}
	}

	unlock := rt.fills.Lock(key)
	defer unlock()
	// The cache may change while this request waits behind another fill. Discard
	// the pre-lock stale snapshot and rebuild the candidate from the current cache
	// state so an admin purge, expiry, or replacement cannot be bypassed by a
	// stale pointer retained from the first lookup.
	stale = nil
	if lookup {
		now = time.Now()
		entry, fresh, isStale := rt.cache.Get(key, now)
		allowed := requestAllowsCachedEntry(req, entry, now)
		if fresh && allowed {
			result := requestResult{cacheStatus: "HIT"}
			if err := serveCacheEntry(w, req, entry, "HIT", now); err != nil {
				h.recordResponseCopyError(&result, req, rt.cfg.Name, id, err)
			}
			return result
		}
		if isStale && allowed {
			stale = &entry
		}
	}
	return h.fetchAndServe(w, req, rt, id, stale, "MISS", store, started)
}

func (h *Handler) fetchAndServe(w http.ResponseWriter, req *http.Request, rt *routeRuntime, id string, stale *cache.Entry, cacheStatus string, store bool, started time.Time) requestResult {
	result := requestResult{cacheStatus: cacheStatus}
	operationalProbe := isOperationalProbe(req)
	ctx := req.Context()
	upgradeRequest := hasProtocolUpgrade(req.Header)
	if timeout := rt.cfg.Proxy.RequestTimeout.Duration; timeout > 0 && !upgradeRequest {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	attempts := 1
	if isIdempotent(req.Method) && (req.Body == nil || req.Body == http.NoBody || req.GetBody != nil) {
		attempts += rt.cfg.Proxy.RetryCount
	}
	var resp *http.Response
	var lastErr error
	var activeNode *upstream
	excluded := make(map[*upstream]bool)
	for attempt := 0; attempt < attempts; attempt++ {
		var node *upstream
		if operationalProbe {
			node = rt.pool.pickProbe(excluded)
		} else {
			node = rt.pool.pick(excluded)
		}
		if node == nil {
			if lastErr == nil {
				lastErr = errors.New("no eligible upstream available")
			}
			break
		}
		outReq, err := cloneRequest(ctx, req, node, rt.cfg, id, rt.forwardedForHeader)
		if err != nil {
			if !operationalProbe {
				rt.pool.releaseActive(node)
			}
			lastErr = err
			break
		}

		started := time.Now()
		resp, err = node.transport.RoundTrip(outReq)
		elapsed := time.Since(started)
		clientCanceled := err != nil && req.Context().Err() != nil
		if !operationalProbe && !clientCanceled {
			rt.pool.observe(node, elapsed)
		}
		result.upstreamDuration += elapsed
		result.upstreamCalls++
		// Count only retry requests that actually reached RoundTrip. A route
		// timeout may expire during retry_backoff, in which case no second
		// origin call occurred and request-level retry telemetry must remain 0.
		if result.upstreamCalls > 1 {
			result.retries = result.upstreamCalls - 1
		}
		result.upstream = node.url.String()
		status := 0
		if resp != nil {
			status = resp.StatusCode
			result.upstreamStatus = status
		}
		retryableResponse := err == nil && resp != nil && retryableStatus(resp.StatusCode)
		failed := err != nil || retryableResponse
		telemetryFailed := err != nil || (resp != nil && resp.StatusCode >= http.StatusInternalServerError)
		attemptErr := err
		if retryableResponse {
			attemptErr = fmt.Errorf("upstream returned %s", resp.Status)
		}
		timedOut := isTimeoutError(err)
		originFailed := telemetryFailed && !clientCanceled
		originTimedOut := timedOut && !clientCanceled
		if !operationalProbe {
			h.metrics.RecordUpstream(rt.cfg.Name, node.url.String(), metrics.UpstreamObservation{
				Status:   status,
				Duration: elapsed,
				Failed:   originFailed,
				Canceled: clientCanceled,
				Timeout:  originTimedOut,
				Retry:    attempt > 0,
			})
			h.recordUpstreamAttempt(req, rt.cfg.Name, id, node.url.String(), attempt+1, status, elapsed, attempt > 0, originTimedOut, attemptErr, originFailed, clientCanceled)
		}

		if !failed {
			activeNode = node
			lastErr = nil
			result.errorMessage = ""
			if !operationalProbe {
				setNodeHealth(node, true, healthChange{Upstream: node.url.String(), Healthy: true, Status: status, Duration: elapsed}, func(change healthChange) {
					h.recordHealthChange(rt.cfg.Name, change)
				})
			}
			break
		}

		// A cancellation or deadline inherited from the client request does not
		// indicate an origin failure. Preserve the origin's health and stop here:
		// every retry would inherit the same already-terminated context.
		if clientCanceled {
			result.clientCanceled = true
			if !operationalProbe {
				rt.pool.releaseActive(node)
			}
			if resp != nil && resp.Body != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				_ = resp.Body.Close()
				resp = nil
			}
			lastErr = req.Context().Err()
			result.errorMessage = errorText(lastErr)
			break
		}

		lastErr = attemptErr
		result.errorMessage = errorText(lastErr)
		excluded[node] = true
		if !operationalProbe {
			setNodeHealth(node, false, healthChange{Upstream: node.url.String(), Healthy: false, Status: status, Duration: elapsed, Error: errorText(lastErr)}, func(change healthChange) {
				h.recordHealthChange(rt.cfg.Name, change)
			})
		}

		canRetry := attempt+1 < attempts
		if retryableResponse && !canRetry {
			activeNode = node
			// The Origin produced a complete HTTP response. Once retries are exhausted,
			// preserve its status, headers, and body instead of replacing useful 502,
			// 503, or 504 semantics with a generic proxy-generated 502 response.
			lastErr = nil
			result.errorMessage = ""
			break
		}
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			resp = nil
		}
		if !operationalProbe {
			rt.pool.releaseActive(node)
		}

		// The route-wide timeout applies to the whole request, not each retry. Once
		// it expires, record the failed origin but do not attempt another origin
		// with an already-done context.
		if ctx.Err() != nil {
			lastErr = ctx.Err()
			result.errorMessage = errorText(lastErr)
			break
		}

		if attempt+1 < attempts {
			if backoff := rt.cfg.Proxy.RetryBackoff.Duration; backoff > 0 {
				timer := time.NewTimer(backoff * time.Duration(attempt+1))
				select {
				case <-ctx.Done():
					timer.Stop()
					lastErr = ctx.Err()
					result.errorMessage = errorText(lastErr)
					if req.Context().Err() != nil {
						result.clientCanceled = true
					}
					attempt = attempts
				case <-timer.C:
				}
			}
		}
	}

	if activeNode != nil && !operationalProbe {
		defer rt.pool.releaseActive(activeNode)
	}
	// Once the client request context is canceled there is no client-facing
	// response left to complete. Do not synthesize a 502, serve stale content,
	// or count the cancellation as a proxy/server failure.
	if result.clientCanceled || req.Context().Err() != nil {
		result.clientCanceled = true
		result.proxyError = false
		if result.errorMessage == "" {
			result.errorMessage = errorText(req.Context().Err())
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return result
	}
	if lastErr != nil || resp == nil {
		if stale != nil {
			result.cacheStatus = "STALE"
			if err := serveCacheEntry(w, req, *stale, "STALE", time.Now()); err != nil {
				h.recordResponseCopyError(&result, req, rt.cfg.Name, id, err)
			}
			return result
		}
		result.proxyError = true
		result.errorMessage = errorText(lastErr)
		if !operationalProbe {
			h.logger.Error("upstream request failed",
				"request_id", id,
				"route", rt.cfg.Name,
				"upstream", result.upstream,
				"upstream_calls", result.upstreamCalls,
				"retries", result.retries,
				"error", lastErr,
			)
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		result.cacheStatus = "BYPASS"
		tunnel, err := h.proxyProtocolUpgrade(w, req, resp, id, started)
		result.tunnelBytesIn = tunnel.bytesIn
		result.tunnelBytesOut = tunnel.bytesOut
		result.responseDuration = tunnel.handshakeDuration
		if err != nil {
			result.proxyError = true
			result.errorMessage = errorText(err)
			h.logger.Warn("protocol upgrade failed", "request_id", id, "route", rt.cfg.Name, "upstream", result.upstream, "error", err)
			if !tunnel.hijacked {
				http.Error(w, "bad gateway", http.StatusBadGateway)
			}
		}
		return result
	}

	if stale != nil && retryableStatus(resp.StatusCode) {
		result.cacheStatus = "STALE"
		if err := serveCacheEntry(w, req, *stale, "STALE", time.Now()); err != nil {
			h.recordResponseCopyError(&result, req, rt.cfg.Name, id, err)
		}
		return result
	}

	// A successful unsafe request changes server state and therefore invalidates
	// every cached representation of its effective request URI. Purge all Vary
	// variants before returning the mutation response so a following GET cannot
	// observe stale data until the normal TTL expires.
	invalidateUnsafeRequest(rt, req, resp.StatusCode)

	removeHopByHop(resp.Header)
	sanitizeOriginResponseHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Via", "1.1 edgeproxy-go")
	w.Header().Set("X-Cache", cacheStatus)
	w.Header().Set("X-Upstream-Response-Time", formatDuration(result.upstreamDuration))

	policyNow := time.Now()
	cacheable, expiresAt, staleUntil, initialAge := responseCachePolicy(req, resp, rt.cfg.Cache, policyNow)
	// requestCacheMode is the authoritative request-side decision. A request
	// bypassed because it carries credentials, cookies, a Range field, an
	// unsupported method, or an explicit no-store directive must never populate
	// the shared cache even when the Origin response is otherwise cacheable.
	cacheable = cacheable && store
	if !cacheable || req.Method == http.MethodHead || rt.cache == nil {
		if !cacheable {
			result.cacheStatus = "BYPASS"
			w.Header().Set("X-Cache", "BYPASS")
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			h.recordResponseCopyError(&result, req, rt.cfg.Name, id, err)
		}
		return result
	}

	w.WriteHeader(resp.StatusCode)
	capture := &cappedBuffer{max: rt.cfg.Cache.MaxObjectBytes}
	_, copyErr := io.Copy(io.MultiWriter(w, capture), resp.Body)
	if copyErr != nil {
		h.recordResponseCopyError(&result, req, rt.cfg.Name, id, copyErr)
	}
	if copyErr == nil && !capture.overflow {
		cacheHeader := resp.Header.Clone()
		// A response may be explicitly eligible for body caching even when it
		// sets a cookie. Never replay that per-client cookie from shared cache.
		cacheHeader.Del("Set-Cookie")
		entry := cache.Entry{
			StatusCode: resp.StatusCode,
			Header:     cacheHeader,
			Body:       append([]byte(nil), capture.Bytes()...),
			StoredAt:   policyNow.Add(-initialAge),
			ExpiresAt:  expiresAt,
			StaleUntil: staleUntil,
		}
		if !operationalProbe && rt.cache.Set(cacheKey(req, rt.cfg.Cache), entry) {
			h.metrics.RecordCacheStore(rt.cfg.Name)
		}
	}
	return result
}

type protocolTunnelResult struct {
	bytesIn           uint64
	bytesOut          uint64
	handshakeDuration time.Duration
	hijacked          bool
}

type tunnelCopyResult struct {
	direction string
	bytes     int64
}

// proxyProtocolUpgrade completes a validated HTTP/1.1 protocol switch and
// then proxies the resulting byte stream in both directions. Request-scoped
// HTTP timeouts are intentionally disabled for upgrade requests because the
// switched protocol (for example WebSocket) can be long-lived. Managed handler
// shutdown explicitly closes tracked client/backend tunnel connections.
func (h *Handler) proxyProtocolUpgrade(w http.ResponseWriter, req *http.Request, resp *http.Response, requestID string, started time.Time) (protocolTunnelResult, error) {
	requested, err := protocolUpgrade(req.Header)
	if err != nil {
		return protocolTunnelResult{}, err
	}
	if requested == "" {
		return protocolTunnelResult{}, errors.New("origin switched protocols without a valid client upgrade request")
	}
	selected, err := protocolUpgrade(resp.Header)
	if err != nil {
		return protocolTunnelResult{}, fmt.Errorf("invalid origin protocol upgrade response: %w", err)
	}
	if selected == "" || !strings.EqualFold(requested, selected) {
		return protocolTunnelResult{}, fmt.Errorf("origin switched to protocol %q while client requested %q", selected, requested)
	}
	backend, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return protocolTunnelResult{}, errors.New("origin protocol upgrade response is not bidirectional")
	}

	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return protocolTunnelResult{}, fmt.Errorf("hijack client connection: %w", err)
	}
	// net/http may leave the Server ReadTimeout/WriteTimeout deadlines on a
	// hijacked connection. Those limits protect the HTTP handshake, but must not
	// become the lifetime limit of the switched protocol (for example WebSocket).
	if err := client.SetDeadline(time.Time{}); err != nil {
		_ = client.Close()
		_ = backend.Close()
		return protocolTunnelResult{hijacked: true}, fmt.Errorf("clear hijacked client deadline: %w", err)
	}
	result := protocolTunnelResult{hijacked: true}
	tunnel, ok := h.registerProtocolTunnel(client, backend)
	if !ok {
		return result, errors.New("proxy is shutting down")
	}
	defer h.unregisterProtocolTunnel(tunnel)
	defer tunnel.Close()
	if recorder, ok := w.(interface{ markHijackedStatus(int) }); ok {
		recorder.markHijackedStatus(http.StatusSwitchingProtocols)
	}

	header := resp.Header.Clone()
	removeHopByHop(header)
	sanitizeOriginResponseHeaders(header)
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", selected)
	header.Set("Via", "1.1 edgeproxy-go")
	header.Set("X-Request-ID", requestID)
	response := new(http.Response)
	*response = *resp
	response.Header = header
	response.Body = nil
	if err := response.Write(buffered); err != nil {
		return result, fmt.Errorf("write protocol upgrade response: %w", err)
	}
	if err := buffered.Flush(); err != nil {
		return result, fmt.Errorf("flush protocol upgrade response: %w", err)
	}
	result.handshakeDuration = time.Since(started)

	results := make(chan tunnelCopyResult, 2)
	go func() {
		// The bufio.Reader returned by Hijack may already contain protocol bytes
		// read ahead by net/http together with the HTTP upgrade request. Continue
		// client -> backend copying through that reader so those bytes are not
		// stranded or lost before the raw net.Conn is consumed. Once its buffer
		// is empty, the reader transparently continues from the same connection.
		n, _ := io.Copy(backend, buffered.Reader)
		results <- tunnelCopyResult{direction: "in", bytes: n}
	}()
	go func() {
		n, _ := io.Copy(client, backend)
		results <- tunnelCopyResult{direction: "out", bytes: n}
	}()

	first := <-results
	tunnel.Close()
	second := <-results
	for _, copyResult := range []tunnelCopyResult{first, second} {
		if copyResult.bytes < 0 {
			continue
		}
		if copyResult.direction == "in" {
			result.bytesIn = uint64(copyResult.bytes)
		} else {
			result.bytesOut = uint64(copyResult.bytes)
		}
	}
	return result, nil
}

func invalidateUnsafeRequest(rt *routeRuntime, req *http.Request, status int) int {
	if rt == nil || rt.cache == nil || req == nil || !unsafeMethod(req.Method) || status < 200 || status >= 400 {
		return 0
	}
	return rt.cache.PurgeRequest(cacheHost(req.Host), canonicalRequestURI(req.URL), cacheKeyRequest)
}

func unsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

func (h *Handler) recordResponseCopyError(result *requestResult, req *http.Request, route, requestID string, err error) {
	if err == nil {
		return
	}
	if req != nil && req.Context().Err() != nil {
		result.clientCanceled = true
		result.proxyError = false
		result.errorMessage = errorText(req.Context().Err())
		h.logger.Info("response forwarding canceled with client request",
			"request_id", requestID,
			"route", route,
			"client_ip", clientIP(req),
			"upstream", result.upstream,
			"error", req.Context().Err(),
		)
		return
	}
	result.proxyError = true
	result.errorMessage = errorText(err)
	h.logger.Warn("response body forwarding failed",
		"request_id", requestID,
		"route", route,
		"client_ip", clientIP(req),
		"upstream", result.upstream,
		"error", err,
	)
}

func (h *Handler) recordUpstreamAttempt(req *http.Request, route, requestID, upstreamURL string, attempt, status int, duration time.Duration, retry, timeout bool, err error, failed, canceled bool) {
	if h.logs == nil {
		return
	}
	level := "INFO"
	message := "origin request attempt completed"
	if failed {
		level = "WARN"
	}
	if err != nil && !canceled {
		level = "ERROR"
	}
	if canceled {
		message = "origin request attempt canceled with client request"
	}
	h.logs.Append(accesslog.Entry{
		Level:              level,
		Event:              "upstream_attempt",
		Message:            message,
		RequestID:          requestID,
		ClientIP:           clientIP(req),
		Method:             req.Method,
		Host:               req.Host,
		Path:               req.URL.EscapedPath(),
		Query:              sanitizedQuery(req),
		Route:              route,
		Upstream:           upstreamURL,
		UpstreamStatus:     status,
		UpstreamDurationMS: durationMS(duration),
		Attempt:            attempt,
		Retry:              retry,
		Timeout:            timeout,
		Canceled:           canceled,
		Error:              errorText(err),
		Tags:               []string{"origin", "upstream"},
	})
}

func (h *Handler) recordHealthChange(route string, change healthChange) {
	level := "INFO"
	message := "origin recovered"
	if !change.Healthy {
		level = "WARN"
		message = "origin became unhealthy"
	}
	h.logger.Log(context.Background(), parseLogLevel(level), message,
		"route", route,
		"upstream", change.Upstream,
		"healthy", change.Healthy,
		"status", change.Status,
		"duration_ms", durationMS(change.Duration),
		"error", change.Error,
	)
	if h.logs != nil {
		healthy := change.Healthy
		h.logs.Append(accesslog.Entry{
			Level:              level,
			Event:              "upstream_health_changed",
			Message:            message,
			Route:              route,
			Upstream:           change.Upstream,
			UpstreamStatus:     change.Status,
			UpstreamDurationMS: durationMS(change.Duration),
			Healthy:            &healthy,
			Error:              change.Error,
			Tags:               []string{"health", "origin"},
		})
	}
}

func parseLogLevel(level string) slog.Level {
	if strings.EqualFold(level, "ERROR") {
		return slog.LevelError
	}
	if strings.EqualFold(level, "WARN") {
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func sanitizedQuery(req *http.Request) string {
	values := req.URL.Query()
	for key := range values {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") || strings.Contains(lower, "passwd") ||
			strings.Contains(lower, "authorization") || strings.Contains(lower, "api_key") ||
			strings.Contains(lower, "apikey") || strings.Contains(lower, "signature") {
			values.Set(key, "[REDACTED]")
		}
	}
	return values.Encode()
}

func durationMS(duration time.Duration) float64 {
	if duration < 0 {
		return 0
	}
	return float64(duration) / float64(time.Millisecond)
}

func maxInt64(value, minimum int64) int64 {
	if value < minimum {
		return minimum
	}
	return value
}

func saturatingAddUint64(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}

func cloneRequest(ctx context.Context, in *http.Request, node *upstream, cfg *config.RouteConfig, id, forwardedForHeader string) (*http.Request, error) {
	upgrade, err := protocolUpgrade(in.Header)
	if err != nil {
		return nil, err
	}
	out := in.Clone(ctx)
	out.URL = rewriteURL(in.URL, node.url, cfg.PathPrefix, cfg.StripPrefix)
	out.RequestURI = ""
	out.Close = false
	out.Header = in.Header.Clone()
	removeHopByHop(out.Header)
	out.Header.Del(internalProbeHeader)
	// Treat all inbound forwarding identity headers as untrusted. This edge
	// reconstructs the canonical forwarding metadata below from the resolved
	// client address and the actual incoming request.
	removeForwardingIdentityHeaders(out.Header, forwardedForHeader)
	if !cfg.PreserveHost {
		out.Host = node.url.Host
	}
	ip := clientIP(in)
	// This process is the trusted edge. Discard a client-supplied X-Forwarded-For
	// value so an untrusted client cannot spoof its source address.
	out.Header.Set("X-Forwarded-For", ip)
	proto := "http"
	if in.TLS != nil {
		proto = "https"
	}
	out.Header.Set("X-Forwarded-Proto", proto)
	out.Header.Set("X-Forwarded-Host", in.Host)
	out.Header.Set("X-Request-ID", id)
	out.Header.Add("Via", "1.1 edgeproxy-go")
	if upgrade != "" {
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", upgrade)
	}
	if in.GetBody != nil && in.Body != nil {
		body, err := in.GetBody()
		if err != nil {
			return nil, err
		}
		out.Body = body
	}
	return out, nil
}

func retryableStatus(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func serveCacheEntry(w http.ResponseWriter, req *http.Request, entry cache.Entry, status string, now time.Time) error {
	if err := req.Context().Err(); err != nil {
		return err
	}
	// Sanitize a private header copy rather than the destination map. The
	// destination already contains the current request's authoritative edge
	// metadata, including X-Request-ID.
	header := entry.Header.Clone()
	removeHopByHop(header)
	sanitizeOriginResponseHeaders(header)
	copyHeaders(w.Header(), header)
	age := int(now.Sub(entry.StoredAt).Seconds())
	if age < 0 {
		age = 0
	}
	w.Header().Set("Age", strconv.Itoa(age))
	w.Header().Set("X-Cache", status)
	w.Header().Set("Via", "1.1 edgeproxy-go")
	if conditionalNotModified(req, entry.Header, entry.StatusCode) {
		w.Header().Del("Content-Length")
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(entry.Body)))
	w.WriteHeader(entry.StatusCode)
	if req.Method != http.MethodHead {
		_, err := w.Write(entry.Body)
		return err
	}
	return nil
}

func formatDuration(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d.Microseconds())/1000)
}

// countingReadCloser records bytes consumed from a request body whose size was
// not declared up front (for example, an HTTP/1.1 chunked upload). The atomic
// counter remains safe if the transport finishes reading or closing the body
// concurrently with response processing.
type countingReadCloser struct {
	io.ReadCloser
	bytes atomic.Uint64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.bytes.Add(uint64(n))
	}
	return n, err
}

func (r *countingReadCloser) BytesRead() uint64 { return r.bytes.Load() }

type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseCapture) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}
func (w *responseCapture) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *responseCapture) markHijackedStatus(status int) {
	if w.status == 0 {
		w.status = status
	}
}
