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
}

func NewHandler(cfg config.Config, logger *slog.Logger, registry *metrics.Registry, logStore *accesslog.Store) (*Handler, error) {
	h := &Handler{logger: logger, metrics: registry, logs: logStore}
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
				rt.pool.runHealthChecks(ctx, rt.cfg.HealthCheck, func(change healthChange) {
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
	h.mu.Lock()
	routes, life := h.routes, h.life
	h.routes = map[string]*routeRuntime{}
	h.life = nil
	h.mu.Unlock()
	closeHandlerState(routes, life)
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
	finish := h.metrics.Begin(rt.cfg.Name, req.Method)
	rw := &responseCapture{ResponseWriter: w}
	result := requestResult{cacheStatus: "BYPASS"}
	defer func() {
		if streamedBody != nil {
			bytesIn = streamedBody.BytesRead()
		}
		status := rw.status
		if status == 0 {
			status = http.StatusOK
		}
		duration := time.Since(started)
		finish(metrics.RequestObservation{
			Status:      status,
			BytesIn:     bytesIn,
			BytesOut:    uint64(maxInt64(rw.bytes, 0)),
			Duration:    duration,
			ProxyError:  result.proxyError,
			Retries:     result.retries,
			CacheStatus: result.cacheStatus,
		})

		level := "INFO"
		if status >= 500 || result.proxyError {
			level = "ERROR"
		} else if status >= 400 {
			level = "WARN"
		}
		if h.logs != nil {
			h.logs.Append(accesslog.Entry{
				Level:              level,
				Event:              "request_completed",
				Message:            "client request completed",
				RequestID:          id,
				ClientIP:           clientIP(req),
				Method:             req.Method,
				Host:               req.Host,
				Path:               req.URL.EscapedPath(),
				Query:              sanitizedQuery(req),
				Route:              rt.cfg.Name,
				Status:             status,
				BytesIn:            bytesIn,
				BytesOut:           uint64(maxInt64(rw.bytes, 0)),
				DurationMS:         durationMS(duration),
				CacheStatus:        result.cacheStatus,
				Upstream:           result.upstream,
				UpstreamStatus:     result.upstreamStatus,
				UpstreamDurationMS: durationMS(result.upstreamDuration),
				UpstreamCalls:      result.upstreamCalls,
				Retries:            result.retries,
				ProxyError:         result.proxyError,
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
			"bytes_out", rw.bytes,
			"duration_ms", durationMS(duration),
			"upstream", result.upstream,
			"upstream_status", result.upstreamStatus,
			"upstream_calls", result.upstreamCalls,
			"upstream_duration_ms", durationMS(result.upstreamDuration),
			"cache", result.cacheStatus,
			"retries", result.retries,
			"proxy_error", result.proxyError,
		)
	}()

	result = h.handleRoute(rw, req, rt, id)
}

type requestResult struct {
	cacheStatus      string
	upstream         string
	upstreamStatus   int
	upstreamDuration time.Duration
	upstreamCalls    uint64
	retries          uint64
	proxyError       bool
	errorMessage     string
}

func (h *Handler) handleRoute(w http.ResponseWriter, req *http.Request, rt *routeRuntime, id string) requestResult {
	lookup, store, _ := requestCacheMode(req, rt.cfg.Cache)
	if !lookup && !store {
		return h.fetchAndServe(w, req, rt, id, nil, "BYPASS", false)
	}

	key := cacheKey(req, rt.cfg.Cache)
	now := time.Now()
	var stale *cache.Entry
	if lookup {
		entry, fresh, isStale := rt.cache.Get(key, now)
		allowed := requestAllowsCachedEntry(req, entry, now)
		if fresh && allowed {
			serveCacheEntry(w, req, entry, "HIT", now)
			return requestResult{cacheStatus: "HIT"}
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
			serveCacheEntry(w, req, entry, "HIT", now)
			return requestResult{cacheStatus: "HIT"}
		}
		if isStale && allowed {
			stale = &entry
		}
	}
	return h.fetchAndServe(w, req, rt, id, stale, "MISS", store)
}

func (h *Handler) fetchAndServe(w http.ResponseWriter, req *http.Request, rt *routeRuntime, id string, stale *cache.Entry, cacheStatus string, store bool) requestResult {
	result := requestResult{cacheStatus: cacheStatus}
	ctx := req.Context()
	if timeout := rt.cfg.Proxy.RequestTimeout.Duration; timeout > 0 {
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
	excluded := make(map[*upstream]bool)
	for attempt := 0; attempt < attempts; attempt++ {
		node := rt.pool.pick(excluded)
		if node == nil {
			if lastErr == nil {
				lastErr = errors.New("no eligible upstream available")
			}
			break
		}
		outReq, err := cloneRequest(ctx, req, node, rt.cfg, id, rt.forwardedForHeader)
		if err != nil {
			rt.pool.release(node, 0)
			lastErr = err
			break
		}

		started := time.Now()
		resp, err = node.transport.RoundTrip(outReq)
		elapsed := time.Since(started)
		rt.pool.release(node, elapsed)
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
		attemptErr := err
		if retryableResponse {
			attemptErr = fmt.Errorf("upstream returned %s", resp.Status)
		}
		timedOut := isTimeoutError(err)
		h.metrics.RecordUpstream(rt.cfg.Name, node.url.String(), metrics.UpstreamObservation{
			Status:   status,
			Duration: elapsed,
			Failed:   failed,
			Timeout:  timedOut,
			Retry:    attempt > 0,
		})
		h.recordUpstreamAttempt(req, rt.cfg.Name, id, node.url.String(), attempt+1, status, elapsed, attempt > 0, timedOut, attemptErr, failed)

		if !failed {
			lastErr = nil
			result.errorMessage = ""
			setNodeHealth(node, true, healthChange{Upstream: node.url.String(), Healthy: true, Status: status, Duration: elapsed}, func(change healthChange) {
				h.recordHealthChange(rt.cfg.Name, change)
			})
			break
		}

		// A cancellation or deadline inherited from the client request does not
		// indicate an origin failure. Preserve the origin's health and stop here:
		// every retry would inherit the same already-terminated context.
		if err != nil && req.Context().Err() != nil {
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
		setNodeHealth(node, false, healthChange{Upstream: node.url.String(), Healthy: false, Status: status, Duration: elapsed, Error: errorText(lastErr)}, func(change healthChange) {
			h.recordHealthChange(rt.cfg.Name, change)
		})

		canRetry := attempt+1 < attempts
		if retryableResponse && !canRetry {
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
					attempt = attempts
				case <-timer.C:
				}
			}
		}
	}

	if lastErr != nil || resp == nil {
		if stale != nil {
			serveCacheEntry(w, req, *stale, "STALE", time.Now())
			result.cacheStatus = "STALE"
			return result
		}
		result.proxyError = true
		result.errorMessage = errorText(lastErr)
		h.logger.Error("upstream request failed",
			"request_id", id,
			"route", rt.cfg.Name,
			"upstream", result.upstream,
			"upstream_calls", result.upstreamCalls,
			"retries", result.retries,
			"error", lastErr,
		)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return result
	}
	defer resp.Body.Close()

	if stale != nil && retryableStatus(resp.StatusCode) {
		serveCacheEntry(w, req, *stale, "STALE", time.Now())
		result.cacheStatus = "STALE"
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
		if rt.cache.Set(cacheKey(req, rt.cfg.Cache), entry) {
			h.metrics.RecordCacheStore(rt.cfg.Name)
		}
	}
	return result
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

func (h *Handler) recordUpstreamAttempt(req *http.Request, route, requestID, upstreamURL string, attempt, status int, duration time.Duration, retry, timeout bool, err error, failed bool) {
	if h.logs == nil {
		return
	}
	level := "INFO"
	if failed {
		level = "WARN"
	}
	if err != nil {
		level = "ERROR"
	}
	h.logs.Append(accesslog.Entry{
		Level:              level,
		Event:              "upstream_attempt",
		Message:            "origin request attempt completed",
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

func cloneRequest(ctx context.Context, in *http.Request, node *upstream, cfg *config.RouteConfig, id, forwardedForHeader string) (*http.Request, error) {
	out := in.Clone(ctx)
	out.URL = rewriteURL(in.URL, node.url, cfg.PathPrefix, cfg.StripPrefix)
	out.RequestURI = ""
	out.Close = false
	out.Header = in.Header.Clone()
	removeHopByHop(out.Header)
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

func serveCacheEntry(w http.ResponseWriter, req *http.Request, entry cache.Entry, status string, now time.Time) {
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
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(entry.Body)))
	w.WriteHeader(entry.StatusCode)
	if req.Method != http.MethodHead {
		_, _ = w.Write(entry.Body)
	}
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
