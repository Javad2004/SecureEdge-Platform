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
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/cache"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/router"
)

type routeRuntime struct {
	cfg   *config.RouteConfig
	pool  *upstreamPool
	cache *cache.Cache
	fills *cache.KeyLocker
}

type Handler struct {
	logger  *slog.Logger
	router  *router.Router
	metrics *metrics.Registry
	logs    *accesslog.Store
	routes  map[string]*routeRuntime
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewHandler(cfg config.Config, logger *slog.Logger, registry *metrics.Registry, logStore *accesslog.Store) (*Handler, error) {
	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{
		logger:  logger,
		router:  router.New(cfg.Routes),
		metrics: registry,
		logs:    logStore,
		routes:  make(map[string]*routeRuntime),
		cancel:  cancel,
	}
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		pool, err := newUpstreamPool(*route)
		if err != nil {
			cancel()
			return nil, err
		}
		runtime := &routeRuntime{cfg: route, pool: pool, fills: cache.NewKeyLocker()}
		if route.Cache.Enabled {
			runtime.cache = cache.New(route.Cache.MaxEntries, route.Cache.MaxBytes)
		}
		h.routes[route.Name] = runtime
		if route.HealthCheck.Enabled {
			h.wg.Add(1)
			go func(rt *routeRuntime) {
				defer h.wg.Done()
				rt.pool.runHealthChecks(ctx, rt.cfg.HealthCheck, func(change healthChange) {
					h.recordHealthChange(rt.cfg.Name, change)
				})
			}(runtime)
		}
	}
	return h, nil
}

func (h *Handler) Close() {
	h.cancel()
	h.wg.Wait()
	for _, route := range h.routes {
		route.pool.closeIdleConnections()
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	started := time.Now()
	match, ok := h.router.Match(req)
	if !ok {
		http.Error(w, "no route configured for this host and path", http.StatusNotFound)
		return
	}
	rt := h.routes[match.Route.Name]
	id := requestID(req)
	w.Header().Set("X-Request-ID", id)

	bytesIn := uint64(0)
	if req.ContentLength > 0 {
		bytesIn = uint64(req.ContentLength)
	}
	finish := h.metrics.Begin(rt.cfg.Name, req.Method, bytesIn)
	rw := &responseCapture{ResponseWriter: w}
	result := requestResult{cacheStatus: "BYPASS"}
	defer func() {
		status := rw.status
		if status == 0 {
			status = http.StatusOK
		}
		duration := time.Since(started)
		finish(metrics.RequestObservation{
			Status:      status,
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
		return h.fetchAndServe(w, req, rt, id, nil, "BYPASS")
	}

	key := cacheKey(req, rt.cfg.Cache)
	now := time.Now()
	var stale *cache.Entry
	if lookup {
		entry, fresh, isStale := rt.cache.Get(key, now)
		if fresh {
			serveCacheEntry(w, req, entry, "HIT", now)
			return requestResult{cacheStatus: "HIT"}
		}
		if isStale {
			stale = &entry
		}
	}

	unlock := rt.fills.Lock(key)
	defer unlock()
	if lookup {
		entry, fresh, isStale := rt.cache.Get(key, time.Now())
		if fresh {
			serveCacheEntry(w, req, entry, "HIT", time.Now())
			return requestResult{cacheStatus: "HIT"}
		}
		if isStale {
			stale = &entry
		}
	}
	return h.fetchAndServe(w, req, rt, id, stale, "MISS")
}

func (h *Handler) fetchAndServe(w http.ResponseWriter, req *http.Request, rt *routeRuntime, id string, stale *cache.Entry, cacheStatus string) requestResult {
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
		outReq, err := cloneRequest(ctx, req, node, rt.cfg, id)
		if err != nil {
			lastErr = err
			break
		}

		started := time.Now()
		resp, err = node.transport.RoundTrip(outReq)
		elapsed := time.Since(started)
		result.upstreamDuration += elapsed
		result.upstreamCalls++
		result.upstream = node.url.String()
		status := 0
		if resp != nil {
			status = resp.StatusCode
			result.upstreamStatus = status
		}
		failed := err != nil || (resp != nil && retryableStatus(resp.StatusCode))
		attemptErr := err
		if attemptErr == nil && resp != nil && retryableStatus(resp.StatusCode) {
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
			if !node.healthy.Swap(true) {
				h.recordHealthChange(rt.cfg.Name, healthChange{Upstream: node.url.String(), Healthy: true, Status: status, Duration: elapsed})
			}
			break
		}

		if err == nil && resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		}
		lastErr = attemptErr
		result.errorMessage = errorText(lastErr)
		excluded[node] = true
		if node.healthy.Swap(false) {
			h.recordHealthChange(rt.cfg.Name, healthChange{Upstream: node.url.String(), Healthy: false, Status: status, Duration: elapsed, Error: errorText(lastErr)})
		}
		if attempt+1 < attempts {
			result.retries++
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

	removeHopByHop(resp.Header)
	sanitizeOriginResponseHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Via", "1.1 edgeproxy-go")
	w.Header().Set("X-Cache", cacheStatus)
	w.Header().Set("X-Upstream-Response-Time", formatDuration(result.upstreamDuration))

	cacheable, expiresAt, staleUntil := responseCachePolicy(req, resp, rt.cfg.Cache, time.Now())
	if !cacheable || req.Method == http.MethodHead || rt.cache == nil {
		if !cacheable {
			result.cacheStatus = "BYPASS"
			w.Header().Set("X-Cache", "BYPASS")
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return result
	}

	w.WriteHeader(resp.StatusCode)
	capture := &cappedBuffer{max: rt.cfg.Cache.MaxObjectBytes}
	_, copyErr := io.Copy(io.MultiWriter(w, capture), resp.Body)
	if copyErr == nil && !capture.overflow {
		entry := cache.Entry{
			StatusCode: resp.StatusCode,
			Header:     resp.Header.Clone(),
			Body:       append([]byte(nil), capture.Bytes()...),
			StoredAt:   time.Now(),
			ExpiresAt:  expiresAt,
			StaleUntil: staleUntil,
		}
		if rt.cache.Set(cacheKey(req, rt.cfg.Cache), entry) {
			h.metrics.RecordCacheStore(rt.cfg.Name)
		}
	}
	return result
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

func cloneRequest(ctx context.Context, in *http.Request, node *upstream, cfg *config.RouteConfig, id string) (*http.Request, error) {
	out := in.Clone(ctx)
	out.URL = rewriteURL(in.URL, node.url, cfg.PathPrefix, cfg.StripPrefix)
	out.RequestURI = ""
	out.Close = false
	out.Header = in.Header.Clone()
	removeHopByHop(out.Header)
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
	copyHeaders(w.Header(), entry.Header)
	removeHopByHop(w.Header())
	sanitizeOriginResponseHeaders(w.Header())
	age := int(now.Sub(entry.StoredAt).Seconds())
	if age < 0 {
		age = 0
	}
	w.Header().Set("Age", strconv.Itoa(age))
	w.Header().Set("X-Cache", status)
	w.Header().Set("Via", "1.1 edgeproxy-go")
	if conditionalNotModified(req, entry.Header) {
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
