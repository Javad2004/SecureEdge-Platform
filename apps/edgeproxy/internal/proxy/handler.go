package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/bachelor-project/edgeproxy/internal/cache"
	"github.com/bachelor-project/edgeproxy/internal/config"
	"github.com/bachelor-project/edgeproxy/internal/metrics"
	"github.com/bachelor-project/edgeproxy/internal/router"
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
	routes  map[string]*routeRuntime
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewHandler(cfg config.Config, logger *slog.Logger, registry *metrics.Registry) (*Handler, error) {
	ctx, cancel := context.WithCancel(context.Background())
	h := &Handler{logger: logger, router: router.New(cfg.Routes), metrics: registry, routes: make(map[string]*routeRuntime), cancel: cancel}
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
			go func(rt *routeRuntime) { defer h.wg.Done(); rt.pool.runHealthChecks(ctx, rt.cfg.HealthCheck) }(runtime)
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
	finish := h.metrics.Begin(rt.cfg.Name, bytesIn)
	rw := &responseCapture{ResponseWriter: w}
	result := requestResult{cacheStatus: "BYPASS"}
	defer func() {
		status := rw.status
		if status == 0 {
			status = http.StatusOK
		}
		finish(status, uint64(rw.bytes), time.Since(started), result.upstreamDuration, result.proxyError, result.upstreamCalls, result.retries, result.cacheStatus)
		h.logger.Info("request",
			"request_id", id, "client_ip", clientIP(req), "method", req.Method,
			"host", req.Host, "path", req.URL.RequestURI(), "route", rt.cfg.Name,
			"status", status, "bytes_out", rw.bytes, "duration_ms", float64(time.Since(started).Microseconds())/1000,
			"upstream", result.upstream, "upstream_duration_ms", float64(result.upstreamDuration.Microseconds())/1000,
			"cache", result.cacheStatus, "retries", result.retries,
		)
	}()

	result = h.handleRoute(rw, req, rt, id)
}

type requestResult struct {
	cacheStatus      string
	upstream         string
	upstreamDuration time.Duration
	upstreamCalls    uint64
	retries          uint64
	proxyError       bool
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
	result := h.fetchAndServe(w, req, rt, id, stale, "MISS")
	return result
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
	for attempt := 0; attempt < attempts; attempt++ {
		node := rt.pool.pick(nil)
		if node == nil {
			break
		}
		outReq, err := cloneRequest(ctx, req, node, rt.cfg, id)
		if err != nil {
			lastErr = err
			break
		}
		start := time.Now()
		resp, err = node.transport.RoundTrip(outReq)
		elapsed := time.Since(start)
		result.upstreamDuration += elapsed
		result.upstreamCalls++
		result.upstream = node.url.String()
		if err == nil && !retryableStatus(resp.StatusCode) {
			lastErr = nil
			break
		}
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			lastErr = fmt.Errorf("upstream returned %s", resp.Status)
		} else {
			lastErr = err
		}
		node.healthy.Store(false)
		if attempt+1 < attempts {
			result.retries++
			if backoff := rt.cfg.Proxy.RetryBackoff.Duration; backoff > 0 {
				timer := time.NewTimer(backoff * time.Duration(attempt+1))
				select {
				case <-ctx.Done():
					timer.Stop()
					lastErr = ctx.Err()
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
		h.logger.Error("upstream request failed", "request_id", id, "route", rt.cfg.Name, "error", lastErr)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return result
	}
	defer resp.Body.Close()
	for _, node := range rt.pool.nodes {
		if node.url.String() == result.upstream {
			node.healthy.Store(true)
			break
		}
	}

	if stale != nil && retryableStatus(resp.StatusCode) {
		serveCacheEntry(w, req, *stale, "STALE", time.Now())
		result.cacheStatus = "STALE"
		return result
	}

	removeHopByHop(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Via", "1.1 edgeproxy-go")
	w.Header().Set("X-Cache", cacheStatus)
	w.Header().Set("X-Upstream", result.upstream)
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
			StoredAt:   time.Now(), ExpiresAt: expiresAt, StaleUntil: staleUntil,
		}
		if rt.cache.Set(cacheKey(req, rt.cfg.Cache), entry) {
			h.metrics.RecordCacheStore(rt.cfg.Name)
		}
	}
	return result
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
