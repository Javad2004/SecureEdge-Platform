package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/cache"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
)

func testConfig(origin string) config.Config {
	return config.Config{Routes: []config.RouteConfig{{
		Name: "test", Hosts: []string{"proxy.test"}, PathPrefix: "/", Upstreams: []config.UpstreamConfig{{URL: origin}},
		Proxy: config.ProxyConfig{RequestTimeout: config.Duration{Duration: 5 * time.Second}, DialTimeout: config.Duration{Duration: time.Second}, ResponseHeaderTimeout: config.Duration{Duration: 2 * time.Second}, IdleConnTimeout: config.Duration{Duration: time.Minute}, RetryBackoff: config.Duration{Duration: time.Millisecond}, MaxIdleConns: 10, MaxIdleConnsPerHost: 10, MaxResponseHeaderBytes: 1 << 20},
		Cache: config.CacheConfig{Enabled: true, DefaultTTL: config.Duration{Duration: time.Minute}, StaleIfError: config.Duration{Duration: time.Minute}, MaxEntries: 10, MaxBytes: 1 << 20, MaxObjectBytes: 1 << 16, RespectOriginHeaders: true, VaryRequestHeaders: []string{"Accept"}, CacheableStatusCodes: []int{200}},
	}}}
}

func TestProxyCacheMissThenHit(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("missing X-Forwarded-For")
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "origin-body")
	}))
	defer origin.Close()
	h, err := NewHandler(testConfig(origin.URL), slog.New(slog.NewTextHandler(os.Stderr, nil)), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	for i, expected := range []string{"MISS", "HIT"} {
		req := httptest.NewRequest("GET", "http://proxy.test/data", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 || strings.TrimSpace(rr.Body.String()) != "origin-body" {
			t.Fatalf("request %d failed: %d %q", i, rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("X-Cache"); got != expected {
			t.Fatalf("request %d expected %s got %s", i, expected, got)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one origin call, got %d", calls.Load())
	}
}

func TestSuccessfulUnsafeRequestInvalidatesCachedVariants(t *testing.T) {
	var value atomic.Value
	value.Store("v1")
	var getCalls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getCalls.Add(1)
			w.Header().Set("Cache-Control", "public, max-age=60")
			_, _ = io.WriteString(w, value.Load().(string))
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read mutation body: %v", err)
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			value.Store(string(body))
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	get := func(accept, wantCache, wantBody string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://proxy.test/item?id=1", nil)
		req.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("X-Cache") != wantCache || strings.TrimSpace(rec.Body.String()) != wantBody {
			t.Fatalf("accept=%q code=%d cache=%q body=%q", accept, rec.Code, rec.Header().Get("X-Cache"), rec.Body.String())
		}
	}

	for _, accept := range []string{"text/plain", "application/json"} {
		get(accept, "MISS", "v1")
		get(accept, "HIT", "v1")
	}

	mutation := httptest.NewRequest(http.MethodPut, "http://proxy.test/item?id=1", strings.NewReader("v2"))
	mutationRec := httptest.NewRecorder()
	h.ServeHTTP(mutationRec, mutation)
	if mutationRec.Code != http.StatusNoContent {
		t.Fatalf("mutation status=%d body=%q", mutationRec.Code, mutationRec.Body.String())
	}

	for _, accept := range []string{"text/plain", "application/json"} {
		get(accept, "MISS", "v2")
	}
	if got := getCalls.Load(); got != 4 {
		t.Fatalf("origin GET calls=%d, want 4", got)
	}
}

func TestFailedUnsafeRequestKeepsCachedRepresentation(t *testing.T) {
	var getCalls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.Error(w, "mutation failed", http.StatusInternalServerError)
			return
		}
		getCalls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "stable")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://proxy.test/item", nil))
	if first.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("initial cache=%q", first.Header().Get("X-Cache"))
	}

	failed := httptest.NewRecorder()
	h.ServeHTTP(failed, httptest.NewRequest(http.MethodPost, "http://proxy.test/item", strings.NewReader("ignored")))
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("failed mutation status=%d", failed.Code)
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://proxy.test/item", nil))
	if second.Header().Get("X-Cache") != "HIT" || strings.TrimSpace(second.Body.String()) != "stable" {
		t.Fatalf("post-failure cache=%q body=%q", second.Header().Get("X-Cache"), second.Body.String())
	}
	if got := getCalls.Load(); got != 1 {
		t.Fatalf("origin GET calls=%d, want 1", got)
	}
}

func TestNoStoreBypassesCache(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "dynamic")
	}))
	defer origin.Close()
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", "http://proxy.test/time", nil))
		if rr.Header().Get("X-Cache") != "BYPASS" {
			t.Fatalf("expected bypass")
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls, got %d", calls.Load())
	}
}

func TestRetryOnTemporaryUpstreamFailure(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "recovered")
	}))
	defer origin.Close()
	cfg := testConfig(origin.URL)
	cfg.Routes[0].Proxy.RetryCount = 1
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://proxy.test/retry", nil))
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "recovered" {
		t.Fatalf("unexpected response: code=%d body=%q", rr.Code, rr.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("expected retry to create 2 calls, got %d", calls.Load())
	}
}

func TestStaleIfError(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=1")
		_, _ = io.WriteString(w, "cached-value")
	}))
	cfg := testConfig(origin.URL)
	cfg.Routes[0].Proxy.RetryCount = 0
	cfg.Routes[0].Cache.DefaultTTL = config.Duration{Duration: 10 * time.Millisecond}
	cfg.Routes[0].Cache.StaleIfError = config.Duration{Duration: time.Minute}
	cfg.Routes[0].Cache.RespectOriginHeaders = false
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://proxy.test/stale", nil))
	if first.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected initial MISS, got %q", first.Header().Get("X-Cache"))
	}
	origin.Close()
	time.Sleep(20 * time.Millisecond)

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://proxy.test/stale", nil))
	if second.Code != http.StatusOK || second.Header().Get("X-Cache") != "STALE" || strings.TrimSpace(second.Body.String()) != "cached-value" {
		t.Fatalf("expected stale response, code=%d cache=%q body=%q", second.Code, second.Header().Get("X-Cache"), second.Body.String())
	}
}

func TestCacheStampedePrevention(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "shared")
	}))
	defer origin.Close()
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	const clients = 12
	start := make(chan struct{})
	done := make(chan error, clients)
	for i := 0; i < clients; i++ {
		go func() {
			<-start
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://proxy.test/shared", nil))
			if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "shared" {
				done <- fmt.Errorf("code=%d body=%q", rr.Code, rr.Body.String())
				return
			}
			done <- nil
		}()
	}
	close(start)
	for i := 0; i < clients; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one origin fill, got %d", calls.Load())
	}
}

func TestCookieRangeAndUnsupportedVaryBypass(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		if r.URL.Path == "/vary" {
			w.Header().Set("Vary", "User-Agent")
		}
		_, _ = io.WriteString(w, "value")
	}))
	defer origin.Close()
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "http://proxy.test/cookie", nil),
		httptest.NewRequest(http.MethodGet, "http://proxy.test/range", nil),
		httptest.NewRequest(http.MethodGet, "http://proxy.test/vary", nil),
	}
	requests[0].Header.Set("Cookie", "session=abc")
	requests[1].Header.Set("Range", "bytes=0-2")
	for _, req := range requests {
		for i := 0; i < 2; i++ {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req.Clone(req.Context()))
			if rr.Header().Get("X-Cache") != "BYPASS" {
				t.Fatalf("path %s expected BYPASS, got %q", req.URL.Path, rr.Header().Get("X-Cache"))
			}
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("expected 6 origin calls, got %d", calls.Load())
	}
}

func TestConditionalRequestFromCache(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, "etag-body")
	}))
	defer origin.Close()
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://proxy.test/etag", nil))
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/etag", nil)
	req.Header.Set("If-None-Match", `"v1"`)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotModified || rr.Header().Get("X-Cache") != "HIT" || rr.Body.Len() != 0 {
		t.Fatalf("unexpected conditional response: code=%d cache=%q body=%q", rr.Code, rr.Header().Get("X-Cache"), rr.Body.String())
	}
}

func TestRoundRobinMetricsAndPerOriginLogs(t *testing.T) {
	originA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "origin-a")
	}))
	defer originA.Close()
	originB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "origin-b")
	}))
	defer originB.Close()

	cfg := testConfig(originA.URL)
	cfg.Routes[0].Upstreams = []config.UpstreamConfig{{URL: originA.URL}, {URL: originB.URL}}
	registry := metrics.New()
	logs := accesslog.New(100)
	h, err := NewHandler(cfg, slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	got := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://proxy.test/time", nil))
		got = append(got, strings.TrimSpace(rr.Body.String()))
	}
	want := []string{"origin-a", "origin-b", "origin-a", "origin-b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d expected %q got %q; all=%v", i, want[i], got[i], got)
		}
	}

	snapshot := registry.Snapshot()
	route := snapshot.Routes["test"]
	if route.Upstreams[originA.URL].Calls != 2 || route.Upstreams[originB.URL].Calls != 2 {
		t.Fatalf("unexpected per-origin metrics: %#v", route.Upstreams)
	}
	originALogs := logs.Query(accesslog.Filter{Event: "upstream_attempt", Upstream: originA.URL, Limit: 10})
	originBLogs := logs.Query(accesslog.Filter{Event: "upstream_attempt", Upstream: originB.URL, Limit: 10})
	if len(originALogs.Entries) != 2 || len(originBLogs.Entries) != 2 {
		t.Fatalf("unexpected per-origin logs: a=%d b=%d", len(originALogs.Entries), len(originBLogs.Entries))
	}
}

func TestRetryUsesAnotherOriginAndCorrelatesLogs(t *testing.T) {
	var firstCalls atomic.Int64
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstCalls.Add(1)
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer first.Close()
	var secondCalls atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondCalls.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "recovered-by-second-origin")
	}))
	defer second.Close()

	cfg := testConfig(first.URL)
	cfg.Routes[0].Upstreams = []config.UpstreamConfig{{URL: first.URL}, {URL: second.URL}}
	cfg.Routes[0].Proxy.RetryCount = 1
	registry := metrics.New()
	logs := accesslog.New(100)
	h, err := NewHandler(cfg, slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://proxy.test/retry-two-origins", nil))
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "recovered-by-second-origin" {
		t.Fatalf("unexpected response: code=%d body=%q", rr.Code, rr.Body.String())
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatalf("unexpected calls: first=%d second=%d", firstCalls.Load(), secondCalls.Load())
	}

	attempts := logs.Query(accesslog.Filter{Event: "upstream_attempt", Limit: 10})
	if len(attempts.Entries) != 2 {
		t.Fatalf("expected 2 attempt logs, got %d", len(attempts.Entries))
	}
	// Entries are newest-first: second origin is the retry.
	if !attempts.Entries[0].Retry || attempts.Entries[0].Attempt != 2 || attempts.Entries[0].Upstream != second.URL {
		t.Fatalf("unexpected retry entry: %#v", attempts.Entries[0])
	}
	if attempts.Entries[0].RequestID == "" || attempts.Entries[0].RequestID != attempts.Entries[1].RequestID {
		t.Fatalf("attempt logs are not correlated: %#v", attempts.Entries)
	}
}

func TestProcessLogRedactsSensitiveQueryValues(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	h, err := NewHandler(testConfig(origin.URL), logger, metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/data?token=super-secret&normal=value", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	logged := output.String()
	if strings.Contains(logged, "super-secret") || !strings.Contains(logged, "normal=value") || !strings.Contains(logged, "%5BREDACTED%5D") {
		t.Fatalf("process log did not safely redact the query: %s", logged)
	}
}

func TestAccessLogRedactsSensitiveQueryValues(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	logs := accesslog.New(20)
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/data?token=super-secret&normal=value", nil)
	req.Header.Set("Authorization", "Bearer must-not-be-retained")
	h.ServeHTTP(httptest.NewRecorder(), req)
	result := logs.Query(accesslog.Filter{Event: "request_completed", Limit: 10})
	if len(result.Entries) != 1 {
		t.Fatalf("expected request log")
	}
	query := result.Entries[0].Query
	if strings.Contains(query, "super-secret") || !strings.Contains(query, "normal=value") || !strings.Contains(query, "REDACTED") {
		t.Fatalf("query was not safely redacted: %q", query)
	}
}

func TestClientCancellationPreservesOriginHealthAndStopsRetries(t *testing.T) {
	var firstCalls atomic.Int64
	started := make(chan struct{}, 1)
	first := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer first.Close()

	var secondCalls atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	cfg := testConfig(first.URL)
	cfg.Routes[0].Upstreams = []config.UpstreamConfig{{URL: first.URL}, {URL: second.URL}}
	cfg.Routes[0].Cache.Enabled = false
	cfg.Routes[0].Proxy.RetryCount = 3
	cfg.Routes[0].Proxy.RetryBackoff = config.Duration{}
	logs := accesslog.New(20)
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/cancel", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin did not receive the request")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not stop after client cancellation")
	}

	if firstCalls.Load() != 1 || secondCalls.Load() != 0 {
		t.Fatalf("unexpected origin calls after cancellation: first=%d second=%d", firstCalls.Load(), secondCalls.Load())
	}
	attempts := logs.Query(accesslog.Filter{Event: "upstream_attempt", Limit: 10})
	if len(attempts.Entries) != 1 {
		t.Fatalf("upstream attempts=%d, want 1", len(attempts.Entries))
	}
	for _, node := range h.routes["test"].pool.nodes {
		if !node.healthy.Load() {
			t.Fatalf("client cancellation marked origin %s unhealthy", node.url)
		}
	}
	if status := h.Readiness(); !status.Ready {
		t.Fatalf("client cancellation changed readiness: %#v", status)
	}
}

func TestRouteTimeoutStopsRetriesAfterMarkingFailedOrigin(t *testing.T) {
	var firstCalls atomic.Int64
	first := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		<-r.Context().Done()
	}))
	defer first.Close()

	var secondCalls atomic.Int64
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	cfg := testConfig(first.URL)
	cfg.Routes[0].Upstreams = []config.UpstreamConfig{{URL: first.URL}, {URL: second.URL}}
	cfg.Routes[0].Cache.Enabled = false
	cfg.Routes[0].Proxy.RequestTimeout = config.Duration{Duration: 25 * time.Millisecond}
	cfg.Routes[0].Proxy.RetryCount = 3
	cfg.Routes[0].Proxy.RetryBackoff = config.Duration{}
	logs := accesslog.New(20)
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.test/timeout", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusBadGateway)
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 0 {
		t.Fatalf("unexpected origin calls after route timeout: first=%d second=%d", firstCalls.Load(), secondCalls.Load())
	}
	attempts := logs.Query(accesslog.Filter{Event: "upstream_attempt", Limit: 10})
	if len(attempts.Entries) != 1 || !attempts.Entries[0].Timeout {
		t.Fatalf("unexpected timeout attempts: %#v", attempts.Entries)
	}
	nodes := h.routes["test"].pool.nodes
	if nodes[0].healthy.Load() {
		t.Fatal("timed-out origin remained healthy")
	}
	if !nodes[1].healthy.Load() {
		t.Fatal("unattempted origin was marked unhealthy")
	}
}

func TestReadinessRequiresOneHealthyOriginPerRoute(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if status := h.Readiness(); !status.Ready || len(status.UnhealthyRoutes) != 0 {
		t.Fatalf("expected ready handler, got %#v", status)
	}

	h.routes["test"].pool.nodes[0].healthy.Store(false)
	status := h.Readiness()
	if status.Ready || len(status.UnhealthyRoutes) != 1 || status.UnhealthyRoutes[0] != "test" {
		t.Fatalf("expected test route to be not ready, got %#v", status)
	}
}

func TestProxyHidesOriginImplementationHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Server", "origin-server/1.0")
		w.Header().Set("X-Powered-By", "example-framework")
		w.Header().Set("X-AspNet-Version", "4.0")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	for _, expectedCache := range []string{"MISS", "HIT"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://proxy.test/headers", nil))
		if rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != expectedCache {
			t.Fatalf("unexpected response: code=%d cache=%q", rr.Code, rr.Header().Get("X-Cache"))
		}
		for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Upstream"} {
			if value := rr.Header().Get(name); value != "" {
				t.Fatalf("response leaked %s=%q", name, value)
			}
		}
	}
}

func TestConditionalRequestDoesNotPartiallyMatchETag(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", `"v1"`)
		_, _ = io.WriteString(w, "etag-body")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://proxy.test/etag-exact", nil))

	partial := httptest.NewRequest(http.MethodGet, "http://proxy.test/etag-exact", nil)
	partial.Header.Set("If-None-Match", `"v10"`)
	partialResponse := httptest.NewRecorder()
	h.ServeHTTP(partialResponse, partial)
	if partialResponse.Code != http.StatusOK || partialResponse.Body.String() != "etag-body" {
		t.Fatalf("partial ETag incorrectly matched: code=%d body=%q", partialResponse.Code, partialResponse.Body.String())
	}

	weak := httptest.NewRequest(http.MethodGet, "http://proxy.test/etag-exact", nil)
	weak.Header.Set("If-None-Match", `W/"v1"`)
	weakResponse := httptest.NewRecorder()
	h.ServeHTTP(weakResponse, weak)
	if weakResponse.Code != http.StatusNotModified {
		t.Fatalf("weak ETag should match a strong ETag for If-None-Match, got %d", weakResponse.Code)
	}
}

func TestIfNoneMatchWildcardMatchesCachedResponseWithoutETag(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "cached-body")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://proxy.test/wildcard", nil))

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/wildcard", nil)
	req.Header.Set("If-None-Match", "*")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 || response.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("code=%d body=%q cache=%q", response.Code, response.Body.String(), response.Header().Get("X-Cache"))
	}
}

func TestIfNoneMatchWildcardDoesNotMatchCachedNotFound(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "missing")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.CacheableStatusCodes = append(cfg.Routes[0].Cache.CacheableStatusCodes, http.StatusNotFound)
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://proxy.test/missing", nil))

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/missing", nil)
	req.Header.Set("If-None-Match", "*")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound || response.Body.String() != "missing" || response.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("code=%d body=%q cache=%q", response.Code, response.Body.String(), response.Header().Get("X-Cache"))
	}
}

func TestConditionalHeadersDoNotConvertCachedNotFoundToNotModified(t *testing.T) {
	modified := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", `"missing-v1"`)
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "missing")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.CacheableStatusCodes = append(cfg.Routes[0].Cache.CacheableStatusCodes, http.StatusNotFound)
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://proxy.test/missing-conditional", nil))

	for name, header := range map[string]string{
		"etag":          `"missing-v1"`,
		"last-modified": modified.Add(time.Minute).Format(http.TimeFormat),
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://proxy.test/missing-conditional", nil)
			if name == "etag" {
				req.Header.Set("If-None-Match", header)
			} else {
				req.Header.Set("If-Modified-Since", header)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if response.Code != http.StatusNotFound || response.Body.String() != "missing" || response.Header().Get("X-Cache") != "HIT" {
				t.Fatalf("code=%d body=%q cache=%q", response.Code, response.Body.String(), response.Header().Get("X-Cache"))
			}
		})
	}
}

func TestTrustedProxyPreservesOriginalClientIP(t *testing.T) {
	var forwarded string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("X-Forwarded-For")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Server.TrustedProxyCIDRs = []string{"127.0.0.0/8"}
	cfg.Server.ForwardedForHeader = "X-Forwarded-For"
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/client-ip", nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.25")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if forwarded != "198.51.100.25" {
		t.Fatalf("expected original client IP, got %q", forwarded)
	}
}

func TestUntrustedClientCannotSpoofForwardedFor(t *testing.T) {
	var forwarded string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("X-Forwarded-For")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Server.TrustedProxyCIDRs = []string{"127.0.0.0/8"}
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/client-ip", nil)
	req.RemoteAddr = "203.0.113.44:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.25")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if forwarded != "203.0.113.44" {
		t.Fatalf("spoofed forwarded address was trusted: %q", forwarded)
	}
}

func TestForwardingIdentityHeadersAreRebuilt(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/identity", nil)
	req.RemoteAddr = "203.0.113.44:43210"
	for name, value := range map[string]string{
		"Forwarded":          "for=198.51.100.25;proto=https",
		"CF-Connecting-IP":   "198.51.100.25",
		"X-Client-IP":        "198.51.100.25",
		"X-Real-IP":          "198.51.100.25",
		"True-Client-IP":     "198.51.100.25",
		"X-Forwarded-For":    "198.51.100.25",
		"X-Forwarded-Host":   "spoofed.example",
		"X-Forwarded-Proto":  "https",
		"X-Forwarded-Port":   "443",
		"X-Forwarded-Server": "spoofed-edge",
	} {
		req.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}

	headers := <-seen
	for _, name := range []string{"Forwarded", "CF-Connecting-IP", "X-Client-IP", "X-Real-IP", "True-Client-IP", "X-Forwarded-Port", "X-Forwarded-Server"} {
		if got := headers.Get(name); got != "" {
			t.Fatalf("untrusted %s leaked to origin: %q", name, got)
		}
	}
	if got := headers.Get("X-Forwarded-For"); got != "203.0.113.44" {
		t.Fatalf("X-Forwarded-For=%q", got)
	}
	if got := headers.Get("X-Forwarded-Host"); got != "proxy.test" {
		t.Fatalf("X-Forwarded-Host=%q", got)
	}
	if got := headers.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto=%q", got)
	}
}

func TestNoCacheResponseIsNotStored(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = io.WriteString(w, "must-revalidate")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://proxy.test/no-cache", nil))
		if rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != "BYPASS" {
			t.Fatalf("request %d code=%d cache=%q", i, rr.Code, rr.Header().Get("X-Cache"))
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("no-cache response was stored; origin calls=%d", calls.Load())
	}
}

func TestIfNoneMatchTakesPrecedenceOverIfModifiedSince(t *testing.T) {
	header := make(http.Header)
	header.Set("ETag", `"current"`)
	header.Set("Last-Modified", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
	req.Header.Set("If-None-Match", `"different"`)
	req.Header.Set("If-Modified-Since", time.Now().UTC().Format(http.TimeFormat))
	if conditionalNotModified(req, header, http.StatusOK) {
		t.Fatal("If-Modified-Since must be ignored when If-None-Match is present and does not match")
	}
}

func TestResponseCachePolicyAccountsForAgeAndDate(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	cfg := testConfig("http://127.0.0.1").Routes[0].Cache

	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	resp.Header.Set("Cache-Control", "public, max-age=60")
	resp.Header.Set("Age", "40")
	resp.Header.Set("Date", now.Add(-30*time.Second).Format(http.TimeFormat))

	cacheable, expiresAt, staleUntil, initialAge := responseCachePolicy(
		httptest.NewRequest(http.MethodGet, "http://proxy.test/aged", nil),
		resp,
		cfg,
		now,
	)
	if !cacheable {
		t.Fatal("response with remaining freshness should be cacheable")
	}
	if initialAge != 40*time.Second {
		t.Fatalf("initial age=%s, want 40s", initialAge)
	}
	if got := expiresAt.Sub(now); got != 20*time.Second {
		t.Fatalf("remaining freshness=%s, want 20s", got)
	}
	if got := staleUntil.Sub(expiresAt); got != cfg.StaleIfError.Duration {
		t.Fatalf("stale window=%s, want %s", got, cfg.StaleIfError.Duration)
	}

	resp.Header.Del("Age")
	resp.Header.Set("Date", now.Add(-50*time.Second).Format(http.TimeFormat))
	cacheable, expiresAt, _, initialAge = responseCachePolicy(
		httptest.NewRequest(http.MethodGet, "http://proxy.test/dated", nil),
		resp,
		cfg,
		now,
	)
	if !cacheable || initialAge != 50*time.Second || expiresAt.Sub(now) != 10*time.Second {
		t.Fatalf("date-derived age not applied: cacheable=%v age=%s remaining=%s", cacheable, initialAge, expiresAt.Sub(now))
	}
}

func TestCachedResponsePreservesUpstreamAge(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Age", "30")
		w.Header().Set("Date", time.Now().Add(-20*time.Second).UTC().Format(http.TimeFormat))
		_, _ = io.WriteString(w, "aged-body")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://proxy.test/aged", nil))
	if first.Code != http.StatusOK || first.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first response code=%d cache=%q", first.Code, first.Header().Get("X-Cache"))
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://proxy.test/aged", nil))
	if second.Code != http.StatusOK || second.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second response code=%d cache=%q", second.Code, second.Header().Get("X-Cache"))
	}
	age, err := strconv.Atoi(second.Header().Get("Age"))
	if err != nil || age < 30 {
		t.Fatalf("cached Age=%q, want at least 30", second.Header().Get("Age"))
	}
	if calls.Load() != 1 {
		t.Fatalf("origin calls=%d, want 1", calls.Load())
	}
}

func TestResponseCachePolicyUsesExpiresRelativeToDate(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 40, 0, time.UTC)
	cfg := testConfig("http://127.0.0.1").Routes[0].Cache
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	resp.Header.Set("Date", now.Add(-40*time.Second).Format(http.TimeFormat))
	resp.Header.Set("Expires", now.Add(20*time.Second).Format(http.TimeFormat))

	cacheable, expiresAt, _, initialAge := responseCachePolicy(
		httptest.NewRequest(http.MethodGet, "http://proxy.test/expires", nil),
		resp,
		cfg,
		now,
	)
	if !cacheable {
		t.Fatal("response with 20 seconds of Expires freshness remaining should be cacheable")
	}
	if initialAge != 40*time.Second {
		t.Fatalf("initial age=%s, want 40s", initialAge)
	}
	if got := expiresAt.Sub(now); got != 20*time.Second {
		t.Fatalf("remaining freshness=%s, want 20s", got)
	}
}

func TestRequestIDAcceptsOnlySafeCorrelationTokens(t *testing.T) {
	for _, tc := range []struct {
		value string
		keep  bool
	}{
		{value: "trace-1234_abcd:01", keep: true},
		{value: "request id with spaces"},
		{value: "request\twith-tab"},
		{value: strings.Repeat("a", 129)},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://project.test/", nil)
		req.Header.Set("X-Request-ID", tc.value)
		got := requestID(req)
		if tc.keep {
			if got != tc.value {
				t.Fatalf("valid request ID changed: got %q want %q", got, tc.value)
			}
			continue
		}
		if got == tc.value || !validRequestID(got) {
			t.Fatalf("unsafe request ID was not replaced: input=%q output=%q", tc.value, got)
		}
	}
}

func TestCachePartitionsAuthorizedAndCookieRequests(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Vary", "Authorization, Cookie")
		_, _ = fmt.Fprintf(w, "%s|%s", r.Header.Get("Authorization"), r.Header.Get("Cookie"))
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.CacheAuthorizedRequests = true
	cfg.Routes[0].Cache.CacheCookieRequests = true
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	do := func(auth, cookie string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://proxy.test/account", nil)
		req.Header.Set("Authorization", auth)
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := do("Bearer user-a-secret", "session=user-a")
	if first.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first cache status=%q, want MISS", first.Header().Get("X-Cache"))
	}
	repeat := do("Bearer user-a-secret", "session=user-a")
	if repeat.Header().Get("X-Cache") != "HIT" || repeat.Body.String() != first.Body.String() {
		t.Fatalf("repeat response cache=%q body=%q", repeat.Header().Get("X-Cache"), repeat.Body.String())
	}
	otherAuth := do("Bearer user-b-secret", "session=user-a")
	if otherAuth.Header().Get("X-Cache") != "MISS" || strings.Contains(otherAuth.Body.String(), "user-a-secret") {
		t.Fatalf("authorization identities shared a cache entry: cache=%q body=%q", otherAuth.Header().Get("X-Cache"), otherAuth.Body.String())
	}
	otherCookie := do("Bearer user-a-secret", "session=user-b")
	if otherCookie.Header().Get("X-Cache") != "MISS" || strings.Contains(otherCookie.Body.String(), "session=user-a") {
		t.Fatalf("cookie identities shared a cache entry: cache=%q body=%q", otherCookie.Header().Get("X-Cache"), otherCookie.Body.String())
	}
	if calls.Load() != 3 {
		t.Fatalf("origin calls=%d, want 3", calls.Load())
	}

	keyReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/account", nil)
	keyReq.Header.Set("Authorization", "Bearer user-a-secret")
	keyReq.Header.Set("Cookie", "session=user-a")
	key := cacheKey(keyReq, cfg.Routes[0].Cache)
	if strings.Contains(key, "user-a-secret") || strings.Contains(key, "session=user-a") {
		t.Fatalf("sensitive header value leaked into cache key: %q", key)
	}
}

func TestCachedResponseNeverReplaysSetCookie(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Set-Cookie", "session=origin-secret; Path=/; HttpOnly")
		_, _ = io.WriteString(w, "cacheable-body")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.CacheSetCookieResponses = true
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://proxy.test/cookie", nil))
	if first.Header().Get("X-Cache") != "MISS" || first.Header().Get("Set-Cookie") == "" {
		t.Fatalf("live response cache=%q set-cookie=%q", first.Header().Get("X-Cache"), first.Header().Get("Set-Cookie"))
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://proxy.test/cookie", nil))
	if second.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second cache status=%q, want HIT", second.Header().Get("X-Cache"))
	}
	if got := second.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("cached response replayed Set-Cookie: %#v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("origin calls=%d, want 1", calls.Load())
	}
}

func TestMustRevalidateDisablesStaleIfError(t *testing.T) {
	now := time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC)
	cfg := testConfig("http://127.0.0.1").Routes[0].Cache
	cfg.StaleIfError = config.Duration{Duration: 2 * time.Minute}

	for _, directive := range []string{"must-revalidate", "proxy-revalidate"} {
		t.Run(directive, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
			resp.Header.Set("Cache-Control", "public, max-age=60, "+directive)
			cacheable, expiresAt, staleUntil, _ := responseCachePolicy(
				httptest.NewRequest(http.MethodGet, "http://proxy.test/revalidate", nil),
				resp,
				cfg,
				now,
			)
			if !cacheable {
				t.Fatal("response should remain cacheable while fresh")
			}
			if !staleUntil.Equal(expiresAt) {
				t.Fatalf("%s must disable stale serving: expires=%v stale_until=%v", directive, expiresAt, staleUntil)
			}
		})
	}
}

func TestCacheKeySeparatesRequestAuthoritiesByPort(t *testing.T) {
	cfg := testConfig("http://127.0.0.1").Routes[0].Cache
	first := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
	first.Host = "Proxy.Test:8080"
	second := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
	second.Host = "proxy.test:9090"

	if cacheKey(first, cfg) == cacheKey(second, cfg) {
		t.Fatal("cache keys must not merge distinct request authorities")
	}
	if got := cacheHost("Proxy.Test.:8080"); got != "proxy.test:8080" {
		t.Fatalf("cache authority was not normalized: %q", got)
	}
}

func TestOriginTransportIgnoresAmbientProxySettings(t *testing.T) {
	route := testConfig("http://origin.internal:9000").Routes[0]
	pool, err := newUpstreamPool(route)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool.nodes) != 1 {
		t.Fatalf("unexpected upstream count: %d", len(pool.nodes))
	}
	if pool.nodes[0].transport.Proxy != nil {
		t.Fatal("origin transport must connect directly instead of honoring HTTP_PROXY/HTTPS_PROXY")
	}
}

func TestPurgeCacheUsesExactHostAndPathBoundaries(t *testing.T) {
	calls := map[string]int{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	request := func(rawURL string) string {
		req := httptest.NewRequest(http.MethodGet, rawURL, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", rawURL, rr.Code, rr.Body.String())
		}
		return rr.Header().Get("X-Cache")
	}

	for _, rawURL := range []string{
		"http://proxy.test/api",
		"http://proxy.test/api/items?q=raw|h:delimiter",
		"http://proxy.test/apix",
	} {
		if got := request(rawURL); got != "MISS" {
			t.Fatalf("first request %s cache=%q, want MISS", rawURL, got)
		}
		if got := request(rawURL); got != "HIT" {
			t.Fatalf("second request %s cache=%q, want HIT", rawURL, got)
		}
	}

	purged, ok, err := h.PurgeCache("test", "PROXY.TEST.", "/api/")
	if err != nil || !ok || purged != 2 {
		t.Fatalf("purge result entries=%d ok=%v err=%v, want 2 true nil", purged, ok, err)
	}
	if got := request("http://proxy.test/api"); got != "MISS" {
		t.Fatalf("exact path was not purged: cache=%q", got)
	}
	if got := request("http://proxy.test/api/items?q=raw|h:delimiter"); got != "MISS" {
		t.Fatalf("child path was not purged: cache=%q", got)
	}
	if got := request("http://proxy.test/apix"); got != "HIT" {
		t.Fatalf("sibling prefix was incorrectly purged: cache=%q", got)
	}
	if calls["/apix"] != 1 {
		t.Fatalf("/apix origin calls=%d, want 1", calls["/apix"])
	}
}

func TestPurgeCacheRejectsAmbiguousPathPrefix(t *testing.T) {
	h := &Handler{routes: map[string]*routeRuntime{
		"test": {cache: cache.New(10, 1024)},
	}}
	for _, value := range []string{"api", "/api/../admin", "/api//items", "/api%2Fitems", "/api?x=1"} {
		if _, ok, err := h.PurgeCache("test", "", value); !ok || err == nil {
			t.Fatalf("path_prefix %q: ok=%v err=%v, want existing route and validation error", value, ok, err)
		}
	}
}

func TestRequestCacheModeTreatsZeroPaddedMaxAgeAsRevalidation(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
	req.Header.Set("Cache-Control", "max-age=000")
	cfg := config.CacheConfig{Enabled: true}
	lookup, store, reason := requestCacheMode(req, cfg)
	if lookup || !store || reason != "" {
		t.Fatalf("lookup=%v store=%v reason=%q, want false, true, empty", lookup, store, reason)
	}
}

func TestParseCacheControlTrimsOptionalWhitespace(t *testing.T) {
	directives := parseCacheControl([]string{`public, max-age = "60", no-store`})
	if got := directives["max-age"]; got != "60" {
		t.Fatalf("max-age=%q, want 60", got)
	}
	if !hasCacheDirective(directives, "no-store") {
		t.Fatal("no-store directive was not parsed")
	}
}

func TestOriginCannotSpoofAuthoritativeEdgeHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-ID", "origin-spoof")
		w.Header().Set("X-Cache", "ORIGIN")
		w.Header().Set("X-Upstream-Response-Time", "999s")
		w.Header().Set("X-Security-Action", "BLOCK")
		w.Header().Set("X-Security-Score", "999")
		w.Header().Set("X-Security-Gateway", "origin")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	for index, expectedCache := range []string{"MISS", "HIT"} {
		requestID := fmt.Sprintf("client-%d", index)
		req := httptest.NewRequest(http.MethodGet, "http://proxy.test/headers", nil)
		req.Header.Set("X-Request-ID", requestID)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Result().Header.Values("X-Request-ID"); len(got) != 1 || got[0] != requestID {
			t.Fatalf("request %d IDs=%#v, want [%q]", index, got, requestID)
		}
		if got := rec.Result().Header.Values("X-Cache"); len(got) != 1 || got[0] != expectedCache {
			t.Fatalf("request %d cache headers=%#v, want [%q]", index, got, expectedCache)
		}
		if got := rec.Result().Header.Values("X-Upstream-Response-Time"); index == 0 && (len(got) != 1 || got[0] == "999s") {
			t.Fatalf("request %d timing headers=%#v", index, got)
		}
		for _, name := range []string{"X-Security-Action", "X-Security-Score", "X-Security-Gateway"} {
			if got := rec.Result().Header.Values(name); len(got) != 0 {
				t.Fatalf("request %d leaked %s=%#v", index, name, got)
			}
		}
	}
}

func TestRewriteURLStripsPrefixFromCanonicalPath(t *testing.T) {
	in, err := url.Parse("http://proxy.test/api/../admin/settings?view=full")
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse("http://origin.test/base")
	if err != nil {
		t.Fatal(err)
	}
	got := rewriteURL(in, base, "/admin", true)
	if got.Path != "/base/settings" || got.RawQuery != "view=full" {
		t.Fatalf("rewritten URL=%q, want path /base/settings with original query", got.String())
	}
}

func TestCacheKeyUsesCanonicalForwardedPath(t *testing.T) {
	cfg := config.CacheConfig{}
	a := httptest.NewRequest(http.MethodGet, "http://proxy.test/api/../admin/settings?q=1", nil)
	b := httptest.NewRequest(http.MethodGet, "http://proxy.test/admin/settings?q=1", nil)
	if gotA, gotB := cacheKey(a, cfg), cacheKey(b, cfg); gotA != gotB {
		t.Fatalf("equivalent forwarded paths produced different keys:\n%s\n%s", gotA, gotB)
	}
}

func TestResponseBodyCopyFailureIsReported(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "abc")
	}))
	defer origin.Close()

	registry := metrics.New()
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/truncated", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := registry.Snapshot().Total.ProxyErrors; got != 1 {
		t.Fatalf("proxy_errors=%d, want 1 after truncated upstream response", got)
	}
}

func TestInvalidOriginFreshnessDoesNotFallBackToDefaultTTL(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{name: "invalid shared max age", header: "Cache-Control", value: "public, s-maxage=invalid"},
		{name: "invalid max age", header: "Cache-Control", value: "public, max-age=invalid"},
		{name: "invalid expires", header: "Expires", value: "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set(tc.header, tc.value)
				_, _ = io.WriteString(w, "body")
			}))
			defer origin.Close()

			h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()

			for i := 0; i < 2; i++ {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.test/invalid-freshness", nil))
				if rec.Code != http.StatusOK || rec.Header().Get("X-Cache") != "BYPASS" {
					t.Fatalf("request %d: code=%d cache=%q", i+1, rec.Code, rec.Header().Get("X-Cache"))
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("invalid freshness metadata was cached: origin calls=%d", calls.Load())
			}
		})
	}
}

func TestConfiguredClientIPHeaderIsNotForwardedToOrigin(t *testing.T) {
	var customHeader string
	var forwarded string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customHeader = r.Header.Get("X-Real-IP")
		forwarded = r.Header.Get("X-Forwarded-For")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Server.TrustedProxyCIDRs = []string{"127.0.0.0/8"}
	cfg.Server.ForwardedForHeader = "X-Real-IP"
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/client-ip", nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Set("X-Real-IP", "198.51.100.25")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if customHeader != "" {
		t.Fatalf("configured client-IP source header leaked to origin: %q", customHeader)
	}
	if forwarded != "198.51.100.25" {
		t.Fatalf("canonical forwarded client IP=%q", forwarded)
	}
}
