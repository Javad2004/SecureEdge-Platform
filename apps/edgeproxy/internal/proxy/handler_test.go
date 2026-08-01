package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bachelor-project/edgeproxy/internal/accesslog"
	"github.com/bachelor-project/edgeproxy/internal/config"
	"github.com/bachelor-project/edgeproxy/internal/metrics"
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
