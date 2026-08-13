package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
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

type deadlineTrackingConn struct {
	net.Conn
	cleared atomic.Bool
}

func (c *deadlineTrackingConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.cleared.Store(true)
	}
	return c.Conn.SetDeadline(deadline)
}

type protocolHijackWriter struct {
	header http.Header
	conn   net.Conn
	reader *bufio.Reader
}

func (w *protocolHijackWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *protocolHijackWriter) WriteHeader(int)             {}
func (w *protocolHijackWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *protocolHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	reader := w.reader
	if reader == nil {
		reader = bufio.NewReader(w.conn)
	}
	return w.conn, bufio.NewReadWriter(reader, bufio.NewWriter(w.conn)), nil
}

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

func TestTrustedOperationalProbeDoesNotPolluteApplicationTelemetry(t *testing.T) {
	var calls atomic.Int64
	var sawMarker atomic.Bool
	var sawNoStore atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get(internalProbeHeader) != "" {
			sawMarker.Store(true)
		}
		if r.Header.Get("Cache-Control") == "no-store" && r.Header.Get("Pragma") == "no-cache" {
			sawNoStore.Store(true)
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "origin-body")
	}))
	defer origin.Close()

	registry := metrics.New()
	logs := accesslog.New(100)
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	probe := httptest.NewRequest(http.MethodHead, "http://proxy.test/data", nil)
	probe.RemoteAddr = "127.0.0.1:43210"
	probe.Header.Set(internalProbeHeader, internalProbeValue)
	probe.Header.Set("User-Agent", internalProbeUserAgent)
	probeResponse := httptest.NewRecorder()
	h.ServeHTTP(probeResponse, probe)
	if probeResponse.Code != http.StatusOK || probeResponse.Header().Get("X-Cache") != "BYPASS" {
		t.Fatalf("probe status=%d cache=%q", probeResponse.Code, probeResponse.Header().Get("X-Cache"))
	}
	if got := probeResponse.Header().Get(internalProbeHeader); got != internalProbeResponseValue {
		t.Fatalf("trusted matched probe acknowledgement=%q, want %q", got, internalProbeResponseValue)
	}
	if sawMarker.Load() {
		t.Fatal("operational probe marker leaked to Origin")
	}
	if !sawNoStore.Load() {
		t.Fatal("operational probe did not reach Origin with a no-store cache policy")
	}
	if calls.Load() != 1 {
		t.Fatalf("origin calls after probe=%d, want 1", calls.Load())
	}

	snapshot := registry.Snapshot()
	if snapshot.Total.Requests != 0 || snapshot.Total.CacheHits != 0 || snapshot.Total.CacheMisses != 0 || snapshot.Total.CacheBypasses != 0 || snapshot.Total.UpstreamCalls != 0 {
		t.Fatalf("operational probe polluted application metrics: %#v", snapshot.Total)
	}
	if len(snapshot.Routes) != 0 || len(snapshot.Upstreams) != 0 {
		t.Fatalf("operational probe created route/upstream telemetry: routes=%#v upstreams=%#v", snapshot.Routes, snapshot.Upstreams)
	}
	if stats := logs.Stats(); stats.Retained != 0 {
		t.Fatalf("operational probe polluted access log: %#v", stats)
	}
	node := h.routes["test"].pool.nodes[0]
	if node.selections.Load() != 0 || node.active.Load() != 0 || node.ewmaMS() != 0 {
		t.Fatalf("operational probe polluted scheduler state: selections=%d active=%d ewma=%f", node.selections.Load(), node.active.Load(), node.ewmaMS())
	}

	for i, wantCache := range []string{"MISS", "HIT"} {
		req := httptest.NewRequest(http.MethodGet, "http://proxy.test/data", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != wantCache {
			t.Fatalf("client request %d status=%d cache=%q", i, rr.Code, rr.Header().Get("X-Cache"))
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("origin calls after client traffic=%d, want 2", calls.Load())
	}
	snapshot = registry.Snapshot()
	if snapshot.Total.Requests != 2 || snapshot.Total.CacheHits != 1 || snapshot.Total.CacheMisses != 1 || snapshot.Total.CacheBypasses != 0 || snapshot.Total.UpstreamCalls != 1 {
		t.Fatalf("client telemetry after probe=%#v", snapshot.Total)
	}
	if got := snapshot.Total.Methods[http.MethodGet]; got != 2 {
		t.Fatalf("GET method count=%d, want 2", got)
	}
	if node.selections.Load() != 1 {
		t.Fatalf("scheduler selections=%d, want only the cache-miss client request", node.selections.Load())
	}
}

func TestUnmatchedRequestIsIncludedInApplicationTelemetry(t *testing.T) {
	registry := metrics.New()
	logs := accesslog.New(100)
	h, err := NewHandler(testConfig("http://127.0.0.1:1"), slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://unknown.test/missing", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusNotFound)
	}
	requestID := rr.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Fatal("unmatched response is missing X-Request-ID")
	}

	snapshot := registry.Snapshot()
	total := snapshot.Total
	if total.Requests != 1 || total.Success != 0 || total.ClientErrors != 1 || total.ServerErrors != 0 || total.ProxyErrors != 0 {
		t.Fatalf("unmatched request was not classified as one client-facing 404: %#v", total)
	}
	if total.SuccessRate != 0 || total.ErrorRate != 1 || total.ResponseLatencyMS.Count != 1 || total.StatusCodes["404"] != 1 || total.Methods[http.MethodGet] != 1 {
		t.Fatalf("unmatched request derived telemetry is inconsistent: %#v", total)
	}
	if total.UpstreamCalls != 0 || total.CacheHits != 0 || total.CacheMisses != 0 || total.CacheStale != 0 {
		t.Fatalf("unmatched request unexpectedly created upstream/cache activity: %#v", total)
	}
	unmatched, ok := snapshot.Routes["__unmatched__"]
	if !ok || unmatched.Requests != 1 || unmatched.ClientErrors != 1 || unmatched.StatusCodes["404"] != 1 {
		t.Fatalf("unmatched pseudo-route telemetry is missing or inconsistent: %#v", snapshot.Routes)
	}

	entries := logs.Query(accesslog.Filter{Event: "request_completed", Limit: 10}).Entries
	if len(entries) != 1 {
		t.Fatalf("unmatched request access logs=%d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.RequestID != requestID || entry.Route != "__unmatched__" || entry.Status != http.StatusNotFound || entry.Level != "WARN" || entry.ProxyError || entry.Canceled {
		t.Fatalf("unexpected unmatched access log: %#v", entry)
	}
}

func TestTrustedUnmatchedOperationalProbeDoesNotPolluteTelemetry(t *testing.T) {
	registry := metrics.New()
	logs := accesslog.New(100)
	h, err := NewHandler(testConfig("http://127.0.0.1:1"), slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	probe := httptest.NewRequest(http.MethodHead, "http://unknown.test/missing", nil)
	probe.RemoteAddr = "127.0.0.1:43210"
	probe.Header.Set(internalProbeHeader, internalProbeValue)
	probe.Header.Set("User-Agent", internalProbeUserAgent)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, probe)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusNotFound)
	}
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("unmatched operational probe response is missing X-Request-ID")
	}
	if got := rr.Header().Get(internalProbeHeader); got != "" {
		t.Fatalf("unmatched operational probe received a false route-match acknowledgement: %q", got)
	}
	if snapshot := registry.Snapshot(); snapshot.Total.Requests != 0 || len(snapshot.Routes) != 0 {
		t.Fatalf("trusted unmatched operational probe polluted metrics: %#v", snapshot)
	}
	if stats := logs.Stats(); stats.Retained != 0 {
		t.Fatalf("trusted unmatched operational probe polluted access logs: %#v", stats)
	}
}

func TestTrustedOperationalProbeFailureDoesNotMutateOriginHealth(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer origin.Close()

	registry := metrics.New()
	logs := accesslog.New(100)
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	node := h.routes["test"].pool.nodes[0]
	if !node.healthy.Load() {
		t.Fatal("test origin should start healthy when active health checks are disabled")
	}

	probe := httptest.NewRequest(http.MethodHead, "http://proxy.test/data", nil)
	probe.RemoteAddr = "127.0.0.1:43210"
	probe.Header.Set(internalProbeHeader, internalProbeValue)
	probe.Header.Set("User-Agent", internalProbeUserAgent)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, probe)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if !node.healthy.Load() {
		t.Fatal("synthetic connectivity failure changed EdgeProxy origin-health state")
	}
	if node.healthFailures.Load() != 0 || node.healthRecoveries.Load() != 0 {
		t.Fatalf("synthetic connectivity failure changed health counters: failures=%d recoveries=%d", node.healthFailures.Load(), node.healthRecoveries.Load())
	}
	if node.selections.Load() != 0 || node.active.Load() != 0 || node.ewmaMS() != 0 {
		t.Fatalf("synthetic connectivity failure changed scheduler telemetry: selections=%d active=%d ewma=%f", node.selections.Load(), node.active.Load(), node.ewmaMS())
	}
	snapshot := registry.Snapshot()
	if snapshot.Total.Requests != 0 || snapshot.Total.CacheHits != 0 || snapshot.Total.CacheMisses != 0 || snapshot.Total.CacheBypasses != 0 || snapshot.Total.UpstreamCalls != 0 {
		t.Fatalf("synthetic connectivity failure polluted application metrics: %#v", snapshot.Total)
	}
	if stats := logs.Stats(); stats.Retained != 0 {
		t.Fatalf("synthetic connectivity failure polluted retained logs: %#v", stats)
	}
}

func TestTrustedOperationalProbePreservesRetryableResponseWhenNoAlternateOrigin(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Proxy.RetryCount = 1
	registry := metrics.New()
	logs := accesslog.New(100)
	h, err := NewHandler(cfg, slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	probe := httptest.NewRequest(http.MethodHead, "http://proxy.test/data", nil)
	probe.RemoteAddr = "127.0.0.1:43210"
	probe.Header.Set(internalProbeHeader, internalProbeValue)
	probe.Header.Set("User-Agent", internalProbeUserAgent)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, probe)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want preserved %d", rr.Code, http.StatusServiceUnavailable)
	}
	if got := rr.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After=%q, want preserved Origin header", got)
	}
	if got := rr.Header().Get(internalProbeHeader); got != internalProbeResponseValue {
		t.Fatalf("probe acknowledgement=%q, want %q", got, internalProbeResponseValue)
	}
	if calls.Load() != 1 {
		t.Fatalf("Origin calls=%d, want one call when no alternate Origin exists", calls.Load())
	}
	if snapshot := registry.Snapshot(); snapshot.Total.Requests != 0 || snapshot.Total.UpstreamCalls != 0 {
		t.Fatalf("operational probe polluted metrics: %#v", snapshot.Total)
	}
	if stats := logs.Stats(); stats.Retained != 0 {
		t.Fatalf("operational probe polluted retained logs: %#v", stats)
	}
}

func TestUntrustedClientCannotHideTrafficWithOperationalProbeMarker(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(internalProbeHeader); got != "" {
			t.Errorf("reserved probe marker leaked to Origin: %q", got)
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	registry := metrics.New()
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodHead, "http://proxy.test/data", nil)
	req.RemoteAddr = "203.0.113.25:43210"
	req.Header.Set(internalProbeHeader, internalProbeValue)
	req.Header.Set("User-Agent", internalProbeUserAgent)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}

	snapshot := registry.Snapshot()
	if snapshot.Total.Requests != 1 || snapshot.Total.CacheMisses != 1 || snapshot.Total.UpstreamCalls != 1 {
		t.Fatalf("untrusted marker incorrectly hid client telemetry: %#v", snapshot.Total)
	}
}

func TestProtocolUpgradeClearsHijackedServerDeadline(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	tracked := &deadlineTrackingConn{Conn: serverConn}
	backendConn, originPeer := net.Pipe()
	h := &Handler{tunnels: make(map[*activeProtocolTunnel]struct{})}
	writer := &protocolHijackWriter{conn: tracked}
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/socket", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo-test")
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 Switching Protocols",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"echo-test"}},
		Body:   backendConn,
	}

	done := make(chan error, 1)
	go func() {
		_, err := h.proxyProtocolUpgrade(writer, req, resp, "request-1", time.Now())
		done <- err
	}()

	clientReader := bufio.NewReader(clientConn)
	response, err := http.ReadResponse(clientReader, req)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status=%d, want 101", response.StatusCode)
	}
	if !tracked.cleared.Load() {
		t.Fatal("hijacked client connection retained net/http server deadline")
	}

	_ = clientConn.Close()
	_ = originPeer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("upgrade tunnel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upgrade tunnel did not terminate after peers closed")
	}
}

func TestProtocolUpgradeForwardsBytesAlreadyBufferedByHTTPServer(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	backendConn, originPeer := net.Pipe()
	h := &Handler{tunnels: make(map[*activeProtocolTunnel]struct{})}
	earlyPayload := []byte("early-protocol-payload")
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(earlyPayload), serverConn))
	writer := &protocolHijackWriter{conn: serverConn, reader: reader}
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/socket", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo-test")
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Status:     "101 Switching Protocols",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"echo-test"}},
		Body:   backendConn,
	}

	done := make(chan error, 1)
	go func() {
		_, err := h.proxyProtocolUpgrade(writer, req, resp, "request-buffered", time.Now())
		done <- err
	}()

	clientReader := bufio.NewReader(clientConn)
	response, err := http.ReadResponse(clientReader, req)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status=%d, want 101", response.StatusCode)
	}

	if err := originPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(earlyPayload))
	if _, err := io.ReadFull(originPeer, received); err != nil {
		t.Fatalf("origin did not receive buffered protocol bytes: %v", err)
	}
	if !bytes.Equal(received, earlyPayload) {
		t.Fatalf("buffered payload=%q, want %q", received, earlyPayload)
	}

	_ = clientConn.Close()
	_ = originPeer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("upgrade tunnel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upgrade tunnel did not terminate after peers closed")
	}
}

func TestProtocolUpgradeBypassesCacheAndOutlivesRequestTimeout(t *testing.T) {
	var normalCalls atomic.Int64
	var upgradeCalls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "echo-test") && headerHasToken(r.Header.Values("Connection"), "upgrade") {
			upgradeCalls.Add(1)
			conn, buffered, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("origin hijack: %v", err)
				return
			}
			defer conn.Close()
			_, _ = fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, X-Origin-Hop\r\nUpgrade: echo-test\r\nX-Origin-Hop: should-not-leak\r\nKeep-Alive: timeout=5\r\n\r\n")
			if err := buffered.Flush(); err != nil {
				t.Errorf("origin flush upgrade: %v", err)
				return
			}
			_, _ = io.Copy(conn, buffered)
			return
		}

		normalCalls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "normal-response")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Proxy.RequestTimeout = config.Duration{Duration: 50 * time.Millisecond}
	registry := metrics.New()
	h, err := NewHandler(cfg, slog.Default(), registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()

	for i, wantCache := range []string{"MISS", "HIT"} {
		req, err := http.NewRequest(http.MethodGet, proxyServer.URL+"/socket", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "proxy.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("normal request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Cache") != wantCache || string(body) != "normal-response" {
			t.Fatalf("normal request %d: status=%d cache=%q body=%q", i, resp.StatusCode, resp.Header.Get("X-Cache"), body)
		}
	}

	request, err := http.NewRequest(http.MethodGet, proxyServer.URL+"/socket", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "proxy.test"
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "echo-test")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("upgrade request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("upgrade status=%d headers=%v body=%q", response.StatusCode, response.Header, body)
	}
	if !strings.EqualFold(response.Header.Get("Upgrade"), "echo-test") {
		t.Fatalf("upgrade response protocol=%q", response.Header.Get("Upgrade"))
	}
	if response.Header.Get("X-Origin-Hop") != "" || response.Header.Get("Keep-Alive") != "" {
		t.Fatalf("origin hop-by-hop headers leaked through upgrade response: %#v", response.Header)
	}
	tunnel, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("upgrade response body type %T is not bidirectional", response.Body)
	}

	// The normal route request timeout must not become a lifetime limit for a
	// successfully switched protocol.
	time.Sleep(100 * time.Millisecond)
	payload := []byte("echo-through-upgrade")
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("write upgraded payload after request timeout: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, got); err != nil {
		t.Fatalf("read upgraded payload after request timeout: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("upgraded echo=%q, want %q", got, payload)
	}
	statuses := h.RouteStatuses()
	if len(statuses) != 1 || len(statuses[0].Upstreams) != 1 {
		t.Fatalf("route statuses=%#v", statuses)
	}
	if active, ok := statuses[0].Upstreams[0]["active_requests"].(int64); !ok || active != 1 {
		t.Fatalf("active upgraded requests=%v, want 1 while tunnel is open", statuses[0].Upstreams[0]["active_requests"])
	}
	// http.Server.Shutdown does not own hijacked connections. The proxy handler
	// must terminate active protocol tunnels explicitly when its generation is
	// retired, otherwise an old WebSocket can outlive a managed restart.
	closed := make(chan struct{})
	go func() {
		h.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		_ = response.Body.Close()
		t.Fatal("handler close did not terminate active protocol tunnel")
	}
	readResult := make(chan error, 1)
	go func() {
		_, err := tunnel.Read(make([]byte, 1))
		readResult <- err
	}()
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("protocol tunnel remained readable after handler close")
		}
	case <-time.After(time.Second):
		_ = response.Body.Close()
		t.Fatal("client side of protocol tunnel was not closed")
	}
	_ = response.Body.Close()

	if normalCalls.Load() != 1 {
		t.Fatalf("normal origin calls=%d, want 1 because the second normal request was cached", normalCalls.Load())
	}
	if upgradeCalls.Load() != 1 {
		t.Fatalf("upgrade origin calls=%d, want 1", upgradeCalls.Load())
	}
	deadline := time.Now().Add(time.Second)
	for {
		snapshot := registry.Snapshot()
		if snapshot.Total.Success == 3 && snapshot.Total.CacheBypasses == 1 && snapshot.Total.BytesIn >= uint64(len(payload)) && snapshot.Total.BytesOut >= uint64(len(payload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upgrade telemetry=%#v, want three successes, one bypass, and tunnel bytes", snapshot.Total)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProtocolUpgradeRequiresUnambiguousToken(t *testing.T) {
	header := make(http.Header)
	header.Set("Upgrade", "websocket")
	if _, err := protocolUpgrade(header); err == nil {
		t.Fatal("Upgrade without Connection: upgrade was accepted")
	}

	header.Set("Connection", "Upgrade")
	header["Upgrade"] = []string{"websocket", "other"}
	if _, err := protocolUpgrade(header); err == nil {
		t.Fatal("multiple Upgrade header fields were accepted")
	}

	header["Upgrade"] = []string{"bad protocol"}
	if _, err := protocolUpgrade(header); err == nil {
		t.Fatal("invalid protocol token was accepted")
	}

	header["Upgrade"] = []string{"websocket"}
	if got, err := protocolUpgrade(header); err != nil || got != "websocket" {
		t.Fatalf("valid protocol upgrade got %q, %v", got, err)
	}
	header["Upgrade"] = []string{"chat/2"}
	if got, err := protocolUpgrade(header); err != nil || got != "chat/2" {
		t.Fatalf("versioned protocol upgrade got %q, %v", got, err)
	}
	header["Upgrade"] = []string{"chat/2/extra"}
	if _, err := protocolUpgrade(header); err == nil {
		t.Fatal("protocol upgrade with multiple version separators was accepted")
	}
}

func TestMalformedProtocolUpgradeIsRejectedBeforeOrigin(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/socket", nil)
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q, want 400", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("origin calls=%d, want 0 for malformed client upgrade", calls.Load())
	}
}

func TestActiveRequestsRemainUntilResponseBodyCompletes(t *testing.T) {
	headersSent := make(chan struct{})
	releaseBody := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(headersSent)
		<-releaseBody
		_, _ = io.WriteString(w, "complete")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.Enabled = false
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	done := make(chan struct{})
	response := httptest.NewRecorder()
	go func() {
		h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://proxy.test/stream", nil))
		close(done)
	}()
	select {
	case <-headersSent:
	case <-time.After(time.Second):
		t.Fatal("origin did not send response headers")
	}

	deadline := time.Now().Add(time.Second)
	for {
		statuses := h.RouteStatuses()
		if len(statuses) == 1 && len(statuses[0].Upstreams) == 1 && statuses[0].Upstreams[0]["active_requests"] == int64(1) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("active request was released before response body completed: %#v", statuses)
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseBody)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy response did not complete")
	}
	statuses := h.RouteStatuses()
	if got := statuses[0].Upstreams[0]["active_requests"]; got != int64(0) {
		t.Fatalf("active requests=%v after response completion, want 0", got)
	}
}

func TestChunkedRequestReportsActualInboundBytes(t *testing.T) {
	const payload = "streamed-request-body"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read origin body: %v", err)
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		if string(body) != payload {
			t.Errorf("origin body=%q, want %q", body, payload)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	registry := metrics.New()
	logs := accesslog.New(10)
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	req := httptest.NewRequest(http.MethodPost, "http://proxy.test/upload", io.NopCloser(strings.NewReader(payload)))
	req.ContentLength = -1
	req.GetBody = nil
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}

	want := uint64(len(payload))
	snapshot := registry.Snapshot()
	if snapshot.Total.BytesIn != want || snapshot.Routes["test"].BytesIn != want {
		t.Fatalf("bytes_in total=%d route=%d, want %d", snapshot.Total.BytesIn, snapshot.Routes["test"].BytesIn, want)
	}
	entries := logs.Query(accesslog.Filter{Event: "request_completed", Limit: 10}).Entries
	if len(entries) != 1 || entries[0].BytesIn != want {
		t.Fatalf("access log entries=%#v, want bytes_in=%d", entries, want)
	}
}

type cancelingUploadBody struct {
	payload []byte
	cancel  context.CancelFunc
	sent    bool
}

func (b *cancelingUploadBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, b.payload), nil
	}
	b.cancel()
	return 0, context.Canceled
}

func (b *cancelingUploadBody) Close() error { return nil }

func TestKnownLengthCanceledUploadReportsOnlyConsumedInboundBytes(t *testing.T) {
	const declaredLength = int64(100000)
	const actualLength = 700
	origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer origin.Close()

	registry := metrics.New()
	logs := accesslog.New(10)
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	ctx, cancel := context.WithCancel(context.Background())
	body := &cancelingUploadBody{payload: bytes.Repeat([]byte("x"), actualLength), cancel: cancel}
	req := httptest.NewRequest(http.MethodPost, "http://proxy.test/upload", body).WithContext(ctx)
	req.ContentLength = declaredLength
	req.GetBody = nil
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	snapshot := registry.Snapshot().Routes["test"]
	if snapshot.Requests != 1 || snapshot.CanceledRequests != 1 || snapshot.BytesIn != actualLength {
		t.Fatalf("canceled upload telemetry=%#v, want requests=1 canceled=1 bytes_in=%d", snapshot.CounterSnapshot, actualLength)
	}
	if snapshot.BytesIn == uint64(declaredLength) {
		t.Fatalf("bytes_in used declared Content-Length %d instead of consumed bytes", declaredLength)
	}
	entries := logs.Query(accesslog.Filter{Event: "request_completed", Limit: 10}).Entries
	if len(entries) != 1 || !entries[0].Canceled || entries[0].BytesIn != actualLength {
		t.Fatalf("access log entries=%#v, want canceled bytes_in=%d", entries, actualLength)
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

func TestOriginHTTP500CountsAsUpstreamFailureWithoutChangingRetryPolicy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "origin failed", http.StatusInternalServerError)
	}))
	defer origin.Close()

	registry := metrics.New()
	logs := accesslog.New(10)
	h, err := NewHandler(testConfig(origin.URL), slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.test/failure", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusInternalServerError)
	}

	snapshot := registry.Snapshot()
	if snapshot.Total.Upstream.Calls != 1 || snapshot.Total.Upstream.Failures != 1 || snapshot.Total.Upstream.Success != 0 {
		t.Fatalf("unexpected upstream aggregate for HTTP 500: %#v", snapshot.Total.Upstream)
	}
	originMetrics := snapshot.Routes["test"].Upstreams[origin.URL]
	if originMetrics.Calls != 1 || originMetrics.Failures != 1 || originMetrics.Success != 0 || originMetrics.Retries != 0 {
		t.Fatalf("unexpected per-Origin telemetry for HTTP 500: %#v", originMetrics)
	}
	if snapshot.Total.ServerErrors != 1 || snapshot.Total.ProxyErrors != 0 {
		t.Fatalf("unexpected client-facing error counters: %#v", snapshot.Total)
	}
	attempts := logs.Query(accesslog.Filter{Event: "upstream_attempt", Limit: 10}).Entries
	if len(attempts) != 1 || attempts[0].Level != "WARN" || attempts[0].UpstreamStatus != http.StatusInternalServerError {
		t.Fatalf("unexpected upstream-attempt log: %#v", attempts)
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

func TestFinalRetryableOriginResponseIsForwarded(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "temporary-%d", call)
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.Enabled = false
	cfg.Routes[0].Proxy.RetryCount = 1
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.test/unavailable", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "temporary-2" {
		t.Fatalf("body=%q, want final Origin response", got)
	}
	if got := rec.Header().Get("Retry-After"); got != "7" {
		t.Fatalf("Retry-After=%q", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("origin calls=%d, want 2", got)
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

func TestMultiValueSensitiveHeadersCannotBypassCachePolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		header      string
		secretValue string
	}{
		{name: "authorization", header: "Authorization", secretValue: "Bearer user-secret"},
		{name: "cookie", header: "Cookie", secretValue: "session=user-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				identity := "anonymous"
				for _, value := range r.Header.Values(tc.header) {
					if strings.TrimSpace(value) != "" {
						identity = value
					}
				}
				w.Header().Set("Cache-Control", "public, max-age=60")
				_, _ = io.WriteString(w, identity)
			}))
			defer origin.Close()

			h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()

			privateReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/account", nil)
			privateReq.Header[tc.header] = []string{"", tc.secretValue}
			privateRec := httptest.NewRecorder()
			h.ServeHTTP(privateRec, privateReq)
			if privateRec.Code != http.StatusOK || privateRec.Header().Get("X-Cache") != "BYPASS" || privateRec.Body.String() != tc.secretValue {
				t.Fatalf("private response: code=%d cache=%q body=%q", privateRec.Code, privateRec.Header().Get("X-Cache"), privateRec.Body.String())
			}

			anonymousRec := httptest.NewRecorder()
			h.ServeHTTP(anonymousRec, httptest.NewRequest(http.MethodGet, "http://proxy.test/account", nil))
			if anonymousRec.Code != http.StatusOK || anonymousRec.Header().Get("X-Cache") != "MISS" || anonymousRec.Body.String() != "anonymous" {
				t.Fatalf("anonymous response: code=%d cache=%q body=%q", anonymousRec.Code, anonymousRec.Header().Get("X-Cache"), anonymousRec.Body.String())
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("origin calls=%d, want 2", got)
			}
		})
	}

	t.Run("range", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://proxy.test/file", nil)
		req.Header["Range"] = []string{"", "bytes=0-9"}
		lookup, store, reason := requestCacheMode(req, config.CacheConfig{Enabled: true})
		if lookup || store || reason != "range" {
			t.Fatalf("lookup=%v store=%v reason=%q, want false false range", lookup, store, reason)
		}
	})

	t.Run("request-no-store", func(t *testing.T) {
		var calls atomic.Int64
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			call := calls.Add(1)
			w.Header().Set("Cache-Control", "public, max-age=60")
			_, _ = fmt.Fprintf(w, "origin-%d", call)
		}))
		defer origin.Close()

		h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()

		noStoreReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/no-store", nil)
		noStoreReq.Header.Set("Cache-Control", "no-store")
		noStoreRec := httptest.NewRecorder()
		h.ServeHTTP(noStoreRec, noStoreReq)
		if noStoreRec.Code != http.StatusOK || noStoreRec.Header().Get("X-Cache") != "BYPASS" || noStoreRec.Body.String() != "origin-1" {
			t.Fatalf("no-store response: code=%d cache=%q body=%q", noStoreRec.Code, noStoreRec.Header().Get("X-Cache"), noStoreRec.Body.String())
		}

		normalRec := httptest.NewRecorder()
		h.ServeHTTP(normalRec, httptest.NewRequest(http.MethodGet, "http://proxy.test/no-store", nil))
		if normalRec.Code != http.StatusOK || normalRec.Header().Get("X-Cache") != "MISS" || normalRec.Body.String() != "origin-2" {
			t.Fatalf("normal response: code=%d cache=%q body=%q", normalRec.Code, normalRec.Header().Get("X-Cache"), normalRec.Body.String())
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("origin calls=%d, want 2", got)
		}
	})

	t.Run("set-cookie-response", func(t *testing.T) {
		var calls atomic.Int64
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			call := calls.Add(1)
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Header()["Set-Cookie"] = []string{"", "session=origin-secret; Path=/; HttpOnly"}
			_, _ = fmt.Fprintf(w, "origin-%d", call)
		}))
		defer origin.Close()

		h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()

		for i, wantBody := range []string{"origin-1", "origin-2"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.test/cookie-response", nil))
			if rec.Code != http.StatusOK || rec.Header().Get("X-Cache") != "BYPASS" || rec.Body.String() != wantBody {
				t.Fatalf("request %d: code=%d cache=%q body=%q", i, rec.Code, rec.Header().Get("X-Cache"), rec.Body.String())
			}
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("origin calls=%d, want 2", got)
		}
	})
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
	registry := metrics.New()
	h, err := NewHandler(cfg, slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/cancel", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(response, req)
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
	if response.Body.Len() != 0 {
		t.Fatalf("client cancellation emitted a synthetic response body: %q", response.Body.String())
	}
	attempts := logs.Query(accesslog.Filter{Event: "upstream_attempt", Limit: 10})
	if len(attempts.Entries) != 1 {
		t.Fatalf("upstream attempts=%d, want 1", len(attempts.Entries))
	}
	if !attempts.Entries[0].Canceled || attempts.Entries[0].Timeout {
		t.Fatalf("client cancellation was not classified independently: %#v", attempts.Entries[0])
	}
	snapshot := registry.Snapshot().Routes["test"]
	if snapshot.Requests != 1 || snapshot.CanceledRequests != 1 || snapshot.Success != 0 || snapshot.ClientErrors != 0 || snapshot.ServerErrors != 0 || snapshot.ProxyErrors != 0 {
		t.Fatalf("client cancellation polluted request outcomes: %#v", snapshot.CounterSnapshot)
	}
	if snapshot.ResponseLatencyMS.Count != 0 || len(snapshot.StatusCodes) != 0 {
		t.Fatalf("client cancellation polluted response latency/status telemetry: %#v", snapshot.CounterSnapshot)
	}
	completed := logs.Query(accesslog.Filter{Event: "request_completed", Limit: 10})
	if len(completed.Entries) != 1 || !completed.Entries[0].Canceled || completed.Entries[0].ProxyError || completed.Entries[0].Status != 0 || completed.Entries[0].Level != "INFO" {
		t.Fatalf("client cancellation request log is inconsistent: %#v", completed.Entries)
	}
	if completed.Entries[0].Message != "client request canceled" {
		t.Fatalf("client cancellation request log message=%q", completed.Entries[0].Message)
	}

	originMetric := snapshot.Upstreams[first.URL]
	if originMetric.Calls != 1 || originMetric.Canceled != 1 || originMetric.Success != 0 || originMetric.Failures != 0 || originMetric.Timeouts != 0 || originMetric.LatencyMS.Count != 0 {
		t.Fatalf("client cancellation polluted Origin telemetry: %#v", originMetric)
	}
	for _, node := range h.routes["test"].pool.nodes {
		if !node.healthy.Load() {
			t.Fatalf("client cancellation marked origin %s unhealthy", node.url)
		}
		if node.url.String() == first.URL && node.ewmaMS() != 0 {
			t.Fatalf("client cancellation polluted adaptive-latency telemetry: ewma=%f", node.ewmaMS())
		}
	}
	if status := h.Readiness(); !status.Ready {
		t.Fatalf("client cancellation changed readiness: %#v", status)
	}
}

func TestClientCancellationDoesNotServeStaleFallback(t *testing.T) {
	started := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.Enabled = false
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/cancel-stale", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	stale := &cache.Entry{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       []byte("stale fallback must not be written"),
		StoredAt:   time.Now().Add(-time.Minute),
	}

	resultCh := make(chan requestResult, 1)
	go func() {
		resultCh <- h.fetchAndServe(response, req, h.routes["test"], "cancel-stale", stale, "MISS", false, time.Now())
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("origin did not receive the request")
	}
	cancel()

	var result requestResult
	select {
	case result = <-resultCh:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not stop after client cancellation")
	}
	if !result.clientCanceled || result.proxyError {
		t.Fatalf("unexpected cancellation result: %#v", result)
	}
	if result.cacheStatus == "STALE" || response.Body.Len() != 0 || response.Header().Get("X-Cache") == "STALE" {
		t.Fatalf("client cancellation served stale fallback: status=%q body=%q", result.cacheStatus, response.Body.String())
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

func TestRetryBackoffTimeoutDoesNotCountUnsentRetry(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Cache.Enabled = false
	cfg.Routes[0].Proxy.RequestTimeout = config.Duration{Duration: 30 * time.Millisecond}
	cfg.Routes[0].Proxy.RetryCount = 1
	cfg.Routes[0].Proxy.RetryBackoff = config.Duration{Duration: 100 * time.Millisecond}
	registry := metrics.New()
	logs := accesslog.New(20)
	h, err := NewHandler(cfg, slog.Default(), registry, logs)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy.test/backoff-timeout", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusBadGateway)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("origin calls=%d, want one actual attempt", got)
	}

	snapshot := registry.Snapshot()
	if snapshot.Total.Retries != 0 || snapshot.Total.Upstream.Retries != 0 {
		t.Fatalf("retry telemetry counted an unsent request: total=%d upstream=%d", snapshot.Total.Retries, snapshot.Total.Upstream.Retries)
	}
	completed := logs.Query(accesslog.Filter{Event: "request_completed", Limit: 10})
	if len(completed.Entries) != 1 || completed.Entries[0].Retries != 0 || completed.Entries[0].UpstreamCalls != 1 {
		t.Fatalf("unexpected completion log: %#v", completed.Entries)
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

func TestCacheHostCanonicalizesBracketedIPv6(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "[2001:0DB8::1]", want: "2001:db8::1"},
		{input: "2001:0DB8::1", want: "2001:db8::1"},
		{input: "[2001:0DB8::1]:8080", want: "[2001:db8::1]:8080"},
	} {
		if got := cacheHost(tc.input); got != tc.want {
			t.Fatalf("cacheHost(%q)=%q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestPurgeCacheMatchesCanonicalIPv6Host(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, "cached")
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	cfg.Routes[0].Hosts = []string{"2001:db8::1"}
	h, err := NewHandler(cfg, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	request := func() string {
		req := httptest.NewRequest(http.MethodGet, "http://[2001:db8::1]/resource", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request returned %d: %s", rr.Code, rr.Body.String())
		}
		return rr.Header().Get("X-Cache")
	}
	if got := request(); got != "MISS" {
		t.Fatalf("first request cache=%q, want MISS", got)
	}
	if got := request(); got != "HIT" {
		t.Fatalf("second request cache=%q, want HIT", got)
	}
	purged, ok, err := h.PurgeCache("test", "2001:0DB8::1", "/resource")
	if err != nil || !ok || purged != 1 {
		t.Fatalf("purge entries=%d ok=%v err=%v, want 1 true nil", purged, ok, err)
	}
	if got := request(); got != "MISS" {
		t.Fatalf("IPv6 cache entry was not purged: cache=%q", got)
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

func TestRequestAllowsCachedEntryHonorsPositiveMaxAge(t *testing.T) {
	now := time.Now()
	entry := cache.Entry{StoredAt: now.Add(-30 * time.Second)}
	tests := []struct {
		name    string
		header  string
		allowed bool
	}{
		{name: "no constraint", allowed: true},
		{name: "younger than limit", header: "max-age=40", allowed: true},
		{name: "older than limit", header: "max-age=10", allowed: false},
		{name: "invalid constraint ignored", header: "max-age=invalid", allowed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
			if tc.header != "" {
				req.Header.Set("Cache-Control", tc.header)
			}
			if got := requestAllowsCachedEntry(req, entry, now); got != tc.allowed {
				t.Fatalf("allowed=%v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestRequestMaxAgeRejectsOlderFreshEntry(t *testing.T) {
	var calls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Age", "30")
		_, _ = fmt.Fprintf(w, "origin-%d", call)
	}))
	defer origin.Close()

	h, err := NewHandler(testConfig(origin.URL), slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://proxy.test/max-age", nil))
	if first.Code != http.StatusOK || first.Header().Get("X-Cache") != "MISS" || first.Body.String() != "origin-1" {
		t.Fatalf("first response: code=%d cache=%q body=%q", first.Code, first.Header().Get("X-Cache"), first.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodGet, "http://proxy.test/max-age", nil)
	secondReq.Header.Set("Cache-Control", "max-age=10")
	second := httptest.NewRecorder()
	h.ServeHTTP(second, secondReq)
	if second.Code != http.StatusOK || second.Header().Get("X-Cache") != "MISS" || second.Body.String() != "origin-2" {
		t.Fatalf("bounded-age response: code=%d cache=%q body=%q", second.Code, second.Header().Get("X-Cache"), second.Body.String())
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("origin calls=%d, want 2 because cached age exceeds request max-age", got)
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

func TestRequestCacheModeRejectsConflictingMaxAgeDirectives(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Cache-Control", "max-age=60")

	lookup, store, reason := requestCacheMode(req, config.CacheConfig{Enabled: true})
	if lookup || store || reason != "invalid-cache-control" {
		t.Fatalf("lookup=%v store=%v reason=%q, want false, false, invalid-cache-control", lookup, store, reason)
	}
	entry := cache.Entry{StoredAt: time.Now()}
	if requestAllowsCachedEntry(req, entry, time.Now()) {
		t.Fatal("conflicting max-age directives must not select a cached entry")
	}
}

func TestResponseCachePolicyRejectsDuplicateFreshnessDirectives(t *testing.T) {
	now := time.Now()
	cfg := config.CacheConfig{
		DefaultTTL:           config.Duration{Duration: time.Minute},
		RespectOriginHeaders: true,
		CacheableStatusCodes: []int{http.StatusOK},
	}
	for _, directive := range []string{"max-age", "s-maxage"} {
		t.Run(directive, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
			resp.Header.Add("Cache-Control", "public, "+directive+"=60")
			resp.Header.Add("Cache-Control", directive+"=3600")
			cacheable, _, _, _ := responseCachePolicy(
				httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil),
				resp,
				cfg,
				now,
			)
			if cacheable {
				t.Fatalf("response with duplicate %s directives must not be cached", directive)
			}
		})
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

func TestParseCacheControlPreservesQuotedCommas(t *testing.T) {
	parsed := parseCacheControlDetailed([]string{`extension="a,b", max-age=60`})
	if parsed.invalid {
		t.Fatal("valid quoted comma was marked invalid")
	}
	if got := parsed.directives["extension"]; got != "a,b" {
		t.Fatalf("extension=%q, want a,b", got)
	}
	if got := parsed.directives["max-age"]; got != "60" {
		t.Fatalf("max-age=%q, want 60", got)
	}

	malformed := parseCacheControlDetailed([]string{`extension="unterminated, no-store`})
	if !malformed.invalid {
		t.Fatal("unterminated quoted Cache-Control value must be invalid")
	}
}

func TestConditionalRequestCombinesRepeatedIfNoneMatchFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
	req.Header.Add("If-None-Match", `"different"`)
	req.Header.Add("If-None-Match", `W/"v1"`)
	header := make(http.Header)
	header.Set("ETag", `"v1"`)

	if !conditionalNotModified(req, header, http.StatusOK) {
		t.Fatal("a matching ETag in a later If-None-Match field must produce 304")
	}
}

func TestConditionalRequestHandlesCommaInsideETag(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/resource", nil)
	req.Header.Set("If-None-Match", `"other", W/"v1,part"`)
	header := make(http.Header)
	header.Set("ETag", `"v1,part"`)

	if !conditionalNotModified(req, header, http.StatusOK) {
		t.Fatal("a quoted comma inside an entity tag must not split the tag")
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
		w.Header().Set(internalProbeHeader, internalProbeResponseValue)
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
		for _, name := range []string{"X-Security-Action", "X-Security-Score", "X-Security-Gateway", internalProbeHeader} {
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

type blockingFillLocker struct {
	entered chan struct{}
	release chan struct{}
}

func (l *blockingFillLocker) Lock(string) func() {
	close(l.entered)
	<-l.release
	return func() {}
}

func TestCacheFillWaiterDoesNotServePurgedStaleEntry(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1").Routes[0]
	rt := &routeRuntime{
		cfg:   &cfg,
		pool:  &upstreamPool{},
		cache: cache.New(cfg.Cache.MaxEntries, cfg.Cache.MaxBytes),
		fills: &blockingFillLocker{entered: make(chan struct{}), release: make(chan struct{})},
	}
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/purged-stale", nil)
	key := cacheKey(req, cfg.Cache)
	now := time.Now()
	if !rt.cache.Set(key, cache.Entry{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       []byte("stale-body"),
		StoredAt:   now.Add(-2 * time.Minute),
		ExpiresAt:  now.Add(-time.Minute),
		StaleUntil: now.Add(time.Minute),
	}) {
		t.Fatal("store stale cache entry")
	}

	h := &Handler{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), metrics: metrics.New()}
	recorder := httptest.NewRecorder()
	done := make(chan requestResult, 1)
	go func() {
		done <- h.handleRoute(recorder, req, rt, "request-id", time.Now())
	}()

	locker := rt.fills.(*blockingFillLocker)
	<-locker.entered // The first stale lookup completed; the request is waiting for the fill lock.
	if !rt.cache.Delete(key) {
		t.Fatal("purge stale cache entry")
	}
	close(locker.release)
	result := <-done

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status=%d cache=%q body=%q, want 502 after purge", recorder.Code, recorder.Header().Get("X-Cache"), recorder.Body.String())
	}
	if result.cacheStatus == "STALE" || recorder.Header().Get("X-Cache") == "STALE" {
		t.Fatalf("purged stale entry was served: result=%+v headers=%v", result, recorder.Header())
	}
}

type informationalCaptureWriter struct {
	header   http.Header
	statuses []int
}

func (w *informationalCaptureWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *informationalCaptureWriter) WriteHeader(status int) {
	w.statuses = append(w.statuses, status)
}

func (w *informationalCaptureWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestResponseCaptureForwardsInformationalBeforeFinalStatus(t *testing.T) {
	underlying := &informationalCaptureWriter{}
	capture := &responseCapture{ResponseWriter: underlying}

	capture.WriteHeader(http.StatusEarlyHints)
	if capture.status != 0 {
		t.Fatalf("informational response latched as final status: %d", capture.status)
	}
	capture.WriteHeader(http.StatusOK)

	if capture.status != http.StatusOK {
		t.Fatalf("captured final status=%d, want %d", capture.status, http.StatusOK)
	}
	if len(underlying.statuses) != 2 || underlying.statuses[0] != http.StatusEarlyHints || underlying.statuses[1] != http.StatusOK {
		t.Fatalf("forwarded statuses=%v, want [%d %d]", underlying.statuses, http.StatusEarlyHints, http.StatusOK)
	}
}

func TestResponseCaptureTreatsSwitchingProtocolsAsFinal(t *testing.T) {
	underlying := &informationalCaptureWriter{}
	capture := &responseCapture{ResponseWriter: underlying}

	capture.WriteHeader(http.StatusSwitchingProtocols)
	capture.WriteHeader(http.StatusOK)

	if capture.status != http.StatusSwitchingProtocols {
		t.Fatalf("captured protocol-upgrade status=%d, want %d", capture.status, http.StatusSwitchingProtocols)
	}
	if len(underlying.statuses) != 1 || underlying.statuses[0] != http.StatusSwitchingProtocols {
		t.Fatalf("forwarded statuses=%v, want [%d]", underlying.statuses, http.StatusSwitchingProtocols)
	}
}

func TestEarlyHintsThenOKKeepsFinalResponseTelemetry(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()

	cfg := testConfig(origin.URL)
	registry := metrics.New()
	h, err := NewHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()

	req, err := http.NewRequest(http.MethodGet, proxyServer.URL+"/early", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "proxy.test"
	resp, err := proxyServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("client response status=%d body=%q", resp.StatusCode, body)
	}

	total := registry.Snapshot().Total
	if total.Requests != 1 || total.Success != 1 || total.ClientErrors != 0 || total.ServerErrors != 0 ||
		total.CanceledRequests != 0 || total.StatusCodes["200"] != 1 || total.StatusCodes["103"] != 0 {
		t.Fatalf("final response telemetry inconsistent after Early Hints: %#v", total)
	}
}

func TestRouteStatusesReadyMatchesCapturedOriginHealthUnderConcurrentTransition(t *testing.T) {
	originURL, err := url.Parse("http://origin.internal")
	if err != nil {
		t.Fatal(err)
	}
	node := &upstream{name: "origin", url: originURL, weight: 1}
	node.healthy.Store(true)
	pool := &upstreamPool{nodes: []*upstream{node}, algorithm: "round_robin"}
	h := &Handler{routes: map[string]*routeRuntime{
		"test": {cfg: &config.RouteConfig{Name: "test"}, pool: pool},
	}}

	var stop atomic.Bool
	flipperDone := make(chan struct{})
	go func() {
		defer close(flipperDone)
		for !stop.Load() {
			node.healthy.Store(false)
			node.healthy.Store(true)
		}
	}()
	defer func() {
		stop.Store(true)
		<-flipperDone
	}()

	for i := 0; i < 100_000; i++ {
		statuses := h.RouteStatuses()
		if len(statuses) != 1 || len(statuses[0].Upstreams) != 1 {
			t.Fatalf("route statuses=%#v", statuses)
		}
		capturedHealthy, ok := statuses[0].Upstreams[0]["healthy"].(bool)
		if !ok {
			t.Fatalf("captured healthy value=%#v", statuses[0].Upstreams[0]["healthy"])
		}
		if statuses[0].Ready != capturedHealthy {
			t.Fatalf("torn route status at iteration %d: ready=%v captured_origin_healthy=%v", i, statuses[0].Ready, capturedHealthy)
		}
	}
}
