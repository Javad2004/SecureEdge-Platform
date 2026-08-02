package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/admission"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/clientip"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/ratelimit"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/routes"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/securitylog"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/traffic"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/waf"
)

type policies struct {
	p config.Policy
	s config.ServerConfig
}

func (p policies) Policy(string) config.Policy       { return p.p }
func (p policies) ServerConfig() config.ServerConfig { return p.s }

func newTestHandler(t *testing.T, next http.Handler, p config.Policy) *Handler {
	handler, _ := newTestHandlerWithTraffic(t, next, p)
	return handler
}

func newTestHandlerWithTraffic(t *testing.T, next http.Handler, p config.Policy) (*Handler, *traffic.Tracker) {
	t.Helper()
	tableFile := t.TempDir() + "/edge.json"
	if err := os.WriteFile(tableFile, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	table, err := routes.Load(tableFile)
	if err != nil {
		t.Fatal(err)
	}
	i, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	l := ratelimit.New(time.Hour, time.Hour)
	t.Cleanup(l.Close)
	resolver, err := clientip.New(nil, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	tracker := traffic.New(100, time.Minute)
	return New(next, table, policies{p: p, s: config.Default().Server}, i, l, ratelimit.NewBanManager(), admission.New(), resolver, metrics.New(), securitylog.New(100), tracker, slog.Default()), tracker
}
func TestBlocksXSSBeforeNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	h := newTestHandler(t, next, p)
	req := httptest.NewRequest("GET", "http://project.test/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d called=%v", rec.Code, called)
	}
}
func TestRejectsOversizedPath(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	p.MaxPathBytes = 8
	h := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") }), p)
	req := httptest.NewRequest("GET", "http://project.test/this-is-too-long", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestURITooLong || !strings.Contains(rec.Body.String(), "path_too_large") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRepeatedHeaderFieldsCountTowardLimit(t *testing.T) {
	policy := config.Default().DefaultPolicy
	policy.RateLimit.Enabled = false
	policy.MaxHeaderCount = 2
	h := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called for an over-limit repeated header")
	}), policy)

	req := httptest.NewRequest(http.MethodGet, "http://project.test/", nil)
	req.Header["X-Repeated"] = []string{"one", "two", "three"}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusRequestHeaderFieldsTooLarge || !strings.Contains(response.Body.String(), "too_many_headers") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRateLimitReturns429(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.RequestsPerSecond = 1
	p.RateLimit.Burst = 1
	p.RateLimit.GlobalRequestsPerSecond = 100
	p.RateLimit.GlobalBurst = 100
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), p)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "http://project.test/", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if i == 1 && rec.Code != 429 {
			t.Fatalf("expected 429 got %d", rec.Code)
		}
	}
}
func TestRepeatedViolationsTriggerTemporaryBan(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	p.AutoBan.ViolationThreshold = 2
	p.AutoBan.Window = config.Duration{Duration: time.Minute}
	p.AutoBan.BanDuration = config.Duration{Duration: time.Minute}
	p.AutoBan.MaxTrackedClients = 100
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), p)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "http://project.test/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
		req.RemoteAddr = "10.0.0.9:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("violation %d status %d", i, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "http://project.test/clean", nil)
	req.RemoteAddr = "10.0.0.9:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), "temporarily_banned") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBlocksBodyWhenInspectionLimitIsExceeded(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	p.MaxInspectionBodyBytes = 8
	p.BlockOnInspectionLimit = true
	h := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") }), p)
	req := httptest.NewRequest(http.MethodPost, "http://project.test/upload", strings.NewReader(`{"value":"payload-after-limit"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "inspection_limit_exceeded") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRejectsUnsupportedRequestBodyTypeWhenConfigured(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	p.RejectUnsupportedBodyTypes = true
	h := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") }), p)
	req := httptest.NewRequest(http.MethodPost, "http://project.test/upload", strings.NewReader("binary-like-data"))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType || !strings.Contains(rec.Body.String(), "unsupported_body_type") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSuspiciousPathAndUserAgentAreFingerprintOnly(t *testing.T) {
	path, pathFP := logSafePath("/<script>alert(1)</script>", "BLOCK", "waf_threshold", true)
	if path != "[redacted]" || pathFP == "" || strings.Contains(pathFP, "script") {
		t.Fatalf("path=%q fingerprint=%q", path, pathFP)
	}
	uaFP := fingerprint("sqlmap/1.8 malicious-payload")
	if uaFP == "" || strings.Contains(uaFP, "sqlmap") {
		t.Fatalf("unsafe user-agent fingerprint %q", uaFP)
	}
}

func TestRecentTrafficCapturesFinalDownstreamStatusAndCacheResult(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	h, tracker := newTestHandlerWithTraffic(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Cache", "MISS")
		w.WriteHeader(http.StatusBadGateway)
	}), p)
	req := httptest.NewRequest(http.MethodGet, "http://project.test/api/products", nil)
	req.RemoteAddr = "10.0.0.15:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", rec.Code)
	}
	snapshot := tracker.Snapshot(time.Now())
	if snapshot.LastRequest == nil || snapshot.LastRequest.Status != http.StatusBadGateway || snapshot.LastRequest.CacheStatus != "MISS" || snapshot.LastRequest.ClientIP != "10.0.0.15" {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestResolvedClientIPIsAvailableToDownstreamTransport(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	var resolved string
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved = ResolvedClientIP(r.Context())
		w.WriteHeader(http.StatusOK)
	}), p)
	req := httptest.NewRequest(http.MethodGet, "http://project.test/", nil)
	req.RemoteAddr = "198.51.100.25:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || resolved != "198.51.100.25" {
		t.Fatalf("status=%d resolved=%q", rec.Code, resolved)
	}
}

func TestGlobalRateLimitDoesNotAutoBanIndividualClient(t *testing.T) {
	p := config.Default().DefaultPolicy
	p.RateLimit.RequestsPerSecond = 100
	p.RateLimit.Burst = 100
	p.RateLimit.GlobalRequestsPerSecond = 1
	p.RateLimit.GlobalBurst = 1
	p.AutoBan.Enabled = true
	p.AutoBan.ViolationThreshold = 1
	p.AutoBan.Window = config.Duration{Duration: time.Minute}
	p.AutoBan.BanDuration = config.Duration{Duration: time.Minute}
	p.AutoBan.MaxTrackedClients = 100
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), p)

	first := httptest.NewRequest(http.MethodGet, "http://project.test/first", nil)
	first.RemoteAddr = "10.0.0.1:1234"
	h.ServeHTTP(httptest.NewRecorder(), first)

	second := httptest.NewRequest(http.MethodGet, "http://project.test/second", nil)
	second.RemoteAddr = "10.0.0.2:1234"
	secondResponse := httptest.NewRecorder()
	h.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("expected global rate limit, got %d", secondResponse.Code)
	}
	if banned, _ := h.bans.IsBanned("10.0.0.2", time.Now()); banned {
		t.Fatal("a client rejected by the global rate limit must not be auto-banned")
	}
}

func TestDownstreamCannotSpoofSecurityDecisionHeaders(t *testing.T) {
	policy := config.Default().DefaultPolicy
	policy.RateLimit.Enabled = false
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-ID", "downstream-spoof")
		w.Header().Set("X-Security-Action", "BLOCK")
		w.Header().Set("X-Security-Score", "999")
		w.WriteHeader(http.StatusOK)
	}), policy)

	req := httptest.NewRequest(http.MethodGet, "http://project.test/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Result().Header.Values("X-Request-ID"); len(got) != 1 || got[0] == "downstream-spoof" || got[0] == "" {
		t.Fatalf("request IDs=%#v", got)
	}
	if got := rec.Result().Header.Values("X-Security-Action"); len(got) != 1 || got[0] != "ALLOW" {
		t.Fatalf("security actions=%#v", got)
	}
	if got := rec.Result().Header.Values("X-Security-Score"); len(got) != 1 || got[0] != "0" {
		t.Fatalf("security scores=%#v", got)
	}
}

type informationalResponseWriter struct {
	header   http.Header
	statuses []int
}

func (w *informationalResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *informationalResponseWriter) WriteHeader(status int) {
	w.statuses = append(w.statuses, status)
}
func (w *informationalResponseWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestDecisionWriterPreservesFinalStatusAfterInformationalResponse(t *testing.T) {
	underlying := &informationalResponseWriter{}
	writer := &decisionWriter{ResponseWriter: underlying, requestID: "request-1", action: "ALLOW", score: 0, addSecurityHeaders: true}
	writer.WriteHeader(http.StatusEarlyHints)
	writer.WriteHeader(http.StatusOK)
	if writer.Status() != http.StatusOK {
		t.Fatalf("final status=%d, want %d", writer.Status(), http.StatusOK)
	}
	if len(underlying.statuses) != 2 || underlying.statuses[0] != http.StatusEarlyHints || underlying.statuses[1] != http.StatusOK {
		t.Fatalf("forwarded statuses=%v, want [103 200]", underlying.statuses)
	}
}

func TestGeneratedRequestIDDoesNotConsumeInboundHeaderLimit(t *testing.T) {
	policy := config.Default().DefaultPolicy
	policy.RateLimit.Enabled = false
	policy.MaxHeaderCount = 1
	called := false
	h := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), policy)

	req := httptest.NewRequest(http.MethodGet, "http://project.test/", nil)
	req.Header.Set("X-Client-Metadata", "one")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("status=%d called=%v body=%s", response.Code, called, response.Body.String())
	}
}

func TestOversizedInboundRequestIDIsValidatedBeforeReplacement(t *testing.T) {
	policy := config.Default().DefaultPolicy
	policy.RateLimit.Enabled = false
	policy.MaxHeaderValueBytes = 8
	h := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called for an oversized inbound request ID")
	}), policy)

	req := httptest.NewRequest(http.MethodGet, "http://project.test/", nil)
	req.Header.Set("X-Request-ID", "client-controlled-request-id")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusRequestHeaderFieldsTooLarge || !strings.Contains(response.Body.String(), "header_value_too_large") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestInspectionMaxBytesErrorReturnsPayloadTooLarge(t *testing.T) {
	policy := config.Default().DefaultPolicy
	policy.RateLimit.Enabled = false
	policy.MaxInspectionBodyBytes = 64
	h := newTestHandler(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called for an oversized request body")
	}), policy)

	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://project.test/upload", strings.NewReader(strings.Repeat("x", 32)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "text/plain")
	req.Body = http.MaxBytesReader(response, req.Body, 8)
	h.ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge || !strings.Contains(response.Body.String(), "body_too_large") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
