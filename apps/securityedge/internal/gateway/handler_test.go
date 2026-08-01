package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/admission"
	"github.com/bachelor-project/edgeproxy-security/internal/clientip"
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/ratelimit"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/waf"
)

type policies struct {
	p config.Policy
	s config.ServerConfig
}

func (p policies) Policy(string) config.Policy       { return p.p }
func (p policies) ServerConfig() config.ServerConfig { return p.s }

func newTestHandler(t *testing.T, next http.Handler, p config.Policy) *Handler {
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
	return New(next, table, policies{p: p, s: config.Default().Server}, i, l, ratelimit.NewBanManager(), admission.New(), resolver, metrics.New(), securitylog.New(100), slog.Default())
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
