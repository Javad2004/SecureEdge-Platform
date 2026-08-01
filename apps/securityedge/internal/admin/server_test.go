package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/admission"
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/ratelimit"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/waf"
)

type fakeRuntime struct{ cfg config.Config }

func (f *fakeRuntime) Config() config.Config { return f.cfg }
func (f *fakeRuntime) Routes() []routes.Route {
	return []routes.Route{{Name: "demo-app", Hosts: []string{"project.test"}, PathPrefix: "/"}}
}
func (f *fakeRuntime) EffectivePolicy(string) config.Policy          { return f.cfg.DefaultPolicy }
func (f *fakeRuntime) UpdateDefaultPolicy(config.Policy) error       { return nil }
func (f *fakeRuntime) UpdateRoutePolicy(string, config.Policy) error { return nil }
func (f *fakeRuntime) DeleteRoutePolicy(string) error                { return nil }
func (f *fakeRuntime) Reload() error                                 { return nil }
func (f *fakeRuntime) LimiterSize() int                              { return 0 }
func (f *fakeRuntime) ActiveBans() []ratelimit.Ban                   { return nil }
func (f *fakeRuntime) ActiveBanCount() int                           { return 0 }
func (f *fakeRuntime) DeleteBan(string) bool                         { return false }
func (f *fakeRuntime) ClearBans() int                                { return 0 }
func (f *fakeRuntime) AdmissionSnapshot() admission.Snapshot         { return admission.Snapshot{} }
func (f *fakeRuntime) Audit(string, string, map[string]string)       {}
func (f *fakeRuntime) EdgeJSON(context.Context, string, string, url.Values, any) (json.RawMessage, int, error) {
	return json.RawMessage(`{"status":"ready"}`), http.StatusOK, nil
}

func newAdminTestServer(t *testing.T, failures int) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.AuthToken = "secret-token"
	cfg.Admin.AuthFailuresPerMinute = failures
	cfg.Admin.AuthLockoutDuration = config.Duration{Duration: time.Minute}
	inspector, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg.Admin, &fakeRuntime{cfg: cfg}, metrics.New(), securitylog.New(100), inspector)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(s.HTTPServer().Handler)
}

func TestAdminRequiresBearerTokenAndServesBuildInfo(t *testing.T) {
	ts := newAdminTestServer(t, 10)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	build, ok := body["build"].(map[string]any)
	if !ok || build["name"] != "SecurityEdge" {
		t.Fatalf("body=%#v", body)
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("security headers missing: %#v", resp.Header)
	}
}

func TestAdminAuthenticationLockout(t *testing.T) {
	ts := newAdminTestServer(t, 2)
	defer ts.Close()
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d", i, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
}

func TestConnectivityEndpointRequiresAuthAndReturnsSnapshot(t *testing.T) {
	ts := newAdminTestServer(t, 10)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/connectivity/check", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body struct {
		OverallStatus string `json:"overall_status"`
		Components    []any  `json:"components"`
		GeneratedAt   string `json:"generated_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.GeneratedAt == "" || body.OverallStatus == "" || len(body.Components) == 0 {
		t.Fatalf("body=%#v", body)
	}
}
