package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/admission"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/ratelimit"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/routes"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/securitylog"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/traffic"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/waf"
)

type fakeRuntime struct {
	cfg       config.Config
	reloadErr error
}

func (f *fakeRuntime) Config() config.Config { return f.cfg }
func (f *fakeRuntime) Routes() []routes.Route {
	return []routes.Route{{Name: "demo-app", Hosts: []string{"project.test"}, PathPrefix: "/"}}
}
func (f *fakeRuntime) EffectivePolicy(string) config.Policy          { return f.cfg.DefaultPolicy }
func (f *fakeRuntime) UpdateDefaultPolicy(config.Policy) error       { return nil }
func (f *fakeRuntime) UpdateRoutePolicy(string, config.Policy) error { return nil }
func (f *fakeRuntime) DeleteRoutePolicy(string) error                { return nil }
func (f *fakeRuntime) Reload() error                                 { return f.reloadErr }
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
	ts, _ := newAdminTestServerWithTraffic(t, failures)
	return ts
}

func newAdminTestServerWithTraffic(t *testing.T, failures int) (*httptest.Server, *traffic.Tracker) {
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
	tracker := traffic.New(100, time.Minute)
	s, err := New(cfg.Admin, &fakeRuntime{cfg: cfg}, metrics.New(), securitylog.New(100), tracker, inspector)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(s.HTTPServer().Handler), tracker
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

func TestAdminRejectsMultipleAuthorizationFields(t *testing.T) {
	ts := newAdminTestServer(t, 10)
	defer ts.Close()
	for _, values := range [][]string{
		{"Bearer secret-token", "Bearer secret-token"},
		{"Bearer secret-token", "Bearer conflicting-token"},
	} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/info", nil)
		req.Header["Authorization"] = values
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected ambiguous credentials %q to be rejected with 401, got %d", values, resp.StatusCode)
		}
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

func TestRecentTrafficEndpointReturnsPassiveObservedTraffic(t *testing.T) {
	ts, tracker := newAdminTestServerWithTraffic(t, 10)
	defer ts.Close()
	tracker.Observe(traffic.Event{ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), ClientIP: "10.0.0.8", Method: http.MethodGet, Path: "/", Route: "demo-app", Action: "ALLOW", Status: http.StatusOK})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/traffic/recent", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body traffic.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "traffic_observed" || body.LastRequest == nil || body.LastRequest.ClientIP != "10.0.0.8" {
		t.Fatalf("body=%#v", body)
	}
}

func TestLogExportRejectsUnsupportedFormatBeforeWritingHeaders(t *testing.T) {
	ts := newAdminTestServer(t, 10)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/logs/export?format=xml", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content type=%q, want JSON error", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var apiError struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &apiError); err != nil {
		t.Fatalf("decode error response: %v body=%q", err, body)
	}
	if apiError.Error.Code != "invalid_format" {
		t.Fatalf("error code=%q, want invalid_format", apiError.Error.Code)
	}
}

func TestAuthFailureTrackingIsBounded(t *testing.T) {
	cfg := config.Default().Admin
	cfg.AuthFailuresPerMinute = 10
	cfg.AuthLockoutDuration = config.Duration{Duration: time.Minute}
	s := &Server{cfg: cfg, authFails: make(map[string]*authFailure)}
	now := time.Now()
	for i := 0; i < maxTrackedAuthClients+128; i++ {
		s.recordAuthFailure("198.51.100."+strconv.Itoa(i), now.Add(time.Duration(i)*time.Microsecond))
	}
	if got := len(s.authFails); got > maxTrackedAuthClients {
		t.Fatalf("tracked auth clients=%d, max=%d", got, maxTrackedAuthClients)
	}
}

func TestSecureTokenEqualHandlesDifferentLengths(t *testing.T) {
	if !secureTokenEqual("secret-token", "secret-token") {
		t.Fatal("equal tokens did not match")
	}
	if secureTokenEqual("short", "a-much-longer-token") {
		t.Fatal("different tokens matched")
	}
}

type fakeRestartRequiredError struct{}

func (fakeRestartRequiredError) Error() string         { return "listener change requires restart" }
func (fakeRestartRequiredError) RestartRequired() bool { return true }

func TestReloadReturnsConflictWhenRestartIsRequired(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.AuthToken = "secret-token"
	inspector, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{cfg: cfg, reloadErr: fakeRestartRequiredError{}}
	s, err := New(cfg.Admin, runtime, metrics.New(), securitylog.New(100), traffic.New(100, time.Minute), inspector)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.HTTPServer().Handler)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/reload", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status=%d, want %d", resp.StatusCode, http.StatusConflict)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	errorBody, _ := body["error"].(map[string]any)
	if errorBody["code"] != "restart_required" {
		t.Fatalf("body=%#v", body)
	}
}

func TestRequestIDMiddlewareRejectsUnsafeValues(t *testing.T) {
	handler := requestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, value := range []string{"valid-id_123:abc", "bad id", "bad\tvalue", strings.Repeat("a", 129)} {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		req.Header.Set("X-Request-ID", value)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		got := rr.Header().Get("X-Request-ID")
		if value == "valid-id_123:abc" {
			if got != value {
				t.Fatalf("valid request ID changed: got %q want %q", got, value)
			}
			continue
		}
		if got == value || !validRequestID(got) {
			t.Fatalf("unsafe request ID was not replaced: input=%q output=%q", value, got)
		}
	}
}

func TestLogQueryRejectsInvertedTimeRange(t *testing.T) {
	ts := newAdminTestServer(t, 10)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/logs?since=2026-08-02T12:00:00Z&until=2026-08-02T11:00:00Z", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "since cannot be after until") {
		t.Fatalf("body=%s", body)
	}
}

func TestAuthFailureCapacityPreservesActiveLockouts(t *testing.T) {
	cfg := config.Default().Admin
	cfg.AuthFailuresPerMinute = 1
	cfg.AuthLockoutDuration = config.Duration{Duration: time.Hour}
	s := &Server{cfg: cfg, authFails: make(map[string]*authFailure)}
	now := time.Now()
	for i := 0; i < maxTrackedAuthClients; i++ {
		client := "locked-" + strconv.Itoa(i)
		s.authFails[client] = &authFailure{count: 1, windowStart: now, lockedUntil: now.Add(time.Hour)}
	}

	s.recordAuthFailure("new-client", now.Add(time.Second))
	if _, exists := s.authFails["new-client"]; exists {
		t.Fatal("new auth failure replaced an active lockout")
	}
	if got := len(s.authFails); got != maxTrackedAuthClients {
		t.Fatalf("tracked auth clients=%d, want %d", got, maxTrackedAuthClients)
	}
	if locked, _ := s.authLocked("locked-0", now.Add(time.Second)); !locked {
		t.Fatal("active lockout was evicted before its expiry")
	}
}

func TestPolicyUpdateRejectsOversizedAdminBodyWith413(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.AuthToken = "secret-token"
	cfg.Admin.MaxRequestBodyBytes = 32
	inspector, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg.Admin, &fakeRuntime{cfg: cfg}, metrics.New(), securitylog.New(100), traffic.New(100, time.Minute), inspector)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.HTTPServer().Handler)
	defer ts.Close()

	body := strings.NewReader(`{"enabled":true,"padding":"` + strings.Repeat("x", 128) + `"}`)
	req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/policies/default", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%q, want 413", resp.StatusCode, payload)
	}
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != "body_too_large" {
		t.Fatalf("error code=%q, want body_too_large", payload.Error.Code)
	}
}
