package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

type boundedChunkResponseWriter struct {
	header      http.Header
	status      int
	maxChunk    int
	maxObserved int
	written     int
}

func (w *boundedChunkResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *boundedChunkResponseWriter) WriteHeader(status int) { w.status = status }

func (w *boundedChunkResponseWriter) Write(data []byte) (int, error) {
	if len(data) > w.maxObserved {
		w.maxObserved = len(data)
	}
	if w.maxChunk > 0 && len(data) > w.maxChunk {
		return 0, errors.New("response write exceeded bounded chunk")
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.written += len(data)
	return len(data), nil
}

type fakeRuntime struct {
	mu         sync.Mutex
	cfg        config.Config
	reloadErr  error
	replaceErr error
	edgeRaw    json.RawMessage
	edgeStatus int
	edgeErr    error
	lastMethod string
	lastPath   string
	lastQuery  url.Values
	lastBody   any
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
func (f *fakeRuntime) ReplaceConfig(candidate config.Config) error {
	if f.replaceErr != nil {
		return f.replaceErr
	}
	f.mu.Lock()
	f.cfg = candidate
	f.mu.Unlock()
	return nil
}
func (f *fakeRuntime) RedactedConfig() config.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.cfg
	if out.Admin.AuthToken != "" {
		out.Admin.AuthToken = "[REDACTED]"
	}
	if out.EdgeProxy.AdminToken != "" {
		out.EdgeProxy.AdminToken = "[REDACTED]"
	}
	return out
}
func (f *fakeRuntime) WatchStatusMap() map[string]any          { return map[string]any{"revision": 1} }
func (f *fakeRuntime) LimiterSize() int                        { return 0 }
func (f *fakeRuntime) ActiveBans() []ratelimit.Ban             { return nil }
func (f *fakeRuntime) ActiveBanCount() int                     { return 0 }
func (f *fakeRuntime) DeleteBan(string) bool                   { return false }
func (f *fakeRuntime) ClearBans() int                          { return 0 }
func (f *fakeRuntime) AdmissionSnapshot() admission.Snapshot   { return admission.Snapshot{} }
func (f *fakeRuntime) Audit(string, string, map[string]string) {}
func (f *fakeRuntime) EdgeJSON(_ context.Context, method, path string, query url.Values, body any) (json.RawMessage, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastMethod, f.lastPath, f.lastQuery, f.lastBody = method, path, query, body
	if f.edgeRaw == nil && f.edgeStatus == 0 && f.edgeErr == nil {
		return json.RawMessage(`{"status":"ready"}`), http.StatusOK, nil
	}
	return f.edgeRaw, f.edgeStatus, f.edgeErr
}

func (f *fakeRuntime) lastEdgeRequest() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastMethod, f.lastPath
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

func TestLogExportStreamsInBoundedChunks(t *testing.T) {
	store := securitylog.New(256)
	for i := 0; i < 200; i++ {
		store.Append(securitylog.Entry{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Event:     "request",
			Path:      "/" + strings.Repeat("x", 1024),
			Action:    "ALLOW",
			Status:    http.StatusOK,
		})
	}
	cfg := config.Default().Admin
	cfg.LogStore.Capacity = 256
	cfg.LogStore.DefaultPageSize = 100
	cfg.LogStore.MaxPageSize = 256
	server := &Server{cfg: cfg, logs: store}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs/export?format=csv", nil)
	w := &boundedChunkResponseWriter{maxChunk: 8 << 10}

	server.exportLogs(w, req)

	if w.status != http.StatusOK {
		t.Fatalf("status=%d, want %d", w.status, http.StatusOK)
	}
	if w.written <= w.maxChunk {
		t.Fatalf("export was too small to exercise streaming: wrote %d bytes", w.written)
	}
	if w.maxObserved > w.maxChunk {
		t.Fatalf("export materialized an oversized response chunk: %d bytes", w.maxObserved)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "security-events.csv") {
		t.Fatalf("content disposition=%q", got)
	}
}

func TestReadyEndpointDoesNotExposeEdgeProxyDetails(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.AuthToken = "secret-token"
	inspector, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		runtime    *fakeRuntime
		wantStatus int
		forbidden  []string
	}{
		{
			name: "transport error",
			runtime: &fakeRuntime{
				cfg:     cfg,
				edgeErr: errors.New(`Get "http://127.0.0.1:9090/private": connection refused`),
			},
			wantStatus: http.StatusServiceUnavailable,
			forbidden:  []string{"127.0.0.1:9090", "connection refused", `"error"`},
		},
		{
			name: "dependency not ready",
			runtime: &fakeRuntime{
				cfg:        cfg,
				edgeRaw:    json.RawMessage(`{"status":"not_ready","unhealthy_routes":["private-route"]}`),
				edgeStatus: http.StatusServiceUnavailable,
			},
			wantStatus: http.StatusServiceUnavailable,
			forbidden:  []string{"private-route", "unhealthy_routes"},
		},
		{
			name: "dependency ready",
			runtime: &fakeRuntime{
				cfg:        cfg,
				edgeRaw:    json.RawMessage(`{"status":"ready","routes":["private-route"]}`),
				edgeStatus: http.StatusOK,
			},
			wantStatus: http.StatusOK,
			forbidden:  []string{"private-route", `"routes"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(cfg.Admin, tt.runtime, metrics.New(), securitylog.New(100), traffic.New(100, time.Minute), inspector)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			rr := httptest.NewRecorder()
			s.HTTPServer().Handler.ServeHTTP(rr, req)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status=%d body=%q, want %d", rr.Code, rr.Body.String(), tt.wantStatus)
			}
			body := rr.Body.String()
			for _, value := range tt.forbidden {
				if strings.Contains(body, value) {
					t.Fatalf("readiness response exposed %q: %s", value, body)
				}
			}
			var payload map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["dependency"] != "edgeproxy" || payload["generated_at"] == "" {
				t.Fatalf("body=%#v", payload)
			}
		})
	}
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

func TestReloadAcceptsAutomaticRestartWhenRequired(t *testing.T) {
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
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status=%d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["restart_required"] != true || body["automatic_restart"] != true {
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

func TestEdgeProxyAdvancedControlPlaneForwarding(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.AuthToken = "secret-token"
	inspector, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{cfg: cfg}
	server, err := New(cfg.Admin, runtime, metrics.New(), securitylog.New(100), traffic.New(100, time.Minute), inspector)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		method, requestPath, forwardedPath, body string
	}{
		{http.MethodGet, "/api/v1/edgeproxy/telemetry", "/api/v1/telemetry", ""},
		{http.MethodGet, "/api/v1/edgeproxy/server", "/api/v1/server", ""},
		{http.MethodPut, "/api/v1/edgeproxy/admin", "/api/v1/admin", `{}`},
		{http.MethodGet, "/api/v1/edgeproxy/routes/demo-app/load-balancing", "/api/v1/routes/demo-app/load-balancing", ""},
		{http.MethodPut, "/api/v1/edgeproxy/routes/demo-app/cache", "/api/v1/routes/demo-app/cache", `{"enabled":false}`},
		{http.MethodPost, "/api/v1/edgeproxy/routes/demo-app/cache/purge?host=project.test&path_prefix=%2Fapi", "/api/v1/routes/demo-app/cache/purge", ""},
		{http.MethodGet, "/api/v1/edgeproxy/routes/demo-app/origins/origin-1/telemetry", "/api/v1/routes/demo-app/origins/origin-1/telemetry", ""},
	}
	for _, tt := range tests {
		var body io.Reader
		if tt.body != "" {
			body = strings.NewReader(tt.body)
		}
		req := httptest.NewRequest(tt.method, tt.requestPath, body)
		req.Header.Set("Authorization", "Bearer secret-token")
		if tt.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rr := httptest.NewRecorder()
		server.HTTPServer().Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s status=%d body=%s", tt.method, tt.requestPath, rr.Code, rr.Body.String())
		}
		lastMethod, lastPath := runtime.lastEdgeRequest()
		if lastMethod != tt.method || lastPath != tt.forwardedPath {
			t.Fatalf("%s %s forwarded as %s %s", tt.method, tt.requestPath, lastMethod, lastPath)
		}
	}
}

func TestSecurityConfigSectionEndpoints(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.EdgeProxy.AdminToken = "edge-secret"
	cfg.Admin.AuthToken = "secret-token"
	inspector, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{cfg: cfg}
	server, err := New(cfg.Admin, runtime, metrics.New(), securitylog.New(100), traffic.New(100, time.Minute), inspector)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/v1/server", "/api/v1/admin", "/api/v1/edgeproxy-settings", "/api/v1/waf"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		rr := httptest.NewRecorder()
		server.HTTPServer().Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "secret-token") || strings.Contains(rr.Body.String(), "edge-secret") {
			t.Fatalf("GET %s exposed a secret: %s", path, rr.Body.String())
		}
	}

	serverSection := cfg.Server
	serverSection.MaxConcurrentRequests++
	body, _ := json.Marshal(serverSection)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/server", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT server status=%d body=%s", rr.Code, rr.Body.String())
	}
	if runtime.cfg.Server.MaxConcurrentRequests != serverSection.MaxConcurrentRequests {
		t.Fatal("server section was not applied")
	}
	if runtime.cfg.Admin.AuthToken != "[REDACTED]" {
		t.Fatalf("test runtime did not receive redacted token marker: %q", runtime.cfg.Admin.AuthToken)
	}

	adminSection := cfg.Admin
	adminSection.PollTimeout = config.Duration{Duration: 7 * time.Second}
	adminSection.AuthToken = "[REDACTED]"
	body, _ = json.Marshal(adminSection)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/admin", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer secret-token")
	rr = httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT admin status=%d body=%s", rr.Code, rr.Body.String())
	}
	if runtime.cfg.Admin.PollTimeout.Duration != 7*time.Second {
		t.Fatal("admin section was not applied")
	}

	edgeSection := cfg.EdgeProxy
	edgeSection.Timeout = config.Duration{Duration: 9 * time.Second}
	edgeSection.AdminToken = "[REDACTED]"
	body, _ = json.Marshal(edgeSection)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/edgeproxy-settings", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer secret-token")
	rr = httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT edgeproxy-settings status=%d body=%s", rr.Code, rr.Body.String())
	}
	if runtime.cfg.EdgeProxy.Timeout.Duration != 9*time.Second {
		t.Fatal("EdgeProxy dependency section was not applied")
	}

	wafSection := cfg.WAF
	wafSection.MaximumMatchesPerRequest = 48
	body, _ = json.Marshal(wafSection)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/waf", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer secret-token")
	rr = httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT waf status=%d body=%s", rr.Code, rr.Body.String())
	}
	if runtime.cfg.WAF.MaximumMatchesPerRequest != 48 {
		t.Fatal("WAF section was not applied")
	}

	req = httptest.NewRequest(http.MethodPut, "/api/v1/waf", strings.NewReader(`{"maximum_matches_per_request":48,"unknown":true}`))
	req.Header.Set("Authorization", "Bearer secret-token")
	rr = httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT WAF with unknown field status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSecurityConfigSectionEndpointReturns202ForRestart(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.AuthToken = "secret-token"
	inspector, err := waf.NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{cfg: cfg, replaceErr: fakeRestartRequiredError{}}
	server, err := New(cfg.Admin, runtime, metrics.New(), securitylog.New(100), traffic.New(100, time.Minute), inspector)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(cfg.Server)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/server", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
