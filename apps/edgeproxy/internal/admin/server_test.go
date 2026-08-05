package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

func testAdminServer(store *accesslog.Store) *Server {
	cfg := config.AdminConfig{
		Enabled:    true,
		ListenAddr: "127.0.0.1:9090",
		AuthToken:  "test-token",
		LogStore:   config.AdminLogConfig{Enabled: true, Capacity: 100, DefaultPageSize: 20, MaxPageSize: 50},
	}
	return New(cfg, slog.Default(), metrics.New(), nil, store)
}

func TestLogsEndpointRequiresTokenAndSupportsFilters(t *testing.T) {
	store := accesslog.New(100)
	store.Append(accesslog.Entry{Event: "upstream_attempt", Route: "demo", Upstream: "http://origin-a", UpstreamStatus: 200})
	store.Append(accesslog.Entry{Event: "upstream_attempt", Route: "demo", Upstream: "http://origin-b", UpstreamStatus: 503})
	server := testAdminServer(store)

	unauthorized := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthorized.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs?event=upstream_attempt&status=5xx&limit=10", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rr := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var result accesslog.QueryResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Upstream != "http://origin-b" {
		t.Fatalf("unexpected filtered logs: %#v", result.Entries)
	}
}

func TestLogsEndpointRejectsOversizedPageAndCanClear(t *testing.T) {
	store := accesslog.New(100)
	store.Append(accesslog.Entry{Event: "request_completed", Status: 200})
	server := testAdminServer(store)

	badReq := httptest.NewRequest(http.MethodGet, "/api/v1/logs?limit=51", nil)
	badReq.Header.Set("Authorization", "Bearer test-token")
	bad := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(bad, badReq)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", bad.Code)
	}

	clearReq := httptest.NewRequest(http.MethodDelete, "/api/v1/logs", nil)
	clearReq.Header.Set("Authorization", "Bearer test-token")
	cleared := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(cleared, clearReq)
	if cleared.Code != http.StatusOK || store.Stats().Retained != 0 {
		t.Fatalf("clear failed: code=%d retained=%d", cleared.Code, store.Stats().Retained)
	}
}

func TestLogsEndpointRejectsNonFiniteMinimumDuration(t *testing.T) {
	server := testAdminServer(accesslog.New(10))

	for _, value := range []string{"NaN", "+Inf", "-Inf"} {
		t.Run(value, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/logs?min_duration_ms="+value, nil)
			req.Header.Set("Authorization", "Bearer test-token")
			rr := httptest.NewRecorder()
			server.HTTPServer().Handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %q, got %d: %s", value, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestAuthAcceptsCaseInsensitiveBearerAndReturnsChallenge(t *testing.T) {
	server := testAdminServer(accesslog.New(10))

	missing := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", missing.Code)
	}
	if got := missing.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("expected WWW-Authenticate challenge")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil)
	req.Header.Set("Authorization", "bearer test-token")
	rr := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected lowercase bearer scheme to work, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAuthRejectsMultipleAuthorizationFields(t *testing.T) {
	server := testAdminServer(accesslog.New(10))
	for _, values := range [][]string{
		{"Bearer test-token", "Bearer test-token"},
		{"Bearer test-token", "Bearer conflicting-token"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil)
		req.Header["Authorization"] = values
		rr := httptest.NewRecorder()
		server.HTTPServer().Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected ambiguous credentials %q to be rejected with 401, got %d: %s", values, rr.Code, rr.Body.String())
		}
	}
}

func TestSecureTokenEqualHandlesDifferentLengths(t *testing.T) {
	if !secureTokenEqual("test-token", "test-token") {
		t.Fatal("equal tokens did not match")
	}
	if secureTokenEqual("short", "a-much-longer-token") {
		t.Fatal("different tokens matched")
	}
}

func TestReadinessEndpointDoesNotExposeRouteDetails(t *testing.T) {
	const routeName = "secret-internal-route"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer origin.Close()

	handler, err := proxy.NewHandler(config.Config{
		Server: config.ServerConfig{ForwardedForHeader: "X-Forwarded-For"},
		Routes: []config.RouteConfig{{
			Name:       routeName,
			Hosts:      []string{"secret.internal"},
			PathPrefix: "/",
			Upstreams:  []config.UpstreamConfig{{URL: origin.URL}},
			Proxy: config.ProxyConfig{
				DialTimeout:            config.Duration{Duration: time.Second},
				ResponseHeaderTimeout:  config.Duration{Duration: time.Second},
				IdleConnTimeout:        config.Duration{Duration: time.Minute},
				MaxResponseHeaderBytes: 1 << 20,
			},
			HealthCheck: config.HealthCheckConfig{
				Enabled:         true,
				Path:            "/",
				Interval:        config.Duration{Duration: time.Hour},
				Timeout:         config.Duration{Duration: time.Second},
				HealthyStatuses: []int{http.StatusOK},
			},
		}},
	}, slog.Default(), metrics.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	server := New(config.AdminConfig{
		Enabled:    true,
		ListenAddr: "127.0.0.1:9090",
		AuthToken:  "test-token",
	}, slog.Default(), metrics.New(), handler, nil)

	ready := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", ready.Code, ready.Body.String())
	}
	body := ready.Body.String()
	for _, secret := range []string{routeName, "secret.internal", "unhealthy_routes"} {
		if strings.Contains(body, secret) {
			t.Fatalf("public readiness leaked %q: %s", secret, body)
		}
	}
	var public map[string]any
	if err := json.Unmarshal(ready.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	if public["status"] != "not_ready" {
		t.Fatalf("unexpected readiness payload: %#v", public)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	statusReq.Header.Set("Authorization", "Bearer test-token")
	status := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(status, statusReq)
	if status.Code != http.StatusOK {
		t.Fatalf("expected authenticated status 200, got %d: %s", status.Code, status.Body.String())
	}
	if !strings.Contains(status.Body.String(), routeName) {
		t.Fatalf("authenticated status omitted route diagnostics: %s", status.Body.String())
	}
}
