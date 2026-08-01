package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bachelor-project/edgeproxy/internal/accesslog"
	"github.com/bachelor-project/edgeproxy/internal/config"
	"github.com/bachelor-project/edgeproxy/internal/metrics"
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
