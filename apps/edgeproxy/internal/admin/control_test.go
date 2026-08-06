package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/control"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

func newControlPlaneTestServer(t *testing.T) (*Server, *control.Manager, string) {
	t.Helper()
	cfg, err := config.LoadFile("../../configs/local-dev.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.ListenAddr = "127.0.0.1:18080"
	cfg.Admin.ListenAddr = "127.0.0.1:19090"
	cfg.Admin.AuthToken = "test-token"
	cfg.Routes[0].HealthCheck.Enabled = false
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := control.New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Close)
	manager.Attach(handler, cfg)
	server := New(cfg.Admin, logger, metrics.New(), handler, accesslog.New(100), manager)
	return server, manager, path
}

func controlRequest(t *testing.T, server *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer test-token")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	return rr
}

func TestControlPlaneCRUDAndRestartAcceptance(t *testing.T) {
	server, manager, configPath := newControlPlaneTestServer(t)

	get := controlRequest(t, server, http.MethodGet, "/api/v1/config", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET config=%d: %s", get.Code, get.Body.String())
	}
	var redacted config.Config
	if err := json.Unmarshal(get.Body.Bytes(), &redacted); err != nil {
		t.Fatal(err)
	}
	if redacted.Admin.AuthToken != "[REDACTED]" {
		t.Fatalf("admin token was exposed: %q", redacted.Admin.AuthToken)
	}

	newRoute := redacted.Routes[0]
	newRoute.Name = "API-Route"
	newRoute.Hosts = []string{"api.project.test"}
	newRoute.Cache.Enabled = false
	newRoute.Upstreams = []config.UpstreamConfig{{
		Name: "primary", URL: "http://127.0.0.1:19001", Weight: 2, Priority: 1,
	}}
	created := controlRequest(t, server, http.MethodPost, "/api/v1/routes", newRoute)
	if created.Code != http.StatusOK {
		t.Fatalf("create route=%d: %s", created.Code, created.Body.String())
	}

	newRoute.LoadBalancing.Algorithm = "least_connections"
	updated := controlRequest(t, server, http.MethodPut, "/api/v1/routes/api-route", newRoute)
	if updated.Code != http.StatusOK {
		t.Fatalf("update route=%d: %s", updated.Code, updated.Body.String())
	}
	if got := manager.Config().Routes[1].LoadBalancing.Algorithm; got != "least_connections" {
		t.Fatalf("algorithm=%q", got)
	}

	origin := config.UpstreamConfig{Name: "secondary", URL: "http://127.0.0.1:19002", Weight: 3, Priority: 2}
	addedOrigin := controlRequest(t, server, http.MethodPost, "/api/v1/routes/API-ROUTE/origins", origin)
	if addedOrigin.Code != http.StatusOK {
		t.Fatalf("create origin=%d: %s", addedOrigin.Code, addedOrigin.Body.String())
	}
	deletedOrigin := controlRequest(t, server, http.MethodDelete, "/api/v1/routes/api-route/origins/SECONDARY", nil)
	if deletedOrigin.Code != http.StatusOK {
		t.Fatalf("delete origin=%d: %s", deletedOrigin.Code, deletedOrigin.Body.String())
	}

	deletedRoute := controlRequest(t, server, http.MethodDelete, "/api/v1/routes/api-route", nil)
	if deletedRoute.Code != http.StatusOK {
		t.Fatalf("delete route=%d: %s", deletedRoute.Code, deletedRoute.Body.String())
	}

	restartConfig := manager.Config()
	restartConfig.Server.ListenAddr = "127.0.0.1:18081"
	restart := controlRequest(t, server, http.MethodPut, "/api/v1/config", restartConfig)
	if restart.Code != http.StatusAccepted {
		t.Fatalf("restart-required replace=%d: %s", restart.Code, restart.Body.String())
	}
	watch := manager.WatchStatus()
	if !watch.RestartScheduled || watch.Revision <= watch.AppliedRevision {
		t.Fatalf("restart was not reflected in watch status: %#v", watch)
	}
	saved, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server.ListenAddr != "127.0.0.1:18081" || saved.Admin.AuthToken != "test-token" {
		t.Fatalf("persisted restart config is invalid: listen=%q token=%q", saved.Server.ListenAddr, saved.Admin.AuthToken)
	}
}

func TestControlPlaneRejectsUnknownJSONFields(t *testing.T) {
	server, _, _ := newControlPlaneTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", bytes.NewBufferString(`{"name":"bad","unexpected":true}`))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d: %s", rr.Code, rr.Body.String())
	}
}
