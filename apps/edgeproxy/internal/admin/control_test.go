package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	if created.Code != http.StatusCreated {
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
	if addedOrigin.Code != http.StatusCreated {
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
	restartConfig.Server.ListenAddr = "127.0.0.1:0"
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
	if saved.Server.ListenAddr != "127.0.0.1:0" || saved.Admin.AuthToken != "test-token" {
		t.Fatalf("persisted restart config is invalid: listen=%q token=%q", saved.Server.ListenAddr, saved.Admin.AuthToken)
	}
}

func TestControlPlaneRejectsInvalidUTF8JSONWithoutMutation(t *testing.T) {
	server, manager, _ := newControlPlaneTestServer(t)
	before := manager.Config()
	payload := []byte(`{"name":"bad-name","url":"http://127.0.0.1:19002","weight":1,"priority":1,"insecure_skip_verify":false}`)
	marker := []byte("bad-name")
	idx := bytes.Index(payload, marker)
	if idx < 0 {
		t.Fatal("fixture marker not found")
	}
	payload[idx+3] = 0xff

	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/demo-app/origins", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid UTF-8 status=%d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "request body must be valid UTF-8") {
		t.Fatalf("invalid UTF-8 response=%s", rr.Body.String())
	}
	after := manager.Config()
	if len(after.Routes) != len(before.Routes) || len(after.Routes[0].Upstreams) != len(before.Routes[0].Upstreams) {
		t.Fatalf("rejected invalid UTF-8 mutation changed config: before=%#v after=%#v", before.Routes, after.Routes)
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

func TestControlPlaneDedicatedRouteSectionsAndTelemetry(t *testing.T) {
	server, manager, _ := newControlPlaneTestServer(t)
	routeName := manager.Config().Routes[0].Name
	base := "/api/v1/routes/" + routeName

	loadBalancing := manager.Config().Routes[0].LoadBalancing
	loadBalancing.Algorithm = "adaptive_latency"
	loadBalancing.LatencySensitivity = 1.7
	loadBalancing.EWMAAlpha = 0.4
	response := controlRequest(t, server, http.MethodPut, base+"/load-balancing", loadBalancing)
	if response.Code != http.StatusOK {
		t.Fatalf("load-balancing update=%d: %s", response.Code, response.Body.String())
	}

	cacheConfig := manager.Config().Routes[0].Cache
	cacheConfig.Enabled = false
	cacheConfig.DefaultTTL = config.Duration{}
	cacheConfig.StaleIfError = config.Duration{}
	response = controlRequest(t, server, http.MethodPut, base+"/cache", cacheConfig)
	if response.Code != http.StatusOK {
		t.Fatalf("cache update=%d: %s", response.Code, response.Body.String())
	}
	response = controlRequest(t, server, http.MethodGet, base+"/cache", nil)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"enabled":false`)) {
		t.Fatalf("cache get=%d: %s", response.Code, response.Body.String())
	}

	proxyConfig := manager.Config().Routes[0].Proxy
	proxyConfig.RetryCount = 3
	response = controlRequest(t, server, http.MethodPut, base+"/proxy", proxyConfig)
	if response.Code != http.StatusOK {
		t.Fatalf("proxy update=%d: %s", response.Code, response.Body.String())
	}

	healthConfig := manager.Config().Routes[0].HealthCheck
	healthConfig.Enabled = false
	response = controlRequest(t, server, http.MethodPut, base+"/health-check", healthConfig)
	if response.Code != http.StatusOK {
		t.Fatalf("health-check update=%d: %s", response.Code, response.Body.String())
	}

	response = controlRequest(t, server, http.MethodGet, base+"/telemetry", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("route telemetry=%d: %s", response.Code, response.Body.String())
	}
	var telemetry map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &telemetry); err != nil {
		t.Fatal(err)
	}
	if telemetry["route"] == nil || telemetry["metrics"] == nil || telemetry["runtime"] == nil {
		t.Fatalf("route telemetry is incomplete: %#v", telemetry)
	}

	origin := manager.Config().Routes[0].Upstreams[0]
	response = controlRequest(t, server, http.MethodGet, base+"/origins/"+origin.Name+"/telemetry", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("origin telemetry=%d: %s", response.Code, response.Body.String())
	}

	response = controlRequest(t, server, http.MethodGet, "/api/v1/telemetry", nil)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"schema_version":"1.0"`)) {
		t.Fatalf("telemetry=%d: %s", response.Code, response.Body.String())
	}
}

func TestRouteScopedCachePurgeIsCaseInsensitive(t *testing.T) {
	server, manager, _ := newControlPlaneTestServer(t)
	name := strings.ToUpper(manager.Config().Routes[0].Name)
	response := controlRequest(t, server, http.MethodPost, "/api/v1/routes/"+name+"/cache/purge", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("route cache purge=%d: %s", response.Code, response.Body.String())
	}
}
