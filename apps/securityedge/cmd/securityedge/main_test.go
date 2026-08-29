package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/edgeprobe"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/envfile"
)

type closeTrackingListener struct {
	closed bool
}

func (l *closeTrackingListener) Accept() (net.Conn, error) {
	return nil, errors.New("unused test listener")
}

func (l *closeTrackingListener) Close() error {
	l.closed = true
	return nil
}

func (l *closeTrackingListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func TestBindSecurityListenersClosesGatewayWhenAdminBindFails(t *testing.T) {
	cfg := config.Default()
	cfg.Server.ListenAddr = "gateway.test:8080"
	cfg.Admin.ListenAddr = "admin.test:9191"
	gateway := &closeTrackingListener{}
	adminBindErr := errors.New("forced admin bind failure")
	listenCalls := 0

	_, _, err := bindSecurityListeners(cfg, &http.Server{}, &http.Server{}, func(network, address string) (net.Listener, error) {
		listenCalls++
		switch listenCalls {
		case 1:
			if network != "tcp" || address != cfg.Server.ListenAddr {
				t.Fatalf("unexpected gateway listen request: network=%q address=%q", network, address)
			}
			return gateway, nil
		case 2:
			if network != "tcp" || address != cfg.Admin.ListenAddr {
				t.Fatalf("unexpected admin listen request: network=%q address=%q", network, address)
			}
			return nil, adminBindErr
		default:
			t.Fatalf("unexpected extra listen call %d", listenCalls)
			return nil, errors.New("unexpected listen call")
		}
	})
	if err == nil {
		t.Fatal("expected admin listener bind failure")
	}
	if !errors.Is(err, adminBindErr) {
		t.Fatalf("expected wrapped admin bind error, got %v", err)
	}
	if !strings.Contains(err.Error(), cfg.Admin.ListenAddr) {
		t.Fatalf("admin bind error should identify %q: %v", cfg.Admin.ListenAddr, err)
	}
	if listenCalls != 2 {
		t.Fatalf("listen calls = %d, want 2", listenCalls)
	}
	if !gateway.closed {
		t.Fatal("gateway listener was not closed after admin bind failure")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{input: "debug", want: slog.LevelDebug},
		{input: " INFO ", want: slog.LevelInfo},
		{input: "Warn", want: slog.LevelWarn},
		{input: "ERROR", want: slog.LevelError},
	}
	for _, tc := range tests {
		level, err := parseLevel(tc.input)
		if err != nil {
			t.Fatalf("parseLevel(%q): %v", tc.input, err)
		}
		if level != tc.want {
			t.Fatalf("parseLevel(%q)=%v, want %v", tc.input, level, tc.want)
		}
	}
	if _, err := parseLevel("verbose"); err == nil {
		t.Fatal("expected unsupported log level to be rejected")
	}
}

func TestShutdownServersForcesCloseAfterDeadline(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request handler did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	shutdownErr := shutdownServers(ctx, namedHTTPServer{name: "test", server: server})
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("shutdown error=%v, want context deadline exceeded", shutdownErr)
	}

	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("forced shutdown did not cancel the active request")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client request remained blocked after forced shutdown")
	}
	select {
	case serveErr := <-serveDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("Serve returned %v, want http.ErrServerClosed", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop accepting connections")
	}
}

func TestGatewayTransportAppliesResponseHeaderLimit(t *testing.T) {
	target, err := url.Parse("http://edgeproxy:8080")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Server
	cfg.UpstreamTransport.MaxResponseHeaderBytes = 4096
	proxy := newReverseProxy(target, cfg, slog.Default())
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", proxy.Transport)
	}
	if transport.MaxResponseHeaderBytes != cfg.UpstreamTransport.MaxResponseHeaderBytes {
		t.Fatalf("MaxResponseHeaderBytes=%d, want %d", transport.MaxResponseHeaderBytes, cfg.UpstreamTransport.MaxResponseHeaderBytes)
	}
}

func TestGatewayRejectsOversizedUpstreamResponseHeaders(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("a", 8192))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Server
	cfg.UpstreamTransport.MaxResponseHeaderBytes = 4096
	proxy := newReverseProxy(target, cfg, slog.Default())
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://securityedge.test/", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestReverseProxyStripsUpstreamDecisionHeadersFromUpgrade(t *testing.T) {
	target, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(target, config.Default().Server, slog.Default())
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{
		"Server":                 []string{"origin"},
		"X-Request-Id":           []string{"upstream-id"},
		"X-Security-Action":      []string{"BLOCK"},
		"X-Security-Score":       []string{"999"},
		"X-Content-Type-Options": []string{"unsafe"},
		"Referrer-Policy":        []string{"unsafe-url"},
		"X-Frame-Options":        []string{"ALLOWALL"},
		"Permissions-Policy":     []string{"camera=*"},
	}}
	if err := proxy.ModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Server", "X-Request-ID", "X-Security-Action", "X-Security-Score", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Permissions-Policy"} {
		if got := resp.Header.Get(name); got != "" {
			t.Fatalf("%s=%q, want removed from upstream 101", name, got)
		}
	}
	if got := resp.Header.Get("X-Security-Gateway"); got != "SecurityEdge" {
		t.Fatalf("X-Security-Gateway=%q", got)
	}
}

func TestGatewayTransportIgnoresAmbientProxySettings(t *testing.T) {
	target, err := url.Parse("http://edgeproxy:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(target, config.Default().Server, slog.Default())
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", proxy.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("SecurityEdge data-plane transport must connect directly instead of honoring HTTP_PROXY/HTTPS_PROXY")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected EdgeProxy TLS client configuration: %#v", transport.TLSClientConfig)
	}
}

func TestGatewayRemovesConfiguredClientIPHeader(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Server
	cfg.ForwardedForHeader = "X-Real-IP"
	proxy := newReverseProxy(target, cfg, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "http://securityedge.test/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.25")
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}

	headers := <-seen
	if got := headers.Get("X-Real-IP"); got != "" {
		t.Fatalf("configured client-IP source header leaked downstream: %q", got)
	}
	if got := headers.Get("X-Forwarded-For"); got == "198.51.100.25" {
		t.Fatalf("unresolved client-supplied address was propagated: %q", got)
	}
}

func TestGatewayStripsClientSuppliedOperationalProbeMarker(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(target, config.Default().Server, slog.Default())
	req := httptest.NewRequest(http.MethodHead, "http://securityedge.test/", nil)
	req.Header.Set(edgeprobe.HeaderName, edgeprobe.HeaderValue)
	req.Header.Set("User-Agent", edgeprobe.UserAgent)
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}

	headers := <-seen
	if got := headers.Get(edgeprobe.HeaderName); got != "" {
		t.Fatalf("client-supplied operational probe marker leaked to EdgeProxy: %q", got)
	}
}

func TestGatewayRebuildsForwardingIdentityHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(target, config.Default().Server, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "http://securityedge.test/", nil)
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
	proxy.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}

	headers := <-seen
	for _, name := range []string{"Forwarded", "CF-Connecting-IP", "X-Client-IP", "X-Real-IP", "True-Client-IP", "X-Forwarded-Port", "X-Forwarded-Server"} {
		if got := headers.Get(name); got != "" {
			t.Fatalf("untrusted %s leaked downstream: %q", name, got)
		}
	}
	if got := headers.Get("X-Forwarded-For"); got != "203.0.113.44" {
		t.Fatalf("X-Forwarded-For=%q", got)
	}
	if got := headers.Get("X-Forwarded-Host"); got != "securityedge.test" {
		t.Fatalf("X-Forwarded-Host=%q", got)
	}
	if got := headers.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto=%q", got)
	}
}

func TestResolveConfigPathUsesEnvironmentFileDirectory(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	want := filepath.Join(dir, "configs", "securityedge.json")
	if got := resolveConfigPath("", "configs/securityedge.json", envPath, true, "fallback.json"); got != want {
		t.Fatalf("resolved path=%q, want %q", got, want)
	}
	if got := resolveConfigPath("cli.json", "configs/securityedge.json", envPath, true, "fallback.json"); got != "cli.json" {
		t.Fatalf("CLI path lost precedence: %q", got)
	}
}

func TestResolveConfigPathKeepsProcessEnvironmentRelativeToWorkingDirectory(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), ".env")
	if got := resolveConfigPath("", "configs/process.json", envPath, false, "fallback.json"); got != "configs/process.json" {
		t.Fatalf("process environment path was rebased to dotenv directory: %q", got)
	}
}

func TestGatewayPreserveHostBehavior(t *testing.T) {
	tests := []struct {
		name         string
		preserveHost bool
		wantClient   bool
	}{
		{name: "target host by default", preserveHost: false, wantClient: false},
		{name: "incoming host when enabled", preserveHost: true, wantClient: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seenHost := make(chan string, 1)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenHost <- r.Host
				w.WriteHeader(http.StatusNoContent)
			}))
			defer origin.Close()

			target, err := url.Parse(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.Default().Server
			cfg.PreserveHost = tc.preserveHost
			proxy := newReverseProxy(target, cfg, slog.Default())
			req := httptest.NewRequest(http.MethodGet, "http://client.example/api", nil)
			req.Host = "client.example"
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
			if response.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			want := target.Host
			if tc.wantClient {
				want = "client.example"
			}
			if got := <-seenHost; got != want {
				t.Fatalf("upstream Host=%q, want %q", got, want)
			}
		})
	}
}

func TestWatchedConfigPathFollowsDotenvOnlyWhenAllowed(t *testing.T) {
	directory := t.TempDir()
	fallback := filepath.Join(directory, "default.json")
	current := filepath.Join(directory, "current.json")
	envPath := filepath.Join(directory, ".env")

	t.Setenv("SECURITYEDGE_CONFIG", "profiles/alternate.json")
	if got, want := watchedConfigPath(fallback, envPath, current, true), filepath.Join(directory, "profiles", "alternate.json"); got != want {
		t.Fatalf("watched path=%q, want %q", got, want)
	}
	if got := watchedConfigPath(fallback, envPath, current, false); got != current {
		t.Fatalf("pinned path changed to %q", got)
	}
	t.Setenv("SECURITYEDGE_CONFIG", "")
	if got := watchedConfigPath(fallback, envPath, current, true); got != fallback {
		t.Fatalf("empty dotenv path=%q, want %q", got, fallback)
	}
}

func TestRestoreSecurityFallbackRestoresManagedEnvironment(t *testing.T) {
	initial := envfile.SnapshotManagedEnvironment()
	t.Cleanup(func() {
		if err := envfile.RestoreManagedEnvironment(initial); err != nil {
			t.Errorf("restore initial environment: %v", err)
		}
		_ = os.Unsetenv("SECURITYEDGE_RUNTIME_FALLBACK_TEST")
	})
	dir := t.TempDir()
	healthyEnv := filepath.Join(dir, "healthy.env")
	candidateEnv := filepath.Join(dir, "candidate.env")
	if err := os.WriteFile(healthyEnv, []byte("SECURITYEDGE_RUNTIME_FALLBACK_TEST=healthy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidateEnv, []byte("SECURITYEDGE_RUNTIME_FALLBACK_TEST=candidate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := envfile.Load(healthyEnv); err != nil {
		t.Fatal(err)
	}
	snapshot := envfile.SnapshotManagedEnvironment()
	if err := envfile.Reload(candidateEnv); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("SECURITYEDGE_RUNTIME_FALLBACK_TEST"); got != "candidate" {
		t.Fatalf("candidate environment=%q", got)
	}
	fallback := securityRestartFallback{path: filepath.Join(dir, "healthy.json"), environment: &snapshot}
	if err := restoreSecurityFallback(fallback, filepath.Join(dir, "different-candidate.json")); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("SECURITYEDGE_RUNTIME_FALLBACK_TEST"); got != "healthy" {
		t.Fatalf("restored environment=%q", got)
	}
}

func TestRestoreSecurityFallbackRestoresSamePathCandidate(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "security.json")
	healthy := config.Default()
	healthy.EdgeProxy.ConfigPath = "edge.json"
	healthy.Admin.AuthToken = "healthy-token"
	if err := config.Save(path, healthy); err != nil {
		t.Fatal(err)
	}
	candidate := healthy
	candidate.Admin.AuthToken = "candidate-token"
	if err := config.Save(path, candidate); err != nil {
		t.Fatal(err)
	}

	fallback := securityRestartFallback{path: path, cfg: healthy}
	if err := restoreSecurityFallback(fallback, path); err != nil {
		t.Fatal(err)
	}
	restored, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Admin.AuthToken != healthy.Admin.AuthToken {
		t.Fatalf("restored token=%q, want %q", restored.Admin.AuthToken, healthy.Admin.AuthToken)
	}
}

func TestRestoreSecurityFallbackLeavesPreviousPathUntouchedAfterConfigPathSwitch(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	healthyPath := filepath.Join(dir, "healthy.json")
	candidatePath := filepath.Join(dir, "candidate.json")
	healthy := config.Default()
	healthy.EdgeProxy.ConfigPath = "edge.json"
	healthy.Admin.AuthToken = "healthy-token"
	if err := config.Save(healthyPath, healthy); err != nil {
		t.Fatal(err)
	}
	candidate := healthy
	candidate.Admin.AuthToken = "candidate-token"
	if err := config.Save(candidatePath, candidate); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(healthyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreSecurityFallback(securityRestartFallback{path: healthyPath, cfg: healthy}, candidatePath); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(healthyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("config-path rollback rewrote the untouched healthy configuration")
	}
}

func TestEdgeProxyWatchReadyRequiresAppliedRevision(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "hot applied", raw: `{"revision":4,"applied_revision":4,"restart_scheduled":false}`, want: true},
		{name: "restart pending", raw: `{"revision":5,"applied_revision":4,"restart_scheduled":true}`, want: false},
		{name: "candidate persisted but not applied", raw: `{"revision":5,"applied_revision":4,"restart_scheduled":false}`, want: false},
		{name: "failed replacement rolled back", raw: `{"revision":5,"applied_revision":4,"restart_scheduled":false,"last_source":"restart_rollback"}`, want: true},
		{name: "applied ahead", raw: `{"revision":5,"applied_revision":6,"restart_scheduled":false}`, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := edgeProxyWatchReady(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("ready=%v, want %v", got, tc.want)
			}
		})
	}
	if _, err := edgeProxyWatchReady(json.RawMessage(`not-json`)); err == nil {
		t.Fatal("expected invalid watch payload to fail closed")
	}
}
