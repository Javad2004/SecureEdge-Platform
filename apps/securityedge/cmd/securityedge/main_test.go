package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

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
	if got := resolveConfigPath("", "configs/securityedge.json", envPath, "fallback.json"); got != want {
		t.Fatalf("resolved path=%q, want %q", got, want)
	}
	if got := resolveConfigPath("cli.json", "configs/securityedge.json", envPath, "fallback.json"); got != "cli.json" {
		t.Fatalf("CLI path lost precedence: %q", got)
	}
}
