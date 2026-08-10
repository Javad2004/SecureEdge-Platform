package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

func TestStartGenerationClosesMainListenerWhenAdminBindFails(t *testing.T) {
	occupiedAdmin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupiedAdmin.Close()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mainAddress := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFile(filepath.Join("..", "..", "configs", "local-dev.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.ListenAddr = mainAddress
	cfg.Admin.ListenAddr = occupiedAdmin.Addr().String()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := startGeneration(cfg, logger, nil); err == nil {
		t.Fatal("expected occupied admin listener to fail generation startup")
	}

	rebound, err := net.Listen("tcp", mainAddress)
	if err != nil {
		t.Fatalf("failed generation leaked main listener %q: %v", mainAddress, err)
	}
	_ = rebound.Close()
}

func TestShutdownServersClosesAllListenersBeforeWaitingForHandlers(t *testing.T) {
	type runningServer struct {
		server      *http.Server
		started     chan struct{}
		release     chan struct{}
		serveDone   chan error
		requestDone chan error
	}

	start := func() runningServer {
		started := make(chan struct{})
		release := make(chan struct{})
		var startedOnce sync.Once
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			startedOnce.Do(func() { close(started) })
			<-release
			w.WriteHeader(http.StatusNoContent)
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
		return runningServer{server: server, started: started, release: release, serveDone: serveDone, requestDone: requestDone}
	}

	first := start()
	second := start()
	for name, started := range map[string]<-chan struct{}{"first": first.started, "second": second.started} {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s request handler did not start", name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- shutdownServers(ctx,
			namedHTTPServer{name: "first", server: first.server},
			namedHTTPServer{name: "second", server: second.server},
		)
	}()

	// Shutdown closes every listener before waiting for active handlers. Both
	// Serve calls must therefore stop even though neither handler is released yet.
	for name, done := range map[string]<-chan error{"first": first.serveDone, "second": second.serveDone} {
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("%s Serve returned %v, want http.ErrServerClosed", name, err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("%s listener remained open while another server was draining", name)
		}
	}

	close(first.release)
	close(second.release)
	for name, done := range map[string]<-chan error{"first": first.requestDone, "second": second.requestDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s request failed after handler release: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s request did not finish", name)
		}
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdownServers returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdownServers did not return")
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

func TestStartGenerationServesNativeTLS(t *testing.T) {
	certPath, keyPath, roots := writeEdgeProxyTestCertificate(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	cfg, err := config.LoadFile(filepath.Join("..", "..", "configs", "local-dev.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.ListenAddr = unusedEdgeProxyListenerAddress(t)
	cfg.Server.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}
	cfg.Admin.Enabled = false
	cfg.Routes[0].Upstreams[0].URL = origin.URL
	cfg.Routes[0].HealthCheck.Enabled = false
	cfg.Routes[0].Cache.Enabled = false

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gen, err := startGeneration(cfg, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = shutdownServers(ctx, namedHTTPServer{name: "proxy", server: gen.mainServer})
		gen.handler.Close()
	}()

	if gen.mainServer.TLSConfig == nil || gen.mainServer.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected TLS server configuration: %#v", gen.mainServer.TLSConfig)
	}
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}
	response, err := client.Get("https://" + cfg.Server.ListenAddr + "/api/time")
	if err != nil {
		t.Fatalf("HTTPS proxy request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTPS proxy status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}

	plainClient := &http.Client{Timeout: time.Second}
	if response, err := plainClient.Get("http://" + cfg.Server.ListenAddr + "/api/time"); err == nil {
		_ = response.Body.Close()
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			t.Fatal("TLS-enabled EdgeProxy unexpectedly served a successful plaintext HTTP request")
		}
	}
}

func TestStartGenerationRejectsInvalidTLSBeforeBinding(t *testing.T) {
	address := unusedEdgeProxyListenerAddress(t)
	cfg, err := config.LoadFile(filepath.Join("..", "..", "configs", "local-dev.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.ListenAddr = address
	cfg.Server.TLS = config.TLSConfig{
		Enabled:  true,
		CertFile: filepath.Join(t.TempDir(), "missing-cert.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "missing-key.pem"),
	}
	cfg.Admin.Enabled = false

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := startGeneration(cfg, logger, nil); err == nil {
		t.Fatal("expected unreadable TLS material to reject generation startup")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("failed TLS startup leaked proxy listener %q: %v", address, err)
	}
	_ = listener.Close()
}

func unusedEdgeProxyListenerAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func writeEdgeProxyTestCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server-cert.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add generated certificate to test root pool")
	}
	return certPath, keyPath, roots
}
