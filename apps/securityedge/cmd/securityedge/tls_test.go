package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	securityedge "github.com/Javad2004/SecureEdge-Platform/apps/securityedge"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func TestStartSecurityGenerationServesNativeTLS(t *testing.T) {
	certPath, keyPath, roots := writeTestServerCertificate(t)
	gatewayAddress := unusedListenerAddress(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "edge.json"), []byte(`{"routes":[{"name":"demo-app","hosts":["127.0.0.1"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.ListenAddr = gatewayAddress
	cfg.Server.UpstreamProxyURL = origin.URL
	cfg.Server.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}
	cfg.Admin.Enabled = false
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gen, err := startSecurityGeneration(cfgPath, "", securityedge.WatchStatus{}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = shutdownServers(ctx, namedHTTPServer{name: "gateway", server: gen.gatewayServer})
		gen.runtime.Close()
	}()

	if gen.gatewayServer.TLSConfig == nil || gen.gatewayServer.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected TLS server configuration: %#v", gen.gatewayServer.TLSConfig)
	}
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}
	response, err := client.Get("https://" + gatewayAddress + "/api/products")
	if err != nil {
		t.Fatalf("HTTPS health request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTPS gateway status=%d, want %d", response.StatusCode, http.StatusNoContent)
	}

	plainClient := &http.Client{Timeout: time.Second}
	if response, err := plainClient.Get("http://" + gatewayAddress + "/api/products"); err == nil {
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("TLS-enabled SecurityEdge unexpectedly served a successful plaintext HTTP request")
		}
	}
}

func TestStartSecurityGenerationRejectsInvalidTLSBeforeBinding(t *testing.T) {
	gatewayAddress := unusedListenerAddress(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "edge.json"), []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.ListenAddr = gatewayAddress
	cfg.Server.TLS = config.TLSConfig{
		Enabled:  true,
		CertFile: filepath.Join(dir, "missing-cert.pem"),
		KeyFile:  filepath.Join(dir, "missing-key.pem"),
	}
	cfg.Admin.Enabled = false
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := startSecurityGeneration(cfgPath, "", securityedge.WatchStatus{}, logger); err == nil {
		t.Fatal("expected unreadable TLS material to reject generation startup")
	}
	listener, err := net.Listen("tcp", gatewayAddress)
	if err != nil {
		t.Fatalf("failed TLS startup leaked gateway listener %q: %v", gatewayAddress, err)
	}
	_ = listener.Close()
}

func unusedListenerAddress(t *testing.T) string {
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

func writeTestServerCertificate(t *testing.T) (string, string, *x509.CertPool) {
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
