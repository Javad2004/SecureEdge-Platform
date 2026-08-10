package securityedge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func TestRestartRequiredChangesIncludeGatewayTLS(t *testing.T) {
	current := config.Default()
	next := cloneConfig(current)
	next.Server.TLS = config.TLSConfig{Enabled: true, CertFile: "server.crt", KeyFile: "server.key"}

	fields := restartRequiredChanges(current, next)
	if !containsString(fields, "server.tls") {
		t.Fatalf("missing TLS restart field: %#v", fields)
	}
}

func TestRestartPreflightRevalidatesUnchangedTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeRestartTestCertificate(t, dir)
	cfg := config.Default()
	cfg.Server.ListenAddr = availableListenerAddress(t)
	cfg.Server.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}
	cfg.Admin.Enabled = false
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}

	next := runtime.Config()
	next.Server.ReadTimeout.Duration += time.Second
	err = runtime.ReplaceConfig(next)
	if err == nil || !strings.Contains(err.Error(), "load server TLS certificate") {
		t.Fatalf("expected restart preflight to revalidate unchanged TLS material, got %v", err)
	}
	persisted, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Server.ReadTimeout != cfg.Server.ReadTimeout {
		t.Fatal("restart candidate with missing TLS material was persisted")
	}
}

func writeRestartTestCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server-cert.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestReloadEnvironmentHotAppliesTrustedProxyOverride(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	t.Setenv("SECURITYEDGE_TRUSTED_PROXY_CIDRS", "10.10.0.0/16")
	if err := runtime.ReloadEnvironment(); err != nil {
		t.Fatalf("reload environment: %v", err)
	}
	got := runtime.Config().Server.TrustedProxyCIDRs
	if len(got) != 1 || got[0] != "10.10.0.0/16" {
		t.Fatalf("trusted proxies=%#v, want environment override", got)
	}
	persisted, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.Server.TrustedProxyCIDRs) != 0 {
		t.Fatalf("runtime-only environment override leaked into JSON: %#v", persisted.Server.TrustedProxyCIDRs)
	}
}

func TestReloadEnvironmentSchedulesValidatedTLSRestartWithoutPersistingOverride(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeRestartTestCertificate(t, dir)
	cfg := config.Default()
	cfg.Server.ListenAddr = availableListenerAddress(t)
	cfg.Admin.Enabled = false
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	t.Setenv("SECURITYEDGE_TLS_ENABLED", "true")
	t.Setenv("SECURITYEDGE_TLS_CERT_FILE", certPath)
	t.Setenv("SECURITYEDGE_TLS_KEY_FILE", keyPath)
	err = runtime.ReloadEnvironment()
	var marker restartRequiredMarker
	if err == nil || !errors.As(err, &marker) || !marker.RestartRequired() {
		t.Fatalf("expected validated TLS environment change to require restart, got %v", err)
	}
	if runtime.Config().Server.TLS.Enabled {
		t.Fatal("restart-required TLS environment change mutated the active generation")
	}
	persisted, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Server.TLS.Enabled || persisted.Server.TLS.CertFile != "" || persisted.Server.TLS.KeyFile != "" {
		t.Fatalf("runtime-only TLS environment override leaked into JSON: %#v", persisted.Server.TLS)
	}
}
