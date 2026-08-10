package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdProfileKeepsMutableSettingsFileBacked(t *testing.T) {
	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "runtime-securityedge-token")
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "runtime-edgeproxy-token")
	for _, key := range []string{
		"SECURITYEDGE_SERVER_LISTEN_ADDR",
		"SECURITYEDGE_UPSTREAM_PROXY_URL",
		"SECURITYEDGE_FORWARDED_FOR_HEADER",
		"SECURITYEDGE_TLS_ENABLED",
		"SECURITYEDGE_TLS_CERT_FILE",
		"SECURITYEDGE_TLS_KEY_FILE",
		"SECURITYEDGE_ADMIN_LISTEN_ADDR",
		"SECURITYEDGE_LOG_FILE_PATH",
		"SECURITYEDGE_TELEMETRY_HISTORY_FILE",
		"SECURITYEDGE_DNS_SERVER",
		"SECURITYEDGE_EDGEPROXY_CONFIG_PATH",
		"SECURITYEDGE_EDGEPROXY_ADMIN_URL",
		"SECURITYEDGE_TRUSTED_PROXY_CIDRS",
		"SECURITYEDGE_DNS_NAMES",
		"SECURITYEDGE_DNS_EXPECTED_ADDRESSES",
		"SECURITYEDGE_DNS_ENABLED",
		"SECURITYEDGE_DNS_CRITICAL",
	} {
		t.Setenv(key, "")
	}

	profile := filepath.Join("..", "..", "deploy", "systemd", "securityedge.json")
	cfg, err := Load(profile)
	if err != nil {
		t.Fatalf("load systemd profile: %v", err)
	}
	if cfg.Admin.AuthToken != "runtime-securityedge-token" || cfg.EdgeProxy.AdminToken != "runtime-edgeproxy-token" {
		t.Fatalf("runtime credentials were not injected")
	}
	if cfg.Server.ListenAddr != "0.0.0.0:443" || cfg.Admin.ListenAddr != "127.0.0.1:9191" {
		t.Fatalf("unexpected initial systemd listeners: server=%q admin=%q", cfg.Server.ListenAddr, cfg.Admin.ListenAddr)
	}
	if !cfg.Server.TLS.Enabled || cfg.Server.TLS.CertFile != "/etc/securityedge/tls/fullchain.pem" || cfg.Server.TLS.KeyFile != "/etc/securityedge/tls/privkey.pem" {
		t.Fatalf("unexpected systemd TLS configuration: %#v", cfg.Server.TLS)
	}
	if cfg.EdgeProxy.ConfigPath != "/var/lib/edgeproxy/config.json" {
		t.Fatalf("unexpected shared Route-table path %q", cfg.EdgeProxy.ConfigPath)
	}

	tempDir := t.TempDir()
	managedPath := filepath.Join(tempDir, "securityedge.json")
	raw, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("read systemd profile: %v", err)
	}
	if err := os.WriteFile(managedPath, raw, 0o640); err != nil {
		t.Fatalf("write managed profile: %v", err)
	}
	persisted, err := LoadFile(managedPath)
	if err != nil {
		t.Fatalf("load file-backed profile: %v", err)
	}
	persisted.Server.ListenAddr = "127.0.0.1:18081"
	if err := Save(managedPath, persisted); err != nil {
		t.Fatalf("persist listener update: %v", err)
	}
	updated, err := Load(managedPath)
	if err != nil {
		t.Fatalf("reload updated profile: %v", err)
	}
	if updated.Server.ListenAddr != "127.0.0.1:18081" {
		t.Fatalf("mutable listener remained pinned outside JSON: got %q", updated.Server.ListenAddr)
	}
}

func TestSystemdEnvironmentTemplateContainsOnlyRuntimeSecrets(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "systemd", "securityedge.env.example")
	keys := activeSystemdEnvironmentKeys(t, path)
	want := []string{"SECURITYEDGE_ADMIN_TOKEN", "EDGEPROXY_ADMIN_TOKEN"}
	if len(keys) != len(want) {
		t.Fatalf("systemd environment must contain only runtime secrets, got %v", keys)
	}
	for index := range want {
		if keys[index] != want[index] {
			t.Fatalf("unexpected systemd environment keys: got %v want %v", keys, want)
		}
	}
}

func TestPowerShellDotenvPreservesOriginMetadata(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "dotenv.ps1")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read PowerShell dotenv loader: %v", err)
	}
	script := string(data)
	for _, required := range []string{
		"$urls.Count -gt 256",
		"foreach ($property in $existing[$i].PSObject.Properties)",
		"$origin[$property.Name] = $property.Value",
		"$origin['url'] = [string]$urls[$i]",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("PowerShell dotenv loader is missing metadata-preservation contract %q", required)
		}
	}
}

func activeSystemdEnvironmentKeys(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open environment template: %v", err)
	}
	defer file.Close()

	var keys []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) == "" {
			t.Fatalf("invalid environment assignment %q", line)
		}
		keys = append(keys, strings.TrimSpace(key))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan environment template: %v", err)
	}
	return keys
}

func TestEnvironmentManagedChangesAreRejected(t *testing.T) {
	profile := filepath.Join("..", "..", "deploy", "systemd", "securityedge.json")
	current, err := LoadFile(profile)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "runtime-token")
	next := current
	next.Admin.AuthToken = "file-rotation"
	if err := ValidateEnvironmentManagedChanges(current, next); err == nil || !strings.Contains(err.Error(), "SECURITYEDGE_ADMIN_TOKEN") {
		t.Fatalf("expected managed SecurityEdge token change to be rejected, got %v", err)
	}

	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "")
	t.Setenv("SECURITYEDGE_EDGEPROXY_CONFIG_PATH", "/runtime/edgeproxy.json")
	next = current
	next.EdgeProxy.ConfigPath = "/another/edgeproxy.json"
	if err := ValidateEnvironmentManagedChanges(current, next); err == nil || !strings.Contains(err.Error(), "SECURITYEDGE_EDGEPROXY_CONFIG_PATH") {
		t.Fatalf("expected managed dependency path change to be rejected, got %v", err)
	}

	t.Setenv("SECURITYEDGE_EDGEPROXY_CONFIG_PATH", "")
	if err := ValidateEnvironmentManagedChanges(current, next); err != nil {
		t.Fatalf("unmanaged file-backed change was rejected: %v", err)
	}

	t.Setenv("SECURITYEDGE_TLS_ENABLED", "false")
	next = current
	next.Server.TLS.Enabled = !current.Server.TLS.Enabled
	if err := ValidateEnvironmentManagedChanges(current, next); err == nil || !strings.Contains(err.Error(), "SECURITYEDGE_TLS_ENABLED") {
		t.Fatalf("expected managed TLS mode change to be rejected, got %v", err)
	}
}
