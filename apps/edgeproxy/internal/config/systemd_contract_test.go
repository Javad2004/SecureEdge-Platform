package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdProfileKeepsMutableSettingsFileBacked(t *testing.T) {
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "runtime-edgeproxy-token")
	for _, key := range []string{
		"EDGEPROXY_SERVER_LISTEN_ADDR",
		"EDGEPROXY_ADMIN_LISTEN_ADDR",
		"EDGEPROXY_FORWARDED_FOR_HEADER",
		"EDGEPROXY_TRUSTED_PROXY_CIDRS",
		"EDGEPROXY_TLS_ENABLED",
		"EDGEPROXY_TLS_CERT_FILE",
		"EDGEPROXY_TLS_KEY_FILE",
	} {
		t.Setenv(key, "")
	}

	profile := filepath.Join("..", "..", "deploy", "systemd", "edgeproxy.json")
	cfg, err := Load(profile)
	if err != nil {
		t.Fatalf("load systemd profile: %v", err)
	}
	if cfg.Admin.AuthToken != "runtime-edgeproxy-token" {
		t.Fatalf("admin token was not injected from the runtime environment")
	}
	if cfg.Server.ListenAddr != "127.0.0.1:8080" || cfg.Admin.ListenAddr != "127.0.0.1:9090" {
		t.Fatalf("unexpected initial systemd listeners: server=%q admin=%q", cfg.Server.ListenAddr, cfg.Admin.ListenAddr)
	}

	tempDir := t.TempDir()
	managedPath := filepath.Join(tempDir, "config.json")
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
	persisted.Server.ListenAddr = "127.0.0.1:18080"
	if err := Save(managedPath, persisted); err != nil {
		t.Fatalf("persist listener update: %v", err)
	}
	updated, err := Load(managedPath)
	if err != nil {
		t.Fatalf("reload updated profile: %v", err)
	}
	if updated.Server.ListenAddr != "127.0.0.1:18080" {
		t.Fatalf("mutable listener remained pinned outside JSON: got %q", updated.Server.ListenAddr)
	}
}

func TestSystemdEnvironmentTemplateContainsOnlyRuntimeSecret(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "systemd", "edgeproxy.env.example")
	keys := activeEnvironmentKeys(t, path)
	if len(keys) != 1 || keys[0] != "EDGEPROXY_ADMIN_TOKEN" {
		t.Fatalf("systemd environment must contain only EDGEPROXY_ADMIN_TOKEN, got %v", keys)
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

func activeEnvironmentKeys(t *testing.T, path string) []string {
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
	profile := filepath.Join("..", "..", "deploy", "systemd", "edgeproxy.json")
	current, err := LoadFile(profile)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("EDGEPROXY_SERVER_LISTEN_ADDR", "127.0.0.1:28080")
	next := current
	next.Server.ListenAddr = "127.0.0.1:38080"
	if err := ValidateEnvironmentManagedChanges(current, next); err == nil || !strings.Contains(err.Error(), "EDGEPROXY_SERVER_LISTEN_ADDR") {
		t.Fatalf("expected managed listener change to be rejected, got %v", err)
	}

	t.Setenv("EDGEPROXY_SERVER_LISTEN_ADDR", "")
	t.Setenv("EDGEPROXY_ROUTE_DEMO_APP_UPSTREAM_URLS", "http://127.0.0.1:29000")
	next = current
	next.Routes = append([]RouteConfig(nil), current.Routes...)
	next.Routes[0].Upstreams = append([]UpstreamConfig(nil), current.Routes[0].Upstreams...)
	next.Routes[0].Upstreams[0].URL = "http://127.0.0.1:39000"
	if err := ValidateEnvironmentManagedChanges(current, next); err == nil || !strings.Contains(err.Error(), "EDGEPROXY_ROUTE_DEMO_APP_UPSTREAM_URLS") {
		t.Fatalf("expected managed upstream change to be rejected, got %v", err)
	}

	t.Setenv("EDGEPROXY_ROUTE_DEMO_APP_UPSTREAM_URLS", "")
	if err := ValidateEnvironmentManagedChanges(current, next); err != nil {
		t.Fatalf("unmanaged file-backed change was rejected: %v", err)
	}
}
