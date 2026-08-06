package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func persistenceConfig(t *testing.T) Config {
	t.Helper()
	cfg := Default()
	cfg.Admin.AuthToken = "secret"
	cfg.Routes = []RouteConfig{{
		Name: "demo", Hosts: []string{"project.test"}, PathPrefix: "/",
		Upstreams: []UpstreamConfig{{URL: "http://127.0.0.1:9000"}},
		Proxy: ProxyConfig{
			RequestTimeout: Duration{Duration: 5 * time.Second}, DialTimeout: Duration{Duration: time.Second},
			ResponseHeaderTimeout: Duration{Duration: 2 * time.Second}, IdleConnTimeout: Duration{Duration: time.Minute},
			RetryBackoff: Duration{Duration: 10 * time.Millisecond}, MaxIdleConns: 8, MaxIdleConnsPerHost: 4,
			MaxResponseHeaderBytes: 1 << 20,
		},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLoadFileRecoversInterruptedAtomicUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edgeproxy.json")
	cfg := persistenceConfig(t)
	cfg.Routes[0].Upstreams[0].Weight = 7

	staged := filepath.Join(dir, "staged.json")
	if err := Save(staged, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("recover staged configuration: %v", err)
	}
	if loaded.Routes[0].Upstreams[0].Weight != 7 {
		t.Fatalf("recovered weight=%d, want 7", loaded.Routes[0].Upstreams[0].Weight)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("restored configuration is missing: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("staged backup still exists after recovery: %v", err)
	}
}

func TestLoadFileDoesNotRestoreInvalidBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edgeproxy.json")
	backup := path + ".bak"
	if err := os.WriteFile(backup, []byte(`{"server":`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("expected parse error, got %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("invalid backup was restored to the configured path: %v", statErr)
	}
	if _, statErr := os.Stat(backup); statErr != nil {
		t.Fatalf("invalid backup should remain available for diagnosis: %v", statErr)
	}
}

func TestLoadFileRejectsUnknownFieldsAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}

	oversized := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversized, make([]byte, maxConfigFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(oversized); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestSaveRetainsBackupsAndRedactsPresentation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := persistenceConfig(t)
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxConfigBackups+3; i++ {
		cfg.Routes[0].Upstreams[0].Weight = i + 1
		if err := Save(path, cfg); err != nil {
			t.Fatal(err)
		}
	}
	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != maxConfigBackups {
		t.Fatalf("backup count=%d, want %d", len(backups), maxConfigBackups)
	}
	if got := Redacted(cfg).Admin.AuthToken; got != "[REDACTED]" {
		t.Fatalf("redacted token=%q", got)
	}
}

func TestSaveRejectsOversizedExistingConfigWithoutBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edgeproxy.json")
	original := make([]byte, maxConfigFileBytes+1)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	err := Save(path, persistenceConfig(t))
	if err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || info.Size() != int64(len(original)) {
		t.Fatalf("oversized source was modified: info=%v err=%v", info, statErr)
	}
	backups, globErr := filepath.Glob(path + ".bak-*")
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(backups) != 0 {
		t.Fatalf("unexpected partial backups: %v", backups)
	}
}
