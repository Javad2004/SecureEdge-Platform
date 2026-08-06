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
