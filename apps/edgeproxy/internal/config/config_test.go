package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurationJSON(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"150ms"`), &d); err != nil {
		t.Fatal(err)
	}
	if d.Duration != 150*time.Millisecond {
		t.Fatalf("unexpected duration: %s", d.Duration)
	}
}

func TestValidateRejectsUnsafeCacheLimits(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{{
		Name: "bad", Hosts: []string{"example.local"}, PathPrefix: "/",
		Upstreams: []UpstreamConfig{{URL: "http://127.0.0.1:9000"}},
		Cache:     CacheConfig{Enabled: true, DefaultTTL: Duration{Duration: time.Second}, MaxEntries: 10, MaxBytes: 100, MaxObjectBytes: 200},
	}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDefaultAdminLogStoreIsSafeAndBounded(t *testing.T) {
	cfg := Default()
	if !cfg.Admin.LogStore.Enabled {
		t.Fatal("expected admin log store to be enabled by default")
	}
	if cfg.Admin.LogStore.Capacity != 5000 || cfg.Admin.LogStore.DefaultPageSize != 100 || cfg.Admin.LogStore.MaxPageSize != 500 {
		t.Fatalf("unexpected defaults: %#v", cfg.Admin.LogStore)
	}
}

func TestValidateRejectsInvalidAdminLogStore(t *testing.T) {
	cfg := Default()
	cfg.Admin.LogStore.MaxPageSize = cfg.Admin.LogStore.Capacity + 1
	cfg.Routes = []RouteConfig{{
		Name: "demo", Hosts: []string{"example.test"}, PathPrefix: "/",
		Upstreams: []UpstreamConfig{{URL: "http://127.0.0.1:9000"}},
	}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected admin log-store validation error")
	}
}
