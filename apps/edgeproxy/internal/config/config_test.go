package config

import (
	"encoding/json"
	"os"
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

func validRouteForValidation() RouteConfig {
	return RouteConfig{
		Name:       "demo",
		Hosts:      []string{"example.test"},
		PathPrefix: "/",
		Upstreams:  []UpstreamConfig{{URL: "http://127.0.0.1:9000"}},
		Proxy: ProxyConfig{
			RequestTimeout:         Duration{Duration: 5 * time.Second},
			DialTimeout:            Duration{Duration: time.Second},
			ResponseHeaderTimeout:  Duration{Duration: 2 * time.Second},
			IdleConnTimeout:        Duration{Duration: time.Minute},
			RetryBackoff:           Duration{Duration: 100 * time.Millisecond},
			MaxIdleConns:           10,
			MaxIdleConnsPerHost:    10,
			MaxResponseHeaderBytes: 1 << 20,
		},
		Cache: CacheConfig{
			Enabled:              true,
			DefaultTTL:           Duration{Duration: time.Minute},
			StaleIfError:         Duration{Duration: time.Minute},
			MaxEntries:           10,
			MaxBytes:             1 << 20,
			MaxObjectBytes:       1 << 16,
			CacheableStatusCodes: []int{200},
		},
	}
}

func TestValidateRequiresTokenForNonLoopbackAdmin(t *testing.T) {
	cfg := Default()
	cfg.Admin.ListenAddr = "0.0.0.0:9090"
	cfg.Admin.AuthToken = ""
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-loopback admin listener without token to be rejected")
	}

	cfg.Admin.AuthToken = "strong-test-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected token-protected non-loopback admin listener to validate: %v", err)
	}
}

func TestLoadAdminTokenEnvironmentOverride(t *testing.T) {
	cfg := Default()
	cfg.Admin.AuthToken = "file-token"
	cfg.Routes = []RouteConfig{validRouteForValidation()}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "environment-token")
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Admin.AuthToken != "environment-token" {
		t.Fatalf("expected environment token override, got %q", loaded.Admin.AuthToken)
	}
}

func TestValidateNormalizesWhitespaceUsedAtRuntime(t *testing.T) {
	cfg := Default()
	cfg.Admin.AuthToken = "  demo-token  "
	route := validRouteForValidation()
	route.Name = "  demo  "
	route.Hosts = []string{" Example.TEST. "}
	route.PathPrefix = "   "
	route.Upstreams[0].URL = "  http://127.0.0.1:9000  "
	cfg.Routes = []RouteConfig{route}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.AuthToken != "demo-token" || cfg.Routes[0].Name != "demo" || cfg.Routes[0].Hosts[0] != "example.test" || cfg.Routes[0].PathPrefix != "/" || cfg.Routes[0].Upstreams[0].URL != "http://127.0.0.1:9000" {
		t.Fatalf("configuration was not normalized as expected: %#v", cfg)
	}
}

func TestValidateRejectsAmbiguousDuplicateRouteSelector(t *testing.T) {
	cfg := Default()
	first := validRouteForValidation()
	first.Name = "first"
	second := validRouteForValidation()
	second.Name = "second"
	second.Hosts = []string{"EXAMPLE.TEST."}
	cfg.Routes = []RouteConfig{first, second}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate host/path route selector to be rejected")
	}
}
