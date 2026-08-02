package config

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
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

func TestLoadRejectsUnknownConfigurationField(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	server := object["server"].(map[string]any)
	server["listen_adrr"] = server["listen_addr"]
	delete(server, "listen_addr")
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestTrustedProxyConfigurationIsNormalized(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Server.TrustedProxyCIDRs = []string{" 127.0.0.1/8 ", "127.0.0.0/8"}
	cfg.Server.ForwardedForHeader = " X-Forwarded-For "
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.TrustedProxyCIDRs) != 1 || cfg.Server.TrustedProxyCIDRs[0] != "127.0.0.0/8" {
		t.Fatalf("unexpected trusted proxies: %#v", cfg.Server.TrustedProxyCIDRs)
	}
	if cfg.Server.ForwardedForHeader != "X-Forwarded-For" {
		t.Fatalf("unexpected forwarding header: %q", cfg.Server.ForwardedForHeader)
	}
}

func TestRejectsInvalidTrustedProxyConfiguration(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Server.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid trusted proxy CIDR to be rejected")
	}

	cfg = Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Server.ForwardedForHeader = "X Forwarded For"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid forwarding header name to be rejected")
	}
}

func TestValidateNormalizesCanonicalRouteAndHealthPaths(t *testing.T) {
	cfg := Default()
	route := validRouteForValidation()
	route.PathPrefix = " /api/ "
	route.HealthCheck = HealthCheckConfig{
		Enabled: true, Path: " /healthz/ ", Interval: Duration{Duration: time.Second}, Timeout: Duration{Duration: time.Second}, HealthyStatuses: []int{200},
	}
	cfg.Routes = []RouteConfig{route}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Routes[0].PathPrefix != "/api" || cfg.Routes[0].HealthCheck.Path != "/healthz/" {
		t.Fatalf("unexpected normalized paths: route=%q health=%q", cfg.Routes[0].PathPrefix, cfg.Routes[0].HealthCheck.Path)
	}
}

func TestValidateRejectsNonCanonicalRoutePaths(t *testing.T) {
	for _, value := range []string{"api", "/api/../admin", "/api//admin", "/api%2Fadmin", "/api?debug=1"} {
		cfg := Default()
		route := validRouteForValidation()
		route.PathPrefix = value
		cfg.Routes = []RouteConfig{route}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected path_prefix %q to be rejected", value)
		}
	}
}

func TestValidateNormalizesCacheVaryHeadersAndAddsSensitivePartitions(t *testing.T) {
	cfg := Default()
	route := validRouteForValidation()
	route.Cache.Enabled = true
	route.Cache.DefaultTTL = Duration{Duration: time.Minute}
	route.Cache.MaxEntries = 10
	route.Cache.MaxBytes = 1 << 20
	route.Cache.MaxObjectBytes = 1 << 16
	route.Cache.CacheableStatusCodes = []int{http.StatusOK}
	route.Cache.VaryRequestHeaders = []string{" accept-language ", "Accept-Language"}
	route.Cache.CacheAuthorizedRequests = true
	route.Cache.CacheCookieRequests = true
	cfg.Routes = []RouteConfig{route}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	got := cfg.Routes[0].Cache.VaryRequestHeaders
	want := []string{"Accept-Language", "Authorization", "Cookie"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vary headers=%#v, want %#v", got, want)
	}
}

func TestValidateRejectsInvalidCacheVaryHeader(t *testing.T) {
	cfg := Default()
	route := validRouteForValidation()
	route.Cache.Enabled = true
	route.Cache.DefaultTTL = Duration{Duration: time.Minute}
	route.Cache.MaxEntries = 10
	route.Cache.MaxBytes = 1 << 20
	route.Cache.MaxObjectBytes = 1 << 16
	route.Cache.CacheableStatusCodes = []int{http.StatusOK}
	route.Cache.VaryRequestHeaders = []string{"X Invalid Header"}
	cfg.Routes = []RouteConfig{route}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "vary_request_headers") {
		t.Fatalf("expected invalid vary-header error, got %v", err)
	}
}

func TestValidateRejectsInvalidRouteHostPatterns(t *testing.T) {
	for _, host := range []string{"example.test:8080", "foo*bar.example", "*.127.0.0.1", "bad..example", "-bad.example", "bad_.example"} {
		cfg := Default()
		route := validRouteForValidation()
		route.Hosts = []string{host}
		cfg.Routes = []RouteConfig{route}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected host pattern %q to be rejected", host)
		}
	}
}

func TestValidateNormalizesValidRouteHostPatterns(t *testing.T) {
	cfg := Default()
	route := validRouteForValidation()
	route.Hosts = []string{" Example.TEST. ", "*.Sub.Example.TEST.", "[::1]"}
	cfg.Routes = []RouteConfig{route}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"example.test", "*.sub.example.test", "::1"}
	if !reflect.DeepEqual(cfg.Routes[0].Hosts, want) {
		t.Fatalf("hosts=%#v, want %#v", cfg.Routes[0].Hosts, want)
	}
}

func TestValidateRejectsExcessiveAdminLogCapacity(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Admin.Enabled = true
	cfg.Admin.LogStore.Enabled = true
	cfg.Admin.LogStore.Capacity = 100001
	cfg.Admin.LogStore.MaxPageSize = 500
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("expected excessive log capacity error, got %v", err)
	}
}

func TestValidateRejectsExplicitEmptyPorts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "public listener", mutate: func(cfg *Config) { cfg.Server.ListenAddr = "127.0.0.1:" }},
		{name: "admin listener", mutate: func(cfg *Config) { cfg.Admin.ListenAddr = "127.0.0.1:" }},
		{name: "upstream URL", mutate: func(cfg *Config) { cfg.Routes[0].Upstreams[0].URL = "http://127.0.0.1:" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Routes = []RouteConfig{validRouteForValidation()}
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "port is required") {
				t.Fatalf("expected missing-port validation error, got %v", err)
			}
		})
	}
}

func TestValidateRejectsOutOfRangePorts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "public listener", mutate: func(cfg *Config) { cfg.Server.ListenAddr = "127.0.0.1:70000" }},
		{name: "admin listener", mutate: func(cfg *Config) { cfg.Admin.ListenAddr = "127.0.0.1:-1" }},
		{name: "upstream URL", mutate: func(cfg *Config) { cfg.Routes[0].Upstreams[0].URL = "http://127.0.0.1:70000" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Routes = []RouteConfig{validRouteForValidation()}
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "port must be between") {
				t.Fatalf("expected port-range validation error, got %v", err)
			}
		})
	}
}
