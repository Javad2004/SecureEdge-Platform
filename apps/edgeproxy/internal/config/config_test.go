package config

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCheckedInConfigurationsValidate(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate configuration test source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	repositoryRoot := filepath.Clean(filepath.Join(moduleRoot, "..", ".."))
	paths := []string{
		filepath.Join(moduleRoot, "configs", "compose.json"),
		filepath.Join(moduleRoot, "configs", "edgeproxy.json"),
		filepath.Join(moduleRoot, "configs", "local-dev.json"),
		filepath.Join(moduleRoot, "configs", "examples", "multi-origin.json"),
		filepath.Join(moduleRoot, "configs", "examples", "multi-route.json"),
		filepath.Join(repositoryRoot, "integration", "edgeproxy-behind-waf.json"),
		filepath.Join(repositoryRoot, "integration", "edgeproxy-compose-behind-waf.json"),
		filepath.Join(repositoryRoot, "integration", "edgeproxy-local-behind-waf.json"),
	}
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "")
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := Load(path); err != nil {
				t.Fatalf("validate %s: %v", path, err)
			}
		})
	}
}

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

func TestValidateRejectsExcessiveServerHeaderLimit(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Server.MaxHeaderBytes = maxServerHeaderBytes
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected maximum supported server header limit to validate: %v", err)
	}

	cfg.Server.MaxHeaderBytes = maxServerHeaderBytes + 1
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "server.max_header_bytes") {
		t.Fatalf("expected excessive server header limit to be rejected, got %v", err)
	}
}

func TestValidateRejectsExcessiveProxyResponseHeaderLimit(t *testing.T) {
	cfg := Default()
	route := validRouteForValidation()
	route.Proxy.MaxResponseHeaderBytes = maxProxyResponseHeaderBytes
	cfg.Routes = []RouteConfig{route}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected maximum supported proxy response header limit to validate: %v", err)
	}

	cfg.Routes[0].Proxy.MaxResponseHeaderBytes = maxProxyResponseHeaderBytes + 1
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "proxy.max_response_header_bytes") {
		t.Fatalf("expected excessive proxy response header limit to be rejected, got %v", err)
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

func TestRejectsReservedClientIPSourceHeaders(t *testing.T) {
	for _, header := range []string{"Authorization", "Cookie", "Forwarded", "Host", "X-Request-ID", "X-Forwarded-Proto"} {
		t.Run(header, func(t *testing.T) {
			cfg := Default()
			cfg.Routes = []RouteConfig{validRouteForValidation()}
			cfg.Server.ForwardedForHeader = header
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("expected reserved client IP source header %q to be rejected, got %v", header, err)
			}
		})
	}

	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Server.ForwardedForHeader = "X-Trusted-Client-IP"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected dedicated custom client IP header to be accepted: %v", err)
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

func TestValidateRejectsUnknownServicePorts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "public listener", mutate: func(cfg *Config) { cfg.Server.ListenAddr = "127.0.0.1:definitely-not-a-service" }},
		{name: "admin listener", mutate: func(cfg *Config) { cfg.Admin.ListenAddr = "127.0.0.1:definitely-not-a-service" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Routes = []RouteConfig{validRouteForValidation()}
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "registered TCP service") {
				t.Fatalf("expected unknown-service validation error, got %v", err)
			}
		})
	}
}

func TestApplyEnvironmentOverridesCoversEndpointsAndRouteValues(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Routes[0].Name = "demo-app"

	t.Setenv("EDGEPROXY_SERVER_LISTEN_ADDR", "0.0.0.0:8180")
	t.Setenv("EDGEPROXY_ADMIN_LISTEN_ADDR", "127.0.0.1:9190")
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "runtime-token")
	t.Setenv("EDGEPROXY_TRUSTED_PROXY_CIDRS", "127.0.0.1/32, 10.0.0.0/8")
	t.Setenv("EDGEPROXY_ROUTE_DEMO_APP_UPSTREAM_URLS", "http://10.0.0.10:9000,http://10.0.0.11:9000")
	t.Setenv("EDGEPROXY_TLS_ENABLED", "false")

	if err := ApplyEnvironmentOverrides(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddr != "0.0.0.0:8180" || cfg.Admin.ListenAddr != "127.0.0.1:9190" || cfg.Admin.AuthToken != "runtime-token" {
		t.Fatalf("listener or token overrides were not applied: %#v", cfg)
	}
	if len(cfg.Server.TrustedProxyCIDRs) != 2 || len(cfg.Routes[0].Upstreams) != 2 {
		t.Fatalf("list overrides were not applied: %#v", cfg)
	}
	if !reflect.DeepEqual(cfg.Routes[0].Hosts, validRouteForValidation().Hosts) {
		t.Fatalf("route selectors must remain JSON-backed: %#v", cfg.Routes[0].Hosts)
	}
	if cfg.Routes[0].Upstreams[1].URL != "http://10.0.0.11:9000" {
		t.Fatalf("unexpected upstream override: %#v", cfg.Routes[0].Upstreams)
	}
}

func TestApplyEnvironmentOverridesRejectsRouteHostOverride(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	cfg.Routes[0].Name = "demo-app"
	t.Setenv("EDGEPROXY_ROUTE_DEMO_APP_HOSTS", "different.example.test")
	if err := ApplyEnvironmentOverrides(&cfg); err == nil || !strings.Contains(err.Error(), "shared JSON profile") {
		t.Fatalf("expected route-host override rejection, got %v", err)
	}
}

func TestApplyEnvironmentOverridesRejectsInvalidTLSBoolean(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	t.Setenv("EDGEPROXY_TLS_ENABLED", "sometimes")
	if err := ApplyEnvironmentOverrides(&cfg); err == nil || !strings.Contains(err.Error(), "EDGEPROXY_TLS_ENABLED") {
		t.Fatalf("expected invalid TLS boolean error, got %v", err)
	}
}

func TestValidateRejectsOverlappingServerAndAdminListeners(t *testing.T) {
	cases := []struct {
		name   string
		server string
		admin  string
	}{
		{name: "identical", server: "127.0.0.1:8080", admin: "127.0.0.1:8080"},
		{name: "IPv4 wildcard", server: "0.0.0.0:8080", admin: "127.0.0.1:8080"},
		{name: "IPv6 wildcard", server: "[::]:8080", admin: "[::1]:8080"},
		{name: "loopback aliases", server: "localhost:8080", admin: "127.0.0.1:8080"},
		{name: "service name", server: "127.0.0.1:http", admin: "127.0.0.1:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.ListenAddr = tc.server
			cfg.Admin.ListenAddr = tc.admin
			cfg.Admin.AuthToken = "test-token"
			cfg.Routes = []RouteConfig{validRouteForValidation()}
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("expected listener overlap to be rejected, got %v", err)
			}
		})
	}
}

func TestValidateAllowsDistinctOrDynamicListeners(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server string
		admin  string
	}{
		{name: "different ports", server: "127.0.0.1:8080", admin: "127.0.0.1:9090"},
		{name: "dynamic server", server: "127.0.0.1:0", admin: "127.0.0.1:9090"},
		{name: "dynamic admin", server: "127.0.0.1:8080", admin: "127.0.0.1:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.ListenAddr = tc.server
			cfg.Admin.ListenAddr = tc.admin
			cfg.Routes = []RouteConfig{validRouteForValidation()}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("expected listeners to validate: %v", err)
			}
		})
	}
}

func TestConfigRejectsCaseInsensitiveDuplicateRouteNames(t *testing.T) {
	cfg := Default()
	cfg.Routes = []RouteConfig{validRouteForValidation()}
	duplicate := cfg.Routes[0]
	duplicate.Name = strings.ToUpper(cfg.Routes[0].Name)
	duplicate.Hosts = []string{"other.example.test"}
	cfg.Routes = append(cfg.Routes, duplicate)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Fatalf("expected case-insensitive duplicate route error, got %v", err)
	}
}
