package config

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRejectsInvalidCustomRule(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.WAF.CustomRules = []CustomRuleConfig{{ID: "BAD", Name: "Bad", Category: "custom", Description: "bad regex", Score: 1, Targets: []string{"query"}, Pattern: "("}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestCustomRuleScoreBounds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		score     int
		wantError bool
	}{
		{name: "zero", score: 0, wantError: true},
		{name: "maximum", score: MaxCustomRuleScore},
		{name: "above maximum", score: MaxCustomRuleScore + 1, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			cfg.WAF.CustomRules = []CustomRuleConfig{{
				ID: "SCORE-BOUND", Name: "Score bound", Category: "custom",
				Description: "checks custom-rule score validation", Score: tc.score,
				Targets: []string{"query"}, Pattern: `score-bound-marker`,
			}}
			err := cfg.Validate()
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), ".score must be between") {
					t.Fatalf("expected score validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected boundary score to be accepted: %v", err)
			}
		})
	}
}

func TestRejectsUntrustedProxyCIDRFormat(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Server.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
func TestDefaultConfigurationValid(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsTLSInEmbeddedMode(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Server.TLS = TLSConfig{Enabled: true, CertFile: "server.crt", KeyFile: "server.key"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server.tls.enabled requires server.mode gateway") {
		t.Fatalf("expected embedded TLS to be rejected, got %v", err)
	}
}

func TestValidateRequiresTLSMaterialWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		cert string
		key  string
	}{
		{name: "both missing"},
		{name: "certificate missing", key: "server.key"},
		{name: "key missing", cert: "server.crt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "gateway"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			cfg.Server.TLS.Enabled = true
			cfg.Server.TLS.CertFile = tc.cert
			cfg.Server.TLS.KeyFile = tc.key
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server.tls.cert_file and key_file") {
				t.Fatalf("expected incomplete TLS material to be rejected, got %v", err)
			}
		})
	}

	cfg := Default()
	cfg.Server.Mode = "gateway"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Server.TLS = TLSConfig{Enabled: true, CertFile: " server.crt ", KeyFile: " server.key "}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected complete TLS paths to validate: %v", err)
	}
	if cfg.Server.TLS.CertFile != "server.crt" || cfg.Server.TLS.KeyFile != "server.key" {
		t.Fatalf("TLS paths were not normalized: %#v", cfg.Server.TLS)
	}
}

func TestRejectsInvalidConnectivityDNSConfiguration(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.Connectivity.DNS.Enabled = true
	cfg.Admin.Connectivity.DNS.Server = "missing-port"
	cfg.Admin.Connectivity.DNS.Names = []string{"project.test"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadFileRejectsUnknownConfigurationField(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
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
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestExcludedPathPrefixesAreNormalizedAndValidated(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.DefaultPolicy.ExcludedPathPrefixes = []string{" /healthz ", "/healthz", "", "/readyz/"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"/healthz", "/readyz"}
	if len(cfg.DefaultPolicy.ExcludedPathPrefixes) != len(want) {
		t.Fatalf("unexpected normalized prefixes: %#v", cfg.DefaultPolicy.ExcludedPathPrefixes)
	}
	for i := range want {
		if cfg.DefaultPolicy.ExcludedPathPrefixes[i] != want[i] {
			t.Fatalf("unexpected normalized prefixes: %#v", cfg.DefaultPolicy.ExcludedPathPrefixes)
		}
	}

	for _, invalid := range []string{"healthz", "/healthz?full=1", "/healthz#fragment", "/healthz/../admin", "/healthz//ready", "/healthz%2Fready"} {
		cfg := Default()
		cfg.Server.Mode = "embedded"
		cfg.EdgeProxy.ConfigPath = "edge.json"
		cfg.DefaultPolicy.ExcludedPathPrefixes = []string{invalid}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected validation error for %q", invalid)
		}
	}
}

func TestRejectsUnsafeTimeoutAndInspectionRelationships(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "negative read timeout", mutate: func(cfg *Config) { cfg.Server.ReadTimeout.Duration = -1 }},
		{name: "zero admin poll timeout", mutate: func(cfg *Config) { cfg.Admin.PollTimeout.Duration = 0 }},
		{name: "zero edgeproxy timeout", mutate: func(cfg *Config) { cfg.EdgeProxy.Timeout.Duration = 0 }},
		{name: "inspection exceeds request limit", mutate: func(cfg *Config) {
			cfg.Server.MaxRequestBodyBytes = 1024
			cfg.DefaultPolicy.MaxInspectionBodyBytes = 2048
		}},
		{name: "inspection enabled with zero limit", mutate: func(cfg *Config) { cfg.DefaultPolicy.MaxInspectionBodyBytes = 0 }},
		{name: "inspection enabled without content types", mutate: func(cfg *Config) { cfg.DefaultPolicy.BodyContentTypes = nil }},
		{name: "rate limiter cannot allocate global and client buckets", mutate: func(cfg *Config) { cfg.DefaultPolicy.RateLimit.MaxBuckets = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestConfigurationNormalizesSafeScalarAndPolicyValues(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = " embedded "
	cfg.Server.ListenAddr = " 127.0.0.1:8081 "
	cfg.Server.ForwardedForHeader = " X-Forwarded-For "
	cfg.Server.TrustedProxyCIDRs = []string{" 127.0.0.1/8 ", "127.0.0.0/8"}
	cfg.Admin.ListenAddr = " 127.0.0.1:9191 "
	cfg.Admin.AuthToken = " token "
	cfg.EdgeProxy.ConfigPath = " edge.json "
	cfg.EdgeProxy.AdminURL = " http://127.0.0.1:9090 "
	cfg.EdgeProxy.AdminToken = " edge-token "
	cfg.DefaultPolicy.BodyContentTypes = []string{" Application/JSON ", "application/json"}
	cfg.DefaultPolicy.AllowedMethods = []string{" get ", "GET"}
	cfg.DefaultPolicy.DisabledRules = []string{" sqli-001 ", "SQLI-001"}
	cfg.DefaultPolicy.IPAllowlist = []string{" 127.0.0.1 ", "127.0.0.1"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddr != "127.0.0.1:8081" || cfg.Admin.ListenAddr != "127.0.0.1:9191" || cfg.EdgeProxy.ConfigPath != "edge.json" {
		t.Fatalf("scalar values were not normalized: %#v", cfg)
	}
	if len(cfg.Server.TrustedProxyCIDRs) != 1 || cfg.Server.TrustedProxyCIDRs[0] != "127.0.0.0/8" {
		t.Fatalf("trusted proxies were not normalized: %#v", cfg.Server.TrustedProxyCIDRs)
	}
	if len(cfg.DefaultPolicy.BodyContentTypes) != 1 || cfg.DefaultPolicy.BodyContentTypes[0] != "application/json" {
		t.Fatalf("body types were not normalized: %#v", cfg.DefaultPolicy.BodyContentTypes)
	}
	if len(cfg.DefaultPolicy.AllowedMethods) != 1 || cfg.DefaultPolicy.AllowedMethods[0] != "GET" {
		t.Fatalf("methods were not normalized: %#v", cfg.DefaultPolicy.AllowedMethods)
	}
	if len(cfg.DefaultPolicy.DisabledRules) != 1 || cfg.DefaultPolicy.DisabledRules[0] != "SQLI-001" {
		t.Fatalf("disabled rules were not normalized: %#v", cfg.DefaultPolicy.DisabledRules)
	}
}

func TestRejectsReservedClientIPSourceHeaders(t *testing.T) {
	for _, header := range []string{"Authorization", "Cookie", "Forwarded", "Host", "X-Request-ID", "X-Forwarded-Proto", "X-SecureEdge-Internal-Probe"} {
		t.Run(header, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			cfg.Server.ForwardedForHeader = header
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("expected reserved client IP source header %q to be rejected, got %v", header, err)
			}
		})
	}

	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Server.ForwardedForHeader = "X-Trusted-Client-IP"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected dedicated custom client IP header to be accepted: %v", err)
	}
}

func TestRejectsPolicyAddressInBothAllowAndDenyLists(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.DefaultPolicy.IPAllowlist = []string{"192.0.2.10"}
	cfg.DefaultPolicy.IPDenylist = []string{"192.0.2.10"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestRejectsReservedUnmatchedRoutePolicyName(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.RoutePolicies = map[string]Policy{"__UNMATCHED__": cfg.DefaultPolicy}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved internal route policy name to be rejected, got %v", err)
	}
}

func TestRoutePoliciesShareProcessWideLimiterResources(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "cleanup interval", mutate: func(p *Policy) { p.RateLimit.CleanupInterval.Duration += time.Minute }},
		{name: "idle ttl", mutate: func(p *Policy) { p.RateLimit.IdleTTL.Duration += time.Minute }},
		{name: "bucket capacity", mutate: func(p *Policy) { p.RateLimit.MaxBuckets++ }},
		{name: "ban tracking capacity", mutate: func(p *Policy) { p.AutoBan.MaxTrackedClients++ }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			policy := cfg.DefaultPolicy
			tc.mutate(&policy)
			cfg.RoutePolicies["demo-app"] = policy
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected route-specific process-wide resource setting to be rejected")
			}
		})
	}
}

func TestApplyEnvironmentOverridesDoesNotRequireFileMutation(t *testing.T) {
	cfg := Default()
	cfg.Admin.AuthToken = "file-admin"
	cfg.EdgeProxy.AdminToken = "file-edge"
	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "runtime-admin")
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "runtime-edge")
	if err := ApplyEnvironmentOverrides(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.AuthToken != "runtime-admin" || cfg.EdgeProxy.AdminToken != "runtime-edge" {
		t.Fatalf("environment overrides were not applied: admin=%q edge=%q", cfg.Admin.AuthToken, cfg.EdgeProxy.AdminToken)
	}
}

func TestValidateRejectsAdminURLQuery(t *testing.T) {
	cfg := Default()
	cfg.EdgeProxy.AdminURL = "http://127.0.0.1:9090?token=unsafe"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "admin_url") {
		t.Fatalf("expected admin URL query to be rejected, got %v", err)
	}
}

func TestValidateRejectsUpstreamProxyURLPathOrQuery(t *testing.T) {
	for _, value := range []string{
		"http://127.0.0.1:8080/edgeproxy",
		"http://127.0.0.1:8080?route=demo",
	} {
		t.Run(value, func(t *testing.T) {
			cfg := Default()
			cfg.EdgeProxy.ConfigPath = "edge.json"
			cfg.Server.UpstreamProxyURL = value
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "upstream_proxy_url") {
				t.Fatalf("expected upstream proxy URL to be rejected, got %v", err)
			}
		})
	}
}

func TestValidateAllowsUpstreamProxyURLWithRootPath(t *testing.T) {
	cfg := Default()
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Server.UpstreamProxyURL = "http://127.0.0.1:8080/"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected root-path upstream URL to be accepted, got %v", err)
	}
}

func TestValidateRejectsExcessiveAdminLogCapacity(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.LogStore.Capacity = 100001
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("expected excessive log capacity error, got %v", err)
	}
}

func TestValidateRejectsExplicitEmptyPorts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "gateway listener", mutate: func(cfg *Config) { cfg.Server.ListenAddr = "127.0.0.1:" }},
		{name: "admin listener", mutate: func(cfg *Config) { cfg.Admin.ListenAddr = "127.0.0.1:" }},
		{name: "upstream proxy URL", mutate: func(cfg *Config) { cfg.Server.UpstreamProxyURL = "http://127.0.0.1:" }},
		{name: "edgeproxy admin URL", mutate: func(cfg *Config) { cfg.EdgeProxy.AdminURL = "http://127.0.0.1:" }},
		{name: "DNS server", mutate: func(cfg *Config) {
			cfg.Admin.Connectivity.DNS.Enabled = true
			cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:"
			cfg.Admin.Connectivity.DNS.Names = []string{"project.test"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "gateway"
			cfg.EdgeProxy.ConfigPath = "edge.json"
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
		{name: "gateway listener", mutate: func(cfg *Config) { cfg.Server.ListenAddr = "127.0.0.1:70000" }},
		{name: "admin listener", mutate: func(cfg *Config) { cfg.Admin.ListenAddr = "127.0.0.1:-1" }},
		{name: "upstream proxy URL", mutate: func(cfg *Config) { cfg.Server.UpstreamProxyURL = "http://127.0.0.1:70000" }},
		{name: "edgeproxy admin URL", mutate: func(cfg *Config) { cfg.EdgeProxy.AdminURL = "http://127.0.0.1:70000" }},
		{name: "DNS server", mutate: func(cfg *Config) {
			cfg.Admin.Connectivity.DNS.Enabled = true
			cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:70000"
			cfg.Admin.Connectivity.DNS.Names = []string{"project.test"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "gateway"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "port must be between") {
				t.Fatalf("expected port-range validation error, got %v", err)
			}
		})
	}
}

func TestValidateNormalizesConnectivityDNSValues(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.Connectivity.DNS.Enabled = true
	cfg.Admin.Connectivity.DNS.Server = " 127.0.0.1:53 "
	cfg.Admin.Connectivity.DNS.Names = []string{" Project.TEST ", "project.test"}
	cfg.Admin.Connectivity.DNS.ExpectedAddresses = []string{" 2001:0db8::1 ", "2001:db8::1"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Admin.Connectivity.DNS.Server; got != "127.0.0.1:53" {
		t.Fatalf("DNS server=%q", got)
	}
	if got := cfg.Admin.Connectivity.DNS.Names; len(got) != 1 || got[0] != "project.test" {
		t.Fatalf("DNS names=%#v", got)
	}
	if got := cfg.Admin.Connectivity.DNS.ExpectedAddresses; len(got) != 1 || got[0] != "2001:db8::1" {
		t.Fatalf("expected addresses=%#v", got)
	}
}

func TestValidateRejectsBlankConnectivityDNSName(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.Connectivity.DNS.Enabled = true
	cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:53"
	cfg.Admin.Connectivity.DNS.Names = []string{"   "}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "empty domain") {
		t.Fatalf("expected blank DNS name to be rejected, got %v", err)
	}
}

func TestValidateRejectsUnknownServicePorts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "gateway listener", mutate: func(cfg *Config) { cfg.Server.ListenAddr = "127.0.0.1:definitely-not-a-service" }},
		{name: "admin listener", mutate: func(cfg *Config) { cfg.Admin.ListenAddr = "127.0.0.1:definitely-not-a-service" }},
		{name: "DNS server", mutate: func(cfg *Config) {
			cfg.Admin.Connectivity.DNS.Enabled = true
			cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:definitely-not-a-service"
			cfg.Admin.Connectivity.DNS.Names = []string{"project.test"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "gateway"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "registered TCP service") {
				t.Fatalf("expected unknown-service validation error, got %v", err)
			}
		})
	}
}

func TestValidateRejectsMalformedConnectivityDNSNames(t *testing.T) {
	for _, name := range []string{
		"bad name",
		"project.test:53",
		"https://project.test",
		"*.project.test",
		"project..test",
		"project.test/path",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			cfg.Admin.Connectivity.DNS.Enabled = true
			cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:53"
			cfg.Admin.Connectivity.DNS.Names = []string{name}
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "dns.names") {
				t.Fatalf("expected malformed DNS name %q to be rejected, got %v", name, err)
			}
		})
	}
}

func TestValidateAllowsAbsoluteAndUnderscoredDNSNames(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.Connectivity.DNS.Enabled = true
	cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:53"
	cfg.Admin.Connectivity.DNS.Names = []string{" Project.TEST. ", "_health.project.test"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid DNS probe names to be accepted: %v", err)
	}
	want := []string{"project.test.", "_health.project.test"}
	if !reflect.DeepEqual(cfg.Admin.Connectivity.DNS.Names, want) {
		t.Fatalf("DNS names=%#v want %#v", cfg.Admin.Connectivity.DNS.Names, want)
	}
}

func TestValidateUpstreamResponseHeaderLimit(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Server.UpstreamTransport.MaxResponseHeaderBytes = maxUpstreamResponseHeaderBytes
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected maximum response-header limit to be accepted: %v", err)
	}

	cfg.Server.UpstreamTransport.MaxResponseHeaderBytes++
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server.upstream_transport.max_response_header_bytes") {
		t.Fatalf("expected excessive response-header limit to be rejected, got %v", err)
	}
}

func TestApplyEnvironmentOverridesCoversRuntimeEndpoints(t *testing.T) {
	cfg := Default()
	cfg.EdgeProxy.ConfigPath = "edge.json"

	t.Setenv("SECURITYEDGE_SERVER_LISTEN_ADDR", "0.0.0.0:8181")
	t.Setenv("SECURITYEDGE_UPSTREAM_PROXY_URL", "http://127.0.0.1:8180")
	t.Setenv("SECURITYEDGE_ADMIN_LISTEN_ADDR", "127.0.0.1:9291")
	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "security-runtime-token")
	t.Setenv("SECURITYEDGE_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,10.0.0.0/8")
	t.Setenv("SECURITYEDGE_TLS_ENABLED", "true")
	t.Setenv("SECURITYEDGE_TLS_CERT_FILE", "/run/securityedge/fullchain.pem")
	t.Setenv("SECURITYEDGE_TLS_KEY_FILE", "/run/securityedge/privkey.pem")
	t.Setenv("SECURITYEDGE_EDGEPROXY_CONFIG_PATH", "../../integration/edge.json")
	t.Setenv("SECURITYEDGE_EDGEPROXY_ADMIN_URL", "http://127.0.0.1:9190")
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "edge-runtime-token")
	t.Setenv("SECURITYEDGE_DNS_ENABLED", "true")
	t.Setenv("SECURITYEDGE_DNS_CRITICAL", "true")
	t.Setenv("SECURITYEDGE_DNS_SERVER", "10.0.0.2:53")
	t.Setenv("SECURITYEDGE_DNS_NAMES", "project.test,www.project.test")
	t.Setenv("SECURITYEDGE_DNS_EXPECTED_ADDRESSES", "10.0.0.2")

	if err := ApplyEnvironmentOverrides(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddr != "0.0.0.0:8181" || cfg.Server.UpstreamProxyURL != "http://127.0.0.1:8180" {
		t.Fatalf("gateway endpoint overrides were not applied: %#v", cfg.Server)
	}
	if !cfg.Server.TLS.Enabled || cfg.Server.TLS.CertFile != "/run/securityedge/fullchain.pem" || cfg.Server.TLS.KeyFile != "/run/securityedge/privkey.pem" {
		t.Fatalf("gateway TLS overrides were not applied: %#v", cfg.Server.TLS)
	}
	if cfg.Admin.ListenAddr != "127.0.0.1:9291" || cfg.Admin.AuthToken != "security-runtime-token" {
		t.Fatalf("admin overrides were not applied: %#v", cfg.Admin)
	}
	if cfg.EdgeProxy.AdminURL != "http://127.0.0.1:9190" || cfg.EdgeProxy.AdminToken != "edge-runtime-token" {
		t.Fatalf("edgeproxy overrides were not applied: %#v", cfg.EdgeProxy)
	}
	if len(cfg.Server.TrustedProxyCIDRs) != 2 || len(cfg.Admin.Connectivity.DNS.Names) != 2 || len(cfg.Admin.Connectivity.DNS.ExpectedAddresses) != 1 {
		t.Fatalf("list overrides were not applied: %#v", cfg)
	}
}

func TestApplyEnvironmentOverridesRejectsInvalidTLSBoolean(t *testing.T) {
	cfg := Default()
	t.Setenv("SECURITYEDGE_TLS_ENABLED", "sometimes")
	if err := ApplyEnvironmentOverrides(&cfg); err == nil || !strings.Contains(err.Error(), "SECURITYEDGE_TLS_ENABLED") {
		t.Fatalf("expected invalid TLS boolean error, got %v", err)
	}
}

func TestApplyEnvironmentOverridesRejectsInvalidDNSBoolean(t *testing.T) {
	cfg := Default()
	t.Setenv("SECURITYEDGE_DNS_ENABLED", "maybe")
	if err := ApplyEnvironmentOverrides(&cfg); err == nil || !strings.Contains(err.Error(), "SECURITYEDGE_DNS_ENABLED") {
		t.Fatalf("expected invalid DNS boolean error, got %v", err)
	}
}

func TestRejectsOverlappingGatewayAndAdminListeners(t *testing.T) {
	cases := []struct {
		name   string
		server string
		admin  string
	}{
		{name: "identical", server: "127.0.0.1:8081", admin: "127.0.0.1:8081"},
		{name: "IPv4 wildcard", server: "0.0.0.0:8081", admin: "127.0.0.1:8081"},
		{name: "IPv6 wildcard", server: "[::]:8081", admin: "[::1]:8081"},
		{name: "loopback aliases", server: "localhost:8081", admin: "127.0.0.1:8081"},
		{name: "service name", server: "127.0.0.1:http", admin: "127.0.0.1:80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "gateway"
			cfg.Server.ListenAddr = tc.server
			cfg.Admin.ListenAddr = tc.admin
			cfg.Admin.AuthToken = "test-token"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("expected listener overlap to be rejected, got %v", err)
			}
		})
	}
}

func TestAllowsDistinctDynamicAndEmbeddedListeners(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   string
		server string
		admin  string
	}{
		{name: "different ports", mode: "gateway", server: "127.0.0.1:8081", admin: "127.0.0.1:9191"},
		{name: "dynamic gateway", mode: "gateway", server: "127.0.0.1:0", admin: "127.0.0.1:9191"},
		{name: "dynamic admin", mode: "gateway", server: "127.0.0.1:8081", admin: "127.0.0.1:0"},
		{name: "embedded has no gateway listener", mode: "embedded", server: "127.0.0.1:9191", admin: "127.0.0.1:9191"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = tc.mode
			cfg.Server.ListenAddr = tc.server
			cfg.Admin.ListenAddr = tc.admin
			cfg.EdgeProxy.ConfigPath = "edge.json"
			if err := cfg.Validate(); err != nil {
				t.Fatalf("expected listeners to validate: %v", err)
			}
		})
	}
}

func TestTelemetryHistoryValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "capacity too small", mutate: func(cfg *Config) { cfg.Admin.TelemetryHistory.Capacity = 1 }},
		{name: "capacity too large", mutate: func(cfg *Config) { cfg.Admin.TelemetryHistory.Capacity = 10001 }},
		{name: "interval too short", mutate: func(cfg *Config) { cfg.Admin.TelemetryHistory.SampleInterval = Duration{Duration: time.Millisecond} }},
		{name: "interval too long", mutate: func(cfg *Config) { cfg.Admin.TelemetryHistory.SampleInterval = Duration{Duration: 2 * time.Hour} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "admin.telemetry_history") {
				t.Fatalf("expected telemetry history validation error, got %v", err)
			}
		})
	}
}

func TestValidateRejectsResourceExhaustionLimits(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Config)
		wantDetail string
	}{
		{
			name: "global concurrency",
			mutate: func(cfg *Config) {
				cfg.Server.MaxConcurrentRequests = maxServerConcurrentRequests + 1
			},
			wantDetail: "max_concurrent_requests",
		},
		{
			name: "upstream transport connections",
			mutate: func(cfg *Config) {
				cfg.Server.UpstreamTransport.MaxIdleConns = maxUpstreamConnections + 1
			},
			wantDetail: "upstream connection limits",
		},
		{
			name: "persistent log file size",
			mutate: func(cfg *Config) {
				cfg.Admin.LogStore.FilePath = "security.ndjson"
				cfg.Admin.LogStore.MaxFileBytes = maxAdminLogFileBytes + 1
			},
			wantDetail: "admin.log_store.max_file_bytes",
		},
		{
			name: "persistent log backup count",
			mutate: func(cfg *Config) {
				cfg.Admin.LogStore.FilePath = "security.ndjson"
				cfg.Admin.LogStore.MaxBackups = maxAdminLogBackups + 1
			},
			wantDetail: "admin.log_store.max_backups",
		},
		{
			name: "rate limit buckets",
			mutate: func(cfg *Config) {
				cfg.DefaultPolicy.RateLimit.MaxBuckets = maxRateLimitBuckets + 1
			},
			wantDetail: "max_buckets",
		},
		{
			name: "automatic ban clients",
			mutate: func(cfg *Config) {
				cfg.DefaultPolicy.AutoBan.MaxTrackedClients = maxAutoBanTrackedClients + 1
			},
			wantDetail: "max_tracked_clients",
		},
		{
			name: "trusted proxy cidrs",
			mutate: func(cfg *Config) {
				cfg.Server.TrustedProxyCIDRs = make([]string, maxTrustedProxyCIDRs+1)
			},
			wantDetail: "trusted_proxy_cidrs",
		},
		{
			name: "dns probe names",
			mutate: func(cfg *Config) {
				cfg.Admin.Connectivity.DNS.Enabled = true
				cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:53"
				cfg.Admin.Connectivity.DNS.Names = make([]string, maxDNSProbeNames+1)
			},
			wantDetail: "dns.names",
		},
		{
			name: "dns expected addresses",
			mutate: func(cfg *Config) {
				cfg.Admin.Connectivity.DNS.Enabled = true
				cfg.Admin.Connectivity.DNS.Server = "127.0.0.1:53"
				cfg.Admin.Connectivity.DNS.ExpectedAddresses = make([]string, maxDNSExpectedAddresses+1)
			},
			wantDetail: "expected_addresses",
		},
		{
			name: "custom rules",
			mutate: func(cfg *Config) {
				cfg.WAF.CustomRules = make([]CustomRuleConfig, maxCustomRules+1)
			},
			wantDetail: "custom_rules",
		},
		{
			name: "custom rule pattern",
			mutate: func(cfg *Config) {
				cfg.WAF.CustomRules = []CustomRuleConfig{{
					ID: "CUSTOM-LONG", Name: "Long", Category: "custom", Description: "long pattern",
					Score: 1, Targets: []string{"query"}, Pattern: strings.Repeat("a", maxCustomRulePatternBytes+1),
				}}
			},
			wantDetail: "pattern cannot exceed",
		},
		{
			name: "route policies",
			mutate: func(cfg *Config) {
				cfg.RoutePolicies = make(map[string]Policy, maxRoutePolicies+1)
				for i := 0; i <= maxRoutePolicies; i++ {
					cfg.RoutePolicies[string(rune(0x1000+i))] = cfg.DefaultPolicy
				}
			},
			wantDetail: "route_policies",
		},
		{
			name: "policy method list",
			mutate: func(cfg *Config) {
				cfg.DefaultPolicy.AllowedMethods = make([]string, maxPolicyMethods+1)
			},
			wantDetail: "allowed_methods",
		},
		{
			name: "policy ip list",
			mutate: func(cfg *Config) {
				cfg.DefaultPolicy.IPDenylist = make([]string, maxPolicyIPEntries+1)
			},
			wantDetail: "IP allow/deny lists",
		},
		{
			name: "non finite rate",
			mutate: func(cfg *Config) {
				cfg.DefaultPolicy.RateLimit.RequestsPerSecond = math.Inf(1)
			},
			wantDetail: "rates and bursts",
		},
		{
			name: "rate burst",
			mutate: func(cfg *Config) {
				cfg.DefaultPolicy.RateLimit.Burst = maxRateLimitBurst + 1
			},
			wantDetail: "burst tokens",
		},
		{
			name: "automatic ban threshold",
			mutate: func(cfg *Config) {
				cfg.DefaultPolicy.AutoBan.ViolationThreshold = maxAutoBanViolationThreshold + 1
			},
			wantDetail: "violation_threshold",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.wantDetail) {
				t.Fatalf("expected validation error containing %q, got %v", tc.wantDetail, err)
			}
		})
	}
}
