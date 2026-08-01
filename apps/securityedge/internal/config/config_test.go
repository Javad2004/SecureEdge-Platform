package config

import (
	"encoding/json"
	"os"
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

func TestRoutePoliciesShareProcessWideLimiterLifecycle(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	policy := cfg.DefaultPolicy
	policy.RateLimit.IdleTTL.Duration += time.Minute
	cfg.RoutePolicies["demo-app"] = policy
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected route-specific limiter lifecycle to be rejected")
	}
}

func TestApplyEnvironmentOverridesDoesNotRequireFileMutation(t *testing.T) {
	cfg := Default()
	cfg.Admin.AuthToken = "file-admin"
	cfg.EdgeProxy.AdminToken = "file-edge"
	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "runtime-admin")
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "runtime-edge")
	ApplyEnvironmentOverrides(&cfg)
	if cfg.Admin.AuthToken != "runtime-admin" || cfg.EdgeProxy.AdminToken != "runtime-edge" {
		t.Fatalf("environment overrides were not applied: admin=%q edge=%q", cfg.Admin.AuthToken, cfg.EdgeProxy.AdminToken)
	}
}
