package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
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
	want := []string{"/healthz", "/readyz/"}
	if len(cfg.DefaultPolicy.ExcludedPathPrefixes) != len(want) {
		t.Fatalf("unexpected normalized prefixes: %#v", cfg.DefaultPolicy.ExcludedPathPrefixes)
	}
	for i := range want {
		if cfg.DefaultPolicy.ExcludedPathPrefixes[i] != want[i] {
			t.Fatalf("unexpected normalized prefixes: %#v", cfg.DefaultPolicy.ExcludedPathPrefixes)
		}
	}

	for _, invalid := range []string{"healthz", "/healthz?full=1", "/healthz#fragment"} {
		cfg := Default()
		cfg.Server.Mode = "embedded"
		cfg.EdgeProxy.ConfigPath = "edge.json"
		cfg.DefaultPolicy.ExcludedPathPrefixes = []string{invalid}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected validation error for %q", invalid)
		}
	}
}
