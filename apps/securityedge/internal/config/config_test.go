package config

import "testing"

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
