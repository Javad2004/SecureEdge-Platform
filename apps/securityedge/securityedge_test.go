package securityedge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func TestPolicyWriteDoesNotPersistEnvironmentSecretsOrAbsoluteRoutePath(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.Admin.AuthToken = "file-security-token"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.EdgeProxy.AdminURL = "http://127.0.0.1:19090"
	cfg.EdgeProxy.AdminToken = "file-edge-token"
	cfgPath := filepath.Join(dir, "security.json")
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "environment-security-secret")
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "environment-edge-secret")
	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	p := runtime.EffectivePolicy("demo-app")
	p.AnomalyThreshold = 9
	if err := runtime.UpdateDefaultPolicy(p); err != nil {
		t.Fatal(err)
	}

	saved, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw config.Config
	if err := json.Unmarshal(saved, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Admin.AuthToken != "file-security-token" || raw.EdgeProxy.AdminToken != "file-edge-token" {
		t.Fatalf("environment secret was persisted: admin=%q edge=%q", raw.Admin.AuthToken, raw.EdgeProxy.AdminToken)
	}
	if raw.EdgeProxy.ConfigPath != "edge.json" {
		t.Fatalf("relative edgeproxy path changed: %q", raw.EdgeProxy.ConfigPath)
	}
	if raw.DefaultPolicy.AnomalyThreshold != 9 {
		t.Fatalf("policy update not persisted")
	}
}

func TestNewRejectsUnknownRoutePolicy(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.RoutePolicies["missing-route"] = cfg.DefaultPolicy
	cfgPath := filepath.Join(dir, "security.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfgPath, nil); err == nil {
		t.Fatal("expected unknown route policy to be rejected")
	}
}
