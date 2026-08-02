package securityedge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func TestValidateDoesNotCreatePersistentLogFiles(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.LogStore.FilePath = filepath.Join(dir, "logs", "security.ndjson")
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	if err := Validate(cfgPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.Admin.LogStore.FilePath); !os.IsNotExist(err) {
		t.Fatalf("validation created persistent log file: err=%v", err)
	}
	if _, err := os.Stat(filepath.Dir(cfg.Admin.LogStore.FilePath)); !os.IsNotExist(err) {
		t.Fatalf("validation created persistent log directory: err=%v", err)
	}
}

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

type restartRequiredMarker interface {
	RestartRequired() bool
}

func TestReloadRejectsRestartRequiredChangesWithoutMutatingRuntime(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	originalListen := runtime.Config().Server.ListenAddr

	cfg.Server.ListenAddr = "127.0.0.1:18082"
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	err = runtime.Reload()
	if err == nil {
		t.Fatal("expected restart-required reload failure")
	}
	var marker restartRequiredMarker
	if !errors.As(err, &marker) || !marker.RestartRequired() {
		t.Fatalf("unexpected reload error: %v", err)
	}
	if got := runtime.Config().Server.ListenAddr; got != originalListen {
		t.Fatalf("runtime listener changed after rejected reload: got %q want %q", got, originalListen)
	}
}

func TestReloadAppliesPolicyOnlyChanges(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	cfg.DefaultPolicy.AnomalyThreshold = 11
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := runtime.EffectivePolicy("demo-app").AnomalyThreshold; got != 11 {
		t.Fatalf("reloaded threshold=%d, want 11", got)
	}
}

func TestPolicyUpdateDoesNotPersistWhenReloadPreparationFails(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := os.Remove(edgePath); err != nil {
		t.Fatal(err)
	}
	policy := runtime.EffectivePolicy("demo-app")
	policy.AnomalyThreshold = 17
	if err := runtime.UpdateDefaultPolicy(policy); err == nil {
		t.Fatal("expected update to fail while EdgeProxy route config is unavailable")
	}
	saved, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.DefaultPolicy.AnomalyThreshold == 17 {
		t.Fatal("failed update was persisted to disk")
	}
}

func TestCloneConfigDoesNotShareNestedSlices(t *testing.T) {
	original := config.Default()
	original.Admin.Connectivity.DNS.Names = []string{"project.test"}
	original.Admin.Connectivity.DNS.ExpectedAddresses = []string{"192.0.2.10"}
	original.WAF.CustomRules = []config.CustomRuleConfig{{
		ID: "CUSTOM-001", Name: "custom", Category: "test", Description: "test rule",
		Score: 1, Targets: []string{"query"}, Pattern: "example",
	}}

	cloned := cloneConfig(original)
	cloned.Admin.Connectivity.DNS.Names[0] = "changed.test"
	cloned.Admin.Connectivity.DNS.ExpectedAddresses[0] = "198.51.100.10"
	cloned.WAF.CustomRules[0].Targets[0] = "headers"

	if got := original.Admin.Connectivity.DNS.Names[0]; got != "project.test" {
		t.Fatalf("DNS names share backing storage: %q", got)
	}
	if got := original.Admin.Connectivity.DNS.ExpectedAddresses[0]; got != "192.0.2.10" {
		t.Fatalf("DNS expected addresses share backing storage: %q", got)
	}
	if got := original.WAF.CustomRules[0].Targets[0]; got != "query" {
		t.Fatalf("custom rule targets share backing storage: %q", got)
	}
}

func TestRestartRequiredChangesIncludeProcessWideCapacities(t *testing.T) {
	current := config.Default()

	next := cloneConfig(current)
	next.DefaultPolicy.RateLimit.MaxBuckets++
	fields := restartRequiredChanges(current, next)
	if !containsString(fields, "default_policy.rate_limit.max_buckets") {
		t.Fatalf("missing rate-limit capacity restart field: %#v", fields)
	}

	next = cloneConfig(current)
	next.DefaultPolicy.AutoBan.MaxTrackedClients++
	fields = restartRequiredChanges(current, next)
	if !containsString(fields, "default_policy.auto_ban.max_tracked_clients") {
		t.Fatalf("missing ban capacity restart field: %#v", fields)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestConcurrentPolicyUpdatesAreSerialized(t *testing.T) {
	dir := t.TempDir()
	const routeCount = 24
	routesList := make([]map[string]any, 0, routeCount)
	for i := 0; i < routeCount; i++ {
		routesList = append(routesList, map[string]any{
			"name":        fmt.Sprintf("route-%02d", i),
			"hosts":       []string{fmt.Sprintf("route-%02d.test", i)},
			"path_prefix": "/",
		})
	}
	edgeData, err := json.Marshal(map[string]any{"routes": routesList})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "edge.json"), edgeData, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	start := make(chan struct{})
	errs := make(chan error, routeCount)
	var wg sync.WaitGroup
	for i := 0; i < routeCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			route := fmt.Sprintf("route-%02d", i)
			policy := runtime.EffectivePolicy(route)
			policy.AnomalyThreshold = i + 1
			errs <- runtime.UpdateRoutePolicy(route, policy)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent policy update failed: %v", err)
		}
	}

	saved, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(saved.RoutePolicies); got != routeCount {
		t.Fatalf("persisted route policies=%d, want %d", got, routeCount)
	}
	if got := len(runtime.Config().RoutePolicies); got != routeCount {
		t.Fatalf("runtime route policies=%d, want %d", got, routeCount)
	}
	for i := 0; i < routeCount; i++ {
		route := fmt.Sprintf("route-%02d", i)
		want := i + 1
		if got := saved.RoutePolicies[route].AnomalyThreshold; got != want {
			t.Fatalf("persisted %s threshold=%d, want %d", route, got, want)
		}
		if got := runtime.EffectivePolicy(route).AnomalyThreshold; got != want {
			t.Fatalf("runtime %s threshold=%d, want %d", route, got, want)
		}
	}
}
