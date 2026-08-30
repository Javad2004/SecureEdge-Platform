package securityedge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func availableListenerAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestCheckedInConfigurationsValidate(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate SecurityEdge test source")
	}
	moduleRoot := filepath.Dir(sourceFile)
	paths := []string{
		filepath.Join(moduleRoot, "configs", "compose.json"),
		filepath.Join(moduleRoot, "configs", "embedded.json"),
		filepath.Join(moduleRoot, "configs", "local-dev.json"),
		filepath.Join(moduleRoot, "configs", "securityedge.json"),
	}
	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "")
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "")
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			if err := Validate(path); err != nil {
				t.Fatalf("validate %s: %v", path, err)
			}
		})
	}
}

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

func TestPolicyWriteDoesNotPersistEnvironmentOverridesOrAbsoluteRoutePath(t *testing.T) {
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
	t.Setenv("SECURITYEDGE_ADMIN_LISTEN_ADDR", "127.0.0.1:19191")
	t.Setenv("SECURITYEDGE_EDGEPROXY_ADMIN_URL", "http://127.0.0.1:19091")
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
	if raw.Admin.ListenAddr != cfg.Admin.ListenAddr || raw.EdgeProxy.AdminURL != cfg.EdgeProxy.AdminURL {
		t.Fatalf("environment endpoint was persisted: admin=%q edge=%q", raw.Admin.ListenAddr, raw.EdgeProxy.AdminURL)
	}
	if raw.EdgeProxy.ConfigPath != "edge.json" {
		t.Fatalf("relative edgeproxy path changed: %q", raw.EdgeProxy.ConfigPath)
	}
	if raw.DefaultPolicy.AnomalyThreshold != 9 {
		t.Fatalf("policy update not persisted")
	}
}

func TestUpdateDefaultPolicyProcessWideSettingsPropagateAndPersistForRestart(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	override := cfg.DefaultPolicy
	override.AnomalyThreshold = 17
	cfg.RoutePolicies = map[string]config.Policy{"demo-app": override}
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()

	policy := runtime.EffectivePolicy("")
	policy.RateLimit.CleanupInterval = config.Duration{Duration: 2 * time.Minute}
	policy.RateLimit.IdleTTL = config.Duration{Duration: 20 * time.Minute}
	policy.RateLimit.MaxBuckets = 200000
	policy.AutoBan.MaxTrackedClients = 200000
	err = runtime.UpdateDefaultPolicy(policy)
	if err == nil {
		t.Fatal("process-wide policy edit unexpectedly hot-applied without a restart")
	}
	var restart interface{ RestartRequired() bool }
	if !errors.As(err, &restart) || !restart.RestartRequired() {
		t.Fatalf("error=%v, want restart-required error", err)
	}

	saved, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.DefaultPolicy.RateLimit.CleanupInterval != policy.RateLimit.CleanupInterval ||
		saved.DefaultPolicy.RateLimit.IdleTTL != policy.RateLimit.IdleTTL ||
		saved.DefaultPolicy.RateLimit.MaxBuckets != policy.RateLimit.MaxBuckets ||
		saved.DefaultPolicy.AutoBan.MaxTrackedClients != policy.AutoBan.MaxTrackedClients {
		t.Fatalf("default process-wide settings were not persisted: %#v", saved.DefaultPolicy)
	}
	routePolicy := saved.RoutePolicies["demo-app"]
	if routePolicy.AnomalyThreshold != 17 {
		t.Fatalf("route-specific policy value changed during inheritance propagation: %d", routePolicy.AnomalyThreshold)
	}
	if routePolicy.RateLimit.CleanupInterval != policy.RateLimit.CleanupInterval ||
		routePolicy.RateLimit.IdleTTL != policy.RateLimit.IdleTTL ||
		routePolicy.RateLimit.MaxBuckets != policy.RateLimit.MaxBuckets ||
		routePolicy.AutoBan.MaxTrackedClients != policy.AutoBan.MaxTrackedClients {
		t.Fatalf("route policy did not inherit persisted process-wide settings: %#v", routePolicy)
	}
	watch := runtime.WatchStatusMap()
	if scheduled, _ := watch["restart_scheduled"].(bool); !scheduled {
		t.Fatalf("restart was not marked scheduled: %#v", watch)
	}
	if live := runtime.Config(); live.DefaultPolicy.RateLimit.MaxBuckets == policy.RateLimit.MaxBuckets {
		t.Fatal("restart-required policy settings changed the live generation before restart")
	}
}

func TestReloadSkipsAlreadyAppliedControlPlaneRevision(t *testing.T) {
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
	policy := runtime.EffectivePolicy("demo-app")
	policy.AnomalyThreshold++
	if err := runtime.UpdateDefaultPolicy(policy); err != nil {
		t.Fatal(err)
	}
	runtime.mu.RLock()
	appliedEdgeClient := runtime.edge
	runtime.mu.RUnlock()

	// The file supervisor observes the API's atomic Save after the API has
	// already applied the same revision. Reload must acknowledge that file state
	// without replacing live components again.
	if err := runtime.Reload(); err != nil {
		t.Fatal(err)
	}
	runtime.mu.RLock()
	currentEdgeClient := runtime.edge
	runtime.mu.RUnlock()
	if currentEdgeClient != appliedEdgeClient {
		t.Fatal("reload reapplied an already-hot-applied Control Plane revision")
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

	cfg.Server.ListenAddr = availableListenerAddress(t)
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

func TestNewRejectsPersistentAdminPathsThatOverlapManagedFiles(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*config.Config, string)
	}{
		{name: "security log overlaps security config", mutate: func(cfg *config.Config, cfgPath string) { cfg.Admin.LogStore.FilePath = cfgPath }},
		{name: "telemetry history overlaps security config", mutate: func(cfg *config.Config, cfgPath string) {
			cfg.Admin.TelemetryHistory.Enabled = true
			cfg.Admin.TelemetryHistory.FilePath = cfgPath
		}},
		{name: "security log overlaps EdgeProxy config", mutate: func(cfg *config.Config, _ string) { cfg.Admin.LogStore.FilePath = edgePath }},
		{name: "telemetry history overlaps EdgeProxy config", mutate: func(cfg *config.Config, _ string) {
			cfg.Admin.TelemetryHistory.Enabled = true
			cfg.Admin.TelemetryHistory.FilePath = edgePath
		}},
		{name: "security log overlaps SecurityEdge retained-backup namespace", mutate: func(cfg *config.Config, cfgPath string) {
			cfg.Admin.LogStore.FilePath = cfgPath + ".bak-operator"
		}},
		{name: "telemetry history overlaps EdgeProxy retained-backup namespace", mutate: func(cfg *config.Config, _ string) {
			cfg.Admin.TelemetryHistory.Enabled = true
			cfg.Admin.TelemetryHistory.FilePath = edgePath + ".bak-operator"
		}},
		{name: "log and telemetry history overlap", mutate: func(cfg *config.Config, _ string) {
			path := filepath.Join(dir, "shared.data")
			cfg.Admin.LogStore.FilePath = path
			cfg.Admin.TelemetryHistory.Enabled = true
			cfg.Admin.TelemetryHistory.FilePath = path
		}},
		{name: "log rotation overlaps telemetry history", mutate: func(cfg *config.Config, _ string) {
			path := filepath.Join(dir, "events.ndjson")
			cfg.Admin.LogStore.FilePath = path
			cfg.Admin.LogStore.MaxBackups = 2
			cfg.Admin.TelemetryHistory.Enabled = true
			cfg.Admin.TelemetryHistory.FilePath = path + ".1"
		}},
		{name: "log overlaps telemetry recovery file", mutate: func(cfg *config.Config, _ string) {
			path := filepath.Join(dir, "history.json")
			cfg.Admin.LogStore.FilePath = path + ".bak"
			cfg.Admin.TelemetryHistory.Enabled = true
			cfg.Admin.TelemetryHistory.FilePath = path
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Server.Mode = "embedded"
			cfg.EdgeProxy.ConfigPath = "edge.json"
			cfgPath := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".json")
			tc.mutate(&cfg, cfgPath)
			if err := config.Save(cfgPath, cfg); err != nil {
				t.Fatal(err)
			}
			runtime, err := New(cfgPath, nil)
			if runtime != nil {
				runtime.Close()
			}
			if err == nil {
				t.Fatal("unsafe managed-file overlap was accepted")
			}
		})
	}
}

func TestPersistentAdminPathIsolationDetectsAliases(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "managed-alias.json")
	if err := os.Link(target, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.LogStore.FilePath = alias
	if err := validatePersistentPathIsolation(target, cfg); err == nil {
		t.Fatal("hard-link alias of the SecurityEdge config was accepted as a log path")
	}
}

func TestPersistentAdminPathIsolationDetectsRetainedBackupAliases(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "security.json")
	backupPath := configPath + ".bak-20260830T000000.000000000Z"
	if err := os.WriteFile(backupPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "backup-hardlink-alias.json")
	if err := os.Link(backupPath, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = filepath.Join(dir, "edge.json")
	cfg.Admin.LogStore.FilePath = alias
	if err := validatePersistentPathIsolation(configPath, cfg); err == nil {
		t.Fatal("hard-link alias of a retained SecurityEdge config backup was accepted as a log path")
	}
}

func TestPersistentAdminPathIsolationResolvesSymlinkedParentForNewFiles(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(dir, "alias")
	if err := os.Symlink(realDir, aliasDir); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = filepath.Join(dir, "edge.json")
	cfg.Admin.LogStore.FilePath = filepath.Join(realDir, "shared.data")
	cfg.Admin.TelemetryHistory.Enabled = true
	cfg.Admin.TelemetryHistory.FilePath = filepath.Join(aliasDir, "shared.data")
	if err := validatePersistentPathIsolation(filepath.Join(dir, "security.json"), cfg); err == nil {
		t.Fatal("not-yet-created persistence files through a symlinked parent were accepted as distinct")
	}
}

func TestPersistentAdminPathIsolationProtectsTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = filepath.Join(dir, "fullchain.pem")
	cfg.Server.TLS.KeyFile = filepath.Join(dir, "privkey.pem")
	cfg.EdgeProxy.ConfigPath = filepath.Join(dir, "edge.json")
	cfg.Admin.LogStore.FilePath = cfg.Server.TLS.CertFile
	if err := validatePersistentPathIsolation(filepath.Join(dir, "security.json"), cfg); err == nil {
		t.Fatal("security log path overlapping the TLS certificate was accepted")
	}

	cfg.Admin.LogStore.FilePath = filepath.Join(dir, "events.ndjson")
	cfg.Admin.TelemetryHistory.Enabled = true
	cfg.Admin.TelemetryHistory.FilePath = cfg.Server.TLS.KeyFile
	if err := validatePersistentPathIsolation(filepath.Join(dir, "security.json"), cfg); err == nil {
		t.Fatal("telemetry history path overlapping the TLS private key was accepted")
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

	next = cloneConfig(current)
	next.Server.ForwardedForHeader = "X-Trusted-Client-IP"
	fields = restartRequiredChanges(current, next)
	if !containsString(fields, "server.forwarded_for_header") {
		t.Fatalf("missing forwarded-header restart field: %#v", fields)
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

func TestReloadAndCloseReleaseEdgeAdminIdleConnections(t *testing.T) {
	newServer := func() (*httptest.Server, <-chan http.ConnState) {
		states := make(chan http.ConnState, 32)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			select {
			case states <- state:
			default:
			}
		}
		server.Start()
		return server, states
	}
	waitForState := func(t *testing.T, states <-chan http.ConnState, want http.ConnState) {
		t.Helper()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			select {
			case state := <-states:
				if state == want {
					return
				}
			case <-timer.C:
				t.Fatalf("timed out waiting for connection state %v", want)
			}
		}
	}

	first, firstStates := newServer()
	defer first.Close()
	second, secondStates := newServer()
	defer second.Close()

	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.EdgeProxy.AdminURL = first.URL
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			runtime.Close()
		}
	}()

	if _, status, err := runtime.EdgeJSON(context.Background(), http.MethodGet, "/healthz", nil, nil); err != nil || status != http.StatusOK {
		t.Fatalf("first EdgeJSON status=%d err=%v", status, err)
	}
	waitForState(t, firstStates, http.StateIdle)

	cfg.EdgeProxy.AdminURL = second.URL
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Reload(); err != nil {
		t.Fatal(err)
	}
	waitForState(t, firstStates, http.StateClosed)

	if _, status, err := runtime.EdgeJSON(context.Background(), http.MethodGet, "/healthz", nil, nil); err != nil || status != http.StatusOK {
		t.Fatalf("second EdgeJSON status=%d err=%v", status, err)
	}
	waitForState(t, secondStates, http.StateIdle)
	runtime.Close()
	closed = true
	waitForState(t, secondStates, http.StateClosed)
}

func TestReloadEdgeRoutesHotSwapsOnlySharedRouteTable(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"first","hosts":["first.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
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
	original := runtime.Config()

	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"second","hosts":["second.test"],"path_prefix":"/api"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.ReloadEdgeRoutes(); err != nil {
		t.Fatal(err)
	}
	routes := runtime.Routes()
	if len(routes) != 1 || routes[0].Name != "second" {
		t.Fatalf("route table was not hot-swapped: %#v", routes)
	}
	current := runtime.Config()
	if current.Server.ListenAddr != original.Server.ListenAddr || current.Admin.ListenAddr != original.Admin.ListenAddr {
		t.Fatalf("shared route reload changed SecurityEdge process configuration: before=%#v after=%#v", original.Server, current.Server)
	}
}

func TestRestartPreflightRevalidatesUnchangedPersistentResources(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedDirectory := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blockedDirectory, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.Admin.LogStore.FilePath = filepath.Join(blockedDirectory, "security.ndjson")
	cfg.Admin.TelemetryHistory.FilePath = filepath.Join(blockedDirectory, "telemetry.json")
	next := cfg
	next.Server.ListenAddr = availableListenerAddress(t)

	err := (&Runtime{}).validateRestartCandidate(filepath.Join(dir, "security.json"), cfg, next)
	if err == nil {
		t.Fatal("expected unchanged persistent resources to be revalidated before restart")
	}
	message := err.Error()
	if !strings.Contains(message, "admin.log_store") {
		t.Fatalf("log-store failure missing from preflight error: %v", err)
	}
	if !strings.Contains(message, "admin.telemetry_history.file_path") {
		t.Fatalf("telemetry-history failure missing from preflight error: %v", err)
	}
}

func TestReplaceConfigRejectsOccupiedRestartListenerWithoutPersisting(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

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

	candidate := runtime.RedactedConfig()
	candidate.Server.Mode = "gateway"
	candidate.Server.ListenAddr = occupied.Addr().String()
	if err := runtime.ReplaceConfig(candidate); err == nil {
		t.Fatal("expected occupied gateway listener to be rejected")
	} else {
		var marker restartRequiredMarker
		if errors.As(err, &marker) {
			t.Fatalf("unusable revision was accepted as restart-required: %v", err)
		}
	}

	saved, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server.Mode != "embedded" || saved.Server.ListenAddr != cfg.Server.ListenAddr {
		t.Fatalf("rejected listener revision was persisted: %#v", saved.Server)
	}
	if got := runtime.Config().Server.Mode; got != "embedded" {
		t.Fatalf("live runtime changed after rejected revision: %q", got)
	}
	if runtime.WatchStatus().RestartScheduled {
		t.Fatal("rejected revision was exposed as a scheduled restart")
	}
}

func TestValidateRestartConfigRejectsMissingRuntimeDependency(t *testing.T) {
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

	candidate := cfg
	candidate.Server.Mode = "gateway"
	candidate.EdgeProxy.ConfigPath = "missing-edge.json"
	candidatePath := filepath.Join(dir, "candidate.json")
	if err := config.Save(candidatePath, candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.ValidateRestartConfig(candidatePath); err == nil {
		t.Fatal("expected missing EdgeProxy route table to fail restart preflight")
	}
}

func TestReplaceConfigPersistsValidatedRestartRevision(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.Admin.AuthToken = "security-secret"
	cfg.EdgeProxy.AdminToken = "edge-secret"
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

	candidate := runtime.RedactedConfig()
	restartAddress := availableListenerAddress(t)
	candidate.Server.ListenAddr = restartAddress
	err = runtime.ReplaceConfig(candidate)
	var marker restartRequiredMarker
	if !errors.As(err, &marker) || !marker.RestartRequired() {
		t.Fatalf("expected restart-required marker, got %v", err)
	}
	saved, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server.ListenAddr != restartAddress {
		t.Fatalf("restart revision was not persisted: got %q want %q", saved.Server.ListenAddr, restartAddress)
	}
	if saved.Admin.AuthToken != "security-secret" || saved.EdgeProxy.AdminToken != "edge-secret" {
		t.Fatalf("redacted markers replaced persisted secrets: admin=%q edge=%q", saved.Admin.AuthToken, saved.EdgeProxy.AdminToken)
	}
	if runtime.Config().Server.ListenAddr == saved.Server.ListenAddr {
		t.Fatal("live listener configuration changed before the generation restart")
	}
	watch := runtime.WatchStatus()
	if !watch.RestartScheduled || watch.LastChangedFile != cfgPath {
		t.Fatalf("accepted restart was not exposed immediately: %#v", watch)
	}
}

func TestRestartFallbackPreservesLatestSuccessfulHotReload(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.Admin.AuthToken = "security-secret"
	cfg.EdgeProxy.AdminToken = "edge-secret"
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

	hot := runtime.RedactedConfig()
	hot.WAF.MaximumMatchesPerRequest = 48
	if err := runtime.ReplaceConfig(hot); err != nil {
		t.Fatalf("hot update failed: %v", err)
	}

	restartCandidate := runtime.RedactedConfig()
	restartCandidate.Server.ListenAddr = availableListenerAddress(t)
	err = runtime.ReplaceConfig(restartCandidate)
	var marker restartRequiredMarker
	if !errors.As(err, &marker) || !marker.RestartRequired() {
		t.Fatalf("expected restart-required marker, got %v", err)
	}

	path, fallback := runtime.RestartFallback()
	if path != cfgPath {
		t.Fatalf("fallback path=%q, want %q", path, cfgPath)
	}
	if fallback.WAF.MaximumMatchesPerRequest != 48 {
		t.Fatalf("fallback lost hot-applied WAF revision: %#v", fallback.WAF)
	}
	if fallback.Server.ListenAddr != cfg.Server.ListenAddr {
		t.Fatalf("fallback captured unstarted listener %q, want %q", fallback.Server.ListenAddr, cfg.Server.ListenAddr)
	}
	if fallback.Admin.AuthToken != "security-secret" || fallback.EdgeProxy.AdminToken != "edge-secret" {
		t.Fatalf("fallback did not preserve file-backed secrets: admin=%q edge=%q", fallback.Admin.AuthToken, fallback.EdgeProxy.AdminToken)
	}
}

func TestWatcherStatusSurvivesManagedGenerationRestart(t *testing.T) {
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
	first, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.ConfigureWatcher("")
	first.RecordWatchChange(cfgPath, false, true, nil)
	before := first.WatchStatus()
	first.Close()

	second, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.ConfigureWatcher("", before)
	after := second.WatchStatus()
	if after.Revision != before.Revision || after.AppliedRevision != before.Revision {
		t.Fatalf("revision history was not preserved: before=%#v after=%#v", before, after)
	}
	if after.RestartScheduled {
		t.Fatalf("completed generation still reports restart scheduled: %#v", after)
	}
}

func TestRoutePolicyOperationsAreCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"Demo-App","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	policy := cfg.DefaultPolicy
	policy.AnomalyThreshold = 77
	cfg.RoutePolicies = map[string]config.Policy{"demo-app": policy}
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if got := runtime.EffectivePolicy("DEMO-APP").AnomalyThreshold; got != 77 {
		t.Fatalf("case-insensitive effective policy threshold=%d, want 77", got)
	}
	updated := policy
	updated.AnomalyThreshold = 88
	if err := runtime.UpdateRoutePolicy("DEMO-app", updated); err != nil {
		t.Fatal(err)
	}
	saved, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := saved.RoutePolicies["Demo-App"]; !exists {
		t.Fatalf("policy was not canonicalized to the EdgeProxy route name: %#v", saved.RoutePolicies)
	}
	if _, exists := saved.RoutePolicies["demo-app"]; exists {
		t.Fatalf("legacy case-variant policy key was retained: %#v", saved.RoutePolicies)
	}
	if err := runtime.DeleteRoutePolicy("demo-APP"); err != nil {
		t.Fatal(err)
	}
	if got := len(runtime.Config().RoutePolicies); got != 0 {
		t.Fatalf("case-insensitive delete left %d policy entries", got)
	}
}

func TestReplaceConfigRejectsEnvironmentManagedSecretWithoutPersisting(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.Admin.AuthToken = "file-security-token"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.EdgeProxy.AdminToken = "file-edge-token"
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SECURITYEDGE_ADMIN_TOKEN", "runtime-security-token")
	appRuntime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer appRuntime.Close()
	candidate := appRuntime.RedactedConfig()
	candidate.Admin.AuthToken = "persisted-rotation"
	if err := appRuntime.ReplaceConfig(candidate); err == nil || !strings.Contains(err.Error(), "SECURITYEDGE_ADMIN_TOKEN") {
		t.Fatalf("expected environment-managed token update rejection, got %v", err)
	}
	persisted, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Admin.AuthToken != cfg.Admin.AuthToken {
		t.Fatalf("rejected managed token update was persisted: got %q", persisted.Admin.AuthToken)
	}
}

func TestManagedAdminTelemetryStartsOnlyAfterActivation(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	edgeStartedAt := "2026-08-17T00:00:00Z"
	edgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"schema_version":"1.5","started_at":%q,"inflight":0,"total":{"requests":0,"client_errors":0,"server_errors":0,"proxy_errors":0,"cache_hits":0,"cache_misses":0,"cache_hit_ratio":0,"response_latency_ms":{"count":0,"p95":0}},"routes":{}}`, edgeStartedAt)
	}))
	defer edgeServer.Close()

	historyPath := filepath.Join(dir, "telemetry-history.json")
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.EdgeProxy.AdminURL = edgeServer.URL
	cfg.EdgeProxy.Timeout = config.Duration{Duration: 100 * time.Millisecond}
	cfg.Admin.Connectivity.Enabled = false
	cfg.Admin.TelemetryHistory.FilePath = historyPath
	cfg.Admin.TelemetryHistory.SampleInterval = config.Duration{Duration: time.Second}
	cfg.Admin.PollTimeout = config.Duration{Duration: 100 * time.Millisecond}
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if _, err := runtime.AdminServer(); err != nil {
		t.Fatal(err)
	}

	// Constructing the managed Admin server is still pre-activation. No
	// telemetry file should exist until the generation has acquired listeners
	// and explicitly starts its background workers.
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(historyPath); !os.IsNotExist(err) {
		t.Fatalf("managed AdminServer started telemetry before activation: stat err=%v", err)
	}

	runtime.StartAdminBackgroundWorkers()
	deadline := time.Now().Add(time.Second)
	for {
		data, readErr := os.ReadFile(historyPath)
		if readErr == nil && len(data) > 0 {
			break
		}
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("activated Admin background workers did not persist an initial telemetry sample")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Activation is idempotent; a duplicate call must not create another
	// sampler or otherwise perturb lifecycle state.
	runtime.StartAdminBackgroundWorkers()
}

func TestEmbeddedAdminHandlerActivatesTelemetrySampler(t *testing.T) {
	dir := t.TempDir()
	edgePath := filepath.Join(dir, "edge.json")
	if err := os.WriteFile(edgePath, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	edgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"1.5","started_at":"2026-08-17T00:00:00Z","inflight":0,"total":{"requests":0,"client_errors":0,"server_errors":0,"proxy_errors":0,"cache_hits":0,"cache_misses":0,"cache_hit_ratio":0,"response_latency_ms":{"count":0,"p95":0}},"routes":{}}`))
	}))
	defer edgeServer.Close()

	historyPath := filepath.Join(dir, "telemetry-history.json")
	cfg := config.Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	cfg.EdgeProxy.AdminURL = edgeServer.URL
	cfg.EdgeProxy.Timeout = config.Duration{Duration: 100 * time.Millisecond}
	cfg.Admin.Connectivity.Enabled = false
	cfg.Admin.TelemetryHistory.FilePath = historyPath
	cfg.Admin.TelemetryHistory.SampleInterval = config.Duration{Duration: time.Second}
	cfg.Admin.PollTimeout = config.Duration{Duration: 100 * time.Millisecond}
	cfgPath := filepath.Join(dir, "security.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	runtime, err := New(cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if _, err := runtime.AdminHandler(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		if data, readErr := os.ReadFile(historyPath); readErr == nil && len(data) > 0 {
			break
		} else if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("embedded AdminHandler did not activate telemetry sampling")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
