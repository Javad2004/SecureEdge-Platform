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
	"sync"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

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
	candidate.Server.ListenAddr = "127.0.0.1:18082"
	err = runtime.ReplaceConfig(candidate)
	var marker restartRequiredMarker
	if !errors.As(err, &marker) || !marker.RestartRequired() {
		t.Fatalf("expected restart-required marker, got %v", err)
	}
	saved, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server.ListenAddr != "127.0.0.1:18082" {
		t.Fatalf("restart revision was not persisted: %q", saved.Server.ListenAddr)
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
