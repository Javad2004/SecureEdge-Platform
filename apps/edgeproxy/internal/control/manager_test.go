package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
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

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Server.ListenAddr = "127.0.0.1:18080"
	cfg.Admin.ListenAddr = "127.0.0.1:19090"
	cfg.Admin.AuthToken = "secret-token"
	cfg.Routes = []config.RouteConfig{{
		Name: "demo", Hosts: []string{"project.test"}, PathPrefix: "/",
		Upstreams: []config.UpstreamConfig{{URL: "http://127.0.0.1:19000"}},
		Proxy: config.ProxyConfig{
			RequestTimeout: config.Duration{Duration: 5 * time.Second}, DialTimeout: config.Duration{Duration: time.Second},
			ResponseHeaderTimeout: config.Duration{Duration: 2 * time.Second}, IdleConnTimeout: config.Duration{Duration: time.Minute},
			RetryBackoff: config.Duration{Duration: 10 * time.Millisecond}, MaxIdleConns: 8, MaxIdleConnsPerHost: 4,
			MaxResponseHeaderBytes: 1 << 20,
		},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestManagerHotApplyAndRestartScheduling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)

	result, err := manager.Update(func(next *config.Config) error {
		next.Routes[0].LoadBalancing.Algorithm = "least_connections"
		return nil
	}, "test_hot_apply")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || result.RestartRequired {
		t.Fatalf("unexpected hot-apply result: %#v", result)
	}
	if got := manager.Config().Routes[0].LoadBalancing.Algorithm; got != "least_connections" {
		t.Fatalf("persisted algorithm=%q", got)
	}

	restartAddress := availableListenerAddress(t)
	result, err = manager.Update(func(next *config.Config) error {
		next.Server.ListenAddr = restartAddress
		return nil
	}, "test_restart")
	if err != nil {
		t.Fatal(err)
	}
	if !result.RestartRequired || result.Applied {
		t.Fatalf("unexpected restart result: %#v", result)
	}
	select {
	case next := <-manager.RestartRequests():
		if next.Server.ListenAddr != restartAddress {
			t.Fatalf("restart config listen=%q, want %q", next.Server.ListenAddr, restartAddress)
		}
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
	status := manager.WatchStatus()
	if !status.RestartScheduled || status.Revision <= status.AppliedRevision {
		t.Fatalf("unexpected watcher status: %#v", status)
	}
}

func TestManagerRejectsOccupiedRestartListenerAndRollsBack(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)

	if _, err := manager.Update(func(next *config.Config) error {
		next.Server.ListenAddr = occupied.Addr().String()
		return nil
	}, "occupied_listener_test"); err == nil {
		t.Fatal("expected occupied listener revision to be rejected")
	}

	saved, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server.ListenAddr != cfg.Server.ListenAddr {
		t.Fatalf("rejected listener was persisted: got %q want %q", saved.Server.ListenAddr, cfg.Server.ListenAddr)
	}
	select {
	case restart := <-manager.RestartRequests():
		t.Fatalf("rejected revision scheduled a restart: %#v", restart.Server)
	default:
	}
	status := manager.WatchStatus()
	if status.RestartScheduled {
		t.Fatalf("rejected revision remained scheduled: %#v", status)
	}
	if status.LastError == "" {
		t.Fatalf("preflight failure was not exposed: %#v", status)
	}
}

func TestRestartPreflightRevalidatesUnchangedTLSMaterial(t *testing.T) {
	cfg := testConfig(t)
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = filepath.Join(t.TempDir(), "missing-cert.pem")
	cfg.Server.TLS.KeyFile = filepath.Join(t.TempDir(), "missing-key.pem")
	next := cfg
	next.Server.ListenAddr = availableListenerAddress(t)
	if err := validateRestartCandidate(cfg, next); err == nil {
		t.Fatal("expected every TLS-enabled restart to revalidate certificate material")
	}
}

func TestManagerRejectsUnreadableRestartTLSMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)

	if _, err := manager.Update(func(next *config.Config) error {
		next.Server.TLS.Enabled = true
		next.Server.TLS.CertFile = filepath.Join(t.TempDir(), "missing-cert.pem")
		next.Server.TLS.KeyFile = filepath.Join(t.TempDir(), "missing-key.pem")
		return nil
	}, "invalid_tls_test"); err == nil {
		t.Fatal("expected unreadable TLS material to be rejected")
	}
	saved, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server.TLS.Enabled {
		t.Fatal("rejected TLS revision was persisted")
	}
}

func TestManagerRecoversLastHealthyConfigurationAfterLateRestartFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)

	candidateAddress := availableListenerAddress(t)
	if _, err := manager.Update(func(next *config.Config) error {
		next.Server.ListenAddr = candidateAddress
		return nil
	}, "late_failure_test"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.RestartRequests():
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}

	recovered, err := manager.RecoverFailedRestart(errors.New("late bind failure"))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Server.ListenAddr != cfg.Server.ListenAddr {
		t.Fatalf("recovered runtime listen=%q, want %q", recovered.Server.ListenAddr, cfg.Server.ListenAddr)
	}
	saved, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server.ListenAddr != cfg.Server.ListenAddr {
		t.Fatalf("last healthy configuration was not restored: got %q want %q", saved.Server.ListenAddr, cfg.Server.ListenAddr)
	}
	status := manager.WatchStatus()
	if status.RestartScheduled || status.LastSource != "restart_rollback" || status.LastError == "" {
		t.Fatalf("unexpected rollback status: %#v", status)
	}
}

func TestManagerRollbackPreservesLatestSuccessfulHotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)

	if result, err := manager.Update(func(next *config.Config) error {
		next.Routes[0].LoadBalancing.Algorithm = "weighted_round_robin"
		return nil
	}, "hot_reload_before_restart"); err != nil {
		t.Fatal(err)
	} else if !result.Applied || result.RestartRequired {
		t.Fatalf("unexpected hot-reload result: %#v", result)
	}

	if _, err := manager.Update(func(next *config.Config) error {
		next.Server.ListenAddr = availableListenerAddress(t)
		return nil
	}, "late_failure_after_hot_reload"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-manager.RestartRequests():
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}

	recovered, err := manager.RecoverFailedRestart(errors.New("late bind failure"))
	if err != nil {
		t.Fatal(err)
	}
	if got := recovered.Routes[0].LoadBalancing.Algorithm; got != "weighted_round_robin" {
		t.Fatalf("recovered runtime lost hot reload: algorithm=%q", got)
	}
	if recovered.Server.ListenAddr != cfg.Server.ListenAddr {
		t.Fatalf("recovered listener=%q, want %q", recovered.Server.ListenAddr, cfg.Server.ListenAddr)
	}
	saved, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := saved.Routes[0].LoadBalancing.Algorithm; got != "weighted_round_robin" {
		t.Fatalf("persisted rollback lost hot reload: algorithm=%q", got)
	}
	if saved.Server.ListenAddr != cfg.Server.ListenAddr {
		t.Fatalf("persisted rollback listener=%q, want %q", saved.Server.ListenAddr, cfg.Server.ListenAddr)
	}
}

func TestManagerPreservesRedactedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	manager, err := New(path, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Config()
	if candidate.Admin.AuthToken != "[REDACTED]" {
		t.Fatalf("secret was not redacted: %q", candidate.Admin.AuthToken)
	}
	candidate.Routes[0].LoadBalancing.Algorithm = "weighted_round_robin"
	// No handler is attached, so this deliberately becomes a failed hot apply;
	// the write must roll back without replacing the real token with the marker.
	if _, err := manager.Replace(candidate, "test_redaction"); err == nil {
		t.Fatal("expected unattached runtime error")
	}
	saved, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Admin.AuthToken != "secret-token" {
		t.Fatalf("secret changed to %q", saved.Admin.AuthToken)
	}
}

func TestManagerSerializesConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)

	const updates = 24
	errCh := make(chan error, updates)
	for range updates {
		go func() {
			_, err := manager.Update(func(next *config.Config) error {
				next.Routes[0].Upstreams[0].Weight++
				return nil
			}, "concurrent_test")
			errCh <- err
		}()
	}
	for range updates {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	got := manager.Config().Routes[0].Upstreams[0].Weight
	if want := 1 + updates; got != want {
		t.Fatalf("serialized weight=%d, want %d", got, want)
	}
}

func TestWatcherDoesNotReapplyManagerRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)

	result, err := manager.Update(func(next *config.Config) error {
		next.Routes[0].LoadBalancing.Algorithm = "weighted_round_robin"
		return nil
	}, "api_test")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied {
		t.Fatalf("revision was not applied: %#v", result)
	}
	revision := manager.WatchStatus().Revision
	time.Sleep(750 * time.Millisecond)
	if got := manager.WatchStatus().Revision; got != revision {
		t.Fatalf("watcher reapplied API revision: revision changed from %d to %d", revision, got)
	}
}

func TestWatcherDoesNotReapplyRevisionFromStaleDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := proxy.NewHandler(cfg, logger, metrics.New(), accesslog.New(100))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	manager.Attach(handler, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Start(ctx)

	// Hold the transaction lock across a watcher tick. The old implementation
	// read the digest before waiting on this lock, so it retained the stale
	// pre-API digest and reapplied the API revision after the lock was released.
	manager.transactionMu.Lock()
	time.Sleep(750 * time.Millisecond)
	manager.mu.RLock()
	candidate := clone(manager.persisted)
	manager.mu.RUnlock()
	candidate.Routes[0].LoadBalancing.Algorithm = "weighted_round_robin"
	if err := config.Save(path, candidate); err != nil {
		manager.transactionMu.Unlock()
		t.Fatal(err)
	}
	runtimeCfg, err := config.Load(path)
	if err != nil {
		manager.transactionMu.Unlock()
		t.Fatal(err)
	}
	result, err := manager.apply(candidate, runtimeCfg, "api_race_test")
	if err != nil {
		manager.transactionMu.Unlock()
		t.Fatal(err)
	}
	digest, err := fileDigest(path)
	if err != nil {
		manager.transactionMu.Unlock()
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.lastDigest = digest
	manager.mu.Unlock()
	manager.transactionMu.Unlock()

	time.Sleep(300 * time.Millisecond)
	if got := manager.WatchStatus().Revision; got != result.Revision {
		t.Fatalf("watcher reapplied a stale-digest API revision: revision changed from %d to %d", result.Revision, got)
	}
}

func TestEnvironmentConfigPathCanFollowDotenvRevision(t *testing.T) {
	directory := t.TempDir()
	fallback := filepath.Join(directory, "default.json")
	envPath := filepath.Join(directory, ".env")
	manager := &Manager{path: fallback, defaultPath: fallback, envPath: envPath, allowEnvPath: true}

	t.Setenv("EDGEPROXY_CONFIG", "profiles/alternate.json")
	if got, want := manager.environmentConfigPath(), filepath.Join(directory, "profiles", "alternate.json"); got != want {
		t.Fatalf("environment config path=%q, want %q", got, want)
	}
	t.Setenv("EDGEPROXY_CONFIG", "")
	if got := manager.environmentConfigPath(); got != fallback {
		t.Fatalf("empty environment path=%q, want fallback %q", got, fallback)
	}
	manager.allowEnvPath = false
	t.Setenv("EDGEPROXY_CONFIG", filepath.Join(directory, "ignored.json"))
	if got := manager.environmentConfigPath(); got != fallback {
		t.Fatalf("pinned path changed to %q", got)
	}
}

func TestFileDigestRejectsOversizedWatchedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxWatchedFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fileDigest(path); err == nil {
		t.Fatal("expected oversized watched file to be rejected")
	}
}

func TestRecordErrorDeduplicatesUnchangedWatcherFailure(t *testing.T) {
	manager := &Manager{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	failure := errors.New("watched file is unavailable")
	manager.recordError("config_watcher", failure)
	first := manager.WatchStatus()
	time.Sleep(time.Millisecond)
	manager.recordError("config_watcher", failure)
	second := manager.WatchStatus()
	if second.LastChangeAt != first.LastChangeAt {
		t.Fatalf("duplicate error changed watcher timestamp: first=%q second=%q", first.LastChangeAt, second.LastChangeAt)
	}
}

func TestManagerRejectsEnvironmentManagedUpdateWithoutPersisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edgeproxy.json")
	cfg := testConfig(t)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDGEPROXY_ADMIN_TOKEN", "runtime-token")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := New(path, "", logger)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Update(func(next *config.Config) error {
		next.Admin.AuthToken = "persisted-rotation"
		return nil
	}, "managed_secret_test"); err == nil || !strings.Contains(err.Error(), "EDGEPROXY_ADMIN_TOKEN") {
		t.Fatalf("expected environment-managed token update rejection, got %v", err)
	}
	persisted, err := config.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Admin.AuthToken != cfg.Admin.AuthToken {
		t.Fatalf("rejected managed token update was persisted: got %q", persisted.Admin.AuthToken)
	}
}
