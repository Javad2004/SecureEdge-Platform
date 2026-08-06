package control

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

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

	result, err = manager.Update(func(next *config.Config) error {
		next.Server.ListenAddr = "127.0.0.1:18081"
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
		if next.Server.ListenAddr != "127.0.0.1:18081" {
			t.Fatalf("restart config listen=%q", next.Server.ListenAddr)
		}
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
	status := manager.WatchStatus()
	if !status.RestartScheduled || status.Revision <= status.AppliedRevision {
		t.Fatalf("unexpected watcher status: %#v", status)
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
