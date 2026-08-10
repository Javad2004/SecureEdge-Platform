package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/envfile"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

const maxWatchedFileBytes int64 = 4 << 20

type ApplyResult struct {
	Applied         bool     `json:"applied"`
	RestartRequired bool     `json:"restart_required"`
	RestartFields   []string `json:"restart_fields,omitempty"`
	Revision        uint64   `json:"revision"`
	Source          string   `json:"source"`
}

type WatchStatus struct {
	Enabled          bool     `json:"enabled"`
	ConfigPath       string   `json:"config_path"`
	EnvironmentPath  string   `json:"environment_path,omitempty"`
	Revision         uint64   `json:"revision"`
	AppliedRevision  uint64   `json:"applied_revision"`
	RestartScheduled bool     `json:"restart_scheduled"`
	RestartFields    []string `json:"restart_fields,omitempty"`
	LastChangeAt     string   `json:"last_change_at,omitempty"`
	LastAppliedAt    string   `json:"last_applied_at,omitempty"`
	LastError        string   `json:"last_error,omitempty"`
	LastSource       string   `json:"last_source,omitempty"`
}

type Manager struct {
	transactionMu          sync.Mutex
	mu                     sync.RWMutex
	path                   string
	defaultPath            string
	envPath                string
	allowEnvPath           bool
	logger                 *slog.Logger
	handler                *proxy.Handler
	current                config.Config
	persisted              config.Config
	healthyPath            string
	healthyConfig          config.Config
	status                 WatchStatus
	lastDigest             [32]byte
	lastEnvDigest          [32]byte
	restartCh              chan config.Config
	restartEnvironmentFrom *envfile.ManagedSnapshot
	watchCancel            context.CancelFunc
}

func New(path, envPath string, logger *slog.Logger, allowEnvironmentPath ...bool) (*Manager, error) {
	persisted, err := config.LoadFile(path)
	if err != nil {
		return nil, err
	}
	runtimeCfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	digest, err := fileDigest(path)
	if err != nil {
		return nil, err
	}
	var envDigest [32]byte
	if strings.TrimSpace(envPath) != "" {
		envDigest, err = fileDigest(envPath)
		if err != nil {
			return nil, err
		}
	}
	allowPath := len(allowEnvironmentPath) > 0 && allowEnvironmentPath[0]
	return &Manager{
		path: path, defaultPath: path, envPath: envPath, allowEnvPath: allowPath, logger: logger, current: runtimeCfg, persisted: persisted,
		healthyPath: path, healthyConfig: clone(persisted),
		status:     WatchStatus{Enabled: true, ConfigPath: path, EnvironmentPath: envPath, Revision: 1, AppliedRevision: 1, LastAppliedAt: now(), LastSource: "startup"},
		lastDigest: digest, lastEnvDigest: envDigest, restartCh: make(chan config.Config, 1),
	}, nil
}

func (m *Manager) Attach(handler *proxy.Handler, current config.Config) {
	m.mu.Lock()
	m.handler = handler
	m.current = current
	m.healthyPath = m.path
	m.healthyConfig = clone(m.persisted)
	m.status.RestartScheduled = false
	m.status.RestartFields = nil
	m.status.AppliedRevision = m.status.Revision
	m.status.LastAppliedAt = now()
	m.restartEnvironmentFrom = nil
	m.mu.Unlock()
}

// RecoverFailedRestart restores the last generation that successfully bound
// all of its listeners. Restart preflight closes the normal configuration
// error window, but a different process can still claim a probed socket before
// the replacement generation binds it. This rollback keeps that rare TOCTOU
// race from terminating an otherwise healthy managed proxy.
func (m *Manager) RecoverFailedRestart(cause error) (config.Config, error) {
	// Dotenv reload validation holds the envfile lock while acquiring
	// transactionMu. Restore the managed environment before taking
	// transactionMu here so recovery follows the same lock ordering and cannot
	// deadlock with a concurrent watcher iteration.
	m.mu.RLock()
	var environmentSnapshot *envfile.ManagedSnapshot
	if m.restartEnvironmentFrom != nil {
		snapshot := *m.restartEnvironmentFrom
		environmentSnapshot = &snapshot
	}
	m.mu.RUnlock()
	if environmentSnapshot != nil {
		if err := envfile.RestoreManagedEnvironment(*environmentSnapshot); err != nil {
			return config.Config{}, fmt.Errorf("restore last-known-good EdgeProxy environment: %w", err)
		}
	}

	m.transactionMu.Lock()
	defer m.transactionMu.Unlock()

	m.mu.RLock()
	healthyPath := m.healthyPath
	healthyConfig := clone(m.healthyConfig)
	healthyRuntime := clone(m.current)
	m.mu.RUnlock()
	if strings.TrimSpace(healthyPath) == "" {
		return config.Config{}, errors.New("no last-known-good EdgeProxy generation is available")
	}

	if err := config.Save(healthyPath, healthyConfig); err != nil {
		return config.Config{}, fmt.Errorf("restore last-known-good EdgeProxy configuration %q: %w", healthyPath, err)
	}
	digest, err := fileDigest(healthyPath)
	if err != nil {
		return config.Config{}, fmt.Errorf("digest restored EdgeProxy configuration %q: %w", healthyPath, err)
	}

	m.mu.Lock()
	m.path = healthyPath
	m.persisted = clone(healthyConfig)
	m.lastDigest = digest
	m.status.ConfigPath = healthyPath
	m.status.RestartScheduled = false
	m.status.RestartFields = nil
	m.status.LastChangeAt = now()
	m.status.LastSource = "restart_rollback"
	m.status.LastError = fmt.Sprintf("replacement generation failed; restored last healthy configuration: %v", cause)
	m.restartEnvironmentFrom = nil
	m.mu.Unlock()

	for {
		select {
		case <-m.restartCh:
		default:
			m.logger.Error("replacement generation failed; restored last healthy EdgeProxy configuration", "config", healthyPath, "error", cause)
			return healthyRuntime, nil
		}
	}
}

func (m *Manager) RestartRequests() <-chan config.Config { return m.restartCh }

func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.watchCancel != nil {
		m.watchCancel()
	}
	watchCtx, cancel := context.WithCancel(ctx)
	m.watchCancel = cancel
	m.mu.Unlock()
	go m.watch(watchCtx)
}

func (m *Manager) Config() config.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return config.Redacted(m.persisted)
}

func (m *Manager) WatchStatus() WatchStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := m.status
	out.RestartFields = append([]string(nil), out.RestartFields...)
	return out
}

func (m *Manager) Reload(source string) (ApplyResult, error) {
	m.transactionMu.Lock()
	defer m.transactionMu.Unlock()
	return m.reload(source)
}

func (m *Manager) reload(source string) (ApplyResult, error) {
	persisted, err := config.LoadFile(m.path)
	if err != nil {
		m.recordError(source, err)
		return ApplyResult{}, err
	}
	m.mu.RLock()
	previousPersisted := clone(m.persisted)
	m.mu.RUnlock()
	if err := config.ValidateEnvironmentManagedChanges(previousPersisted, persisted); err != nil {
		m.recordError(source, err)
		return ApplyResult{}, err
	}
	runtimeCfg, err := config.Load(m.path)
	if err != nil {
		m.recordError(source, err)
		return ApplyResult{}, err
	}
	return m.apply(persisted, runtimeCfg, source)
}

func (m *Manager) Replace(candidate config.Config, source string) (ApplyResult, error) {
	return m.Update(func(cfg *config.Config) error {
		*cfg = candidate
		return nil
	}, source)
}

func (m *Manager) Update(mutator func(*config.Config) error, source string) (ApplyResult, error) {
	m.transactionMu.Lock()
	defer m.transactionMu.Unlock()
	m.mu.RLock()
	base := m.persisted
	m.mu.RUnlock()
	candidate := clone(base)
	if err := mutator(&candidate); err != nil {
		return ApplyResult{}, err
	}
	if candidate.Admin.AuthToken == "[REDACTED]" {
		candidate.Admin.AuthToken = base.Admin.AuthToken
	}
	if err := config.ValidateEnvironmentManagedChanges(base, candidate); err != nil {
		return ApplyResult{}, err
	}
	if err := candidate.Validate(); err != nil {
		return ApplyResult{}, err
	}
	if err := config.Save(m.path, candidate); err != nil {
		return ApplyResult{}, err
	}
	runtimeCfg, err := config.Load(m.path)
	if err != nil {
		_ = config.Save(m.path, base)
		return ApplyResult{}, err
	}
	result, err := m.apply(candidate, runtimeCfg, source)
	if err != nil {
		rollbackErr := config.Save(m.path, base)
		if digest, digestErr := fileDigest(m.path); digestErr == nil {
			m.mu.Lock()
			m.lastDigest = digest
			m.mu.Unlock()
		}
		return ApplyResult{}, errors.Join(err, rollbackErr)
	}
	digest, digestErr := fileDigest(m.path)
	if digestErr == nil {
		m.mu.Lock()
		m.lastDigest = digest
		m.mu.Unlock()
	}
	return result, nil
}

func (m *Manager) apply(persisted, next config.Config, source string) (ApplyResult, error) {
	m.mu.RLock()
	current, handler := m.current, m.handler
	m.mu.RUnlock()
	fields := restartRequiredChanges(current, next)

	m.mu.Lock()
	m.status.Revision++
	revision := m.status.Revision
	m.status.LastChangeAt = now()
	m.status.LastSource = source
	m.status.LastError = ""
	m.mu.Unlock()

	if len(fields) > 0 {
		if err := validateRestartCandidate(current, next); err != nil {
			m.recordError(source, err)
			return ApplyResult{}, err
		}
		m.mu.Lock()
		m.persisted = persisted
		m.status.RestartScheduled = true
		m.status.RestartFields = append([]string(nil), fields...)
		m.mu.Unlock()
		select {
		case m.restartCh <- next:
		default:
			select {
			case <-m.restartCh:
			default:
			}
			m.restartCh <- next
		}
		return ApplyResult{RestartRequired: true, RestartFields: fields, Revision: revision, Source: source}, nil
	}
	if handler == nil {
		err := errors.New("edgeproxy runtime is not attached")
		m.recordError(source, err)
		return ApplyResult{}, err
	}
	if err := handler.Reload(next); err != nil {
		m.recordError(source, err)
		return ApplyResult{}, err
	}
	m.mu.Lock()
	m.current = next
	m.persisted = persisted
	// A successful hot reload becomes part of the currently healthy listener
	// generation. Preserve its file-backed representation as the rollback point
	// for any later listener restart failure; otherwise a failed restart could
	// silently discard Route, Origin, cache, or scheduler edits applied since
	// the generation originally started.
	m.healthyPath = m.path
	m.healthyConfig = clone(persisted)
	m.status.AppliedRevision = revision
	m.status.LastAppliedAt = now()
	m.status.RestartScheduled = false
	m.status.RestartFields = nil
	m.mu.Unlock()
	m.logger.Info("configuration hot-reloaded", "source", source, "revision", revision)
	return ApplyResult{Applied: true, Revision: revision, Source: source}, nil
}

func (m *Manager) watch(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// The environment file is a separate watched source. A successful
			// dotenv transaction is followed by a normal runtime comparison so
			// hot-applicable overrides are swapped in place while listener/process
			// changes are coalesced into the managed restart channel.
			if strings.TrimSpace(m.envPath) != "" {
				envDigest, err := fileDigest(m.envPath)
				if err != nil {
					m.recordError("environment_watcher", err)
				} else {
					m.mu.RLock()
					envChanged := envDigest != m.lastEnvDigest
					m.mu.RUnlock()
					if envChanged {
						previousEnvironment := envfile.SnapshotManagedEnvironment()
						// Install the rollback snapshot before validation can publish a restart
						// request. The managed run loop may consume restartCh immediately, so
						// storing it only after ReloadValidated returns leaves a race where a
						// fast replacement failure has no environment rollback point.
						snapshot := previousEnvironment
						snapshotPtr := &snapshot
						installedSnapshot := false
						m.mu.Lock()
						if m.restartEnvironmentFrom == nil {
							m.restartEnvironmentFrom = snapshotPtr
							installedSnapshot = true
						}
						m.mu.Unlock()

						restartRequired := false
						err := envfile.ReloadValidated(m.envPath, func() error {
							result, reloadErr := m.reloadEnvironmentRevision()
							restartRequired = result.RestartRequired
							return reloadErr
						})
						if installedSnapshot && (err != nil || !restartRequired) {
							m.mu.Lock()
							if m.restartEnvironmentFrom == snapshotPtr {
								m.restartEnvironmentFrom = nil
							}
							m.mu.Unlock()
						}
						if err != nil {
							m.recordError("environment_watcher", err)
						}
						// Remember rejected revisions too. A corrected file has a new
						// digest and will be retried, while one invalid revision cannot
						// flood logs every watcher interval.
						m.mu.Lock()
						m.lastEnvDigest = envDigest
						m.mu.Unlock()
					}
				}
			}

			// Read and compare the digest while holding the same transaction lock used
			// by API mutations. Reading it before the lock leaves a stale-digest race:
			// a watcher can observe the old file, wait for an API save/hot-apply to
			// finish, and then incorrectly reapply that already-committed revision.
			m.transactionMu.Lock()
			digest, err := fileDigest(m.path)
			if err != nil {
				m.transactionMu.Unlock()
				m.recordError("config_watcher", err)
				continue
			}
			m.mu.RLock()
			changed := digest != m.lastDigest
			m.mu.RUnlock()
			if changed {
				_, _ = m.reload("config_watcher")
				// Record rejected revisions too. The last healthy generation remains
				// active, and a corrected file has a different digest.
				m.mu.Lock()
				m.lastDigest = digest
				m.mu.Unlock()
			}
			m.transactionMu.Unlock()
		}
	}
}

func (m *Manager) reloadEnvironmentRevision() (ApplyResult, error) {
	m.transactionMu.Lock()
	defer m.transactionMu.Unlock()

	desired := m.environmentConfigPath()
	m.mu.RLock()
	currentPath := m.path
	currentDigest := m.lastDigest
	m.mu.RUnlock()
	if desired != currentPath {
		persisted, err := config.LoadFile(desired)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("load EDGEPROXY_CONFIG target %q: %w", desired, err)
		}
		runtimeCfg, err := config.Load(desired)
		if err != nil {
			return ApplyResult{}, fmt.Errorf("validate EDGEPROXY_CONFIG target %q: %w", desired, err)
		}
		digest, err := fileDigest(desired)
		if err != nil {
			return ApplyResult{}, err
		}
		m.mu.Lock()
		m.path = desired
		m.status.ConfigPath = desired
		m.lastDigest = digest
		m.mu.Unlock()
		result, err := m.apply(persisted, runtimeCfg, "environment_config_path")
		if err != nil {
			m.mu.Lock()
			m.path = currentPath
			m.status.ConfigPath = currentPath
			m.lastDigest = currentDigest
			m.mu.Unlock()
			return ApplyResult{}, err
		}
		m.logger.Info("configuration path changed from environment", "previous", currentPath, "current", desired, "revision", result.Revision)
		return result, nil
	}
	return m.reload("environment_watcher")
}

func (m *Manager) environmentConfigPath() string {
	m.mu.RLock()
	fallback, envPath, allowed := m.defaultPath, m.envPath, m.allowEnvPath
	m.mu.RUnlock()
	if !allowed {
		return fallback
	}
	value := strings.TrimSpace(os.Getenv("EDGEPROXY_CONFIG"))
	if value == "" {
		return fallback
	}
	if filepath.IsAbs(value) || strings.TrimSpace(envPath) == "" {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(envPath), value))
}

func (m *Manager) recordError(source string, err error) {
	m.mu.Lock()
	if m.status.LastError == err.Error() && m.status.LastSource == source {
		m.mu.Unlock()
		return
	}
	m.status.LastError = err.Error()
	m.status.LastSource = source
	m.status.LastChangeAt = now()
	m.mu.Unlock()
	m.logger.Error("configuration reload failed; keeping last healthy runtime", "source", source, "error", err)
}

func restartRequiredChanges(current, next config.Config) []string {
	var fields []string
	add := func(name string, changed bool) {
		if changed {
			fields = append(fields, name)
		}
	}
	add("server.listen_addr", current.Server.ListenAddr != next.Server.ListenAddr)
	add("server.tls", !reflect.DeepEqual(current.Server.TLS, next.Server.TLS))
	add("server.timeouts", current.Server.ReadHeaderTimeout != next.Server.ReadHeaderTimeout || current.Server.ReadTimeout != next.Server.ReadTimeout || current.Server.WriteTimeout != next.Server.WriteTimeout || current.Server.IdleTimeout != next.Server.IdleTimeout || current.Server.ShutdownTimeout != next.Server.ShutdownTimeout || current.Server.MaxHeaderBytes != next.Server.MaxHeaderBytes)
	add("admin.enabled", current.Admin.Enabled != next.Admin.Enabled)
	add("admin.listen_addr", current.Admin.ListenAddr != next.Admin.ListenAddr)
	add("admin.auth_token", current.Admin.AuthToken != next.Admin.AuthToken)
	add("admin.log_store", !reflect.DeepEqual(current.Admin.LogStore, next.Admin.LogStore))
	return fields
}

func fileDigest(path string) ([32]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("read watched file %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return [32]byte{}, fmt.Errorf("stat watched file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return [32]byte{}, fmt.Errorf("watched path %q is not a regular file", path)
	}
	if info.Size() > maxWatchedFileBytes {
		return [32]byte{}, fmt.Errorf("watched file %q exceeds the %d-byte safety limit", path, maxWatchedFileBytes)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxWatchedFileBytes+1))
	if err != nil {
		return [32]byte{}, fmt.Errorf("hash watched file %q: %w", path, err)
	}
	if written > maxWatchedFileBytes {
		return [32]byte{}, fmt.Errorf("watched file %q exceeds the %d-byte safety limit", path, maxWatchedFileBytes)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func clone(cfg config.Config) config.Config {
	out := cfg
	out.Server.TrustedProxyCIDRs = append([]string(nil), cfg.Server.TrustedProxyCIDRs...)
	out.Routes = make([]config.RouteConfig, len(cfg.Routes))
	for i := range cfg.Routes {
		out.Routes[i] = cfg.Routes[i]
		out.Routes[i].Hosts = append([]string(nil), cfg.Routes[i].Hosts...)
		out.Routes[i].Upstreams = append([]config.UpstreamConfig(nil), cfg.Routes[i].Upstreams...)
		out.Routes[i].Cache.VaryRequestHeaders = append([]string(nil), cfg.Routes[i].Cache.VaryRequestHeaders...)
		out.Routes[i].Cache.CacheableStatusCodes = append([]int(nil), cfg.Routes[i].Cache.CacheableStatusCodes...)
		out.Routes[i].HealthCheck.HealthyStatuses = append([]int(nil), cfg.Routes[i].HealthCheck.HealthyStatuses...)
	}
	return out
}

func FindRoute(cfg *config.Config, name string) (int, bool) {
	name = strings.TrimSpace(name)
	for i := range cfg.Routes {
		if strings.EqualFold(cfg.Routes[i].Name, name) {
			return i, true
		}
	}
	return -1, false
}

func FindOrigin(route *config.RouteConfig, name string) (int, bool) {
	name = strings.TrimSpace(name)
	for i := range route.Upstreams {
		if strings.EqualFold(route.Upstreams[i].Name, name) || strings.EqualFold(route.Upstreams[i].URL, name) {
			return i, true
		}
	}
	return -1, false
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
