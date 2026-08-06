package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/envfile"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

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
	transactionMu sync.Mutex
	mu            sync.RWMutex
	path          string
	envPath       string
	logger        *slog.Logger
	handler       *proxy.Handler
	current       config.Config
	persisted     config.Config
	status        WatchStatus
	lastDigest    [32]byte
	lastEnvDigest [32]byte
	restartCh     chan config.Config
	watchCancel   context.CancelFunc
}

func New(path, envPath string, logger *slog.Logger) (*Manager, error) {
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
	return &Manager{
		path: path, envPath: envPath, logger: logger, current: runtimeCfg, persisted: persisted,
		status:     WatchStatus{Enabled: true, ConfigPath: path, EnvironmentPath: envPath, Revision: 1, AppliedRevision: 1, LastAppliedAt: now(), LastSource: "startup"},
		lastDigest: digest, lastEnvDigest: envDigest, restartCh: make(chan config.Config, 1),
	}, nil
}

func (m *Manager) Attach(handler *proxy.Handler, current config.Config) {
	m.mu.Lock()
	m.handler = handler
	m.current = current
	m.status.RestartScheduled = false
	m.status.RestartFields = nil
	m.status.AppliedRevision = m.status.Revision
	m.status.LastAppliedAt = now()
	m.mu.Unlock()
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
						if err := envfile.Reload(m.envPath); err != nil {
							m.recordError("environment_watcher", err)
						} else {
							_, _ = m.Reload("environment_watcher")
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

			digest, err := fileDigest(m.path)
			if err != nil {
				m.recordError("config_watcher", err)
				continue
			}

			// Serialize the final digest check with API/file transactions. An API
			// mutation saves, hot-applies, and records its digest while holding the
			// same lock. Without this second check, a watcher tick that observed the
			// file in the narrow save-to-digest window could apply the same revision
			// twice and reset scheduler state.
			m.transactionMu.Lock()
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

func (m *Manager) recordError(source string, err error) {
	m.mu.Lock()
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
	data, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("read watched file %q: %w", path, err)
	}
	return sha256.Sum256(data), nil
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
