package securityedge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/admin"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/admission"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/clientip"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/edgeadmin"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/gateway"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/ratelimit"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/routes"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/securitylog"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/traffic"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/waf"
)

type Runtime struct {
	configPath string
	logger     *slog.Logger
	// configMu serializes complete load/validate/persist/apply transactions.
	// Without it, concurrent reloads and policy edits can lose updates or leave
	// the persisted file and live runtime on different revisions.
	configMu     sync.Mutex
	mu           sync.RWMutex
	cfg          config.Config
	table        *routes.Table
	edge         *edgeadmin.Client
	registry     *metrics.Registry
	logs         *securitylog.Store
	traffic      *traffic.Tracker
	inspector    *waf.Inspector
	limiter      *ratelimit.Limiter
	bans         *ratelimit.BanManager
	admission    *admission.Limiter
	clients      *clientip.Resolver
	gateway      *gateway.Handler
	adminMu      sync.Mutex
	adminService *admin.Server
	// healthyFileCfg is the latest persisted configuration that was either used
	// to start this generation or successfully hot-applied to it. Restart
	// rollback must use this revision rather than the file as it existed only at
	// process startup, or later WAF/policy/connection edits can be lost.
	healthyFileCfg config.Config
	watchMu        sync.RWMutex
	watch          WatchStatus
}

type preparedRuntime struct {
	cfg       config.Config
	table     *routes.Table
	edge      *edgeadmin.Client
	inspector *waf.Inspector
	clients   *clientip.Resolver
	watchMu   sync.RWMutex
	watch     WatchStatus
}

// Validate checks the complete SecurityEdge configuration, including the
// referenced EdgeProxy route table, without creating log files or starting
// runtime background workers.
func Validate(configPath string) error {
	_, err := prepareRuntime(configPath)
	return err
}

func prepareRuntime(configPath string) (preparedRuntime, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return preparedRuntime{}, err
	}
	return prepareRuntimeConfig(configPath, cfg)
}

func validatePersistentPathIsolation(configPath string, cfg config.Config) error {
	type managedPath struct {
		field string
		path  string
	}

	securityConfigPath := configPath
	edgeConfigPath := resolveEdgeConfigPath(configPath, cfg.EdgeProxy.ConfigPath)
	configFiles := []managedPath{
		{field: "SecurityEdge configuration", path: securityConfigPath},
		{field: "EdgeProxy route configuration", path: edgeConfigPath},
	}
	protected := []managedPath{
		configFiles[0],
		{field: "SecurityEdge configuration staging file", path: securityConfigPath + ".bak"},
		configFiles[1],
		{field: "EdgeProxy route configuration staging file", path: edgeConfigPath + ".bak"},
	}
	for _, configFile := range configFiles {
		backups, err := existingConfigBackupPaths(configFile.path)
		if err != nil {
			return fmt.Errorf("discover %s backups: %w", configFile.field, err)
		}
		for _, backup := range backups {
			protected = append(protected, managedPath{field: configFile.field + " retained backup", path: backup})
		}
	}
	if cfg.Server.TLS.Enabled {
		protected = append(protected,
			managedPath{field: "server.tls.cert_file", path: cfg.Server.TLS.CertFile},
			managedPath{field: "server.tls.key_file", path: cfg.Server.TLS.KeyFile},
		)
	}

	writers := make([]managedPath, 0, cfg.Admin.LogStore.MaxBackups+3)
	if logPath := strings.TrimSpace(cfg.Admin.LogStore.FilePath); logPath != "" {
		writers = append(writers, managedPath{field: "admin.log_store.file_path", path: logPath})
		for i := 1; i <= cfg.Admin.LogStore.MaxBackups; i++ {
			writers = append(writers, managedPath{field: fmt.Sprintf("admin.log_store rotation .%d", i), path: fmt.Sprintf("%s.%d", logPath, i)})
		}
	}
	if cfg.Admin.TelemetryHistory.Enabled {
		if historyPath := strings.TrimSpace(cfg.Admin.TelemetryHistory.FilePath); historyPath != "" {
			writers = append(writers,
				managedPath{field: "admin.telemetry_history.file_path", path: historyPath},
				managedPath{field: "admin.telemetry_history staging/recovery file", path: historyPath + ".bak"},
			)
		}
	}

	for _, writer := range writers {
		for _, configFile := range configFiles {
			inBackupNamespace, err := managedPathHasPrefix(writer.path, configFile.path+".bak-")
			if err != nil {
				return fmt.Errorf("compare %s with %s retained-backup namespace: %w", writer.field, configFile.field, err)
			}
			if inBackupNamespace {
				return fmt.Errorf("%s must not overlap %s retained-backup namespace", writer.field, configFile.field)
			}
		}
		for _, target := range protected {
			if strings.TrimSpace(target.path) == "" {
				continue
			}
			same, err := managedPathsCollide(writer.path, target.path)
			if err != nil {
				return fmt.Errorf("compare %s with %s: %w", writer.field, target.field, err)
			}
			if same {
				return fmt.Errorf("%s must not overlap %s", writer.field, target.field)
			}
		}
	}
	for i := 0; i < len(writers); i++ {
		for j := i + 1; j < len(writers); j++ {
			same, err := managedPathsCollide(writers[i].path, writers[j].path)
			if err != nil {
				return fmt.Errorf("compare %s with %s: %w", writers[i].field, writers[j].field, err)
			}
			if same {
				return fmt.Errorf("%s must not overlap %s", writers[i].field, writers[j].field)
			}
		}
	}
	return nil
}

func existingConfigBackupPaths(path string) ([]string, error) {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := filepath.Base(path) + ".bak-"
	backups := make([]string, 0)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			backups = append(backups, filepath.Join(dir, entry.Name()))
		}
	}
	return backups, nil
}

func managedPathHasPrefix(path, prefix string) (bool, error) {
	candidate, err := canonicalManagedPath(path)
	if err != nil {
		return false, err
	}
	canonicalPrefix, err := canonicalManagedPath(prefix)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(candidate, canonicalPrefix), nil
}

func managedPathsCollide(left, right string) (bool, error) {
	leftPath, err := canonicalManagedPath(left)
	if err != nil {
		return false, err
	}
	rightPath, err := canonicalManagedPath(right)
	if err != nil {
		return false, err
	}
	if leftPath == rightPath {
		return true, nil
	}
	leftInfo, leftErr := os.Stat(leftPath)
	rightInfo, rightErr := os.Stat(rightPath)
	if leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo) {
		return true, nil
	}
	if leftErr != nil && !errors.Is(leftErr, os.ErrNotExist) {
		return false, leftErr
	}
	if rightErr != nil && !errors.Is(rightErr, os.ErrNotExist) {
		return false, rightErr
	}
	return false, nil
}

func canonicalManagedPath(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	resolved := abs
	if candidate, err := filepath.EvalSymlinks(abs); err == nil {
		resolved = candidate
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	} else {
		// Resolve the nearest existing parent so a not-yet-created persistence
		// file cannot bypass collision checks through a symlinked directory.
		current := abs
		var suffix []string
		for {
			parent := filepath.Dir(current)
			if current == parent {
				break
			}
			suffix = append([]string{filepath.Base(current)}, suffix...)
			current = parent
			candidate, parentErr := filepath.EvalSymlinks(current)
			if parentErr == nil {
				parts := append([]string{candidate}, suffix...)
				resolved = filepath.Join(parts...)
				break
			}
			if !errors.Is(parentErr, os.ErrNotExist) {
				return "", parentErr
			}
		}
	}
	resolved = filepath.Clean(resolved)
	if goruntime.GOOS == "windows" {
		resolved = strings.ToLower(resolved)
	}
	return resolved, nil
}

func prepareRuntimeConfig(configPath string, cfg config.Config) (preparedRuntime, error) {
	if err := validatePersistentPathIsolation(configPath, cfg); err != nil {
		return preparedRuntime{}, err
	}
	table, err := routes.Load(resolveEdgeConfigPath(configPath, cfg.EdgeProxy.ConfigPath))
	if err != nil {
		return preparedRuntime{}, err
	}
	if err := validateRoutePolicies(cfg, table); err != nil {
		return preparedRuntime{}, err
	}
	edge, err := edgeadmin.New(cfg.EdgeProxy.AdminURL, cfg.EdgeProxy.AdminToken, cfg.EdgeProxy.Timeout.Duration)
	if err != nil {
		return preparedRuntime{}, err
	}
	inspector, err := waf.NewInspector(cfg.WAF.CustomRules, cfg.WAF.MaximumMatchesPerRequest)
	if err != nil {
		return preparedRuntime{}, err
	}
	clients, err := clientip.New(cfg.Server.TrustedProxyCIDRs, cfg.Server.ForwardedForHeader)
	if err != nil {
		return preparedRuntime{}, err
	}
	return preparedRuntime{cfg: cfg, table: table, edge: edge, inspector: inspector, clients: clients}, nil
}

func New(configPath string, logger *slog.Logger) (*Runtime, error) {
	if logger == nil {
		logger = slog.Default()
	}
	// Load the file-backed and runtime views from one snapshot. Loading the
	// file twice leaves a small race where a concurrent atomic update can make
	// the rollback baseline differ from the configuration that actually started
	// this generation.
	fileCfg, err := config.LoadFile(configPath)
	if err != nil {
		return nil, err
	}
	runtimeCfg := cloneConfig(fileCfg)
	if err := config.ApplyEnvironmentOverrides(&runtimeCfg); err != nil {
		return nil, err
	}
	if err := runtimeCfg.Validate(); err != nil {
		return nil, err
	}
	prepared, err := prepareRuntimeConfig(configPath, runtimeCfg)
	if err != nil {
		return nil, err
	}
	logs, err := securitylog.NewWithConfig(prepared.cfg.Admin.LogStore)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		configPath: configPath, logger: logger, cfg: prepared.cfg, table: prepared.table, edge: prepared.edge,
		registry: metrics.New(), logs: logs, traffic: traffic.New(traffic.DefaultCapacity, traffic.DefaultWindow), inspector: prepared.inspector,
		limiter: ratelimit.New(prepared.cfg.DefaultPolicy.RateLimit.CleanupInterval.Duration, prepared.cfg.DefaultPolicy.RateLimit.IdleTTL.Duration),
		bans:    ratelimit.NewBanManager(), admission: admission.New(), clients: prepared.clients, healthyFileCfg: cloneConfig(fileCfg),
	}, nil
}

func (r *Runtime) Close() {
	// Stop Admin background workers before releasing the EdgeProxy client,
	// metrics registry, and persistent stores they sample.
	r.adminMu.Lock()
	adminService := r.adminService
	r.adminService = nil
	r.adminMu.Unlock()
	if adminService != nil {
		adminService.Close()
	}

	r.limiter.Close()
	r.mu.Lock()
	gatewayHandler := r.gateway
	r.gateway = nil
	edge := r.edge
	r.mu.Unlock()
	if gatewayHandler != nil {
		gatewayHandler.Close()
	}
	if edge != nil {
		edge.CloseIdleConnections()
	}
	if err := r.logs.Close(); err != nil {
		r.logger.Error("close security log", "error", err)
	}
}

func (r *Runtime) Wrap(next http.Handler) http.Handler {
	handler := gateway.New(next, r, r, r.inspector, r.limiter, r.bans, r.admission, r.clients, r.registry, r.logs, r.traffic, r.logger)
	r.mu.Lock()
	previous := r.gateway
	r.gateway = handler
	r.mu.Unlock()
	if previous != nil {
		previous.Close()
	}
	return handler
}

func (r *Runtime) adminServerService() (*admin.Server, error) {
	r.adminMu.Lock()
	defer r.adminMu.Unlock()
	if r.adminService != nil {
		return r.adminService, nil
	}

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()
	srv, err := admin.New(cfg.Admin, r, r.registry, r.logs, r.traffic, r.inspector)
	if err != nil {
		return nil, err
	}
	r.adminService = srv
	return srv, nil
}

// StartAdminBackgroundWorkers activates background work only after the active
// generation has successfully acquired its listeners. This prevents a failed
// replacement generation from persisting telemetry before it is committed.
func (r *Runtime) StartAdminBackgroundWorkers() {
	r.adminMu.Lock()
	srv := r.adminService
	r.adminMu.Unlock()
	if srv != nil {
		srv.StartTelemetrySampler()
	}
}

func (r *Runtime) AdminHandler() (http.Handler, error) {
	srv, err := r.adminServerService()
	if err != nil {
		return nil, err
	}
	// AdminHandler is the embedded/library entry point and has no listener
	// preflight phase owned by this package, so obtaining the live handler is
	// the activation boundary for its background workers.
	srv.StartTelemetrySampler()
	return srv.HTTPServer().Handler, nil
}

func (r *Runtime) AdminServer() (*http.Server, error) {
	srv, err := r.adminServerService()
	if err != nil {
		return nil, err
	}
	return srv.HTTPServer(), nil
}

func (r *Runtime) Config() config.Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneConfig(r.cfg)
}
func (r *Runtime) RedactedConfig() config.Config {
	cfg := r.Config()
	if strings.TrimSpace(cfg.Admin.AuthToken) != "" {
		cfg.Admin.AuthToken = "[REDACTED]"
	}
	if strings.TrimSpace(cfg.EdgeProxy.AdminToken) != "" {
		cfg.EdgeProxy.AdminToken = "[REDACTED]"
	}
	return cfg
}
func (r *Runtime) WatchStatusMap() map[string]any {
	status := r.WatchStatus()
	return map[string]any{
		"enabled": status.Enabled, "security_config": status.SecurityConfig,
		"edgeproxy_config": status.EdgeProxyConfig, "environment_file": status.EnvironmentFile,
		"revision": status.Revision, "applied_revision": status.AppliedRevision,
		"restart_scheduled": status.RestartScheduled, "last_changed_file": status.LastChangedFile,
		"last_change_at": status.LastChangeAt, "last_applied_at": status.LastAppliedAt, "last_error": status.LastError,
	}
}

func (r *Runtime) ConfigPath() string { return r.configPath }
func (r *Runtime) EdgeConfigPath() string {
	r.mu.RLock()
	edgePath := r.cfg.EdgeProxy.ConfigPath
	r.mu.RUnlock()
	return resolveEdgeConfigPath(r.configPath, edgePath)
}

// RestartFallback returns the latest file-backed revision known to be healthy
// in the active generation. It deliberately excludes a restart-required
// candidate that may already have been persisted but has not successfully
// bound its replacement listeners yet.
func (r *Runtime) RestartFallback() (string, config.Config) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.configPath, cloneConfig(r.healthyFileCfg)
}

// ReloadEdgeRoutes reloads only the shared EdgeProxy route table. It deliberately
// does not compare SecurityEdge listener/admin fields and therefore never
// schedules a SecurityEdge restart for a route or origin edit.
func (r *Runtime) ReloadEdgeRoutes() error {
	r.configMu.Lock()
	defer r.configMu.Unlock()
	r.mu.RLock()
	cfg := cloneConfig(r.cfg)
	r.mu.RUnlock()
	table, err := routes.Load(resolveEdgeConfigPath(r.configPath, cfg.EdgeProxy.ConfigPath))
	if err != nil {
		return err
	}
	if err := validateRoutePolicies(cfg, table); err != nil {
		return err
	}
	r.mu.Lock()
	r.table = table
	r.mu.Unlock()
	return nil
}

func (r *Runtime) ReplaceConfig(candidate config.Config) error {
	r.configMu.Lock()
	defer r.configMu.Unlock()
	fileCfg, err := config.LoadFile(r.configPath)
	if err != nil {
		return err
	}
	if candidate.Admin.AuthToken == "[REDACTED]" {
		candidate.Admin.AuthToken = fileCfg.Admin.AuthToken
	}
	if candidate.EdgeProxy.AdminToken == "[REDACTED]" {
		candidate.EdgeProxy.AdminToken = fileCfg.EdgeProxy.AdminToken
	}
	if err := config.ValidateEnvironmentManagedChanges(fileCfg, candidate); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	runtimeCfg := cloneConfig(candidate)
	if err := config.ApplyEnvironmentOverrides(&runtimeCfg); err != nil {
		return err
	}
	r.mu.RLock()
	current := cloneConfig(r.cfg)
	r.mu.RUnlock()
	if fields := restartRequiredChanges(current, runtimeCfg); len(fields) > 0 {
		if err := r.validateRestartCandidate(r.configPath, current, runtimeCfg); err != nil {
			return err
		}
		// Persist a validated restart-required revision. The file-specific
		// watcher will observe this write and perform a graceful generation
		// restart; route-table-only edits are handled by a different watcher.
		if err := config.Save(r.configPath, candidate); err != nil {
			return err
		}
		r.MarkRestartScheduled(r.configPath)
		return &restartRequiredError{fields: fields}
	}
	prepared, err := r.prepareReload(runtimeCfg)
	if err != nil {
		return err
	}
	if err := config.Save(r.configPath, candidate); err != nil {
		return err
	}
	if err := r.applyReload(prepared); err != nil {
		rollbackErr := config.Save(r.configPath, fileCfg)
		return errors.Join(err, rollbackErr)
	}
	r.mu.Lock()
	r.healthyFileCfg = cloneConfig(candidate)
	r.mu.Unlock()
	return nil
}
func (r *Runtime) ServerConfig() config.ServerConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneServerConfig(r.cfg.Server)
}
func (r *Runtime) Match(req *http.Request) (routes.Route, bool) {
	r.mu.RLock()
	table := r.table
	r.mu.RUnlock()
	return table.Match(req)
}
func (r *Runtime) Routes() []routes.Route {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.table.Routes()
}
func (r *Runtime) Policy(route string) config.Policy { return r.EffectivePolicy(route) }

func (r *Runtime) EffectivePolicy(route string) config.Policy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.cfg.RoutePolicies[route]; ok {
		return clonePolicy(p)
	}
	for name, policy := range r.cfg.RoutePolicies {
		if strings.EqualFold(name, route) {
			return clonePolicy(policy)
		}
	}
	return clonePolicy(r.cfg.DefaultPolicy)
}

func (r *Runtime) EdgeJSON(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, int, error) {
	r.mu.RLock()
	edge := r.edge
	r.mu.RUnlock()
	return edge.JSON(ctx, method, path, query, body)
}

func (r *Runtime) LimiterSize() int                      { return r.limiter.Size() }
func (r *Runtime) ActiveBans() []ratelimit.Ban           { return r.bans.List(time.Now()) }
func (r *Runtime) ActiveBanCount() int                   { return r.bans.ActiveCount(time.Now()) }
func (r *Runtime) DeleteBan(client string) bool          { return r.bans.Remove(client) }
func (r *Runtime) ClearBans() int                        { return r.bans.Clear() }
func (r *Runtime) AdmissionSnapshot() admission.Snapshot { return r.admission.Snapshot(false) }

func (r *Runtime) Audit(event, message string, fields map[string]string) {
	entry := securitylog.Entry{Level: "INFO", Event: event, Message: message, Action: "ADMIN", Tags: []string{"security", "admin", "audit"}}
	if v := fields["request_id"]; v != "" {
		entry.RequestID = v
	}
	if v := fields["client_ip"]; v != "" {
		entry.ClientIP = v
	}
	if v := fields["route"]; v != "" {
		entry.Route = v
	}
	if v := fields["reason"]; v != "" {
		entry.Reason = v
	}
	r.logs.Append(entry)
	r.logger.Info(message, "event", event, "fields", fields)
}

func (r *Runtime) UpdateDefaultPolicy(p config.Policy) error {
	return r.update(func(cfg *config.Config) {
		cfg.DefaultPolicy = p
		// Limiter cleanup/capacity and ban-tracking capacity are process-wide.
		// Keep every Route override aligned with the new Default Policy values so
		// a legitimate Default-Policy edit does not become invalid merely because
		// an existing Route override still carries the previously inherited copy.
		for name, routePolicy := range cfg.RoutePolicies {
			routePolicy.RateLimit.CleanupInterval = p.RateLimit.CleanupInterval
			routePolicy.RateLimit.IdleTTL = p.RateLimit.IdleTTL
			routePolicy.RateLimit.MaxBuckets = p.RateLimit.MaxBuckets
			routePolicy.AutoBan.MaxTrackedClients = p.AutoBan.MaxTrackedClients
			cfg.RoutePolicies[name] = routePolicy
		}
	})
}
func (r *Runtime) UpdateRoutePolicy(route string, p config.Policy) error {
	canonical, ok := r.canonicalRouteName(route)
	if !ok {
		return fmt.Errorf("route %q does not exist in edgeproxy config", route)
	}
	return r.update(func(cfg *config.Config) {
		if cfg.RoutePolicies == nil {
			cfg.RoutePolicies = map[string]config.Policy{}
		}
		for key := range cfg.RoutePolicies {
			if strings.EqualFold(key, canonical) && key != canonical {
				delete(cfg.RoutePolicies, key)
			}
		}
		cfg.RoutePolicies[canonical] = p
	})
}
func (r *Runtime) DeleteRoutePolicy(route string) error {
	if strings.TrimSpace(route) == "" {
		return fmt.Errorf("route name is required")
	}
	return r.update(func(cfg *config.Config) {
		for key := range cfg.RoutePolicies {
			if strings.EqualFold(key, route) {
				delete(cfg.RoutePolicies, key)
			}
		}
	})
}

type restartRequiredError struct {
	fields []string
}

func (e *restartRequiredError) Error() string {
	return "configuration changes require a process restart: " + strings.Join(e.fields, ", ")
}

func (*restartRequiredError) RestartRequired() bool { return true }

type preparedReload struct {
	cfg   config.Config
	table *routes.Table
	edge  *edgeadmin.Client
}

func (r *Runtime) Reload() error {
	r.configMu.Lock()
	defer r.configMu.Unlock()

	fileCfg, err := config.LoadFile(r.configPath)
	if err != nil {
		return err
	}
	r.mu.RLock()
	previousFileCfg := cloneConfig(r.healthyFileCfg)
	r.mu.RUnlock()
	// cloneConfig intentionally owns all slice storage, but empty slices can
	// collapse to nil during cloning. Re-run validation to restore the same
	// canonical representation produced by LoadFile before comparing the two
	// persisted views or checking environment-managed collection fields.
	if err := previousFileCfg.Validate(); err != nil {
		return fmt.Errorf("validate last applied security configuration: %w", err)
	}
	if err := config.ValidateEnvironmentManagedChanges(previousFileCfg, fileCfg); err != nil {
		return err
	}
	// Control Plane mutations persist and hot-apply the file while holding the
	// same config transaction lock. The external file supervisor will still
	// observe the resulting atomic replacement on its next poll; treat that
	// already-applied file revision as a no-op instead of rebuilding the route
	// table, WAF inspector inputs, and EdgeProxy Admin client a second time.
	if reflect.DeepEqual(previousFileCfg, fileCfg) {
		return nil
	}
	cfg := cloneConfig(fileCfg)
	if err := config.ApplyEnvironmentOverrides(&cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	prepared, err := r.prepareReload(cfg)
	if err != nil {
		return err
	}
	if err := r.applyReload(prepared); err != nil {
		return err
	}
	r.mu.Lock()
	r.healthyFileCfg = cloneConfig(fileCfg)
	r.mu.Unlock()
	return nil
}

// ReloadEnvironment rebuilds the effective runtime view after a watched dotenv
// revision without requiring the file-backed JSON to change. Unlike Reload, it
// must not use the persisted-config no-op shortcut: environment-only listener,
// TLS, dependency, and policy overrides can change while the JSON digest stays
// identical. The dotenv loader owns environment rollback when this method
// returns an error.
func (r *Runtime) ReloadEnvironment() error {
	r.configMu.Lock()
	defer r.configMu.Unlock()

	fileCfg, err := config.LoadFile(r.configPath)
	if err != nil {
		return err
	}
	runtimeCfg := cloneConfig(fileCfg)
	if err := config.ApplyEnvironmentOverrides(&runtimeCfg); err != nil {
		return err
	}
	if err := runtimeCfg.Validate(); err != nil {
		return err
	}
	r.mu.RLock()
	current := cloneConfig(r.cfg)
	r.mu.RUnlock()
	if reflect.DeepEqual(current, runtimeCfg) {
		return nil
	}
	prepared, err := r.prepareReload(runtimeCfg)
	if err != nil {
		return err
	}
	if err := r.applyReload(prepared); err != nil {
		return err
	}
	r.mu.Lock()
	r.healthyFileCfg = cloneConfig(fileCfg)
	r.mu.Unlock()
	return nil
}

// ValidateRestartConfig validates a configuration selected by a watched
// SECURITYEDGE_CONFIG path before the healthy generation is drained.
func (r *Runtime) ValidateRestartConfig(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	r.mu.RLock()
	current := cloneConfig(r.cfg)
	r.mu.RUnlock()
	return r.validateRestartCandidate(configPath, current, cfg)
}

func (r *Runtime) prepareReload(cfg config.Config) (preparedReload, error) {
	r.mu.RLock()
	current := cloneConfig(r.cfg)
	r.mu.RUnlock()
	if fields := restartRequiredChanges(current, cfg); len(fields) > 0 {
		if err := r.validateRestartCandidate(r.configPath, current, cfg); err != nil {
			return preparedReload{}, err
		}
		return preparedReload{}, &restartRequiredError{fields: fields}
	}

	table, err := routes.Load(resolveEdgeConfigPath(r.configPath, cfg.EdgeProxy.ConfigPath))
	if err != nil {
		return preparedReload{}, err
	}
	if err := validateRoutePolicies(cfg, table); err != nil {
		return preparedReload{}, err
	}
	edge, err := edgeadmin.New(cfg.EdgeProxy.AdminURL, cfg.EdgeProxy.AdminToken, cfg.EdgeProxy.Timeout.Duration)
	if err != nil {
		return preparedReload{}, err
	}
	// Validate every mutable component before changing the live runtime. The
	// existing instances are updated only after all preparation has succeeded.
	if _, err := waf.NewInspector(cfg.WAF.CustomRules, cfg.WAF.MaximumMatchesPerRequest); err != nil {
		return preparedReload{}, err
	}
	if _, err := clientip.New(cfg.Server.TrustedProxyCIDRs, cfg.Server.ForwardedForHeader); err != nil {
		return preparedReload{}, err
	}
	return preparedReload{cfg: cfg, table: table, edge: edge}, nil
}

func (r *Runtime) applyReload(prepared preparedReload) error {
	if err := r.inspector.Replace(prepared.cfg.WAF.CustomRules, prepared.cfg.WAF.MaximumMatchesPerRequest); err != nil {
		return err
	}
	if err := r.clients.Replace(prepared.cfg.Server.TrustedProxyCIDRs, prepared.cfg.Server.ForwardedForHeader); err != nil {
		return err
	}
	r.mu.Lock()
	previousEdge := r.edge
	r.cfg = prepared.cfg
	r.table = prepared.table
	r.edge = prepared.edge
	r.mu.Unlock()
	if previousEdge != nil && previousEdge != prepared.edge {
		previousEdge.CloseIdleConnections()
	}
	return nil
}

func (r *Runtime) update(mutator func(*config.Config)) error {
	r.configMu.Lock()
	defer r.configMu.Unlock()

	fileCfg, err := config.LoadFile(r.configPath)
	if err != nil {
		return err
	}
	candidate := cloneConfig(fileCfg)
	mutator(&candidate)
	if err := candidate.Validate(); err != nil {
		return err
	}

	runtimeCfg := cloneConfig(candidate)
	if err := config.ApplyEnvironmentOverrides(&runtimeCfg); err != nil {
		return err
	}
	if err := runtimeCfg.Validate(); err != nil {
		return err
	}
	r.mu.RLock()
	current := cloneConfig(r.cfg)
	r.mu.RUnlock()
	if fields := restartRequiredChanges(current, runtimeCfg); len(fields) > 0 {
		if err := r.validateRestartCandidate(r.configPath, current, runtimeCfg); err != nil {
			return err
		}
		// Persist the validated candidate before scheduling the generation
		// restart, mirroring ReplaceConfig. This makes structured Control Plane
		// mutations truthful: a restart-required policy edit is accepted and
		// durable instead of being reported as an invalid policy.
		if err := config.Save(r.configPath, candidate); err != nil {
			return err
		}
		r.MarkRestartScheduled(r.configPath)
		return &restartRequiredError{fields: fields}
	}
	prepared, err := r.prepareReload(runtimeCfg)
	if err != nil {
		return err
	}

	// Persist only after the complete live configuration has been prepared.
	// This prevents a failed reload from leaving disk and memory out of sync.
	if err := config.Save(r.configPath, candidate); err != nil {
		return err
	}
	if err := r.applyReload(prepared); err != nil {
		rollbackErr := config.Save(r.configPath, fileCfg)
		return errors.Join(err, rollbackErr)
	}
	r.mu.Lock()
	r.healthyFileCfg = cloneConfig(candidate)
	r.mu.Unlock()
	return nil
}

func restartRequiredChanges(current, next config.Config) []string {
	var fields []string
	add := func(name string, changed bool) {
		if changed {
			fields = append(fields, name)
		}
	}

	add("server.mode", current.Server.Mode != next.Server.Mode)
	add("server.listen_addr", current.Server.ListenAddr != next.Server.ListenAddr)
	add("server.upstream_proxy_url", current.Server.UpstreamProxyURL != next.Server.UpstreamProxyURL)
	add("server.read_header_timeout", current.Server.ReadHeaderTimeout != next.Server.ReadHeaderTimeout)
	add("server.read_timeout", current.Server.ReadTimeout != next.Server.ReadTimeout)
	add("server.write_timeout", current.Server.WriteTimeout != next.Server.WriteTimeout)
	add("server.idle_timeout", current.Server.IdleTimeout != next.Server.IdleTimeout)
	add("server.shutdown_timeout", current.Server.ShutdownTimeout != next.Server.ShutdownTimeout)
	add("server.max_header_bytes", current.Server.MaxHeaderBytes != next.Server.MaxHeaderBytes)
	add("server.max_request_body_bytes", current.Server.MaxRequestBodyBytes != next.Server.MaxRequestBodyBytes)
	// The gateway ReverseProxy captures the configured source-header name when
	// its handler is built. Reloading only the resolver would create a split
	// trust policy and could leave the newly configured custom header downstream.
	add("server.forwarded_for_header", current.Server.ForwardedForHeader != next.Server.ForwardedForHeader)
	add("server.preserve_host", current.Server.PreserveHost != next.Server.PreserveHost)
	add("server.tls", !reflect.DeepEqual(current.Server.TLS, next.Server.TLS))
	add("server.upstream_transport", !reflect.DeepEqual(current.Server.UpstreamTransport, next.Server.UpstreamTransport))
	add("admin", !reflect.DeepEqual(current.Admin, next.Admin))
	add("default_policy.rate_limit.cleanup_interval", current.DefaultPolicy.RateLimit.CleanupInterval != next.DefaultPolicy.RateLimit.CleanupInterval)
	add("default_policy.rate_limit.idle_ttl", current.DefaultPolicy.RateLimit.IdleTTL != next.DefaultPolicy.RateLimit.IdleTTL)
	add("default_policy.rate_limit.max_buckets", current.DefaultPolicy.RateLimit.MaxBuckets != next.DefaultPolicy.RateLimit.MaxBuckets)
	add("default_policy.auto_ban.max_tracked_clients", current.DefaultPolicy.AutoBan.MaxTrackedClients != next.DefaultPolicy.AutoBan.MaxTrackedClients)
	sort.Strings(fields)
	return fields
}

func validateRoutePolicies(cfg config.Config, table *routes.Table) error {
	known := make(map[string]string)
	for _, route := range table.Routes() {
		known[strings.ToLower(route.Name)] = route.Name
	}
	seen := make(map[string]string)
	for name := range cfg.RoutePolicies {
		key := strings.ToLower(strings.TrimSpace(name))
		if canonical, exists := known[key]; !exists {
			return fmt.Errorf("route policy %q does not match any EdgeProxy route", name)
		} else if previous, duplicate := seen[key]; duplicate {
			return fmt.Errorf("route policies %q and %q refer to the same case-insensitive EdgeProxy route %q", previous, name, canonical)
		}
		seen[key] = name
	}
	return nil
}

func resolveEdgeConfigPath(securityConfigPath, edgeConfigPath string) string {
	if filepath.IsAbs(edgeConfigPath) {
		return edgeConfigPath
	}
	return filepath.Clean(filepath.Join(filepath.Dir(securityConfigPath), edgeConfigPath))
}
func (r *Runtime) canonicalRouteName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	for _, route := range r.Routes() {
		if strings.EqualFold(route.Name, name) {
			return route.Name, true
		}
	}
	return "", false
}

func (r *Runtime) routeExists(name string) bool {
	_, ok := r.canonicalRouteName(name)
	return ok
}

func cloneConfig(in config.Config) config.Config {
	out := in
	out.Server = cloneServerConfig(in.Server)
	out.Admin.Connectivity.DNS.Names = append([]string(nil), in.Admin.Connectivity.DNS.Names...)
	out.Admin.Connectivity.DNS.ExpectedAddresses = append([]string(nil), in.Admin.Connectivity.DNS.ExpectedAddresses...)
	out.WAF.CustomRules = make([]config.CustomRuleConfig, len(in.WAF.CustomRules))
	for i, rule := range in.WAF.CustomRules {
		out.WAF.CustomRules[i] = rule
		out.WAF.CustomRules[i].Targets = append([]string(nil), rule.Targets...)
	}
	out.RoutePolicies = map[string]config.Policy{}
	for k, v := range in.RoutePolicies {
		out.RoutePolicies[k] = clonePolicy(v)
	}
	out.DefaultPolicy = clonePolicy(in.DefaultPolicy)
	return out
}
func cloneServerConfig(in config.ServerConfig) config.ServerConfig {
	out := in
	out.TrustedProxyCIDRs = append([]string(nil), in.TrustedProxyCIDRs...)
	return out
}
func clonePolicy(in config.Policy) config.Policy {
	out := in
	out.BodyContentTypes = append([]string(nil), in.BodyContentTypes...)
	out.AllowedMethods = append([]string(nil), in.AllowedMethods...)
	out.ExcludedPathPrefixes = append([]string(nil), in.ExcludedPathPrefixes...)
	out.DisabledRules = append([]string(nil), in.DisabledRules...)
	out.IPAllowlist = append([]string(nil), in.IPAllowlist...)
	out.IPDenylist = append([]string(nil), in.IPDenylist...)
	return out
}
