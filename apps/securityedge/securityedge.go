package securityedge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
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
	configMu  sync.Mutex
	mu        sync.RWMutex
	cfg       config.Config
	table     *routes.Table
	edge      *edgeadmin.Client
	registry  *metrics.Registry
	logs      *securitylog.Store
	traffic   *traffic.Tracker
	inspector *waf.Inspector
	limiter   *ratelimit.Limiter
	bans      *ratelimit.BanManager
	admission *admission.Limiter
	clients   *clientip.Resolver
	watchMu   sync.RWMutex
	watch     WatchStatus
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

func prepareRuntimeConfig(configPath string, cfg config.Config) (preparedRuntime, error) {
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
	prepared, err := prepareRuntime(configPath)
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
		bans:    ratelimit.NewBanManager(), admission: admission.New(), clients: prepared.clients,
	}, nil
}

func (r *Runtime) Close() {
	r.limiter.Close()
	r.mu.RLock()
	edge := r.edge
	r.mu.RUnlock()
	if edge != nil {
		edge.CloseIdleConnections()
	}
	if err := r.logs.Close(); err != nil {
		r.logger.Error("close security log", "error", err)
	}
}

func (r *Runtime) Wrap(next http.Handler) http.Handler {
	return gateway.New(next, r, r, r.inspector, r.limiter, r.bans, r.admission, r.clients, r.registry, r.logs, r.traffic, r.logger)
}

func (r *Runtime) AdminHandler() (http.Handler, error) {
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()
	srv, err := admin.New(cfg.Admin, r, r.registry, r.logs, r.traffic, r.inspector)
	if err != nil {
		return nil, err
	}
	return srv.HTTPServer().Handler, nil
}

func (r *Runtime) AdminServer() (*http.Server, error) {
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()
	srv, err := admin.New(cfg.Admin, r, r.registry, r.logs, r.traffic, r.inspector)
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
	return r.update(func(cfg *config.Config) { cfg.DefaultPolicy = p })
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

	cfg, err := config.Load(r.configPath)
	if err != nil {
		return err
	}
	prepared, err := r.prepareReload(cfg)
	if err != nil {
		return err
	}
	return r.applyReload(prepared)
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
