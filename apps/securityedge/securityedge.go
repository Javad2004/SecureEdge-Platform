package securityedge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
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
	mu         sync.RWMutex
	cfg        config.Config
	table      *routes.Table
	edge       *edgeadmin.Client
	registry   *metrics.Registry
	logs       *securitylog.Store
	traffic    *traffic.Tracker
	inspector  *waf.Inspector
	limiter    *ratelimit.Limiter
	bans       *ratelimit.BanManager
	admission  *admission.Limiter
	clients    *clientip.Resolver
}

func New(configPath string, logger *slog.Logger) (*Runtime, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	table, err := routes.Load(resolveEdgeConfigPath(configPath, cfg.EdgeProxy.ConfigPath))
	if err != nil {
		return nil, err
	}
	if err := validateRoutePolicies(cfg, table); err != nil {
		return nil, err
	}
	edge, err := edgeadmin.New(cfg.EdgeProxy.AdminURL, cfg.EdgeProxy.AdminToken, cfg.EdgeProxy.Timeout.Duration)
	if err != nil {
		return nil, err
	}
	inspector, err := waf.NewInspector(cfg.WAF.CustomRules, cfg.WAF.MaximumMatchesPerRequest)
	if err != nil {
		return nil, err
	}
	clients, err := clientip.New(cfg.Server.TrustedProxyCIDRs, cfg.Server.ForwardedForHeader)
	if err != nil {
		return nil, err
	}
	logs, err := securitylog.NewWithConfig(cfg.Admin.LogStore)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		configPath: configPath, logger: logger, cfg: cfg, table: table, edge: edge,
		registry: metrics.New(), logs: logs, traffic: traffic.New(traffic.DefaultCapacity, traffic.DefaultWindow), inspector: inspector,
		limiter: ratelimit.New(cfg.DefaultPolicy.RateLimit.CleanupInterval.Duration, cfg.DefaultPolicy.RateLimit.IdleTTL.Duration),
		bans:    ratelimit.NewBanManager(), admission: admission.New(), clients: clients,
	}, nil
}

func (r *Runtime) Close() {
	r.limiter.Close()
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
	if !r.routeExists(route) {
		return fmt.Errorf("route %q does not exist in edgeproxy config", route)
	}
	return r.update(func(cfg *config.Config) {
		if cfg.RoutePolicies == nil {
			cfg.RoutePolicies = map[string]config.Policy{}
		}
		cfg.RoutePolicies[route] = p
	})
}
func (r *Runtime) DeleteRoutePolicy(route string) error {
	if route == "" {
		return fmt.Errorf("route name is required")
	}
	return r.update(func(cfg *config.Config) { delete(cfg.RoutePolicies, route) })
}

func (r *Runtime) Reload() error {
	cfg, err := config.Load(r.configPath)
	if err != nil {
		return err
	}
	table, err := routes.Load(resolveEdgeConfigPath(r.configPath, cfg.EdgeProxy.ConfigPath))
	if err != nil {
		return err
	}
	if err := validateRoutePolicies(cfg, table); err != nil {
		return err
	}
	edge, err := edgeadmin.New(cfg.EdgeProxy.AdminURL, cfg.EdgeProxy.AdminToken, cfg.EdgeProxy.Timeout.Duration)
	if err != nil {
		return err
	}
	if err := r.inspector.Replace(cfg.WAF.CustomRules, cfg.WAF.MaximumMatchesPerRequest); err != nil {
		return err
	}
	if err := r.clients.Replace(cfg.Server.TrustedProxyCIDRs, cfg.Server.ForwardedForHeader); err != nil {
		return err
	}
	r.mu.Lock()
	r.cfg = cfg
	r.table = table
	r.edge = edge
	r.mu.Unlock()
	return nil
}

func (r *Runtime) update(mutator func(*config.Config)) error {
	candidate, err := config.LoadFile(r.configPath)
	if err != nil {
		return err
	}
	mutator(&candidate)
	if err := candidate.Validate(); err != nil {
		return err
	}
	if err := config.Save(r.configPath, candidate); err != nil {
		return err
	}
	return r.Reload()
}

func validateRoutePolicies(cfg config.Config, table *routes.Table) error {
	known := make(map[string]struct{})
	for _, route := range table.Routes() {
		known[route.Name] = struct{}{}
	}
	for name := range cfg.RoutePolicies {
		if _, exists := known[name]; !exists {
			return fmt.Errorf("route policy %q does not match any EdgeProxy route", name)
		}
	}
	return nil
}

func resolveEdgeConfigPath(securityConfigPath, edgeConfigPath string) string {
	if filepath.IsAbs(edgeConfigPath) {
		return edgeConfigPath
	}
	return filepath.Clean(filepath.Join(filepath.Dir(securityConfigPath), edgeConfigPath))
}
func (r *Runtime) routeExists(name string) bool {
	for _, route := range r.Routes() {
		if route.Name == name {
			return true
		}
	}
	return false
}

func cloneConfig(in config.Config) config.Config {
	out := in
	out.Server = cloneServerConfig(in.Server)
	out.WAF.CustomRules = append([]config.CustomRuleConfig(nil), in.WAF.CustomRules...)
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
