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

	"github.com/bachelor-project/edgeproxy-security/internal/admin"
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/edgeadmin"
	"github.com/bachelor-project/edgeproxy-security/internal/gateway"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/ratelimit"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/waf"
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
	inspector  *waf.Inspector
	limiter    *ratelimit.Limiter
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
	edge, err := edgeadmin.New(cfg.EdgeProxy.AdminURL, cfg.EdgeProxy.AdminToken, cfg.EdgeProxy.Timeout.Duration)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		configPath: configPath,
		logger:     logger,
		cfg:        cfg,
		table:      table,
		edge:       edge,
		registry:   metrics.New(),
		logs:       securitylog.New(cfg.Admin.LogStore.Capacity),
		inspector:  waf.NewInspector(),
		limiter:    ratelimit.New(cfg.DefaultPolicy.RateLimit.CleanupInterval.Duration, cfg.DefaultPolicy.RateLimit.IdleTTL.Duration),
	}, nil
}

func (r *Runtime) Close() { r.limiter.Close() }

func (r *Runtime) Wrap(next http.Handler) http.Handler {
	return gateway.New(next, r, r, r.inspector, r.limiter, r.registry, r.logs, r.logger)
}

func (r *Runtime) AdminHandler() (http.Handler, error) {
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()
	srv, err := admin.New(cfg.Admin, r, r.registry, r.logs, r.inspector)
	if err != nil {
		return nil, err
	}
	return srv.HTTPServer().Handler, nil
}

func (r *Runtime) AdminServer() (*http.Server, error) {
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()
	srv, err := admin.New(cfg.Admin, r, r.registry, r.logs, r.inspector)
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

func (r *Runtime) LimiterSize() int { return r.limiter.Size() }

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
	edge, err := edgeadmin.New(cfg.EdgeProxy.AdminURL, cfg.EdgeProxy.AdminToken, cfg.EdgeProxy.Timeout.Duration)
	if err != nil {
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
	out.RoutePolicies = map[string]config.Policy{}
	for k, v := range in.RoutePolicies {
		out.RoutePolicies[k] = clonePolicy(v)
	}
	out.DefaultPolicy = clonePolicy(in.DefaultPolicy)
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
