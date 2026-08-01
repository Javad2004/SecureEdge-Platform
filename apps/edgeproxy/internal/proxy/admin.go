package proxy

import (
	"sort"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/cache"
)

type RouteStatus struct {
	Name      string           `json:"name"`
	Ready     bool             `json:"ready"`
	Upstreams []map[string]any `json:"upstreams"`
	Cache     *cache.Stats     `json:"cache,omitempty"`
}

type ReadinessStatus struct {
	Ready           bool     `json:"ready"`
	UnhealthyRoutes []string `json:"unhealthy_routes"`
}

func (h *Handler) RouteStatuses() []RouteStatus {
	names := make([]string, 0, len(h.routes))
	for name := range h.routes {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]RouteStatus, 0, len(names))
	for _, name := range names {
		rt := h.routes[name]
		status := RouteStatus{
			Name:      rt.cfg.Name,
			Ready:     rt.pool.hasHealthy(),
			Upstreams: rt.pool.healthSnapshot(),
		}
		if rt.cache != nil {
			stats := rt.cache.Stats()
			status.Cache = &stats
		}
		out = append(out, status)
	}
	return out
}

// Readiness reports whether every configured route currently has at least one
// healthy origin. Liveness is intentionally separate: the process may be alive
// while it is temporarily unable to serve one or more routes.
func (h *Handler) Readiness() ReadinessStatus {
	status := ReadinessStatus{Ready: true, UnhealthyRoutes: []string{}}
	for name, rt := range h.routes {
		if !rt.pool.hasHealthy() {
			status.Ready = false
			status.UnhealthyRoutes = append(status.UnhealthyRoutes, name)
		}
	}
	sort.Strings(status.UnhealthyRoutes)
	return status
}

func (h *Handler) PurgeCache(routeName, host, pathPrefix string) (int, bool) {
	rt, ok := h.routes[routeName]
	if !ok || rt.cache == nil {
		return 0, false
	}
	if host == "" && pathPrefix == "" {
		return rt.cache.Clear(), true
	}
	return rt.cache.Purge(host, pathPrefix), true
}
