package proxy

import "github.com/bachelor-project/edgeproxy/internal/cache"

type RouteStatus struct {
	Name      string           `json:"name"`
	Upstreams []map[string]any `json:"upstreams"`
	Cache     *cache.Stats     `json:"cache,omitempty"`
}

func (h *Handler) RouteStatuses() []RouteStatus {
	out := make([]RouteStatus, 0, len(h.routes))
	for _, rt := range h.routes {
		status := RouteStatus{Name: rt.cfg.Name, Upstreams: rt.pool.healthSnapshot()}
		if rt.cache != nil {
			stats := rt.cache.Stats()
			status.Cache = &stats
		}
		out = append(out, status)
	}
	return out
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
