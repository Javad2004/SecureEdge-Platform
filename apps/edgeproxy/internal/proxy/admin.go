package proxy

import (
	"errors"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/cache"
)

type RouteStatus struct {
	Name      string           `json:"name"`
	Ready     bool             `json:"ready"`
	Scheduler map[string]any   `json:"scheduler"`
	Upstreams []map[string]any `json:"upstreams"`
	Cache     *cache.Stats     `json:"cache,omitempty"`
}

type ReadinessStatus struct {
	Ready           bool     `json:"ready"`
	UnhealthyRoutes []string `json:"unhealthy_routes"`
}

func (h *Handler) RouteStatuses() []RouteStatus {
	h.mu.RLock()
	routes := make(map[string]*routeRuntime, len(h.routes))
	for name, runtime := range h.routes {
		routes[name] = runtime
	}
	h.mu.RUnlock()
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]RouteStatus, 0, len(names))
	for _, name := range names {
		rt := routes[name]
		status := RouteStatus{
			Name:      rt.cfg.Name,
			Ready:     rt.pool.hasHealthy(),
			Scheduler: rt.pool.schedulerSnapshot(),
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
	h.mu.RLock()
	defer h.mu.RUnlock()
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

func (h *Handler) PurgeCache(routeName, host, pathPrefix string) (int, bool, error) {
	h.mu.RLock()
	rt, ok := h.routes[routeName]
	if !ok {
		for name, candidate := range h.routes {
			if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(routeName)) {
				rt, ok = candidate, true
				break
			}
		}
	}
	h.mu.RUnlock()
	if !ok || rt.cache == nil {
		return 0, false, nil
	}
	normalizedPath, err := normalizePurgePathPrefix(pathPrefix)
	if err != nil {
		return 0, true, err
	}
	if host == "" && pathPrefix == "" {
		return rt.cache.Clear(), true, nil
	}
	if host != "" {
		host = cacheHost(host)
	}
	return rt.cache.Purge(host, normalizedPath, cacheKeyRequest), true, nil
}

func normalizePurgePathPrefix(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, "/") {
		return "", errors.New("path_prefix must start with /")
	}
	if strings.ContainsAny(value, "?#") {
		return "", errors.New("path_prefix must contain a path only")
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", errors.New("path_prefix contains invalid escaping")
	}
	if decoded != value {
		return "", errors.New("path_prefix must not contain percent-encoded path bytes")
	}
	value = strings.TrimRight(value, "/")
	if value == "" {
		value = "/"
	}
	if path.Clean(value) != value {
		return "", errors.New("path_prefix must be canonical and must not contain dot-segments or repeated slashes")
	}
	return value, nil
}
