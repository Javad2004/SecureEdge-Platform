package admin

import (
	"net/http"
	"strings"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/control"
)

func (s *Server) serverConfigGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.controller.Config().Server)
}

func (s *Server) serverConfigUpdate(w http.ResponseWriter, r *http.Request) {
	var candidate config.ServerConfig
	if err := decodeControlJSON(r, &candidate); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	result, err := s.controller.Update(func(cfg *config.Config) error {
		cfg.Server = candidate
		return nil
	}, "admin_update_server")
	writeMutationResult(w, result, err, "server_not_found", "server_update_failed")
}

func (s *Server) adminConfigGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.controller.Config().Admin)
}

func (s *Server) adminConfigUpdate(w http.ResponseWriter, r *http.Request) {
	var candidate config.AdminConfig
	if err := decodeControlJSON(r, &candidate); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	result, err := s.controller.Update(func(cfg *config.Config) error {
		cfg.Admin = candidate
		return nil
	}, "admin_update_admin")
	writeMutationResult(w, result, err, "admin_not_found", "admin_update_failed")
}

func (s *Server) routeLoadBalancingGet(w http.ResponseWriter, r *http.Request) {
	route, ok := s.controlRoute(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, route.LoadBalancing)
}

func (s *Server) routeLoadBalancingUpdate(w http.ResponseWriter, r *http.Request) {
	var candidate config.LoadBalancingConfig
	if err := decodeControlJSON(r, &candidate); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	s.updateRouteSection(w, r, "admin_update_load_balancing", func(route *config.RouteConfig) {
		route.LoadBalancing = candidate
	})
}

func (s *Server) routeProxyGet(w http.ResponseWriter, r *http.Request) {
	route, ok := s.controlRoute(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, route.Proxy)
}

func (s *Server) routeProxyUpdate(w http.ResponseWriter, r *http.Request) {
	var candidate config.ProxyConfig
	if err := decodeControlJSON(r, &candidate); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	s.updateRouteSection(w, r, "admin_update_proxy", func(route *config.RouteConfig) {
		route.Proxy = candidate
	})
}

func (s *Server) routeCacheGet(w http.ResponseWriter, r *http.Request) {
	route, ok := s.controlRoute(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, route.Cache)
}

func (s *Server) routeCacheUpdate(w http.ResponseWriter, r *http.Request) {
	var candidate config.CacheConfig
	if err := decodeControlJSON(r, &candidate); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	s.updateRouteSection(w, r, "admin_update_cache", func(route *config.RouteConfig) {
		route.Cache = candidate
	})
}

func (s *Server) routeHealthCheckGet(w http.ResponseWriter, r *http.Request) {
	route, ok := s.controlRoute(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, route.HealthCheck)
}

func (s *Server) routeHealthCheckUpdate(w http.ResponseWriter, r *http.Request) {
	var candidate config.HealthCheckConfig
	if err := decodeControlJSON(r, &candidate); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	s.updateRouteSection(w, r, "admin_update_health_check", func(route *config.RouteConfig) {
		route.HealthCheck = candidate
	})
}

func (s *Server) routePurgeHandler(w http.ResponseWriter, r *http.Request) {
	count, ok, err := s.proxy.PurgeCache(r.PathValue("route"), strings.TrimSpace(r.URL.Query().Get("host")), strings.TrimSpace(r.URL.Query().Get("path_prefix")))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_purge_filter", err.Error())
		return
	}
	if !ok {
		writeAPIError(w, http.StatusNotFound, "cache_not_found", "route was not found or caching is disabled")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"purged": count, "route": r.PathValue("route")})
}

func (s *Server) controlRoute(w http.ResponseWriter, r *http.Request) (config.RouteConfig, bool) {
	cfg := s.controller.Config()
	index, ok := control.FindRoute(&cfg, r.PathValue("route"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route was not found")
		return config.RouteConfig{}, false
	}
	return cfg.Routes[index], true
}

func (s *Server) updateRouteSection(w http.ResponseWriter, r *http.Request, source string, mutate func(*config.RouteConfig)) {
	name := r.PathValue("route")
	result, err := s.controller.Update(func(cfg *config.Config) error {
		index, ok := control.FindRoute(cfg, name)
		if !ok {
			return errNotFound
		}
		mutate(&cfg.Routes[index])
		return nil
	}, source)
	writeMutationResult(w, result, err, "route_not_found", "route_update_failed")
}
