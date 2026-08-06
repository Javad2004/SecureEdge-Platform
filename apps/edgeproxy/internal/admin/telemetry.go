package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/control"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

type telemetryEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	GeneratedAt   string              `json:"generated_at"`
	Metrics       metrics.Snapshot    `json:"metrics"`
	Routes        []proxy.RouteStatus `json:"routes"`
	Watch         any                 `json:"watch,omitempty"`
}

func (s *Server) telemetryHandler(w http.ResponseWriter, _ *http.Request) {
	out := telemetryEnvelope{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Metrics:       s.metrics.Snapshot(),
		Routes:        s.proxy.RouteStatuses(),
	}
	if s.controller != nil {
		out.Watch = s.controller.WatchStatus()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) routeTelemetryHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("route"))
	cfg, route, found := s.findConfiguredRoute(name)
	if !found {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route was not found")
		return
	}
	snapshot := s.metrics.Snapshot()
	metric, ok := findRouteMetrics(snapshot.Routes, route.Name)
	if !ok {
		metric = metrics.RouteSnapshot{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": "1.0",
		"generated_at":   snapshot.GeneratedAt,
		"route":          route,
		"runtime":        findRouteStatus(s.proxy.RouteStatuses(), route.Name),
		"metrics":        metric,
		"total_routes":   len(cfg.Routes),
	})
}

func (s *Server) originTelemetryHandler(w http.ResponseWriter, r *http.Request) {
	_, route, found := s.findConfiguredRoute(strings.TrimSpace(r.PathValue("route")))
	if !found {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route was not found")
		return
	}
	originName := strings.TrimSpace(r.PathValue("origin"))
	originIndex, originFound := control.FindOrigin(&route, originName)
	if !originFound {
		writeAPIError(w, http.StatusNotFound, "origin_not_found", "origin was not found")
		return
	}
	origin := route.Upstreams[originIndex]
	snapshot := s.metrics.Snapshot()
	routeMetric, _ := findRouteMetrics(snapshot.Routes, route.Name)
	originMetric := metrics.UpstreamSnapshot{}
	for endpoint, candidate := range routeMetric.Upstreams {
		if endpoint == origin.URL {
			originMetric = candidate
			break
		}
	}
	var live map[string]any
	if status := findRouteStatus(s.proxy.RouteStatuses(), route.Name); status != nil {
		for _, candidate := range status.Upstreams {
			if strings.EqualFold(stringValue(candidate["name"]), origin.Name) || stringValue(candidate["url"]) == origin.URL {
				live = candidate
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": "1.0",
		"generated_at":   snapshot.GeneratedAt,
		"route":          route.Name,
		"origin":         origin,
		"runtime":        live,
		"metrics":        originMetric,
	})
}

func (s *Server) findConfiguredRoute(name string) (config.Config, config.RouteConfig, bool) {
	var cfg config.Config
	if s.controller != nil {
		cfg = s.controller.Config()
	}
	for _, route := range cfg.Routes {
		if strings.EqualFold(strings.TrimSpace(route.Name), name) {
			return cfg, route, true
		}
	}
	return cfg, config.RouteConfig{}, false
}

func findRouteMetrics(values map[string]metrics.RouteSnapshot, name string) (metrics.RouteSnapshot, bool) {
	for key, value := range values {
		if strings.EqualFold(strings.TrimSpace(key), strings.TrimSpace(name)) {
			return value, true
		}
	}
	return metrics.RouteSnapshot{}, false
}

func findRouteStatus(values []proxy.RouteStatus, name string) *proxy.RouteStatus {
	for i := range values {
		if strings.EqualFold(strings.TrimSpace(values[i].Name), strings.TrimSpace(name)) {
			return &values[i]
		}
	}
	return nil
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
