package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/control"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

type Server struct {
	cfg        config.AdminConfig
	logger     *slog.Logger
	metrics    *metrics.Registry
	proxy      *proxy.Handler
	logs       *accesslog.Store
	controller *control.Manager
	http       *http.Server
}

func New(cfg config.AdminConfig, logger *slog.Logger, registry *metrics.Registry, handler *proxy.Handler, logStore *accesslog.Store, controllers ...*control.Manager) *Server {
	var controller *control.Manager
	if len(controllers) > 0 {
		controller = controllers[0]
	}
	s := &Server{cfg: cfg, logger: logger, metrics: registry, proxy: handler, logs: logStore, controller: controller}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/metrics", s.auth(s.metricsHandler))
	mux.HandleFunc("GET /api/v1/status", s.auth(s.statusHandler))
	mux.HandleFunc("GET /api/v1/telemetry", s.auth(s.telemetryHandler))
	mux.HandleFunc("GET /api/v1/routes/{route}/telemetry", s.auth(s.routeTelemetryHandler))
	mux.HandleFunc("GET /api/v1/routes/{route}/origins/{origin}/telemetry", s.auth(s.originTelemetryHandler))
	mux.HandleFunc("GET /api/v1/logs", s.auth(s.logsHandler))
	mux.HandleFunc("DELETE /api/v1/logs", s.auth(s.clearLogsHandler))
	mux.HandleFunc("POST /api/v1/cache/purge", s.auth(s.purgeHandler))
	if controller != nil {
		mux.HandleFunc("GET /api/v1/config", s.auth(s.configGet))
		mux.HandleFunc("PUT /api/v1/config", s.auth(s.configReplace))
		mux.HandleFunc("POST /api/v1/config/reload", s.auth(s.configReload))
		mux.HandleFunc("GET /api/v1/config/watch", s.auth(s.configWatch))
		mux.HandleFunc("GET /api/v1/server", s.auth(s.serverConfigGet))
		mux.HandleFunc("PUT /api/v1/server", s.auth(s.serverConfigUpdate))
		mux.HandleFunc("GET /api/v1/admin", s.auth(s.adminConfigGet))
		mux.HandleFunc("PUT /api/v1/admin", s.auth(s.adminConfigUpdate))
		mux.HandleFunc("GET /api/v1/routes", s.auth(s.routesList))
		mux.HandleFunc("POST /api/v1/routes", s.auth(s.routesCreate))
		mux.HandleFunc("GET /api/v1/routes/{route}", s.auth(s.routeGet))
		mux.HandleFunc("PUT /api/v1/routes/{route}", s.auth(s.routeUpdate))
		mux.HandleFunc("DELETE /api/v1/routes/{route}", s.auth(s.routeDelete))
		mux.HandleFunc("GET /api/v1/routes/{route}/load-balancing", s.auth(s.routeLoadBalancingGet))
		mux.HandleFunc("PUT /api/v1/routes/{route}/load-balancing", s.auth(s.routeLoadBalancingUpdate))
		mux.HandleFunc("GET /api/v1/routes/{route}/proxy", s.auth(s.routeProxyGet))
		mux.HandleFunc("PUT /api/v1/routes/{route}/proxy", s.auth(s.routeProxyUpdate))
		mux.HandleFunc("GET /api/v1/routes/{route}/cache", s.auth(s.routeCacheGet))
		mux.HandleFunc("PUT /api/v1/routes/{route}/cache", s.auth(s.routeCacheUpdate))
		mux.HandleFunc("POST /api/v1/routes/{route}/cache/purge", s.auth(s.routePurgeHandler))
		mux.HandleFunc("GET /api/v1/routes/{route}/health-check", s.auth(s.routeHealthCheckGet))
		mux.HandleFunc("PUT /api/v1/routes/{route}/health-check", s.auth(s.routeHealthCheckUpdate))
		mux.HandleFunc("GET /api/v1/routes/{route}/origins", s.auth(s.originsList))
		mux.HandleFunc("POST /api/v1/routes/{route}/origins", s.auth(s.originsCreate))
		mux.HandleFunc("GET /api/v1/routes/{route}/origins/{origin}", s.auth(s.originGet))
		mux.HandleFunc("PUT /api/v1/routes/{route}/origins/{origin}", s.auth(s.originUpdate))
		mux.HandleFunc("DELETE /api/v1/routes/{route}/origins/{origin}", s.auth(s.originDelete))
	}
	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return s
}

func (s *Server) HTTPServer() *http.Server { return s.http }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AuthToken != "" && !validBearerAuthorization(r.Header, s.cfg.AuthToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="edgeproxy-admin"`)
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "a valid Bearer token is required")
			return
		}
		next(w, r)
	}
}

func validBearerAuthorization(header http.Header, expected string) bool {
	values := header.Values("Authorization")
	// Authorization is a singleton credential field. Reject repeated field lines
	// instead of accepting whichever value Header.Get happens to return; otherwise
	// intermediaries and the application can authenticate different credentials.
	if len(values) != 1 {
		return false
	}
	parts := strings.Fields(values[0])
	return len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && secureTokenEqual(parts[1], expected)
}

func secureTokenEqual(got, want string) bool {
	gotHash := sha256.Sum256([]byte(got))
	wantHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	generatedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "generated_at": generatedAt})
		return
	}
	readiness := s.proxy.Readiness()
	if !readiness.Ready {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":       "not_ready",
			"generated_at": generatedAt,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ready",
		"generated_at": generatedAt,
	})
}

func (s *Server) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.metrics.Snapshot())
}

func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	status := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"routes":       s.proxy.RouteStatuses(),
	}
	if s.logs != nil {
		status["log_store"] = s.logs.Stats()
	} else {
		status["log_store"] = accesslog.Stats{Enabled: false}
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	if s.logs == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "logs_disabled", "the in-memory admin log store is disabled")
		return
	}
	filter, err := s.parseLogFilter(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.logs.Query(filter))
}

func (s *Server) clearLogsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.logs == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "logs_disabled", "the in-memory admin log store is disabled")
		return
	}
	removed := s.logs.Clear()
	s.logger.Warn("admin log store cleared", "removed_entries", removed)
	writeJSON(w, http.StatusOK, map[string]any{
		"removed_entries": removed,
		"cleared_at":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) purgeHandler(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	if route == "" {
		writeAPIError(w, http.StatusBadRequest, "missing_route", "route query parameter is required")
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	pathPrefix := strings.TrimSpace(r.URL.Query().Get("path_prefix"))
	count, ok, err := s.proxy.PurgeCache(route, host, pathPrefix)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route was not found or its cache is disabled")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_path_prefix", err.Error())
		return
	}
	s.logger.Info("cache purged", "route", route, "host", host, "path_prefix", pathPrefix, "entries", count)
	if s.logs != nil {
		s.logs.Append(accesslog.Entry{
			Level:   "INFO",
			Event:   "cache_purged",
			Message: "route cache entries purged through admin API",
			Route:   route,
			Host:    host,
			Path:    pathPrefix,
			Tags:    []string{"admin", "cache"},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"purged_entries": count,
		"route":          route,
		"host":           host,
		"path_prefix":    pathPrefix,
		"purged_at":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) parseLogFilter(r *http.Request) (accesslog.Filter, error) {
	query := r.URL.Query()
	limit := s.cfg.LogStore.DefaultPageSize
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return accesslog.Filter{}, errors.New("limit must be a positive integer")
		}
		limit = parsed
	}
	if limit > s.cfg.LogStore.MaxPageSize {
		return accesslog.Filter{}, fmt.Errorf("limit cannot exceed %d", s.cfg.LogStore.MaxPageSize)
	}

	filter := accesslog.Filter{
		Route:       strings.TrimSpace(query.Get("route")),
		Upstream:    strings.TrimSpace(query.Get("upstream")),
		RequestID:   strings.TrimSpace(query.Get("request_id")),
		Method:      strings.TrimSpace(query.Get("method")),
		Event:       strings.TrimSpace(query.Get("event")),
		Level:       strings.TrimSpace(query.Get("level")),
		CacheStatus: strings.TrimSpace(query.Get("cache")),
		Search:      strings.TrimSpace(query.Get("q")),
		Limit:       limit,
	}

	if raw := strings.TrimSpace(query.Get("before_sequence")); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || value == 0 {
			return accesslog.Filter{}, errors.New("before_sequence must be a positive integer")
		}
		filter.BeforeSequence = value
	}

	if raw := strings.ToLower(strings.TrimSpace(query.Get("status"))); raw != "" {
		if len(raw) == 3 && raw[1:] == "xx" && raw[0] >= '1' && raw[0] <= '5' {
			filter.StatusClass = raw
		} else {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 100 || value > 599 {
				return accesslog.Filter{}, errors.New("status must be an HTTP status code or class such as 5xx")
			}
			filter.Status = value
		}
	}

	if raw := strings.TrimSpace(query.Get("min_duration_ms")); raw != "" {
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return accesslog.Filter{}, errors.New("min_duration_ms must be a finite non-negative number")
		}
		filter.MinDurationMS = value
	}

	var err error
	if raw := strings.TrimSpace(query.Get("since")); raw != "" {
		filter.Since, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return accesslog.Filter{}, errors.New("since must be an RFC3339 timestamp")
		}
	}
	if raw := strings.TrimSpace(query.Get("until")); raw != "" {
		filter.Until, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return accesslog.Filter{}, errors.New("until must be an RFC3339 timestamp")
		}
	}
	if !filter.Since.IsZero() && !filter.Until.IsZero() && filter.Since.After(filter.Until) {
		return accesslog.Filter{}, errors.New("since cannot be after until")
	}
	return filter, nil
}

type apiError struct {
	Error apiErrorBody `json:"error"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: apiErrorBody{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}
