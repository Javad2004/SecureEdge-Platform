package admin

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bachelor-project/edgeproxy/internal/config"
	"github.com/bachelor-project/edgeproxy/internal/metrics"
	"github.com/bachelor-project/edgeproxy/internal/proxy"
)

type Server struct {
	cfg     config.AdminConfig
	logger  *slog.Logger
	metrics *metrics.Registry
	proxy   *proxy.Handler
	http    *http.Server
}

func New(cfg config.AdminConfig, logger *slog.Logger, registry *metrics.Registry, handler *proxy.Handler) *Server {
	s := &Server{cfg: cfg, logger: logger, metrics: registry, proxy: handler}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/metrics", s.auth(s.metricsHandler))
	mux.HandleFunc("GET /api/v1/status", s.auth(s.statusHandler))
	mux.HandleFunc("POST /api/v1/cache/purge", s.auth(s.purgeHandler))
	s.http = &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	return s
}

func (s *Server) HTTPServer() *http.Server { return s.http }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AuthToken != "" {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AuthToken)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
func (s *Server) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.metrics.Snapshot())
}
func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"routes": s.proxy.RouteStatuses()})
}
func (s *Server) purgeHandler(w http.ResponseWriter, r *http.Request) {
	route := r.URL.Query().Get("route")
	if route == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "route query parameter is required"})
		return
	}
	count, ok := s.proxy.PurgeCache(route, r.URL.Query().Get("host"), r.URL.Query().Get("path_prefix"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found or cache disabled"})
		return
	}
	s.logger.Info("cache purged", "route", route, "entries", count)
	writeJSON(w, http.StatusOK, map[string]any{"purged_entries": count})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
