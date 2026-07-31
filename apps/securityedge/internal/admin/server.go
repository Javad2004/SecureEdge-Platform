package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/waf"
)

//go:embed web/*
var webAssets embed.FS

type Runtime interface {
	Config() config.Config
	Routes() []routes.Route
	EffectivePolicy(route string) config.Policy
	UpdateDefaultPolicy(config.Policy) error
	UpdateRoutePolicy(string, config.Policy) error
	DeleteRoutePolicy(string) error
	Reload() error
	LimiterSize() int
	EdgeJSON(context.Context, string, string, url.Values, any) (json.RawMessage, int, error)
}

type Server struct {
	cfg       config.AdminConfig
	runtime   Runtime
	registry  *metrics.Registry
	logs      *securitylog.Store
	inspector *waf.Inspector
	http      *http.Server
}

func New(cfg config.AdminConfig, runtime Runtime, registry *metrics.Registry, logs *securitylog.Store, inspector *waf.Inspector) (*Server, error) {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, runtime: runtime, registry: registry, logs: logs, inspector: inspector}
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", secureStatic(http.FileServer(http.FS(sub)))))
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/session", s.auth(s.session))
	mux.HandleFunc("GET /api/v1/status", s.auth(s.status))
	mux.HandleFunc("GET /api/v1/metrics", s.auth(s.securityMetrics))
	mux.HandleFunc("GET /api/v1/logs", s.auth(s.logsHandler))
	mux.HandleFunc("DELETE /api/v1/logs", s.auth(s.clearLogs))
	mux.HandleFunc("GET /api/v1/rules", s.auth(s.rules))
	mux.HandleFunc("GET /api/v1/policies", s.auth(s.policies))
	mux.HandleFunc("PUT /api/v1/policies/default", s.auth(s.updateDefaultPolicy))
	mux.HandleFunc("PUT /api/v1/policies/{route}", s.auth(s.updateRoutePolicy))
	mux.HandleFunc("DELETE /api/v1/policies/{route}", s.auth(s.deleteRoutePolicy))
	mux.HandleFunc("POST /api/v1/reload", s.auth(s.reload))
	mux.HandleFunc("GET /api/v1/dashboard/overview", s.auth(s.overview))
	mux.HandleFunc("GET /api/v1/edgeproxy/status", s.auth(s.edgeStatus))
	mux.HandleFunc("GET /api/v1/edgeproxy/metrics", s.auth(s.edgeMetrics))
	mux.HandleFunc("GET /api/v1/edgeproxy/logs", s.auth(s.edgeLogs))
	mux.HandleFunc("DELETE /api/v1/edgeproxy/logs", s.auth(s.edgeClearLogs))
	mux.HandleFunc("POST /api/v1/edgeproxy/cache/purge", s.auth(s.edgePurge))
	s.http = &http.Server{Addr: cfg.ListenAddr, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 1 << 20}
	return s, nil
}
func (s *Server) HTTPServer() *http.Server { return s.http }
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AuthToken != "" {
			parts := strings.Fields(r.Header.Get("Authorization"))
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || subtle.ConstantTimeCompare([]byte(parts[1]), []byte(s.cfg.AuthToken)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="securityedge-admin"`)
				writeError(w, http.StatusUnauthorized, "unauthorized", "a valid Bearer token is required")
				return
			}
		}
		next(w, r)
	}
}
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "dashboard unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "generated_at": now()})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	raw, status, err := s.runtime.EdgeJSON(ctx, http.MethodGet, "/readyz", nil, nil)
	if err != nil {
		writeJSON(w, 503, map[string]any{"status": "not_ready", "generated_at": now(), "dependency": "edgeproxy", "error": err.Error()})
		return
	}
	if status != 200 {
		writeRaw(w, 503, raw)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ready", "generated_at": now(), "edgeproxy": json.RawMessage(raw)})
}
func (s *Server) session(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"authenticated": true, "generated_at": now()})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	edgeRaw, edgeStatus, edgeErr := s.runtime.EdgeJSON(r.Context(), http.MethodGet, "/api/v1/status", nil, nil)
	cfg := s.runtime.Config()
	out := map[string]any{"generated_at": now(), "mode": cfg.Server.Mode, "routes": s.runtime.Routes(), "log_store": s.logs.Stats(), "rate_limit_buckets": s.runtime.LimiterSize(), "edgeproxy": map[string]any{"reachable": edgeErr == nil, "http_status": edgeStatus}}
	if edgeErr != nil {
		out["edgeproxy"].(map[string]any)["error"] = edgeErr.Error()
	} else {
		out["edgeproxy"].(map[string]any)["status"] = json.RawMessage(edgeRaw)
	}
	writeJSON(w, 200, out)
}
func (s *Server) securityMetrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.registry.Snapshot())
}
func (s *Server) rules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"generated_at": now(), "rules": s.inspector.Rules()})
}
func (s *Server) policies(w http.ResponseWriter, _ *http.Request) {
	cfg := s.runtime.Config()
	effective := map[string]config.Policy{}
	for _, route := range s.runtime.Routes() {
		effective[route.Name] = s.runtime.EffectivePolicy(route.Name)
	}
	writeJSON(w, 200, map[string]any{"generated_at": now(), "default_policy": cfg.DefaultPolicy, "route_policies": cfg.RoutePolicies, "effective_policies": effective, "routes": s.runtime.Routes()})
}
func (s *Server) updateDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	var p config.Policy
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, 400, "invalid_body", err.Error())
		return
	}
	if err := s.runtime.UpdateDefaultPolicy(p); err != nil {
		writeError(w, 400, "invalid_policy", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"updated": true, "scope": "default", "policy": s.runtime.EffectivePolicy("")})
}
func (s *Server) updateRoutePolicy(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.PathValue("route"))
	if route == "" || route == "default" {
		writeError(w, 400, "invalid_route", "route name is required")
		return
	}
	var p config.Policy
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, 400, "invalid_body", err.Error())
		return
	}
	if err := s.runtime.UpdateRoutePolicy(route, p); err != nil {
		writeError(w, 400, "invalid_policy", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"updated": true, "route": route, "policy": s.runtime.EffectivePolicy(route)})
}
func (s *Server) deleteRoutePolicy(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.PathValue("route"))
	if err := s.runtime.DeleteRoutePolicy(route); err != nil {
		writeError(w, 400, "delete_failed", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "route": route, "effective_policy": s.runtime.EffectivePolicy(route)})
}
func (s *Server) reload(w http.ResponseWriter, _ *http.Request) {
	if err := s.runtime.Reload(); err != nil {
		writeError(w, 500, "reload_failed", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"reloaded": true, "reloaded_at": now()})
}
func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	f, err := s.parseLogFilter(r)
	if err != nil {
		writeError(w, 400, "invalid_query", err.Error())
		return
	}
	writeJSON(w, 200, s.logs.Query(f))
}
func (s *Server) clearLogs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"removed_entries": s.logs.Clear(), "cleared_at": now()})
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	edgeStatus, ss, se := s.runtime.EdgeJSON(ctx, http.MethodGet, "/api/v1/status", nil, nil)
	edgeMetrics, ms, me := s.runtime.EdgeJSON(ctx, http.MethodGet, "/api/v1/metrics", nil, nil)
	out := map[string]any{"generated_at": now(), "security_metrics": s.registry.Snapshot(), "security_logs": s.logs.Query(securitylog.Filter{Limit: 10}), "edgeproxy_status_code": ss, "edgeproxy_metrics_status_code": ms}
	if se != nil {
		out["edgeproxy_status_error"] = se.Error()
	} else {
		out["edgeproxy_status"] = json.RawMessage(edgeStatus)
	}
	if me != nil {
		out["edgeproxy_metrics_error"] = me.Error()
	} else {
		out["edgeproxy_metrics"] = json.RawMessage(edgeMetrics)
	}
	writeJSON(w, 200, out)
}
func (s *Server) edgeStatus(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/status", nil)
}
func (s *Server) edgeMetrics(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/metrics", nil)
}
func (s *Server) edgeLogs(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/logs", r.URL.Query())
}
func (s *Server) edgeClearLogs(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodDelete, "/api/v1/logs", nil)
}
func (s *Server) edgePurge(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodPost, "/api/v1/cache/purge", r.URL.Query())
}
func (s *Server) forward(w http.ResponseWriter, r *http.Request, method, path string, q url.Values) {
	raw, status, err := s.runtime.EdgeJSON(r.Context(), method, path, q, nil)
	if err != nil {
		writeError(w, 502, "edgeproxy_unavailable", err.Error())
		return
	}
	writeRaw(w, status, raw)
}
func (s *Server) parseLogFilter(r *http.Request) (securitylog.Filter, error) {
	q := r.URL.Query()
	limit := s.cfg.LogStore.DefaultPageSize
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return securitylog.Filter{}, errors.New("limit must be a positive integer")
		}
		limit = n
	}
	if limit > s.cfg.LogStore.MaxPageSize {
		return securitylog.Filter{}, fmt.Errorf("limit cannot exceed %d", s.cfg.LogStore.MaxPageSize)
	}
	f := securitylog.Filter{Route: strings.TrimSpace(q.Get("route")), RequestID: strings.TrimSpace(q.Get("request_id")), Method: strings.TrimSpace(q.Get("method")), Event: strings.TrimSpace(q.Get("event")), Level: strings.TrimSpace(q.Get("level")), Action: strings.TrimSpace(q.Get("action")), RuleID: strings.TrimSpace(q.Get("rule_id")), Search: strings.TrimSpace(q.Get("q")), Limit: limit}
	if raw := strings.TrimSpace(q.Get("status")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 100 || n > 599 {
			return securitylog.Filter{}, errors.New("status must be an HTTP status code")
		}
		f.Status = n
	}
	if raw := strings.TrimSpace(q.Get("before_sequence")); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || n == 0 {
			return securitylog.Filter{}, errors.New("before_sequence must be positive")
		}
		f.BeforeSequence = n
	}
	var err error
	if raw := strings.TrimSpace(q.Get("since")); raw != "" {
		f.Since, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return securitylog.Filter{}, errors.New("since must be RFC3339")
		}
	}
	if raw := strings.TrimSpace(q.Get("until")); raw != "" {
		f.Until, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return securitylog.Filter{}, errors.New("until must be RFC3339")
		}
	}
	return f, nil
}
func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	const maxBody = 1 << 20
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(data) > maxBody {
		return errors.New("request body exceeds 1048576 bytes")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeRaw(w http.ResponseWriter, status int, raw json.RawMessage) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func secureStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
