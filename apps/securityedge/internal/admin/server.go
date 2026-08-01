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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/admission"
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/ratelimit"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/version"
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
	ActiveBans() []ratelimit.Ban
	ActiveBanCount() int
	DeleteBan(string) bool
	ClearBans() int
	AdmissionSnapshot() admission.Snapshot
	Audit(string, string, map[string]string)
	EdgeJSON(context.Context, string, string, url.Values, any) (json.RawMessage, int, error)
}

type authFailure struct {
	count                    int
	windowStart, lockedUntil time.Time
}

type Server struct {
	cfg       config.AdminConfig
	runtime   Runtime
	registry  *metrics.Registry
	logs      *securitylog.Store
	inspector *waf.Inspector
	http      *http.Server
	authMu    sync.Mutex
	authFails map[string]*authFailure
}

func New(cfg config.AdminConfig, runtime Runtime, registry *metrics.Registry, logs *securitylog.Store, inspector *waf.Inspector) (*Server, error) {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, runtime: runtime, registry: registry, logs: logs, inspector: inspector, authFails: map[string]*authFailure{}}
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", secureStatic(http.FileServer(http.FS(sub)))))
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/session", s.auth(s.session))
	mux.HandleFunc("GET /api/v1/status", s.auth(s.status))
	mux.HandleFunc("GET /api/v1/info", s.auth(s.info))
	mux.HandleFunc("GET /api/v1/metrics", s.auth(s.securityMetrics))
	mux.HandleFunc("GET /api/v1/metrics/prometheus", s.auth(s.prometheusMetrics))
	mux.HandleFunc("GET /api/v1/logs", s.auth(s.logsHandler))
	mux.HandleFunc("DELETE /api/v1/logs", s.auth(s.clearLogs))
	mux.HandleFunc("GET /api/v1/logs/export", s.auth(s.exportLogs))
	mux.HandleFunc("GET /api/v1/rules", s.auth(s.rules))
	mux.HandleFunc("GET /api/v1/policies", s.auth(s.policies))
	mux.HandleFunc("PUT /api/v1/policies/default", s.auth(s.updateDefaultPolicy))
	mux.HandleFunc("PUT /api/v1/policies/{route}", s.auth(s.updateRoutePolicy))
	mux.HandleFunc("DELETE /api/v1/policies/{route}", s.auth(s.deleteRoutePolicy))
	mux.HandleFunc("POST /api/v1/reload", s.auth(s.reload))
	mux.HandleFunc("GET /api/v1/bans", s.auth(s.bans))
	mux.HandleFunc("DELETE /api/v1/bans/{client}", s.auth(s.deleteBan))
	mux.HandleFunc("DELETE /api/v1/bans", s.auth(s.clearBans))
	mux.HandleFunc("GET /api/v1/dashboard/overview", s.auth(s.overview))
	mux.HandleFunc("GET /api/v1/edgeproxy/status", s.auth(s.edgeStatus))
	mux.HandleFunc("GET /api/v1/edgeproxy/metrics", s.auth(s.edgeMetrics))
	mux.HandleFunc("GET /api/v1/edgeproxy/logs", s.auth(s.edgeLogs))
	mux.HandleFunc("DELETE /api/v1/edgeproxy/logs", s.auth(s.edgeClearLogs))
	mux.HandleFunc("POST /api/v1/edgeproxy/cache/purge", s.auth(s.edgePurge))
	s.http = &http.Server{Addr: cfg.ListenAddr, Handler: securityHeaders(requestIDMiddleware(mux)), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 1 << 20}
	return s, nil
}
func (s *Server) HTTPServer() *http.Server { return s.http }
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := remoteIP(r.RemoteAddr)
		now := time.Now()
		if locked, retry := s.authLocked(client, now); locked {
			w.Header().Set("Retry-After", strconv.Itoa(maxInt(1, int(retry.Round(time.Second).Seconds()))))
			writeError(w, http.StatusTooManyRequests, "admin_auth_locked", "too many failed authentication attempts")
			return
		}
		if s.cfg.AuthToken != "" {
			parts := strings.Fields(r.Header.Get("Authorization"))
			valid := len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && subtle.ConstantTimeCompare([]byte(parts[1]), []byte(s.cfg.AuthToken)) == 1
			if !valid {
				s.recordAuthFailure(client, now)
				w.Header().Set("WWW-Authenticate", `Bearer realm="securityedge-admin"`)
				writeError(w, http.StatusUnauthorized, "unauthorized", "a valid Bearer token is required")
				return
			}
		}
		s.clearAuthFailures(client)
		next(w, r)
	}
}

func (s *Server) authLocked(client string, now time.Time) (bool, time.Duration) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	v := s.authFails[client]
	if v == nil || !now.Before(v.lockedUntil) {
		return false, 0
	}
	return true, v.lockedUntil.Sub(now)
}
func (s *Server) recordAuthFailure(client string, now time.Time) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	v := s.authFails[client]
	if v == nil || now.Sub(v.windowStart) >= time.Minute {
		v = &authFailure{windowStart: now}
		s.authFails[client] = v
	}
	v.count++
	if v.count >= s.cfg.AuthFailuresPerMinute {
		v.lockedUntil = now.Add(s.cfg.AuthLockoutDuration.Duration)
	}
}
func (s *Server) clearAuthFailures(client string) {
	s.authMu.Lock()
	delete(s.authFails, client)
	s.authMu.Unlock()
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
func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"generated_at": now(), "build": version.Info()})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	edgeRaw, edgeStatus, edgeErr := s.runtime.EdgeJSON(r.Context(), http.MethodGet, "/api/v1/status", nil, nil)
	cfg := s.runtime.Config()
	out := map[string]any{"generated_at": now(), "build": version.Info(), "mode": cfg.Server.Mode, "routes": s.runtime.Routes(), "log_store": s.logs.Stats(), "rate_limit_buckets": s.runtime.LimiterSize(), "active_bans": s.runtime.ActiveBanCount(), "admission": s.runtime.AdmissionSnapshot(), "edgeproxy": map[string]any{"reachable": edgeErr == nil, "http_status": edgeStatus}}
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
func (s *Server) prometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, s.registry.Prometheus())
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
	if err := s.decodeJSON(r, &p); err != nil {
		writeError(w, 400, "invalid_body", err.Error())
		return
	}
	if err := s.runtime.UpdateDefaultPolicy(p); err != nil {
		writeError(w, 400, "invalid_policy", err.Error())
		return
	}
	s.runtime.Audit("policy_updated", "default security policy updated", auditFields(r, "default"))
	writeJSON(w, 200, map[string]any{"updated": true, "scope": "default", "policy": s.runtime.EffectivePolicy("")})
}
func (s *Server) updateRoutePolicy(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.PathValue("route"))
	if route == "" || route == "default" {
		writeError(w, 400, "invalid_route", "route name is required")
		return
	}
	var p config.Policy
	if err := s.decodeJSON(r, &p); err != nil {
		writeError(w, 400, "invalid_body", err.Error())
		return
	}
	if err := s.runtime.UpdateRoutePolicy(route, p); err != nil {
		writeError(w, 400, "invalid_policy", err.Error())
		return
	}
	s.runtime.Audit("policy_updated", "route security policy updated", auditFields(r, route))
	writeJSON(w, 200, map[string]any{"updated": true, "route": route, "policy": s.runtime.EffectivePolicy(route)})
}
func (s *Server) deleteRoutePolicy(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.PathValue("route"))
	if err := s.runtime.DeleteRoutePolicy(route); err != nil {
		writeError(w, 400, "delete_failed", err.Error())
		return
	}
	s.runtime.Audit("policy_override_deleted", "route policy override deleted", auditFields(r, route))
	writeJSON(w, 200, map[string]any{"deleted": true, "route": route, "effective_policy": s.runtime.EffectivePolicy(route)})
}
func (s *Server) reload(w http.ResponseWriter, _ *http.Request) {
	if err := s.runtime.Reload(); err != nil {
		writeError(w, 500, "reload_failed", err.Error())
		return
	}
	s.runtime.Audit("configuration_reloaded", "security configuration reloaded", auditFields(nil, ""))
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
	out := map[string]any{"generated_at": now(), "build": version.Info(), "security_metrics": s.registry.Snapshot(), "security_logs": s.logs.Query(securitylog.Filter{Limit: 10}), "security_status": map[string]any{"rate_limit_buckets": s.runtime.LimiterSize(), "active_bans": s.runtime.ActiveBanCount(), "admission": s.runtime.AdmissionSnapshot()}, "edgeproxy_status_code": ss, "edgeproxy_metrics_status_code": ms}
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
func (s *Server) exportLogs(w http.ResponseWriter, r *http.Request) {
	f, err := s.parseLogFilter(r)
	if err != nil {
		writeError(w, 400, "invalid_query", err.Error())
		return
	}
	f.Limit = s.cfg.LogStore.Capacity
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "ndjson"
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="security-events.csv"`)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="security-events.ndjson"`)
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := s.logs.Export(w, f, format); err != nil {
		writeError(w, 400, "export_failed", err.Error())
	}
}
func (s *Server) bans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"generated_at": now(), "bans": s.runtime.ActiveBans()})
}
func (s *Server) deleteBan(w http.ResponseWriter, r *http.Request) {
	client := strings.TrimSpace(r.PathValue("client"))
	if client == "" {
		writeError(w, 400, "invalid_client", "client is required")
		return
	}
	removed := s.runtime.DeleteBan(client)
	s.runtime.Audit("ban_removed", "temporary client ban removed", map[string]string{"client_ip": client, "request_id": r.Header.Get("X-Request-ID")})
	writeJSON(w, 200, map[string]any{"removed": removed, "client": client})
}
func (s *Server) clearBans(w http.ResponseWriter, r *http.Request) {
	removed := s.runtime.ClearBans()
	s.runtime.Audit("bans_cleared", "all temporary client bans cleared", auditFields(r, ""))
	writeJSON(w, 200, map[string]any{"removed": removed})
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
	f := securitylog.Filter{Route: strings.TrimSpace(q.Get("route")), ClientIP: strings.TrimSpace(q.Get("client_ip")), Reason: strings.TrimSpace(q.Get("reason")), RequestID: strings.TrimSpace(q.Get("request_id")), Method: strings.TrimSpace(q.Get("method")), Event: strings.TrimSpace(q.Get("event")), Level: strings.TrimSpace(q.Get("level")), Action: strings.TrimSpace(q.Get("action")), RuleID: strings.TrimSpace(q.Get("rule_id")), Search: strings.TrimSpace(q.Get("q")), Limit: limit}
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
func (s *Server) decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	maxBody := s.cfg.MaxRequestBodyBytes
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxBody {
		return fmt.Errorf("request body exceeds %d bytes", maxBody)
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
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" || len(id) > 128 {
			id = strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		r.Header.Set("X-Request-ID", id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}
func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}
func auditFields(r *http.Request, route string) map[string]string {
	out := map[string]string{"route": route}
	if r != nil {
		out["request_id"] = r.Header.Get("X-Request-ID")
		out["client_ip"] = remoteIP(r.RemoteAddr)
	}
	return out
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
