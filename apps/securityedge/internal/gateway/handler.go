package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/ratelimit"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/waf"
)

type PolicyProvider interface {
	Policy(route string) config.Policy
}

type RouteMatcher interface {
	Match(*http.Request) (routes.Route, bool)
}
type Handler struct {
	next      http.Handler
	routes    RouteMatcher
	policies  PolicyProvider
	inspector *waf.Inspector
	limiter   *ratelimit.Limiter
	metrics   *metrics.Registry
	logs      *securitylog.Store
	logger    *slog.Logger
}

func New(next http.Handler, table RouteMatcher, policies PolicyProvider, inspector *waf.Inspector, limiter *ratelimit.Limiter, registry *metrics.Registry, logs *securitylog.Store, logger *slog.Logger) *Handler {
	return &Handler{next: next, routes: table, policies: policies, inspector: inspector, limiter: limiter, metrics: registry, logs: logs, logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	started := time.Now()
	finish := h.metrics.Begin()
	routeName := "__unmatched__"
	if matched, ok := h.routes.Match(req); ok {
		routeName = matched.Name
	}
	policy := h.policies.Policy(routeName)
	requestID := requestID(req)
	req.Header.Set("X-Request-ID", requestID)
	client := clientIP(req)
	action := "ALLOW"
	score := 0
	var matches []waf.Match
	bodyInspected, bodyTruncated := false, false
	status := 0
	var processingErr error
	var retryAfter time.Duration
	complete := func() {
		ruleIDs, categories := ruleData(matches)
		finish(metrics.Observation{Route: routeName, Method: req.Method, Action: action, Duration: time.Since(started), Score: score, RuleIDs: ruleIDs, Categories: categories, BodyInspected: bodyInspected, BodyTruncated: bodyTruncated, Error: processingErr != nil})
		if action != "ALLOW" || len(matches) > 0 || processingErr != nil {
			h.appendLog(req, requestID, client, routeName, status, action, score, matches, processingErr, time.Since(started), retryAfter)
		}
		w.Header().Set("X-Security-Action", action)
		w.Header().Set("X-Security-Score", strconv.Itoa(score))
	}
	if !policy.Enabled || policy.Mode == "off" {
		complete()
		h.next.ServeHTTP(&requestIDWriter{ResponseWriter: w, requestID: requestID}, req)
		return
	}
	if ipMatches(client, policy.IPAllowlist) {
		complete()
		h.next.ServeHTTP(&requestIDWriter{ResponseWriter: w, requestID: requestID}, req)
		return
	}
	if ipMatches(client, policy.IPDenylist) {
		action = "BLOCK"
		status = http.StatusForbidden
		complete()
		writeBlocked(w, status, "ip_denied", requestID)
		return
	}
	if !methodAllowed(req.Method, policy.AllowedMethods) {
		action = "BLOCK"
		status = http.StatusMethodNotAllowed
		complete()
		w.Header().Set("Allow", strings.Join(policy.AllowedMethods, ", "))
		writeBlocked(w, status, "method_not_allowed", requestID)
		return
	}
	key := routeName + "|" + client
	if allowed, retry := h.limiter.Allow(key, policy.RateLimit, time.Now()); !allowed {
		action = "RATE_LIMIT"
		status = http.StatusTooManyRequests
		retrySeconds := int(retry.Round(time.Second).Seconds())
		if retrySeconds < 1 {
			retrySeconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		retryAfter = retry
		complete()
		writeBlocked(w, status, "rate_limited", requestID)
		return
	}
	result, err := h.inspector.Inspect(req, policy)
	if err != nil {
		processingErr = err
		action = "BLOCK"
		status = http.StatusBadRequest
		complete()
		writeBlocked(w, status, "inspection_failed", requestID)
		return
	}
	score = result.Score
	matches = result.Matches
	bodyInspected = result.BodyInspected
	bodyTruncated = result.BodyTruncated
	if !result.Excluded && len(matches) > 0 {
		if score >= policy.AnomalyThreshold && policy.Mode == "block" {
			action = "BLOCK"
			status = http.StatusForbidden
			complete()
			writeBlocked(w, status, "waf_blocked", requestID)
			return
		}
		action = "LOG"
	}
	complete()
	h.next.ServeHTTP(&requestIDWriter{ResponseWriter: w, requestID: requestID}, req)
}
func (h *Handler) appendLog(req *http.Request, id, client, route string, status int, action string, score int, matches []waf.Match, err error, duration, retry time.Duration) {
	if h.logs == nil {
		return
	}
	level, event, message := "INFO", "waf_allowed", "request allowed by security policy"
	switch action {
	case "BLOCK":
		level, event, message = "WARN", "waf_blocked", "request blocked by web application firewall"
	case "LOG":
		level, event, message = "WARN", "waf_detected", "suspicious request detected in monitoring mode"
	case "RATE_LIMIT":
		level, event, message = "WARN", "rate_limited", "request rejected by rate limiter"
	}
	if err != nil {
		level, event, message = "ERROR", "inspection_error", "request inspection failed"
	}
	ids, _ := ruleData(matches)
	entry := securitylog.Entry{Level: level, Event: event, Message: message, RequestID: id, ClientIP: client, Method: req.Method, Host: req.Host, Path: req.URL.EscapedPath(), Route: route, Status: status, DurationMS: float64(duration) / float64(time.Millisecond), Action: action, Score: score, RuleIDs: ids, Matches: matches, RateLimitKey: func() string {
		if action == "RATE_LIMIT" {
			return route + "|" + client
		}
		return ""
	}(), RetryAfterMS: retry.Milliseconds(), UserAgent: req.UserAgent(), Tags: []string{"security", "waf"}}
	if err != nil {
		entry.Error = err.Error()
	}
	h.logs.Append(entry)
	h.logger.Log(req.Context(), logLevel(level), message, "request_id", id, "client_ip", client, "method", req.Method, "host", req.Host, "path", req.URL.EscapedPath(), "route", route, "action", action, "score", score, "rules", ids)
}

type requestIDWriter struct {
	http.ResponseWriter
	requestID string
}

func (w *requestIDWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *requestIDWriter) WriteHeader(status int) {
	if w.Header().Get("X-Request-ID") == "" {
		w.Header().Set("X-Request-ID", w.requestID)
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *requestIDWriter) Write(data []byte) (int, error) {
	if w.Header().Get("X-Request-ID") == "" {
		w.Header().Set("X-Request-ID", w.requestID)
	}
	return w.ResponseWriter.Write(data)
}

func writeBlocked(w http.ResponseWriter, status int, code, id string) {
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": http.StatusText(status), "request_id": id}})
}
func methodAllowed(method string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, m := range allowed {
		if strings.EqualFold(method, m) {
			return true
		}
	}
	return false
}
func ipMatches(ip string, entries []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if candidate := net.ParseIP(raw); candidate != nil && candidate.Equal(parsed) {
			return true
		}
		if _, network, err := net.ParseCIDR(raw); err == nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}
func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}
func requestID(req *http.Request) string {
	if v := strings.TrimSpace(req.Header.Get("X-Request-ID")); v != "" && len(v) <= 128 {
		return v
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return "fallback-security-request-id"
}
func ruleData(matches []waf.Match) ([]string, []string) {
	ids, cats := []string{}, []string{}
	seenI, seenC := map[string]bool{}, map[string]bool{}
	for _, m := range matches {
		if !seenI[m.RuleID] {
			seenI[m.RuleID] = true
			ids = append(ids, m.RuleID)
		}
		if !seenC[m.Category] {
			seenC[m.Category] = true
			cats = append(cats, m.Category)
		}
	}
	return ids, cats
}
func logLevel(level string) slog.Level {
	switch level {
	case "ERROR":
		return slog.LevelError
	case "WARN":
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}
