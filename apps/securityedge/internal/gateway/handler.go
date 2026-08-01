package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/admission"
	"github.com/bachelor-project/edgeproxy-security/internal/clientip"
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/ratelimit"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/traffic"
	"github.com/bachelor-project/edgeproxy-security/internal/waf"
)

type PolicyProvider interface {
	Policy(route string) config.Policy
	ServerConfig() config.ServerConfig
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
	bans      *ratelimit.BanManager
	admission *admission.Limiter
	clients   *clientip.Resolver
	metrics   *metrics.Registry
	logs      *securitylog.Store
	traffic   *traffic.Tracker
	logger    *slog.Logger
}

func New(next http.Handler, table RouteMatcher, policies PolicyProvider, inspector *waf.Inspector, limiter *ratelimit.Limiter, bans *ratelimit.BanManager, admissionLimiter *admission.Limiter, clients *clientip.Resolver, registry *metrics.Registry, logs *securitylog.Store, trafficTracker *traffic.Tracker, logger *slog.Logger) *Handler {
	return &Handler{next: next, routes: table, policies: policies, inspector: inspector, limiter: limiter, bans: bans, admission: admissionLimiter, clients: clients, metrics: registry, logs: logs, traffic: trafficTracker, logger: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	started := time.Now()
	finish := h.metrics.Begin()
	routeName := "__unmatched__"
	if matched, ok := h.routes.Match(req); ok {
		routeName = matched.Name
	}
	policy := h.policies.Policy(routeName)
	serverCfg := h.policies.ServerConfig()
	requestID := newRequestID()
	req.Header.Set("X-Request-ID", requestID)
	client := h.clients.Resolve(req)
	action, reason := "ALLOW", ""
	score, status := 0, 0
	var matches []waf.Match
	bodyInspected, bodyTruncated, matchLimit := false, false, false
	var processingErr error
	var retryAfter time.Duration
	autoBanned := false
	cacheStatus := ""
	securityDuration := time.Duration(0)

	complete := func() {
		fullDuration := time.Since(started)
		metricDuration := securityDuration
		if metricDuration <= 0 {
			metricDuration = fullDuration
		}
		ruleIDs, categories := ruleData(matches)
		finish(metrics.Observation{Route: routeName, Method: req.Method, Action: action, Reason: reason, Duration: metricDuration, Score: score, RuleIDs: ruleIDs, Categories: categories, BodyInspected: bodyInspected, BodyTruncated: bodyTruncated, Error: processingErr != nil, AutoBan: autoBanned})
		if action != "ALLOW" || len(matches) > 0 || processingErr != nil {
			h.appendLog(req, requestID, client, routeName, status, action, reason, score, matches, processingErr, metricDuration, retryAfter, autoBanned, matchLimit)
		}
		if h.traffic != nil {
			path, pathFingerprint := logSafePath(req.URL.EscapedPath(), action, reason, len(matches) > 0)
			h.traffic.Observe(traffic.Event{
				ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), RequestID: requestID, ClientIP: client,
				Method: req.Method, Host: req.Host, Path: path, PathFingerprint: pathFingerprint, Route: routeName,
				Action: action, Reason: reason, Status: status, DurationMS: float64(fullDuration) / float64(time.Millisecond),
				CacheStatus: cacheStatus,
			})
		}
	}
	defer complete()

	release, admitted, overloadReason := h.admission.Acquire(client, serverCfg.MaxConcurrentRequests, serverCfg.MaxConcurrentPerClient)
	if !admitted {
		action, reason, status = "OVERLOAD", overloadReason, http.StatusServiceUnavailable
		retryAfter = time.Second
		autoBanned, _ = h.recordViolation(client, policy, time.Now())
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		w.Header().Set("Retry-After", "1")
		writeBlocked(w, status, "server_busy", requestID)
		return
	}
	defer release()

	if code, rejectReason := validateRequestShape(req, policy, serverCfg); code != 0 {
		action, reason, status = "BLOCK", rejectReason, code
		autoBanned, _ = h.recordViolation(client, policy, time.Now())
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		writeBlocked(w, status, rejectReason, requestID)
		return
	}

	allowlisted := ipMatches(client, policy.IPAllowlist)
	if !allowlisted {
		if blocked, retry := h.bans.IsBanned(client, time.Now()); blocked {
			action, reason, status, retryAfter = "BANNED", "temporary_auto_ban", http.StatusTooManyRequests, retry
			setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
			w.Header().Set("Retry-After", retrySeconds(retry))
			writeBlocked(w, status, "temporarily_banned", requestID)
			return
		}
	}
	if !policy.Enabled || policy.Mode == "off" || allowlisted {
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		securityDuration = time.Since(started)
		writer := &decisionWriter{ResponseWriter: w, requestID: requestID, addSecurityHeaders: serverCfg.AddSecurityHeaders}
		h.next.ServeHTTP(writer, req)
		status = writer.Status()
		cacheStatus = writer.Header().Get("X-Cache")
		return
	}
	if ipMatches(client, policy.IPDenylist) {
		action, reason, status = "BLOCK", "ip_denied", http.StatusForbidden
		autoBanned, _ = h.recordViolation(client, policy, time.Now())
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		writeBlocked(w, status, "ip_denied", requestID)
		return
	}
	if !methodAllowed(req.Method, policy.AllowedMethods) {
		action, reason, status = "BLOCK", "method_not_allowed", http.StatusMethodNotAllowed
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		w.Header().Set("Allow", strings.Join(policy.AllowedMethods, ", "))
		writeBlocked(w, status, "method_not_allowed", requestID)
		return
	}
	decision := h.limiter.Allow(routeName, client, policy.RateLimit, time.Now())
	if !decision.Allowed {
		action, status, retryAfter = "RATE_LIMIT", http.StatusTooManyRequests, decision.RetryAfter
		if decision.Scope == "global" {
			reason = "global_rate_limit"
		} else {
			reason = "client_rate_limit"
		}
		if decision.Reason == "bucket_capacity" {
			reason = "rate_limit_capacity"
		}
		autoBanned, _ = h.recordViolation(client, policy, time.Now())
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		w.Header().Set("Retry-After", retrySeconds(retryAfter))
		writeBlocked(w, status, "rate_limited", requestID)
		return
	}

	result, err := h.inspector.Inspect(req, policy)
	if err != nil {
		processingErr = err
		action, reason, status = "BLOCK", "inspection_failed", http.StatusBadRequest
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		writeBlocked(w, status, "inspection_failed", requestID)
		return
	}
	score, matches = result.Score, result.Matches
	bodyInspected, bodyTruncated, matchLimit = result.BodyInspected, result.BodyTruncated, result.MatchLimitReached
	if result.BodyTruncated && policy.BlockOnInspectionLimit {
		action, reason, status = "BLOCK", "inspection_limit_exceeded", http.StatusRequestEntityTooLarge
		autoBanned, _ = h.recordViolation(client, policy, time.Now())
		setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
		writeBlocked(w, status, "inspection_limit_exceeded", requestID)
		return
	}
	if !result.Excluded && len(matches) > 0 {
		if score >= policy.AnomalyThreshold && policy.Mode == "block" {
			action, reason, status = "BLOCK", "waf_threshold", http.StatusForbidden
			autoBanned, _ = h.recordViolation(client, policy, time.Now())
			setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
			writeBlocked(w, status, "waf_blocked", requestID)
			return
		}
		action, reason = "LOG", "waf_detection"
	}
	setDecisionHeaders(w, requestID, action, score, serverCfg.AddSecurityHeaders)
	securityDuration = time.Since(started)
	writer := &decisionWriter{ResponseWriter: w, requestID: requestID, addSecurityHeaders: serverCfg.AddSecurityHeaders}
	h.next.ServeHTTP(writer, req)
	status = writer.Status()
	cacheStatus = writer.Header().Get("X-Cache")
}

func validateRequestShape(req *http.Request, policy config.Policy, server config.ServerConfig) (int, string) {
	if len(req.URL.EscapedPath()) > policy.MaxPathBytes {
		return http.StatusRequestURITooLong, "path_too_large"
	}
	if len(req.URL.RawQuery) > policy.MaxQueryBytes {
		return http.StatusRequestURITooLong, "query_too_large"
	}
	if len(req.Header) > policy.MaxHeaderCount {
		return http.StatusRequestHeaderFieldsTooLarge, "too_many_headers"
	}
	for _, values := range req.Header {
		for _, value := range values {
			if len(value) > policy.MaxHeaderValueBytes {
				return http.StatusRequestHeaderFieldsTooLarge, "header_value_too_large"
			}
		}
	}
	if req.ContentLength > server.MaxRequestBodyBytes {
		return http.StatusRequestEntityTooLarge, "body_too_large"
	}
	if policy.RejectEncodedRequestBodies {
		encoding := strings.TrimSpace(req.Header.Get("Content-Encoding"))
		if encoding != "" && !strings.EqualFold(encoding, "identity") {
			return http.StatusUnsupportedMediaType, "encoded_body_rejected"
		}
	}
	if policy.InspectRequestBody && policy.RejectUnsupportedBodyTypes && requestHasBody(req) && !contentTypeAllowed(req.Header.Get("Content-Type"), policy.BodyContentTypes) {
		return http.StatusUnsupportedMediaType, "unsupported_body_type"
	}
	if req.Host == "" || strings.ContainsAny(req.Host, "\r\n\x00") {
		return http.StatusBadRequest, "invalid_host"
	}
	return 0, ""
}

func requestHasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
}

func contentTypeAllowed(raw string, allowed []string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(raw, ";")[0])
	}
	for _, item := range allowed {
		if strings.EqualFold(strings.TrimSpace(item), mediaType) {
			return true
		}
	}
	return false
}

func (h *Handler) recordViolation(client string, policy config.Policy, now time.Time) (bool, time.Duration) {
	return h.bans.RecordViolation(client, policy.AutoBan, now)
}

func (h *Handler) appendLog(req *http.Request, id, client, route string, status int, action, reason string, score int, matches []waf.Match, err error, duration, retry time.Duration, autoBan, matchLimit bool) {
	if h.logs == nil {
		return
	}
	level, event, message := "INFO", "waf_allowed", "request allowed by security policy"
	switch action {
	case "BLOCK":
		level, event, message = "WARN", "waf_blocked", "request blocked by security policy"
	case "LOG":
		level, event, message = "WARN", "waf_detected", "suspicious request detected in monitoring mode"
	case "RATE_LIMIT":
		level, event, message = "WARN", "rate_limited", "request rejected by hierarchical rate limiter"
	case "OVERLOAD":
		level, event, message = "WARN", "overload_rejected", "request rejected by concurrency protection"
	case "BANNED":
		level, event, message = "WARN", "auto_ban_rejected", "request rejected because client is temporarily banned"
	}
	if err != nil {
		level, event, message = "ERROR", "inspection_error", "request inspection failed"
	}
	ids, _ := ruleData(matches)
	path, pathFingerprint := logSafePath(req.URL.EscapedPath(), action, reason, len(matches) > 0)
	entry := securitylog.Entry{
		Level: level, Event: event, Message: message, RequestID: id, ClientIP: client,
		Method: req.Method, Host: req.Host, Path: path, PathFingerprint: pathFingerprint, Route: route,
		Status: status, DurationMS: float64(duration) / float64(time.Millisecond), Action: action,
		Reason: reason, Score: score, RuleIDs: ids, Matches: matches, RetryAfterMS: retry.Milliseconds(),
		UserAgentFingerprint: fingerprint(req.UserAgent()), AutoBanned: autoBan, MatchLimitReached: matchLimit, Tags: []string{"security", "waf"},
	}
	if err != nil {
		entry.Error = err.Error()
	}
	h.logs.Append(entry)
	h.logger.Log(req.Context(), logLevel(level), message, "request_id", id, "client_ip", client, "method", req.Method, "host", req.Host, "path", path, "path_fingerprint", pathFingerprint, "user_agent_fingerprint", fingerprint(req.UserAgent()), "route", route, "action", action, "reason", reason, "score", score, "rules", ids, "auto_banned", autoBan)
}

type decisionWriter struct {
	http.ResponseWriter
	requestID          string
	addSecurityHeaders bool
	status             int
}

func (w *decisionWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *decisionWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
func (w *decisionWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	setBaseHeaders(w.Header(), w.requestID, w.addSecurityHeaders)
	w.ResponseWriter.WriteHeader(status)
}
func (w *decisionWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
func (w *decisionWriter) ReadFrom(reader io.Reader) (int64, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if target, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return target.ReadFrom(reader)
	}
	return io.Copy(struct{ io.Writer }{w.ResponseWriter}, reader)
}
func (w *decisionWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		setBaseHeaders(w.Header(), w.requestID, w.addSecurityHeaders)
		f.Flush()
	}
}

func setDecisionHeaders(w http.ResponseWriter, id, action string, score int, security bool) {
	if security {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	}
	w.Header().Set("X-Security-Action", action)
	w.Header().Set("X-Security-Score", strconv.Itoa(score))
}

func setBaseHeaders(h http.Header, id string, security bool) {
	if h.Get("X-Request-ID") == "" {
		h.Set("X-Request-ID", id)
	}
	if security {
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	}
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

func logSafePath(path, action, reason string, detected bool) (string, string) {
	fp := fingerprint(path)
	if detected || action == "BLOCK" || strings.Contains(reason, "path") || strings.Contains(reason, "query") || strings.Contains(reason, "header") || strings.Contains(reason, "body") {
		return "[redacted]", fp
	}
	if path == "" {
		return "/", fp
	}
	if len(path) > 512 {
		return path[:512], fp
	}
	return path, fp
}

func fingerprint(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func retrySeconds(d time.Duration) string {
	n := int(d.Round(time.Second).Seconds())
	if n < 1 {
		n = 1
	}
	return strconv.Itoa(n)
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
