package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/cache"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

func cacheKey(req *http.Request, cfg config.CacheConfig) string {
	method := req.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	var b strings.Builder
	// Host and URI are encoded so cache-admin filters can parse the key without
	// being confused by delimiters that are legal in a raw query string.
	fmt.Fprintf(&b, "method=%s|host64=%s|uri64=%s", method, encodeCacheKeyField(cacheHost(req.Host)), encodeCacheKeyField(canonicalRequestURI(req.URL)))
	seen := make(map[string]struct{}, len(cfg.VaryRequestHeaders)+2)
	appendHeader := func(name string) {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		key := strings.ToLower(canonical)
		if canonical == "" {
			return
		}
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		values := req.Header.Values(canonical)
		digest := sha256.New()
		for _, value := range values {
			_, _ = digest.Write([]byte(value))
			_, _ = digest.Write([]byte{0})
		}
		fmt.Fprintf(&b, "|h:%s=%x", key, digest.Sum(nil))
	}
	for _, name := range cfg.VaryRequestHeaders {
		appendHeader(name)
	}
	// Opting in to caching authenticated or cookie-bearing requests must also
	// partition the cache by those credentials. Hashing keeps sensitive values
	// out of cache keys while preserving deterministic separation.
	if cfg.CacheAuthorizedRequests {
		appendHeader("Authorization")
	}
	if cfg.CacheCookieRequests {
		appendHeader("Cookie")
	}
	return b.String()
}

func encodeCacheKeyField(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeCacheKeyField(value string) (string, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

func cacheKeyRequest(key string) (host, requestURI string, ok bool) {
	var encodedHost, encodedURI string
	for _, field := range strings.Split(key, "|") {
		switch {
		case strings.HasPrefix(field, "host64="):
			encodedHost = strings.TrimPrefix(field, "host64=")
		case strings.HasPrefix(field, "uri64="):
			encodedURI = strings.TrimPrefix(field, "uri64=")
		}
	}
	if encodedHost == "" || encodedURI == "" {
		return "", "", false
	}
	host, ok = decodeCacheKeyField(encodedHost)
	if !ok {
		return "", "", false
	}
	requestURI, ok = decodeCacheKeyField(encodedURI)
	if !ok {
		return "", "", false
	}
	return host, requestURI, true
}

// requestAllowsCachedEntry applies request-side freshness constraints to a
// candidate cache entry. A client Cache-Control max-age value limits the
// acceptable current age even when the response remains fresh according to the
// Origin's longer lifetime. Invalid values are ignored as malformed extension
// input, while max-age=0 is already handled by requestCacheMode as revalidation.
func requestAllowsCachedEntry(req *http.Request, entry cache.Entry, now time.Time) bool {
	if req == nil {
		return true
	}
	parsed := parseCacheControlDetailed(req.Header.Values("Cache-Control"))
	// Ambiguous freshness constraints must not select a cached representation.
	// RFC 9111 treats repeated freshness directives as invalid; choosing the last
	// value makes behavior depend on how intermediaries coalesce field lines.
	if parsed.invalid || parsed.duplicates["max-age"] {
		return false
	}
	raw, exists := parsed.directives["max-age"]
	if !exists {
		return true
	}
	seconds, valid := cacheDeltaSeconds(raw)
	if !valid {
		return true
	}
	age := now.Sub(entry.StoredAt)
	if age < 0 {
		age = 0
	}
	return age <= time.Duration(seconds)*time.Second
}

func requestCacheMode(req *http.Request, cfg config.CacheConfig) (lookup, store bool, reason string) {
	if !cfg.Enabled {
		return false, false, "disabled"
	}
	if hasProtocolUpgrade(req.Header) {
		return false, false, "protocol-upgrade"
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false, false, "method"
	}
	if headerHasNonEmptyValue(req.Header, "Range") {
		return false, false, "range"
	}
	parsed := parseCacheControlDetailed(req.Header.Values("Cache-Control"))
	if parsed.invalid || parsed.duplicates["max-age"] {
		// A malformed or conflicting request cache policy is not safe to resolve
		// against shared state and must not populate that state either.
		return false, false, "invalid-cache-control"
	}
	cc := parsed.directives
	if hasCacheDirective(cc, "no-store") {
		return false, false, "request-no-store"
	}
	if headerHasNonEmptyValue(req.Header, "Authorization") && !cfg.CacheAuthorizedRequests {
		return false, false, "authorization"
	}
	if headerHasNonEmptyValue(req.Header, "Cookie") && !cfg.CacheCookieRequests {
		return false, false, "cookie"
	}
	forceRevalidation := hasCacheDirective(cc, "no-cache") || headerHasToken(req.Header.Values("Pragma"), "no-cache")
	if raw, exists := cc["max-age"]; exists {
		// delta-seconds permits leading zeroes. Treat max-age=00 exactly like
		// max-age=0 instead of serving a cached response against the client's
		// explicit revalidation request.
		if seconds, valid := cacheDeltaSeconds(raw); valid && seconds == 0 {
			forceRevalidation = true
		}
	}
	lookup = !forceRevalidation
	return lookup, true, ""
}

func responseCachePolicy(req *http.Request, resp *http.Response, cfg config.CacheConfig, now time.Time) (cacheable bool, expiresAt, staleUntil time.Time, initialAge time.Duration) {
	statusAllowed := false
	for _, status := range cfg.CacheableStatusCodes {
		if resp.StatusCode == status {
			statusAllowed = true
			break
		}
	}
	if !statusAllowed {
		return false, time.Time{}, time.Time{}, 0
	}
	if headerHasNonEmptyValue(resp.Header, "Set-Cookie") && !cfg.CacheSetCookieResponses {
		return false, time.Time{}, time.Time{}, 0
	}
	if !varyIsSupported(resp.Header.Values("Vary"), cfg) {
		return false, time.Time{}, time.Time{}, 0
	}

	ttl := cfg.DefaultTTL.Duration
	allowStale := true
	if cfg.RespectOriginHeaders {
		parsed := parseCacheControlDetailed(resp.Header.Values("Cache-Control"))
		// Repeated max-age/s-maxage values are invalid freshness information. Do
		// not let field ordering select an arbitrarily long cache lifetime.
		if parsed.invalid || parsed.duplicates["max-age"] || parsed.duplicates["s-maxage"] {
			return false, time.Time{}, time.Time{}, 0
		}
		cc := parsed.directives
		if hasCacheDirective(cc, "no-store") || hasCacheDirective(cc, "private") || hasCacheDirective(cc, "no-cache") || headerHasToken(resp.Header.Values("Pragma"), "no-cache") {
			return false, time.Time{}, time.Time{}, 0
		}
		if hasCacheDirective(cc, "must-revalidate") || hasCacheDirective(cc, "proxy-revalidate") {
			allowStale = false
		}
		initialAge = responseInitialAge(resp.Header, now)
		switch {
		case hasCacheDirective(cc, "s-maxage"):
			seconds, ok := cacheDeltaSeconds(cc["s-maxage"])
			if !ok {
				return false, time.Time{}, time.Time{}, 0
			}
			ttl = time.Duration(seconds) * time.Second
		case hasCacheDirective(cc, "max-age"):
			seconds, ok := cacheDeltaSeconds(cc["max-age"])
			if !ok {
				return false, time.Time{}, time.Time{}, 0
			}
			ttl = time.Duration(seconds) * time.Second
		case strings.TrimSpace(resp.Header.Get("Expires")) != "":
			parsed, err := http.ParseTime(resp.Header.Get("Expires"))
			if err != nil {
				return false, time.Time{}, time.Time{}, 0
			}
			reference := now
			if date, dateErr := http.ParseTime(resp.Header.Get("Date")); dateErr == nil {
				reference = date
			}
			ttl = parsed.Sub(reference)
		}
		ttl -= initialAge
	}
	if ttl <= 0 {
		return false, time.Time{}, time.Time{}, 0
	}
	expiresAt = now.Add(ttl)
	staleUntil = expiresAt
	if allowStale {
		staleUntil = expiresAt.Add(cfg.StaleIfError.Duration)
	}
	return true, expiresAt, staleUntil, initialAge
}

func cacheDeltaSeconds(value string) (int64, bool) {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	const maxDurationSeconds = int64(1<<63-1) / int64(time.Second)
	if err != nil || seconds < 0 || seconds > maxDurationSeconds {
		return 0, false
	}
	return seconds, true
}

// responseInitialAge applies the shared-cache Age/Date correction needed when
// a response has already spent time in another cache before reaching EdgeProxy.
// Invalid or negative values are ignored rather than extending freshness.
func responseInitialAge(header http.Header, now time.Time) time.Duration {
	var age time.Duration
	if raw := strings.TrimSpace(header.Get("Age")); raw != "" {
		if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds >= 0 {
			const maxAgeSeconds = int64(100 * 365 * 24 * 60 * 60)
			if seconds > maxAgeSeconds {
				seconds = maxAgeSeconds
			}
			age = time.Duration(seconds) * time.Second
		}
	}
	if date, err := http.ParseTime(header.Get("Date")); err == nil && now.After(date) {
		apparent := now.Sub(date)
		if apparent > age {
			age = apparent
		}
	}
	return age
}

type parsedCacheControl struct {
	directives map[string]string
	duplicates map[string]bool
	invalid    bool
}

func parseCacheControlDetailed(values []string) parsedCacheControl {
	parsed := parsedCacheControl{directives: make(map[string]string), duplicates: make(map[string]bool)}
	for _, value := range values {
		directives, valid := splitHeaderList(value)
		if !valid {
			parsed.invalid = true
			continue
		}
		for _, directive := range directives {
			parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			if key == "" {
				parsed.invalid = true
				continue
			}
			if _, exists := parsed.directives[key]; exists {
				parsed.duplicates[key] = true
				continue
			}
			if len(parts) == 1 {
				parsed.directives[key] = "1"
			} else {
				parsed.directives[key] = unquoteHeaderValue(strings.TrimSpace(parts[1]))
			}
		}
	}
	return parsed
}

func parseCacheControl(values []string) map[string]string {
	return parseCacheControlDetailed(values).directives
}

// splitHeaderList separates comma-delimited HTTP list values without splitting
// commas inside quoted strings. It also rejects unterminated quoted strings so
// malformed Cache-Control metadata cannot hide a later no-store directive.
func splitHeaderList(value string) ([]string, bool) {
	items := make([]string, 0, 4)
	start := 0
	quoted, escaped := false, false
	for i := 0; i < len(value); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && value[i] == '\\':
			escaped = true
		case value[i] == '"':
			quoted = !quoted
		case value[i] == ',' && !quoted:
			items = append(items, value[start:i])
			start = i + 1
		}
	}
	if quoted || escaped {
		return nil, false
	}
	items = append(items, value[start:])
	return items, true
}

func unquoteHeaderValue(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	value = value[1 : len(value)-1]
	var b strings.Builder
	b.Grow(len(value))
	escaped := false
	for i := 0; i < len(value); i++ {
		if escaped {
			b.WriteByte(value[i])
			escaped = false
			continue
		}
		if value[i] == '\\' {
			escaped = true
			continue
		}
		b.WriteByte(value[i])
	}
	if escaped {
		b.WriteByte('\\')
	}
	return b.String()
}

func hasCacheDirective(directives map[string]string, name string) bool {
	_, ok := directives[strings.ToLower(name)]
	return ok
}

// headerHasNonEmptyValue checks every field-line value rather than Header.Get,
// which only returns the first value. Security-sensitive cache decisions must
// not be bypassable by placing an empty field before a later Authorization,
// Cookie, Range, or Set-Cookie value.
func headerHasNonEmptyValue(header http.Header, name string) bool {
	for _, value := range header.Values(name) {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func headerHasToken(values []string, token string) bool {
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(raw), token) {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func conditionalNotModified(req *http.Request, header http.Header, statusCode int) bool {
	// HTTP preconditions are ignored when the response without them would not
	// have been a successful (2xx) response. In particular, a cached 404 or 410
	// that happens to carry an ETag or Last-Modified value must remain that error
	// response instead of being transformed into a misleading 304.
	if statusCode < 200 || statusCode >= 300 {
		return false
	}
	if values := req.Header.Values("If-None-Match"); len(values) > 0 {
		items, valid := parseHeaderListValues(values)
		if !valid {
			return false
		}
		if ifNoneMatchWildcard(items) {
			return true
		}
		return weakETagMatch(items, header.Get("ETag"))
	}
	if ims := req.Header.Get("If-Modified-Since"); ims != "" {
		modified, err1 := http.ParseTime(header.Get("Last-Modified"))
		since, err2 := http.ParseTime(ims)
		if err1 == nil && err2 == nil && !modified.After(since) {
			return true
		}
	}
	return false
}

func parseHeaderListValues(values []string) ([]string, bool) {
	items := make([]string, 0, len(values))
	for _, value := range values {
		parts, valid := splitHeaderList(value)
		if !valid {
			return nil, false
		}
		items = append(items, parts...)
	}
	return items, true
}

func ifNoneMatchWildcard(items []string) bool {
	for _, raw := range items {
		if strings.TrimSpace(raw) == "*" {
			return true
		}
	}
	return false
}

func weakETagMatch(items []string, current string) bool {
	current = normalizeETag(current)
	if current == "" {
		return false
	}
	for _, raw := range items {
		candidate := strings.TrimSpace(raw)
		if normalizeETag(candidate) == current {
			return true
		}
	}
	return false
}

func normalizeETag(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (strings.HasPrefix(value, "W/") || strings.HasPrefix(value, "w/")) {
		value = strings.TrimSpace(value[2:])
	}
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return ""
	}
	return value
}

func cacheHost(hostport string) string {
	hostport = strings.ToLower(strings.TrimSpace(hostport))
	if host, port, err := net.SplitHostPort(hostport); err == nil {
		host = strings.TrimSuffix(host, ".")
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		}
		return net.JoinHostPort(host, port)
	}
	// Host permits a bracketed IPv6 literal without a port. Route validation
	// stores IP literals in canonical unbracketed form, so cache keys and admin
	// purge filters must normalize the request-side representation identically.
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		if ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")); ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(hostport); ip != nil {
		return ip.String()
	}
	return strings.TrimSuffix(hostport, ".")
}

func varyIsSupported(varyValues []string, cfg config.CacheConfig) bool {
	allowed := make(map[string]struct{}, len(cfg.VaryRequestHeaders)+2)
	for _, name := range cfg.VaryRequestHeaders {
		allowed[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	if cfg.CacheAuthorizedRequests {
		allowed["authorization"] = struct{}{}
	}
	if cfg.CacheCookieRequests {
		allowed["cookie"] = struct{}{}
	}
	for _, value := range varyValues {
		for _, raw := range strings.Split(value, ",") {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			if name == "*" {
				return false
			}
			if _, ok := allowed[name]; !ok {
				return false
			}
		}
	}
	return true
}
