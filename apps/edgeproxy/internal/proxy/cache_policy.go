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

func requestCacheMode(req *http.Request, cfg config.CacheConfig) (lookup, store bool, reason string) {
	if !cfg.Enabled {
		return false, false, "disabled"
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false, false, "method"
	}
	if req.Header.Get("Range") != "" {
		return false, false, "range"
	}
	cc := parseCacheControl(req.Header.Values("Cache-Control"))
	if hasCacheDirective(cc, "no-store") {
		return false, false, "request-no-store"
	}
	if req.Header.Get("Authorization") != "" && !cfg.CacheAuthorizedRequests {
		return false, false, "authorization"
	}
	if req.Header.Get("Cookie") != "" && !cfg.CacheCookieRequests {
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
	if resp.Header.Get("Set-Cookie") != "" && !cfg.CacheSetCookieResponses {
		return false, time.Time{}, time.Time{}, 0
	}
	if !varyIsSupported(resp.Header.Values("Vary"), cfg) {
		return false, time.Time{}, time.Time{}, 0
	}

	ttl := cfg.DefaultTTL.Duration
	allowStale := true
	if cfg.RespectOriginHeaders {
		cc := parseCacheControl(resp.Header.Values("Cache-Control"))
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

func parseCacheControl(values []string) map[string]string {
	out := make(map[string]string)
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			if key == "" {
				continue
			}
			if len(parts) == 1 {
				out[key] = "1"
			} else {
				out[key] = strings.Trim(strings.TrimSpace(parts[1]), `"`)
			}
		}
	}
	return out
}

func hasCacheDirective(directives map[string]string, name string) bool {
	_, ok := directives[strings.ToLower(name)]
	return ok
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
	if inm := req.Header.Get("If-None-Match"); inm != "" {
		if ifNoneMatchWildcard(inm) && statusCode >= 200 && statusCode < 300 {
			return true
		}
		return weakETagMatch(inm, header.Get("ETag"))
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

func ifNoneMatchWildcard(value string) bool {
	for _, raw := range strings.Split(value, ",") {
		if strings.TrimSpace(raw) == "*" {
			return true
		}
	}
	return false
}

func weakETagMatch(ifNoneMatch, current string) bool {
	current = normalizeETag(current)
	if current == "" {
		return false
	}
	for _, raw := range strings.Split(ifNoneMatch, ",") {
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
		return net.JoinHostPort(host, port)
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
