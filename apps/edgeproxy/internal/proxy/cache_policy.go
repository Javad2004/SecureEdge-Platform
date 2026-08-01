package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bachelor-project/edgeproxy/internal/config"
)

func cacheKey(req *http.Request, cfg config.CacheConfig) string {
	method := req.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	var b strings.Builder
	fmt.Fprintf(&b, "method=%s|host=%s|uri=%s", method, cacheHost(req.Host), req.URL.RequestURI())
	for _, name := range cfg.VaryRequestHeaders {
		fmt.Fprintf(&b, "|h:%s=%s", strings.ToLower(name), req.Header.Get(name))
	}
	return b.String()
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
	if cc["no-store"] != "" {
		return false, false, "request-no-store"
	}
	if req.Header.Get("Authorization") != "" && !cfg.CacheAuthorizedRequests {
		return false, false, "authorization"
	}
	if req.Header.Get("Cookie") != "" && !cfg.CacheCookieRequests {
		return false, false, "cookie"
	}
	lookup = cc["no-cache"] == "" && cc["max-age"] != "0" && req.Header.Get("Pragma") != "no-cache"
	return lookup, true, ""
}

func responseCachePolicy(req *http.Request, resp *http.Response, cfg config.CacheConfig, now time.Time) (cacheable bool, expiresAt, staleUntil time.Time) {
	statusAllowed := false
	for _, status := range cfg.CacheableStatusCodes {
		if resp.StatusCode == status {
			statusAllowed = true
			break
		}
	}
	if !statusAllowed {
		return false, time.Time{}, time.Time{}
	}
	if resp.Header.Get("Set-Cookie") != "" && !cfg.CacheSetCookieResponses {
		return false, time.Time{}, time.Time{}
	}
	if !varyIsSupported(resp.Header.Values("Vary"), cfg.VaryRequestHeaders) {
		return false, time.Time{}, time.Time{}
	}

	ttl := cfg.DefaultTTL.Duration
	if cfg.RespectOriginHeaders {
		cc := parseCacheControl(resp.Header.Values("Cache-Control"))
		if cc["no-store"] != "" || cc["private"] != "" {
			return false, time.Time{}, time.Time{}
		}
		if value := firstNonEmpty(cc["s-maxage"], cc["max-age"]); value != "" {
			seconds, err := strconv.Atoi(value)
			if err == nil {
				ttl = time.Duration(seconds) * time.Second
			}
		} else if expires := resp.Header.Get("Expires"); expires != "" {
			if parsed, err := http.ParseTime(expires); err == nil {
				ttl = parsed.Sub(now)
			}
		}
	}
	if ttl <= 0 {
		return false, time.Time{}, time.Time{}
	}
	expiresAt = now.Add(ttl)
	staleUntil = expiresAt.Add(cfg.StaleIfError.Duration)
	return true, expiresAt, staleUntil
}

func parseCacheControl(values []string) map[string]string {
	out := make(map[string]string)
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			parts := strings.SplitN(strings.TrimSpace(directive), "=", 2)
			key := strings.ToLower(parts[0])
			if len(parts) == 1 {
				out[key] = "1"
			} else {
				out[key] = strings.Trim(parts[1], `"`)
			}
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func conditionalNotModified(req *http.Request, header http.Header) bool {
	if inm := req.Header.Get("If-None-Match"); inm != "" {
		etag := header.Get("ETag")
		if etag != "" && (inm == "*" || strings.Contains(inm, etag)) {
			return true
		}
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

func cacheHost(hostport string) string {
	hostport = strings.ToLower(strings.TrimSpace(hostport))
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.TrimSuffix(host, ".")
	}
	return strings.TrimSuffix(hostport, ".")
}

func varyIsSupported(varyValues, configured []string) bool {
	allowed := make(map[string]struct{}, len(configured))
	for _, name := range configured {
		allowed[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
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
