package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, sf := range strings.Split(f, ",") {
			h.Del(strings.TrimSpace(sf))
		}
	}
	for _, hname := range hopHeaders {
		h.Del(hname)
	}
}

// removeForwardingIdentityHeaders drops every client-controlled forwarding
// identity header before this trusted proxy creates a canonical set. Keeping
// alternate headers such as Forwarded or X-Real-IP would let downstream
// applications observe a spoofed client identity even when X-Forwarded-For is
// sanitized correctly.
func removeForwardingIdentityHeaders(h http.Header, configured string) {
	configured = strings.TrimSpace(configured)
	for name := range h {
		lower := strings.ToLower(name)
		remove := strings.EqualFold(name, configured) || strings.HasPrefix(lower, "x-forwarded-")
		if !remove {
			switch lower {
			case "forwarded", "client-ip", "x-real-ip", "true-client-ip", "x-client-ip", "x-cluster-client-ip", "x-originating-ip", "x-original-forwarded-for", "cf-connecting-ip", "fastly-client-ip", "fly-client-ip", "x-appengine-user-ip", "x-azure-clientip", "proxy-client-ip", "wl-proxy-client-ip":
				remove = true
			}
		}
		if remove {
			h.Del(name)
		}
	}
}

func copyHeaders(dst, src http.Header) {
	for k, values := range src {
		for _, value := range values {
			dst.Add(k, value)
		}
	}
}

// sanitizeOriginResponseHeaders removes implementation details that should not
// be exposed by the edge. Operational details remain available through the
// authenticated Admin API and structured logs.
func sanitizeOriginResponseHeaders(h http.Header) {
	for _, name := range []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		// These headers are authoritative edge metadata. An Origin must not be
		// able to inject, duplicate, or persist them through the shared cache.
		"X-Request-ID",
		"X-Cache",
		"X-Upstream-Response-Time",
		"X-Security-Action",
		"X-Security-Score",
		"X-Security-Gateway",
	} {
		h.Del(name)
	}
}

func requestID(req *http.Request) string {
	if value := strings.TrimSpace(req.Header.Get("X-Request-ID")); validRequestID(value) {
		return value
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return "fallback-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}
		switch b {
		case '-', '_', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}

func clientIP(req *http.Request) string {
	if resolved := resolvedClientIP(req); resolved != "" {
		return resolved
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}

func joinPath(base, next string) string {
	if base == "" {
		base = "/"
	}
	if next == "" {
		next = "/"
	}
	trailing := strings.HasSuffix(next, "/")
	joined := path.Join(base, next)
	if trailing && !strings.HasSuffix(joined, "/") {
		joined += "/"
	}
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	return joined
}

func canonicalRequestPath(value string) string {
	if value == "" {
		return "/"
	}
	trailingSlash := strings.HasSuffix(value, "/")
	cleaned := path.Clean("/" + strings.TrimPrefix(value, "/"))
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

func canonicalRequestURI(in *url.URL) string {
	out := *in
	out.Path = canonicalRequestPath(in.Path)
	out.RawPath = ""
	out.Fragment = ""
	return out.RequestURI()
}

func rewriteURL(in *url.URL, base *url.URL, routePrefix string, stripPrefix bool) *url.URL {
	out := *in
	out.Scheme = base.Scheme
	out.Host = base.Host
	// Route selection is based on the canonical decoded path. Apply prefix
	// stripping to that same path so the selected route and forwarded resource
	// cannot diverge when the request contains dot-segments.
	requestPath := canonicalRequestPath(in.Path)
	if stripPrefix {
		requestPath = strings.TrimPrefix(requestPath, routePrefix)
		if requestPath == "" {
			requestPath = "/"
		}
	}
	out.Path = joinPath(base.Path, requestPath)
	out.RawPath = ""
	if base.RawQuery == "" || in.RawQuery == "" {
		out.RawQuery = base.RawQuery + in.RawQuery
	} else {
		out.RawQuery = base.RawQuery + "&" + in.RawQuery
	}
	return &out
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}
