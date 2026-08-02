package router

import (
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

type Match struct{ Route *config.RouteConfig }

type Router struct{ routes []*config.RouteConfig }

func New(routes []config.RouteConfig) *Router {
	copied := make([]*config.RouteConfig, len(routes))
	for i := range routes {
		copied[i] = &routes[i]
	}
	return &Router{routes: copied}
}

func (r *Router) Match(req *http.Request) (Match, bool) {
	host := canonicalHost(req.Host)
	requestPath := canonicalRequestPath(req.URL.Path)
	var best *config.RouteConfig
	bestPathLength := -1
	bestHostScore := -1

	for _, route := range r.routes {
		matched, hostScore := hostMatchSpecificity(route.Hosts, host)
		if !matched || !pathPrefixMatches(requestPath, route.PathPrefix) {
			continue
		}

		pathLength := len(route.PathPrefix)
		if pathLength > bestPathLength || (pathLength == bestPathLength && hostScore > bestHostScore) {
			best = route
			bestPathLength = pathLength
			bestHostScore = hostScore
		}
	}
	if best == nil {
		return Match{}, false
	}
	return Match{Route: best}, true
}

func canonicalHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		// A Host header may contain a bracketed IPv6 literal without a port.
		// Config validation stores IP literals in canonical, unbracketed form,
		// so normalize the request-side representation the same way.
		if ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")); ip != nil {
			hostport = ip.String()
		}
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

// hostMatchSpecificity returns whether the host matches and a score used to
// resolve overlapping routes. Exact hosts beat wildcard suffixes, longer
// wildcard suffixes beat shorter ones, and the catch-all pattern is last.
func hostMatchSpecificity(patterns []string, host string) (bool, int) {
	best := -1
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
		switch {
		case p == "*":
			if best < 1 {
				best = 1
			}
		case strings.HasPrefix(p, "*."):
			suffix := strings.TrimPrefix(p, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				score := 1_000 + len(suffix)
				if score > best {
					best = score
				}
			}
		case p == host:
			score := 1_000_000 + len(p)
			if score > best {
				best = score
			}
		}
	}
	return best >= 0, best
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

func pathPrefixMatches(requestPath, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if requestPath == prefix {
		return true
	}
	return strings.HasPrefix(requestPath, prefix) && len(requestPath) > len(prefix) && requestPath[len(prefix)] == '/'
}
