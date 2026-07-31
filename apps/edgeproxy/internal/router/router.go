package router

import (
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/bachelor-project/edgeproxy/internal/config"
)

type Match struct{ Route *config.RouteConfig }

type Router struct{ routes []*config.RouteConfig }

func New(routes []config.RouteConfig) *Router {
	copied := make([]*config.RouteConfig, len(routes))
	for i := range routes {
		copied[i] = &routes[i]
	}
	sort.SliceStable(copied, func(i, j int) bool { return len(copied[i].PathPrefix) > len(copied[j].PathPrefix) })
	return &Router{routes: copied}
}

func (r *Router) Match(req *http.Request) (Match, bool) {
	host := canonicalHost(req.Host)
	for _, route := range r.routes {
		if !hostMatches(route.Hosts, host) {
			continue
		}
		if !pathPrefixMatches(req.URL.Path, route.PathPrefix) {
			continue
		}
		return Match{Route: route}, true
	}
	return Match{}, false
}

func canonicalHost(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

func hostMatches(patterns []string, host string) bool {
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
		switch {
		case p == "*":
			return true
		case strings.HasPrefix(p, "*."):
			suffix := strings.TrimPrefix(p, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				return true
			}
		case p == host:
			return true
		}
	}
	return false
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
