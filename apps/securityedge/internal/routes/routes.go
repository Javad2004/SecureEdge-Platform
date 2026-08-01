package routes

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

type EdgeProxyConfig struct {
	Routes []Route `json:"routes"`
}
type Route struct {
	Name       string   `json:"name"`
	Hosts      []string `json:"hosts"`
	PathPrefix string   `json:"path_prefix"`
}

type Table struct{ routes []Route }

func Load(path string) (*Table, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read edgeproxy config: %w", err)
	}
	var cfg EdgeProxyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse edgeproxy config: %w", err)
	}
	if len(cfg.Routes) == 0 {
		return nil, fmt.Errorf("edgeproxy config has no routes")
	}
	seenNames := map[string]bool{}
	for i := range cfg.Routes {
		cfg.Routes[i].Name = strings.TrimSpace(cfg.Routes[i].Name)
		cfg.Routes[i].PathPrefix = strings.TrimSpace(cfg.Routes[i].PathPrefix)
		if cfg.Routes[i].PathPrefix == "" {
			cfg.Routes[i].PathPrefix = "/"
		}
		if cfg.Routes[i].Name == "" || len(cfg.Routes[i].Hosts) == 0 {
			return nil, fmt.Errorf("edgeproxy route %d is incomplete", i)
		}
		if seenNames[cfg.Routes[i].Name] {
			return nil, fmt.Errorf("edgeproxy route name %q is duplicated", cfg.Routes[i].Name)
		}
		seenNames[cfg.Routes[i].Name] = true
		if !strings.HasPrefix(cfg.Routes[i].PathPrefix, "/") {
			return nil, fmt.Errorf("edgeproxy route %q path_prefix must start with /", cfg.Routes[i].Name)
		}
		hosts := make([]string, 0, len(cfg.Routes[i].Hosts))
		seenHosts := map[string]bool{}
		for _, raw := range cfg.Routes[i].Hosts {
			host := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
			if host == "" {
				return nil, fmt.Errorf("edgeproxy route %q contains an empty host", cfg.Routes[i].Name)
			}
			if !seenHosts[host] {
				seenHosts[host] = true
				hosts = append(hosts, host)
			}
		}
		cfg.Routes[i].Hosts = hosts
	}
	return &Table{routes: cfg.Routes}, nil
}

func (t *Table) Match(req *http.Request) (Route, bool) {
	host := canonicalHost(req.Host)
	var best *Route
	bestPathLength, bestHostScore := -1, -1
	for i := range t.routes {
		route := &t.routes[i]
		matched, hostScore := hostMatchSpecificity(route.Hosts, host)
		if !matched || !pathPrefixMatches(req.URL.Path, route.PathPrefix) {
			continue
		}
		pathLength := len(route.PathPrefix)
		if pathLength > bestPathLength || (pathLength == bestPathLength && hostScore > bestHostScore) {
			best, bestPathLength, bestHostScore = route, pathLength, hostScore
		}
	}
	if best == nil {
		return Route{}, false
	}
	return *best, true
}

func (t *Table) Routes() []Route {
	out := make([]Route, len(t.routes))
	for i, route := range t.routes {
		out[i] = route
		out[i].Hosts = append([]string(nil), route.Hosts...)
	}
	return out
}

func canonicalHost(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostport), "."))
}
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
				score := 1000 + len(suffix)
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
func pathPrefixMatches(requestPath, prefix string) bool {
	if prefix == "/" || requestPath == prefix {
		return true
	}
	return strings.HasPrefix(requestPath, prefix) && len(requestPath) > len(prefix) && requestPath[len(prefix)] == '/'
}
