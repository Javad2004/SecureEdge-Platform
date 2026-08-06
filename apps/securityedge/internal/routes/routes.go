package routes

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
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
	selectors := map[string]string{}
	for i := range cfg.Routes {
		cfg.Routes[i].Name = strings.TrimSpace(cfg.Routes[i].Name)
		normalizedPrefix, err := normalizePathPrefix(cfg.Routes[i].PathPrefix)
		if err != nil {
			return nil, fmt.Errorf("edgeproxy route %q path_prefix: %w", cfg.Routes[i].Name, err)
		}
		cfg.Routes[i].PathPrefix = normalizedPrefix
		if cfg.Routes[i].Name == "" || len(cfg.Routes[i].Hosts) == 0 {
			return nil, fmt.Errorf("edgeproxy route %d is incomplete", i)
		}
		nameKey := strings.ToLower(cfg.Routes[i].Name)
		if seenNames[nameKey] {
			return nil, fmt.Errorf("edgeproxy route name %q is duplicated (route names are case-insensitive)", cfg.Routes[i].Name)
		}
		seenNames[nameKey] = true
		hosts := make([]string, 0, len(cfg.Routes[i].Hosts))
		seenHosts := map[string]bool{}
		for _, raw := range cfg.Routes[i].Hosts {
			host, err := normalizeRouteHostPattern(raw)
			if err != nil {
				return nil, fmt.Errorf("edgeproxy route %q host %q: %w", cfg.Routes[i].Name, raw, err)
			}
			if seenHosts[host] {
				return nil, fmt.Errorf("edgeproxy route %q contains duplicate host pattern %q", cfg.Routes[i].Name, host)
			}
			seenHosts[host] = true
			hosts = append(hosts, host)
		}
		cfg.Routes[i].Hosts = hosts
		for _, host := range hosts {
			key := host + "\x00" + cfg.Routes[i].PathPrefix
			if owner, exists := selectors[key]; exists {
				return nil, fmt.Errorf("edgeproxy routes %q and %q have the same host/path selector %q %q", owner, cfg.Routes[i].Name, host, cfg.Routes[i].PathPrefix)
			}
			selectors[key] = cfg.Routes[i].Name
		}
	}
	return &Table{routes: cfg.Routes}, nil
}

func (t *Table) Match(req *http.Request) (Route, bool) {
	host := canonicalHost(req.Host)
	requestPath := canonicalRequestPath(req.URL.Path)
	var best *Route
	bestPathLength, bestHostScore := -1, -1
	for i := range t.routes {
		route := &t.routes[i]
		matched, hostScore := hostMatchSpecificity(route.Hosts, host)
		if !matched || !pathPrefixMatches(requestPath, route.PathPrefix) {
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

func normalizeRouteHostPattern(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", fmt.Errorf("cannot be empty")
	}
	if value == "*" {
		return value, nil
	}
	if strings.ContainsAny(value, " \t\r\n/\\?#@") {
		return "", fmt.Errorf("must contain only a hostname, IP address, or leading wildcard")
	}
	if strings.HasPrefix(value, "*.") {
		if strings.Count(value, "*") != 1 {
			return "", fmt.Errorf("wildcard is only allowed as a single leading '*.'")
		}
		suffix, err := normalizeExactRouteHost(strings.TrimPrefix(value, "*."))
		if err != nil {
			return "", fmt.Errorf("invalid wildcard suffix: %w", err)
		}
		if net.ParseIP(suffix) != nil {
			return "", fmt.Errorf("wildcard suffix cannot be an IP address")
		}
		return "*." + suffix, nil
	}
	if strings.Contains(value, "*") {
		return "", fmt.Errorf("wildcard is only allowed as a single leading '*.'")
	}
	return normalizeExactRouteHost(value)
}

func normalizeExactRouteHost(value string) (string, error) {
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
		if ip == nil {
			return "", fmt.Errorf("contains an invalid bracketed IP address")
		}
		return strings.ToLower(ip.String()), nil
	}
	if ip := net.ParseIP(value); ip != nil {
		return strings.ToLower(ip.String()), nil
	}
	if strings.Contains(value, ":") {
		return "", fmt.Errorf("must not include a port")
	}
	if len(value) > 253 {
		return "", fmt.Errorf("hostname is longer than 253 characters")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("hostname contains an empty or overlong label")
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			alnum := (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
			if !alnum && b != '-' {
				return "", fmt.Errorf("hostname labels may contain only letters, digits, and hyphens")
			}
			if (i == 0 || i == len(label)-1) && !alnum {
				return "", fmt.Errorf("hostname labels must start and end with a letter or digit")
			}
		}
	}
	return value, nil
}

func normalizePathPrefix(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "/", nil
	}
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("must start with /")
	}
	if strings.ContainsAny(value, "?#") {
		return "", fmt.Errorf("must contain a path only")
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", fmt.Errorf("contains invalid escaping: %w", err)
	}
	if decoded != value {
		return "", fmt.Errorf("must not contain percent-encoded path bytes")
	}
	value = strings.TrimRight(value, "/")
	if value == "" {
		value = "/"
	}
	if path.Clean(value) != value {
		return "", fmt.Errorf("must be canonical and must not contain dot-segments or repeated slashes")
	}
	return value, nil
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
	if prefix == "/" || requestPath == prefix {
		return true
	}
	return strings.HasPrefix(requestPath, prefix) && len(requestPath) > len(prefix) && requestPath[len(prefix)] == '/'
}
