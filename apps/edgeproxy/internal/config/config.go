package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	maxAdminLogStoreCapacity    = 100_000
	maxServerHeaderBytes        = 16 << 20
	maxProxyResponseHeaderBytes = 16 << 20
)

type Config struct {
	Server ServerConfig  `json:"server"`
	Admin  AdminConfig   `json:"admin"`
	Routes []RouteConfig `json:"routes"`
}

type ServerConfig struct {
	ListenAddr         string    `json:"listen_addr"`
	TrustedProxyCIDRs  []string  `json:"trusted_proxy_cidrs"`
	ForwardedForHeader string    `json:"forwarded_for_header"`
	ReadHeaderTimeout  Duration  `json:"read_header_timeout"`
	ReadTimeout        Duration  `json:"read_timeout"`
	WriteTimeout       Duration  `json:"write_timeout"`
	IdleTimeout        Duration  `json:"idle_timeout"`
	ShutdownTimeout    Duration  `json:"shutdown_timeout"`
	MaxHeaderBytes     int       `json:"max_header_bytes"`
	TLS                TLSConfig `json:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type AdminConfig struct {
	Enabled    bool           `json:"enabled"`
	ListenAddr string         `json:"listen_addr"`
	AuthToken  string         `json:"auth_token"`
	LogStore   AdminLogConfig `json:"log_store"`
}

type AdminLogConfig struct {
	Enabled         bool `json:"enabled"`
	Capacity        int  `json:"capacity"`
	DefaultPageSize int  `json:"default_page_size"`
	MaxPageSize     int  `json:"max_page_size"`
}

type RouteConfig struct {
	Name          string              `json:"name"`
	Hosts         []string            `json:"hosts"`
	PathPrefix    string              `json:"path_prefix"`
	StripPrefix   bool                `json:"strip_prefix"`
	PreserveHost  bool                `json:"preserve_host"`
	Upstreams     []UpstreamConfig    `json:"upstreams"`
	LoadBalancing LoadBalancingConfig `json:"load_balancing"`
	Proxy         ProxyConfig         `json:"proxy"`
	Cache         CacheConfig         `json:"cache"`
	HealthCheck   HealthCheckConfig   `json:"health_check"`
}

type UpstreamConfig struct {
	Name               string `json:"name,omitempty"`
	URL                string `json:"url"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Weight             int    `json:"weight,omitempty"`
	Priority           int    `json:"priority,omitempty"`
}

type LoadBalancingConfig struct {
	Algorithm          string  `json:"algorithm"`
	LatencySensitivity float64 `json:"latency_sensitivity,omitempty"`
	EWMAAlpha          float64 `json:"ewma_alpha,omitempty"`
}

type ProxyConfig struct {
	RequestTimeout         Duration `json:"request_timeout"`
	DialTimeout            Duration `json:"dial_timeout"`
	ResponseHeaderTimeout  Duration `json:"response_header_timeout"`
	IdleConnTimeout        Duration `json:"idle_conn_timeout"`
	RetryCount             int      `json:"retry_count"`
	RetryBackoff           Duration `json:"retry_backoff"`
	MaxIdleConns           int      `json:"max_idle_conns"`
	MaxIdleConnsPerHost    int      `json:"max_idle_conns_per_host"`
	MaxResponseHeaderBytes int64    `json:"max_response_header_bytes"`
}

type CacheConfig struct {
	Enabled                 bool     `json:"enabled"`
	DefaultTTL              Duration `json:"default_ttl"`
	StaleIfError            Duration `json:"stale_if_error"`
	MaxEntries              int      `json:"max_entries"`
	MaxBytes                int64    `json:"max_bytes"`
	MaxObjectBytes          int64    `json:"max_object_bytes"`
	RespectOriginHeaders    bool     `json:"respect_origin_headers"`
	CacheAuthorizedRequests bool     `json:"cache_authorized_requests"`
	CacheCookieRequests     bool     `json:"cache_cookie_requests"`
	CacheSetCookieResponses bool     `json:"cache_set_cookie_responses"`
	VaryRequestHeaders      []string `json:"vary_request_headers"`
	CacheableStatusCodes    []int    `json:"cacheable_status_codes"`
}

type HealthCheckConfig struct {
	Enabled         bool     `json:"enabled"`
	Path            string   `json:"path"`
	Interval        Duration `json:"interval"`
	Timeout         Duration `json:"timeout"`
	HealthyStatuses []int    `json:"healthy_statuses"`
}

func Load(path string) (Config, error) {
	cfg, err := LoadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := ApplyEnvironmentOverrides(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ApplyEnvironmentOverrides applies deployment-specific endpoints and secrets
// after the JSON profile has been decoded. Empty environment values are ignored,
// preserving the checked-in profile and built-in defaults when no .env file is
// present. Process environment variables take precedence over dotenv values
// because the dotenv loader never overwrites an existing variable.
func ApplyEnvironmentOverrides(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	applyStringEnv("EDGEPROXY_SERVER_LISTEN_ADDR", &cfg.Server.ListenAddr)
	applyStringEnv("EDGEPROXY_ADMIN_LISTEN_ADDR", &cfg.Admin.ListenAddr)
	applyStringEnv("EDGEPROXY_ADMIN_TOKEN", &cfg.Admin.AuthToken)
	applyStringEnv("EDGEPROXY_FORWARDED_FOR_HEADER", &cfg.Server.ForwardedForHeader)
	applyStringEnv("EDGEPROXY_TLS_CERT_FILE", &cfg.Server.TLS.CertFile)
	applyStringEnv("EDGEPROXY_TLS_KEY_FILE", &cfg.Server.TLS.KeyFile)

	if value, ok := nonEmptyEnvironment("EDGEPROXY_TRUSTED_PROXY_CIDRS"); ok {
		cfg.Server.TrustedProxyCIDRs = splitEnvironmentList(value)
	}
	if value, ok := nonEmptyEnvironment("EDGEPROXY_TLS_ENABLED"); ok {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("EDGEPROXY_TLS_ENABLED must be a boolean: %w", err)
		}
		cfg.Server.TLS.Enabled = enabled
	}

	seenSuffixes := make(map[string]string, len(cfg.Routes))
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		suffix := environmentRouteSuffix(route.Name)
		if suffix == "" {
			continue
		}
		hostsKey := "EDGEPROXY_ROUTE_" + suffix + "_HOSTS"
		upstreamsKey := "EDGEPROXY_ROUTE_" + suffix + "_UPSTREAM_URLS"
		if _, hostsSet := nonEmptyEnvironment(hostsKey); hostsSet {
			return fmt.Errorf("%s is not supported; define route hosts in the shared JSON profile", hostsKey)
		}
		if previous, exists := seenSuffixes[suffix]; exists && previous != route.Name {
			_, upstreamsSet := nonEmptyEnvironment(upstreamsKey)
			if upstreamsSet {
				return fmt.Errorf("route names %q and %q map to the same environment suffix %q", previous, route.Name, suffix)
			}
			continue
		}
		seenSuffixes[suffix] = route.Name

		if value, ok := nonEmptyEnvironment(upstreamsKey); ok {
			urls := splitEnvironmentList(value)
			if len(urls) == 0 {
				return fmt.Errorf("%s must contain at least one URL", upstreamsKey)
			}
			upstreams := make([]UpstreamConfig, len(urls))
			for j, rawURL := range urls {
				upstreams[j].URL = rawURL
				if j < len(route.Upstreams) {
					upstreams[j].InsecureSkipVerify = route.Upstreams[j].InsecureSkipVerify
				}
			}
			route.Upstreams = upstreams
		}
	}
	return nil
}

func applyStringEnv(key string, target *string) {
	if value, ok := nonEmptyEnvironment(key); ok {
		*target = value
	}
}

func nonEmptyEnvironment(key string) (string, bool) {
	value, exists := os.LookupEnv(key)
	value = strings.TrimSpace(value)
	return value, exists && value != ""
}

func splitEnvironmentList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func environmentRouteSuffix(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	underscore := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - ('a' - 'A'))
			underscore = false
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			underscore = false
		default:
			if b.Len() > 0 && !underscore {
				b.WriteByte('_')
				underscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr:         ":8080",
			ForwardedForHeader: "X-Forwarded-For",
			ReadHeaderTimeout:  Duration{5 * time.Second},
			ReadTimeout:        Duration{30 * time.Second},
			WriteTimeout:       Duration{60 * time.Second},
			IdleTimeout:        Duration{90 * time.Second},
			ShutdownTimeout:    Duration{10 * time.Second},
			MaxHeaderBytes:     1 << 20,
		},
		Admin: AdminConfig{
			Enabled:    true,
			ListenAddr: "127.0.0.1:9090",
			LogStore: AdminLogConfig{
				Enabled:         true,
				Capacity:        5000,
				DefaultPageSize: 100,
				MaxPageSize:     500,
			},
		},
	}
}

func (c *Config) Validate() error {
	var errs []error
	c.Server.ListenAddr = strings.TrimSpace(c.Server.ListenAddr)
	c.Server.ForwardedForHeader = strings.TrimSpace(c.Server.ForwardedForHeader)
	if c.Server.ForwardedForHeader == "" {
		c.Server.ForwardedForHeader = "X-Forwarded-For"
	}
	c.Server.TLS.CertFile = strings.TrimSpace(c.Server.TLS.CertFile)
	c.Server.TLS.KeyFile = strings.TrimSpace(c.Server.TLS.KeyFile)
	c.Admin.ListenAddr = strings.TrimSpace(c.Admin.ListenAddr)
	c.Admin.AuthToken = strings.TrimSpace(c.Admin.AuthToken)
	if strings.TrimSpace(c.Server.ListenAddr) == "" {
		errs = append(errs, errors.New("server.listen_addr is required"))
	} else if err := validateHostPort("server.listen_addr", c.Server.ListenAddr, true); err != nil {
		errs = append(errs, err)
	}
	if c.Server.ReadHeaderTimeout.Duration <= 0 {
		errs = append(errs, errors.New("server.read_header_timeout must be positive"))
	}
	if c.Server.ReadTimeout.Duration < 0 || c.Server.WriteTimeout.Duration < 0 || c.Server.IdleTimeout.Duration < 0 {
		errs = append(errs, errors.New("server read/write/idle timeouts cannot be negative"))
	}
	if c.Server.ShutdownTimeout.Duration <= 0 {
		errs = append(errs, errors.New("server.shutdown_timeout must be positive"))
	}
	if c.Server.MaxHeaderBytes <= 0 || c.Server.MaxHeaderBytes > maxServerHeaderBytes {
		errs = append(errs, fmt.Errorf("server.max_header_bytes must be between 1 and %d", maxServerHeaderBytes))
	}
	if !validHTTPToken(c.Server.ForwardedForHeader) {
		errs = append(errs, errors.New("server.forwarded_for_header must be a valid HTTP header field name"))
	} else if reservedClientIPSourceHeader(c.Server.ForwardedForHeader) {
		errs = append(errs, fmt.Errorf("server.forwarded_for_header %q is reserved and cannot be used as a client IP source", c.Server.ForwardedForHeader))
	}
	trusted := make([]string, 0, len(c.Server.TrustedProxyCIDRs))
	seenTrusted := map[string]struct{}{}
	for _, raw := range c.Server.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid server.trusted_proxy_cidrs entry %q", raw))
			continue
		}
		canonical := network.String()
		if _, exists := seenTrusted[canonical]; exists {
			continue
		}
		seenTrusted[canonical] = struct{}{}
		trusted = append(trusted, canonical)
	}
	c.Server.TrustedProxyCIDRs = trusted
	if c.Server.TLS.Enabled && (strings.TrimSpace(c.Server.TLS.CertFile) == "" || strings.TrimSpace(c.Server.TLS.KeyFile) == "") {
		errs = append(errs, errors.New("server.tls.cert_file and key_file are required when TLS is enabled"))
	}

	if c.Admin.Enabled {
		if listenerEndpointsOverlap(c.Server.ListenAddr, c.Admin.ListenAddr) {
			errs = append(errs, fmt.Errorf("server.listen_addr %q and admin.listen_addr %q overlap", c.Server.ListenAddr, c.Admin.ListenAddr))
		}
		host, _, err := net.SplitHostPort(c.Admin.ListenAddr)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid admin.listen_addr: %w", err))
		} else if portErr := validateHostPort("admin.listen_addr", c.Admin.ListenAddr, true); portErr != nil {
			errs = append(errs, portErr)
		} else if strings.TrimSpace(c.Admin.AuthToken) == "" && !isLoopbackHost(host) {
			errs = append(errs, errors.New("admin.auth_token is required when admin.listen_addr is not loopback"))
		}
		if c.Admin.LogStore.Enabled {
			if c.Admin.LogStore.Capacity <= 0 || c.Admin.LogStore.Capacity > maxAdminLogStoreCapacity {
				errs = append(errs, fmt.Errorf("admin.log_store.capacity must be between 1 and %d", maxAdminLogStoreCapacity))
			}
			if c.Admin.LogStore.DefaultPageSize <= 0 {
				errs = append(errs, errors.New("admin.log_store.default_page_size must be positive"))
			}
			if c.Admin.LogStore.MaxPageSize <= 0 {
				errs = append(errs, errors.New("admin.log_store.max_page_size must be positive"))
			}
			if c.Admin.LogStore.DefaultPageSize > c.Admin.LogStore.MaxPageSize {
				errs = append(errs, errors.New("admin.log_store.default_page_size cannot exceed max_page_size"))
			}
			if c.Admin.LogStore.MaxPageSize > c.Admin.LogStore.Capacity {
				errs = append(errs, errors.New("admin.log_store.max_page_size cannot exceed capacity"))
			}
		}
	}

	if len(c.Routes) == 0 {
		errs = append(errs, errors.New("at least one route is required"))
	}
	names := map[string]struct{}{}
	selectors := map[string]string{}
	for i := range c.Routes {
		r := &c.Routes[i]
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			errs = append(errs, fmt.Errorf("routes[%d].name is required", i))
		} else {
			nameKey := strings.ToLower(r.Name)
			if _, exists := names[nameKey]; exists {
				errs = append(errs, fmt.Errorf("duplicate route name %q (route names are case-insensitive)", r.Name))
			} else {
				names[nameKey] = struct{}{}
			}
		}
		if len(r.Hosts) == 0 {
			errs = append(errs, fmt.Errorf("route %q requires at least one host", r.Name))
		}
		seenHosts := map[string]struct{}{}
		for j, rawHost := range r.Hosts {
			host, hostErr := normalizeRouteHostPattern(rawHost)
			if hostErr != nil {
				errs = append(errs, fmt.Errorf("route %q hosts[%d]: %w", r.Name, j, hostErr))
				continue
			}
			r.Hosts[j] = host
			if _, exists := seenHosts[host]; exists {
				errs = append(errs, fmt.Errorf("route %q contains duplicate host pattern %q", r.Name, host))
			} else {
				seenHosts[host] = struct{}{}
			}
		}
		normalizedPrefix, prefixErr := normalizePathPrefix(r.PathPrefix)
		if prefixErr != nil {
			errs = append(errs, fmt.Errorf("route %q path_prefix: %w", r.Name, prefixErr))
		} else {
			r.PathPrefix = normalizedPrefix
		}
		if len(r.Upstreams) == 0 {
			errs = append(errs, fmt.Errorf("route %q requires at least one upstream", r.Name))
		}
		r.LoadBalancing.Algorithm = strings.ToLower(strings.TrimSpace(r.LoadBalancing.Algorithm))
		if r.LoadBalancing.Algorithm == "" {
			r.LoadBalancing.Algorithm = "round_robin"
		}
		switch r.LoadBalancing.Algorithm {
		case "round_robin", "weighted_round_robin", "least_connections", "priority_failover", "adaptive_latency", "random_weighted":
		default:
			errs = append(errs, fmt.Errorf("route %q load_balancing.algorithm %q is not supported", r.Name, r.LoadBalancing.Algorithm))
		}
		if r.LoadBalancing.LatencySensitivity == 0 {
			r.LoadBalancing.LatencySensitivity = 1
		}
		if r.LoadBalancing.LatencySensitivity < 0.1 || r.LoadBalancing.LatencySensitivity > 8 {
			errs = append(errs, fmt.Errorf("route %q load_balancing.latency_sensitivity must be between 0.1 and 8", r.Name))
		}
		if r.LoadBalancing.EWMAAlpha == 0 {
			r.LoadBalancing.EWMAAlpha = 0.25
		}
		if r.LoadBalancing.EWMAAlpha <= 0 || r.LoadBalancing.EWMAAlpha > 1 {
			errs = append(errs, fmt.Errorf("route %q load_balancing.ewma_alpha must be greater than 0 and no greater than 1", r.Name))
		}
		for _, host := range r.Hosts {
			if host == "" {
				continue
			}
			key := host + "\x00" + r.PathPrefix
			if owner, exists := selectors[key]; exists && owner != r.Name {
				errs = append(errs, fmt.Errorf("routes %q and %q have the same host/path selector %q %q", owner, r.Name, host, r.PathPrefix))
			} else {
				selectors[key] = r.Name
			}
		}
		seenUpstreamNames := map[string]struct{}{}
		for j := range r.Upstreams {
			r.Upstreams[j].Name = strings.TrimSpace(r.Upstreams[j].Name)
			r.Upstreams[j].URL = strings.TrimSpace(r.Upstreams[j].URL)
			if r.Upstreams[j].Weight == 0 {
				r.Upstreams[j].Weight = 1
			}
			if r.Upstreams[j].Priority == 0 {
				r.Upstreams[j].Priority = j + 1
			}
			if r.Upstreams[j].Name == "" {
				r.Upstreams[j].Name = fmt.Sprintf("origin-%d", j+1)
			}
			nameKey := strings.ToLower(r.Upstreams[j].Name)
			if _, exists := seenUpstreamNames[nameKey]; exists {
				errs = append(errs, fmt.Errorf("route %q contains duplicate upstream name %q", r.Name, r.Upstreams[j].Name))
			} else {
				seenUpstreamNames[nameKey] = struct{}{}
			}
			if r.Upstreams[j].Weight < 1 || r.Upstreams[j].Weight > 10000 {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] weight must be between 1 and 10000", r.Name, j))
			}
			if r.Upstreams[j].Priority < 1 || r.Upstreams[j].Priority > 10000 {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] priority must be between 1 and 10000", r.Name, j))
			}
			up := r.Upstreams[j]
			parsed, err := url.Parse(up.URL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] has invalid URL %q", r.Name, j, up.URL))
				continue
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] scheme must be http or https", r.Name, j))
			}
			if parsed.User != nil {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] must not contain URL credentials", r.Name, j))
			}
			if parsed.Fragment != "" {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] must not contain a URL fragment", r.Name, j))
			}
			if portErr := validateURLPort(fmt.Sprintf("route %q upstream[%d]", r.Name, j), parsed); portErr != nil {
				errs = append(errs, portErr)
			}
			if up.InsecureSkipVerify && parsed.Scheme != "https" {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] insecure_skip_verify is only valid for https", r.Name, j))
			}
		}

		if r.Proxy.RequestTimeout.Duration <= 0 || r.Proxy.DialTimeout.Duration <= 0 || r.Proxy.ResponseHeaderTimeout.Duration <= 0 {
			errs = append(errs, fmt.Errorf("route %q proxy request/dial/response-header timeouts must be positive", r.Name))
		}
		if r.Proxy.IdleConnTimeout.Duration < 0 || r.Proxy.RetryBackoff.Duration < 0 {
			errs = append(errs, fmt.Errorf("route %q proxy idle timeout and retry backoff cannot be negative", r.Name))
		}
		if r.Proxy.RetryCount < 0 {
			errs = append(errs, fmt.Errorf("route %q retry_count cannot be negative", r.Name))
		}
		if r.Proxy.MaxIdleConns <= 0 || r.Proxy.MaxIdleConnsPerHost <= 0 {
			errs = append(errs, fmt.Errorf("route %q proxy connection limits must be positive", r.Name))
		}
		if r.Proxy.MaxResponseHeaderBytes <= 0 || r.Proxy.MaxResponseHeaderBytes > maxProxyResponseHeaderBytes {
			errs = append(errs, fmt.Errorf("route %q proxy.max_response_header_bytes must be between 1 and %d", r.Name, maxProxyResponseHeaderBytes))
		}

		if r.Cache.Enabled {
			varied := make([]string, 0, len(r.Cache.VaryRequestHeaders)+2)
			seenVary := map[string]struct{}{}
			addVary := func(raw string) {
				name := http.CanonicalHeaderKey(strings.TrimSpace(raw))
				if !validHTTPToken(name) {
					errs = append(errs, fmt.Errorf("route %q cache.vary_request_headers contains invalid header %q", r.Name, raw))
					return
				}
				key := strings.ToLower(name)
				if _, exists := seenVary[key]; exists {
					return
				}
				seenVary[key] = struct{}{}
				varied = append(varied, name)
			}
			for _, name := range r.Cache.VaryRequestHeaders {
				addVary(name)
			}
			if r.Cache.CacheAuthorizedRequests {
				addVary("Authorization")
			}
			if r.Cache.CacheCookieRequests {
				addVary("Cookie")
			}
			r.Cache.VaryRequestHeaders = varied
			if r.Cache.DefaultTTL.Duration <= 0 {
				errs = append(errs, fmt.Errorf("route %q cache.default_ttl must be positive", r.Name))
			}
			if r.Cache.StaleIfError.Duration < 0 {
				errs = append(errs, fmt.Errorf("route %q cache.stale_if_error cannot be negative", r.Name))
			}
			if r.Cache.MaxEntries <= 0 || r.Cache.MaxBytes <= 0 || r.Cache.MaxObjectBytes <= 0 {
				errs = append(errs, fmt.Errorf("route %q cache limits must be positive", r.Name))
			}
			if r.Cache.MaxObjectBytes > r.Cache.MaxBytes {
				errs = append(errs, fmt.Errorf("route %q max_object_bytes cannot exceed max_bytes", r.Name))
			}
			if len(r.Cache.CacheableStatusCodes) == 0 {
				errs = append(errs, fmt.Errorf("route %q cache.cacheable_status_codes cannot be empty", r.Name))
			}
			for _, status := range r.Cache.CacheableStatusCodes {
				if status < 100 || status > 599 {
					errs = append(errs, fmt.Errorf("route %q has invalid cacheable status %d", r.Name, status))
				}
			}
		}

		if r.HealthCheck.Enabled {
			normalizedHealthPath, healthPathErr := normalizeAbsolutePath(r.HealthCheck.Path)
			if healthPathErr != nil {
				errs = append(errs, fmt.Errorf("route %q health_check.path: %w", r.Name, healthPathErr))
			} else {
				r.HealthCheck.Path = normalizedHealthPath
			}
			if r.HealthCheck.Interval.Duration <= 0 || r.HealthCheck.Timeout.Duration <= 0 {
				errs = append(errs, fmt.Errorf("route %q health-check durations must be positive", r.Name))
			}
			for _, status := range r.HealthCheck.HealthyStatuses {
				if status < 100 || status > 599 {
					errs = append(errs, fmt.Errorf("route %q has invalid healthy status %d", r.Name, status))
				}
			}
		}
	}
	return errors.Join(errs...)
}

func normalizeRouteHostPattern(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", errors.New("cannot be empty")
	}
	if value == "*" {
		return value, nil
	}
	if strings.ContainsAny(value, " \t\r\n/\\?#@") {
		return "", errors.New("must contain only a hostname, IP address, or leading wildcard")
	}
	if strings.HasPrefix(value, "*.") {
		if strings.Count(value, "*") != 1 {
			return "", errors.New("wildcard is only allowed as a single leading '*.'")
		}
		suffix, err := normalizeExactRouteHost(strings.TrimPrefix(value, "*."))
		if err != nil {
			return "", fmt.Errorf("invalid wildcard suffix: %w", err)
		}
		if net.ParseIP(suffix) != nil {
			return "", errors.New("wildcard suffix cannot be an IP address")
		}
		return "*." + suffix, nil
	}
	if strings.Contains(value, "*") {
		return "", errors.New("wildcard is only allowed as a single leading '*.'")
	}
	return normalizeExactRouteHost(value)
}

func normalizeExactRouteHost(value string) (string, error) {
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
		if ip == nil {
			return "", errors.New("contains an invalid bracketed IP address")
		}
		return strings.ToLower(ip.String()), nil
	}
	if ip := net.ParseIP(value); ip != nil {
		return strings.ToLower(ip.String()), nil
	}
	if strings.Contains(value, ":") {
		return "", errors.New("must not include a port")
	}
	if len(value) > 253 {
		return "", errors.New("hostname is longer than 253 characters")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return "", errors.New("hostname contains an empty or overlong label")
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			alnum := (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
			if !alnum && b != '-' {
				return "", errors.New("hostname labels may contain only letters, digits, and hyphens")
			}
			if (i == 0 || i == len(label)-1) && !alnum {
				return "", errors.New("hostname labels must start and end with a letter or digit")
			}
		}
	}
	return value, nil
}

func normalizePathPrefix(raw string) (string, error) {
	value, err := normalizeAbsolutePath(raw)
	if err != nil {
		return "", err
	}
	if value != "/" {
		value = strings.TrimSuffix(value, "/")
	}
	return value, nil
}

func normalizeAbsolutePath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "/", nil
	}
	if !strings.HasPrefix(value, "/") {
		return "", errors.New("must start with /")
	}
	if strings.ContainsAny(value, "?#") {
		return "", errors.New("must contain a path only")
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", fmt.Errorf("contains invalid escaping: %w", err)
	}
	if decoded != value {
		return "", errors.New("must not contain percent-encoded path bytes")
	}
	trailingSlash := strings.HasSuffix(value, "/")
	cleaned := path.Clean(value)
	if cleaned != value && !(trailingSlash && cleaned+"/" == value) {
		return "", errors.New("must be canonical and must not contain dot-segments or repeated slashes")
	}
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned, nil
}

func listenerEndpointsOverlap(first, second string) bool {
	firstHost, firstPortRaw, firstErr := net.SplitHostPort(strings.TrimSpace(first))
	secondHost, secondPortRaw, secondErr := net.SplitHostPort(strings.TrimSpace(second))
	if firstErr != nil || secondErr != nil {
		return false
	}
	firstPort, firstErr := normalizedListenerPort(firstPortRaw)
	secondPort, secondErr := normalizedListenerPort(secondPortRaw)
	if firstErr != nil || secondErr != nil || firstPort == 0 || secondPort == 0 || firstPort != secondPort {
		return false
	}
	return listenerHostsOverlap(firstHost, secondHost)
}

func normalizedListenerPort(raw string) (int, error) {
	if port, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return port, nil
	}
	return net.LookupPort("tcp", strings.TrimSpace(raw))
}

func listenerHostsOverlap(first, second string) bool {
	first = strings.Trim(strings.TrimSpace(first), "[]")
	second = strings.Trim(strings.TrimSpace(second), "[]")
	if strings.EqualFold(first, second) || anyListenerHost(first) || anyListenerHost(second) {
		return true
	}
	if isLoopbackHost(first) && isLoopbackHost(second) {
		return true
	}
	firstIP, secondIP := net.ParseIP(first), net.ParseIP(second)
	return firstIP != nil && secondIP != nil && firstIP.Equal(secondIP)
}

func anyListenerHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || host == "*" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

func validateHostPort(name, addr string, allowZero bool) error {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return validateNumericPort(name, port, allowZero)
}

func validateURLPort(name string, value *url.URL) error {
	if value == nil {
		return nil
	}
	// url.URL.Port cannot distinguish an omitted port from an explicit empty
	// port (for example, http://127.0.0.1:). Reject the latter rather than
	// silently falling back to the scheme default.
	if strings.HasSuffix(value.Host, ":") {
		return fmt.Errorf("%s port is required after ':'", name)
	}
	if value.Port() == "" {
		return nil
	}
	return validateNumericPort(name, value.Port(), false)
}

func validateNumericPort(name, raw string, allowZero bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%s port is required", name)
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		// net.Listen accepts registered service names, but an arbitrary token is
		// not necessarily resolvable. Validate the name now so -validate cannot
		// succeed for a network endpoint that will fail immediately at runtime
		// with an unknown-port error. TCP is authoritative here because
		// every supported endpoint either listens on TCP or requires TCP fallback.
		if _, lookupErr := net.LookupPort("tcp", raw); lookupErr != nil {
			return fmt.Errorf("%s port %q is neither numeric nor a registered TCP service: %w", name, raw, lookupErr)
		}
		return nil
	}
	minimum := 1
	if allowZero {
		minimum = 0
	}
	if port < minimum || port > 65535 {
		return fmt.Errorf("%s port must be between %d and 65535", name, minimum)
	}
	return nil
}

func reservedClientIPSourceHeader(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "authorization",
		"connection",
		"content-length",
		"content-type",
		"cookie",
		"forwarded",
		"host",
		"keep-alive",
		"proxy-authorization",
		"proxy-connection",
		"set-cookie",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade",
		"via",
		"x-forwarded-host",
		"x-forwarded-port",
		"x-forwarded-proto",
		"x-forwarded-server",
		"x-request-id":
		return true
	default:
		return false
	}
}

func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			continue
		}
		return false
	}
	return true
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
