package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
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
	Name         string            `json:"name"`
	Hosts        []string          `json:"hosts"`
	PathPrefix   string            `json:"path_prefix"`
	StripPrefix  bool              `json:"strip_prefix"`
	PreserveHost bool              `json:"preserve_host"`
	Upstreams    []UpstreamConfig  `json:"upstreams"`
	Proxy        ProxyConfig       `json:"proxy"`
	Cache        CacheConfig       `json:"cache"`
	HealthCheck  HealthCheckConfig `json:"health_check"`
}

type UpstreamConfig struct {
	URL                string `json:"url"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("parse config: expected exactly one JSON value")
		}
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	// An environment variable can override the file value so deployments do not
	// need to bake the admin credential into a committed JSON file.
	if token := strings.TrimSpace(os.Getenv("EDGEPROXY_ADMIN_TOKEN")); token != "" {
		cfg.Admin.AuthToken = token
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
	} else if _, _, err := net.SplitHostPort(c.Server.ListenAddr); err != nil {
		errs = append(errs, fmt.Errorf("invalid server.listen_addr: %w", err))
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
	if c.Server.MaxHeaderBytes <= 0 {
		errs = append(errs, errors.New("server.max_header_bytes must be positive"))
	}
	if !validHTTPToken(c.Server.ForwardedForHeader) {
		errs = append(errs, errors.New("server.forwarded_for_header must be a valid HTTP header field name"))
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
		host, _, err := net.SplitHostPort(c.Admin.ListenAddr)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid admin.listen_addr: %w", err))
		} else if strings.TrimSpace(c.Admin.AuthToken) == "" && !isLoopbackHost(host) {
			errs = append(errs, errors.New("admin.auth_token is required when admin.listen_addr is not loopback"))
		}
		if c.Admin.LogStore.Enabled {
			if c.Admin.LogStore.Capacity <= 0 {
				errs = append(errs, errors.New("admin.log_store.capacity must be positive"))
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
		} else if _, exists := names[r.Name]; exists {
			errs = append(errs, fmt.Errorf("duplicate route name %q", r.Name))
		} else {
			names[r.Name] = struct{}{}
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
		for j := range r.Upstreams {
			r.Upstreams[j].URL = strings.TrimSpace(r.Upstreams[j].URL)
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
		if r.Proxy.MaxIdleConns <= 0 || r.Proxy.MaxIdleConnsPerHost <= 0 || r.Proxy.MaxResponseHeaderBytes <= 0 {
			errs = append(errs, fmt.Errorf("route %q proxy connection/header limits must be positive", r.Name))
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
