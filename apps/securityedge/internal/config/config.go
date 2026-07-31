package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type Config struct {
	Server        ServerConfig      `json:"server"`
	Admin         AdminConfig       `json:"admin"`
	EdgeProxy     EdgeProxyConfig   `json:"edgeproxy"`
	DefaultPolicy Policy            `json:"default_policy"`
	RoutePolicies map[string]Policy `json:"route_policies"`
}

type ServerConfig struct {
	Mode              string   `json:"mode"`
	ListenAddr        string   `json:"listen_addr"`
	UpstreamProxyURL  string   `json:"upstream_proxy_url"`
	ReadHeaderTimeout Duration `json:"read_header_timeout"`
	ReadTimeout       Duration `json:"read_timeout"`
	WriteTimeout      Duration `json:"write_timeout"`
	IdleTimeout       Duration `json:"idle_timeout"`
	ShutdownTimeout   Duration `json:"shutdown_timeout"`
	MaxHeaderBytes    int      `json:"max_header_bytes"`
}

type AdminConfig struct {
	Enabled     bool           `json:"enabled"`
	ListenAddr  string         `json:"listen_addr"`
	AuthToken   string         `json:"auth_token"`
	LogStore    LogStoreConfig `json:"log_store"`
	PollTimeout Duration       `json:"poll_timeout"`
}

type LogStoreConfig struct {
	Capacity        int `json:"capacity"`
	DefaultPageSize int `json:"default_page_size"`
	MaxPageSize     int `json:"max_page_size"`
}

type EdgeProxyConfig struct {
	ConfigPath string   `json:"config_path"`
	AdminURL   string   `json:"admin_url"`
	AdminToken string   `json:"admin_token"`
	Timeout    Duration `json:"timeout"`
}

type Policy struct {
	Enabled                bool            `json:"enabled"`
	Mode                   string          `json:"mode"`
	AnomalyThreshold       int             `json:"anomaly_threshold"`
	InspectRequestBody     bool            `json:"inspect_request_body"`
	MaxInspectionBodyBytes int64           `json:"max_inspection_body_bytes"`
	BodyContentTypes       []string        `json:"body_content_types"`
	AllowedMethods         []string        `json:"allowed_methods"`
	ExcludedPathPrefixes   []string        `json:"excluded_path_prefixes"`
	DisabledRules          []string        `json:"disabled_rules"`
	IPAllowlist            []string        `json:"ip_allowlist"`
	IPDenylist             []string        `json:"ip_denylist"`
	RateLimit              RateLimitConfig `json:"rate_limit"`
}

type RateLimitConfig struct {
	Enabled           bool     `json:"enabled"`
	RequestsPerSecond float64  `json:"requests_per_second"`
	Burst             int      `json:"burst"`
	CleanupInterval   Duration `json:"cleanup_interval"`
	IdleTTL           Duration `json:"idle_ttl"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Mode: "gateway", ListenAddr: "0.0.0.0:8081", UpstreamProxyURL: "http://127.0.0.1:8080",
			ReadHeaderTimeout: Duration{5 * time.Second}, ReadTimeout: Duration{30 * time.Second},
			WriteTimeout: Duration{60 * time.Second}, IdleTimeout: Duration{90 * time.Second},
			ShutdownTimeout: Duration{10 * time.Second}, MaxHeaderBytes: 1 << 20,
		},
		Admin: AdminConfig{
			Enabled: true, ListenAddr: "127.0.0.1:9191", PollTimeout: Duration{5 * time.Second},
			LogStore: LogStoreConfig{Capacity: 5000, DefaultPageSize: 100, MaxPageSize: 500},
		},
		EdgeProxy: EdgeProxyConfig{AdminURL: "http://127.0.0.1:9090", Timeout: Duration{5 * time.Second}},
		DefaultPolicy: Policy{
			Enabled: true, Mode: "block", AnomalyThreshold: 5, InspectRequestBody: true,
			MaxInspectionBodyBytes: 1 << 20,
			BodyContentTypes:       []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "text/xml", "application/xml"},
			AllowedMethods:         []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			RateLimit:              RateLimitConfig{Enabled: true, RequestsPerSecond: 20, Burst: 40, CleanupInterval: Duration{time.Minute}, IdleTTL: Duration{10 * time.Minute}},
		},
		RoutePolicies: map[string]Policy{},
	}
}

func Load(path string) (Config, error) {
	cfg, err := LoadFile(path)
	if err != nil {
		return Config{}, err
	}
	if v := strings.TrimSpace(os.Getenv("SECURITYEDGE_ADMIN_TOKEN")); v != "" {
		cfg.Admin.AuthToken = v
	}
	if v := strings.TrimSpace(os.Getenv("EDGEPROXY_ADMIN_TOKEN")); v != "" {
		cfg.EdgeProxy.AdminToken = v
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadFile reads only the JSON file and deliberately does not apply secret
// environment overrides. It is used for safe policy persistence so an
// environment-provided token is never written back into the configuration.
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read security config: %w", err)
	}
	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse security config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	var errs []error
	c.Server.Mode = strings.ToLower(strings.TrimSpace(c.Server.Mode))
	if c.Server.Mode != "gateway" && c.Server.Mode != "embedded" {
		errs = append(errs, errors.New("server.mode must be gateway or embedded"))
	}
	if c.Server.Mode == "gateway" {
		if err := validateListen("server.listen_addr", c.Server.ListenAddr); err != nil {
			errs = append(errs, err)
		}
		u, err := url.Parse(strings.TrimSpace(c.Server.UpstreamProxyURL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, errors.New("server.upstream_proxy_url must be an absolute http(s) URL"))
		}
	}
	if c.Server.ReadHeaderTimeout.Duration <= 0 || c.Server.ShutdownTimeout.Duration <= 0 {
		errs = append(errs, errors.New("server read_header_timeout and shutdown_timeout must be positive"))
	}
	if c.Server.MaxHeaderBytes <= 0 {
		errs = append(errs, errors.New("server.max_header_bytes must be positive"))
	}
	if c.Admin.Enabled {
		if err := validateListen("admin.listen_addr", c.Admin.ListenAddr); err != nil {
			errs = append(errs, err)
		}
		host, _, _ := net.SplitHostPort(c.Admin.ListenAddr)
		if strings.TrimSpace(c.Admin.AuthToken) == "" && !isLoopback(host) {
			errs = append(errs, errors.New("admin.auth_token is required when admin is not loopback"))
		}
		if c.Admin.LogStore.Capacity <= 0 || c.Admin.LogStore.DefaultPageSize <= 0 || c.Admin.LogStore.MaxPageSize <= 0 {
			errs = append(errs, errors.New("admin.log_store values must be positive"))
		}
		if c.Admin.LogStore.DefaultPageSize > c.Admin.LogStore.MaxPageSize || c.Admin.LogStore.MaxPageSize > c.Admin.LogStore.Capacity {
			errs = append(errs, errors.New("admin.log_store requires default_page_size <= max_page_size <= capacity"))
		}
	}
	if c.EdgeProxy.ConfigPath == "" {
		errs = append(errs, errors.New("edgeproxy.config_path is required"))
	}
	if c.EdgeProxy.AdminURL != "" {
		u, err := url.Parse(c.EdgeProxy.AdminURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, errors.New("edgeproxy.admin_url must be an absolute http(s) URL"))
		}
	}
	if err := validatePolicy("default_policy", &c.DefaultPolicy); err != nil {
		errs = append(errs, err)
	}
	names := make([]string, 0, len(c.RoutePolicies))
	for name := range c.RoutePolicies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := c.RoutePolicies[name]
		if strings.TrimSpace(name) == "" {
			errs = append(errs, errors.New("route policy name cannot be empty"))
			continue
		}
		if err := validatePolicy("route_policies."+name, &p); err != nil {
			errs = append(errs, err)
		}
		c.RoutePolicies[name] = p
	}
	return errors.Join(errs...)
}

func validatePolicy(name string, p *Policy) error {
	var errs []error
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode != "block" && p.Mode != "log" && p.Mode != "off" {
		errs = append(errs, fmt.Errorf("%s.mode must be block, log, or off", name))
	}
	if p.AnomalyThreshold <= 0 {
		errs = append(errs, fmt.Errorf("%s.anomaly_threshold must be positive", name))
	}
	if p.MaxInspectionBodyBytes < 0 || p.MaxInspectionBodyBytes > 16<<20 {
		errs = append(errs, fmt.Errorf("%s.max_inspection_body_bytes must be between 0 and 16777216", name))
	}
	methods := make([]string, 0, len(p.AllowedMethods))
	seen := map[string]bool{}
	for _, m := range p.AllowedMethods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m != "" && !seen[m] {
			methods = append(methods, m)
			seen[m] = true
		}
	}
	p.AllowedMethods = methods
	if p.RateLimit.Enabled {
		if p.RateLimit.RequestsPerSecond <= 0 || p.RateLimit.Burst <= 0 {
			errs = append(errs, fmt.Errorf("%s.rate_limit requests_per_second and burst must be positive", name))
		}
		if p.RateLimit.CleanupInterval.Duration <= 0 || p.RateLimit.IdleTTL.Duration <= 0 {
			errs = append(errs, fmt.Errorf("%s.rate_limit cleanup_interval and idle_ttl must be positive", name))
		}
	}
	return errors.Join(errs...)
}

func validateListen(name, addr string) error {
	if _, _, err := net.SplitHostPort(strings.TrimSpace(addr)); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
