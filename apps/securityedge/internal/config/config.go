package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Config struct {
	Server        ServerConfig      `json:"server"`
	Admin         AdminConfig       `json:"admin"`
	EdgeProxy     EdgeProxyConfig   `json:"edgeproxy"`
	WAF           WAFConfig         `json:"waf"`
	DefaultPolicy Policy            `json:"default_policy"`
	RoutePolicies map[string]Policy `json:"route_policies"`
}

type ServerConfig struct {
	Mode                   string          `json:"mode"`
	ListenAddr             string          `json:"listen_addr"`
	UpstreamProxyURL       string          `json:"upstream_proxy_url"`
	ReadHeaderTimeout      Duration        `json:"read_header_timeout"`
	ReadTimeout            Duration        `json:"read_timeout"`
	WriteTimeout           Duration        `json:"write_timeout"`
	IdleTimeout            Duration        `json:"idle_timeout"`
	ShutdownTimeout        Duration        `json:"shutdown_timeout"`
	MaxHeaderBytes         int             `json:"max_header_bytes"`
	MaxRequestBodyBytes    int64           `json:"max_request_body_bytes"`
	MaxConcurrentRequests  int             `json:"max_concurrent_requests"`
	MaxConcurrentPerClient int             `json:"max_concurrent_per_client"`
	TrustedProxyCIDRs      []string        `json:"trusted_proxy_cidrs"`
	ForwardedForHeader     string          `json:"forwarded_for_header"`
	PreserveHost           bool            `json:"preserve_host"`
	AddSecurityHeaders     bool            `json:"add_security_headers"`
	UpstreamTransport      TransportConfig `json:"upstream_transport"`
}

type TransportConfig struct {
	DialTimeout           Duration `json:"dial_timeout"`
	TLSHandshakeTimeout   Duration `json:"tls_handshake_timeout"`
	ResponseHeaderTimeout Duration `json:"response_header_timeout"`
	ExpectContinueTimeout Duration `json:"expect_continue_timeout"`
	IdleConnTimeout       Duration `json:"idle_conn_timeout"`
	MaxIdleConns          int      `json:"max_idle_conns"`
	MaxIdleConnsPerHost   int      `json:"max_idle_conns_per_host"`
	MaxConnsPerHost       int      `json:"max_conns_per_host"`
}

type AdminConfig struct {
	Enabled               bool               `json:"enabled"`
	ListenAddr            string             `json:"listen_addr"`
	AuthToken             string             `json:"auth_token"`
	LogStore              LogStoreConfig     `json:"log_store"`
	Connectivity          ConnectivityConfig `json:"connectivity"`
	PollTimeout           Duration           `json:"poll_timeout"`
	MaxRequestBodyBytes   int64              `json:"max_request_body_bytes"`
	AuthFailuresPerMinute int                `json:"auth_failures_per_minute"`
	AuthLockoutDuration   Duration           `json:"auth_lockout_duration"`
}

type ConnectivityConfig struct {
	Enabled         bool           `json:"enabled"`
	CheckInterval   Duration       `json:"check_interval"`
	Timeout         Duration       `json:"timeout"`
	StaleAfter      Duration       `json:"stale_after"`
	HistoryCapacity int            `json:"history_capacity"`
	DNS             DNSProbeConfig `json:"dns"`
}

type DNSProbeConfig struct {
	Enabled           bool     `json:"enabled"`
	Critical          bool     `json:"critical"`
	Server            string   `json:"server"`
	Names             []string `json:"names"`
	ExpectedAddresses []string `json:"expected_addresses"`
}

type LogStoreConfig struct {
	Capacity        int    `json:"capacity"`
	DefaultPageSize int    `json:"default_page_size"`
	MaxPageSize     int    `json:"max_page_size"`
	FilePath        string `json:"file_path"`
	MaxFileBytes    int64  `json:"max_file_bytes"`
	MaxBackups      int    `json:"max_backups"`
}

type EdgeProxyConfig struct {
	ConfigPath string   `json:"config_path"`
	AdminURL   string   `json:"admin_url"`
	AdminToken string   `json:"admin_token"`
	Timeout    Duration `json:"timeout"`
}

type WAFConfig struct {
	MaximumMatchesPerRequest int                `json:"maximum_matches_per_request"`
	CustomRules              []CustomRuleConfig `json:"custom_rules"`
}

type CustomRuleConfig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Score       int      `json:"score"`
	Targets     []string `json:"targets"`
	Pattern     string   `json:"pattern"`
}

type Policy struct {
	Enabled                    bool            `json:"enabled"`
	Mode                       string          `json:"mode"`
	AnomalyThreshold           int             `json:"anomaly_threshold"`
	InspectRequestBody         bool            `json:"inspect_request_body"`
	MaxInspectionBodyBytes     int64           `json:"max_inspection_body_bytes"`
	BodyContentTypes           []string        `json:"body_content_types"`
	AllowedMethods             []string        `json:"allowed_methods"`
	ExcludedPathPrefixes       []string        `json:"excluded_path_prefixes"`
	DisabledRules              []string        `json:"disabled_rules"`
	IPAllowlist                []string        `json:"ip_allowlist"`
	IPDenylist                 []string        `json:"ip_denylist"`
	MaxPathBytes               int             `json:"max_path_bytes"`
	MaxQueryBytes              int             `json:"max_query_bytes"`
	MaxHeaderCount             int             `json:"max_header_count"`
	MaxHeaderValueBytes        int             `json:"max_header_value_bytes"`
	RejectEncodedRequestBodies bool            `json:"reject_encoded_request_bodies"`
	RejectUnsupportedBodyTypes bool            `json:"reject_unsupported_body_types"`
	BlockOnInspectionLimit     bool            `json:"block_on_inspection_limit"`
	RateLimit                  RateLimitConfig `json:"rate_limit"`
	AutoBan                    AutoBanConfig   `json:"auto_ban"`
}

type RateLimitConfig struct {
	Enabled                 bool     `json:"enabled"`
	RequestsPerSecond       float64  `json:"requests_per_second"`
	Burst                   int      `json:"burst"`
	GlobalRequestsPerSecond float64  `json:"global_requests_per_second"`
	GlobalBurst             int      `json:"global_burst"`
	CleanupInterval         Duration `json:"cleanup_interval"`
	IdleTTL                 Duration `json:"idle_ttl"`
	MaxBuckets              int      `json:"max_buckets"`
}

type AutoBanConfig struct {
	Enabled            bool     `json:"enabled"`
	ViolationThreshold int      `json:"violation_threshold"`
	Window             Duration `json:"window"`
	BanDuration        Duration `json:"ban_duration"`
	MaxTrackedClients  int      `json:"max_tracked_clients"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Mode: "gateway", ListenAddr: "0.0.0.0:8081", UpstreamProxyURL: "http://127.0.0.1:8080",
			ReadHeaderTimeout: Duration{5 * time.Second}, ReadTimeout: Duration{30 * time.Second},
			WriteTimeout: Duration{60 * time.Second}, IdleTimeout: Duration{90 * time.Second},
			ShutdownTimeout: Duration{10 * time.Second}, MaxHeaderBytes: 64 << 10,
			MaxRequestBodyBytes: 8 << 20, MaxConcurrentRequests: 512, MaxConcurrentPerClient: 32,
			ForwardedForHeader: "X-Forwarded-For", PreserveHost: true, AddSecurityHeaders: true,
			UpstreamTransport: TransportConfig{
				DialTimeout: Duration{5 * time.Second}, TLSHandshakeTimeout: Duration{5 * time.Second},
				ResponseHeaderTimeout: Duration{30 * time.Second}, ExpectContinueTimeout: Duration{1 * time.Second},
				IdleConnTimeout: Duration{90 * time.Second}, MaxIdleConns: 256, MaxIdleConnsPerHost: 128, MaxConnsPerHost: 0,
			},
		},
		Admin: AdminConfig{
			Enabled: true, ListenAddr: "127.0.0.1:9191", PollTimeout: Duration{5 * time.Second},
			MaxRequestBodyBytes: 1 << 20, AuthFailuresPerMinute: 10, AuthLockoutDuration: Duration{5 * time.Minute},
			LogStore:     LogStoreConfig{Capacity: 10000, DefaultPageSize: 100, MaxPageSize: 500, MaxFileBytes: 20 << 20, MaxBackups: 3},
			Connectivity: ConnectivityConfig{Enabled: true, CheckInterval: Duration{5 * time.Second}, Timeout: Duration{3 * time.Second}, StaleAfter: Duration{15 * time.Second}, HistoryCapacity: 50},
		},
		EdgeProxy: EdgeProxyConfig{AdminURL: "http://127.0.0.1:9090", Timeout: Duration{5 * time.Second}},
		WAF:       WAFConfig{MaximumMatchesPerRequest: 32},
		DefaultPolicy: Policy{
			Enabled: true, Mode: "block", AnomalyThreshold: 5, InspectRequestBody: true,
			MaxInspectionBodyBytes: 1 << 20,
			BodyContentTypes:       []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/plain", "text/xml", "application/xml"},
			AllowedMethods:         []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			MaxPathBytes:           4096, MaxQueryBytes: 8192, MaxHeaderCount: 100, MaxHeaderValueBytes: 8192,
			RejectEncodedRequestBodies: true, RejectUnsupportedBodyTypes: false, BlockOnInspectionLimit: true,
			RateLimit: RateLimitConfig{
				Enabled: true, RequestsPerSecond: 20, Burst: 40, GlobalRequestsPerSecond: 500, GlobalBurst: 1000,
				CleanupInterval: Duration{time.Minute}, IdleTTL: Duration{10 * time.Minute}, MaxBuckets: 100000,
			},
			AutoBan: AutoBanConfig{Enabled: true, ViolationThreshold: 20, Window: Duration{time.Minute}, BanDuration: Duration{10 * time.Minute}, MaxTrackedClients: 100000},
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

// LoadFile reads JSON without applying secret environment overrides. This keeps
// environment-provided secrets out of atomically persisted policy updates.
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
	if c.Server.MaxHeaderBytes <= 0 || c.Server.MaxHeaderBytes > 16<<20 {
		errs = append(errs, errors.New("server.max_header_bytes must be between 1 and 16777216"))
	}
	if c.Server.MaxRequestBodyBytes <= 0 || c.Server.MaxRequestBodyBytes > 1<<30 {
		errs = append(errs, errors.New("server.max_request_body_bytes must be between 1 and 1073741824"))
	}
	if c.Server.MaxConcurrentRequests <= 0 || c.Server.MaxConcurrentPerClient <= 0 || c.Server.MaxConcurrentPerClient > c.Server.MaxConcurrentRequests {
		errs = append(errs, errors.New("server concurrency limits must be positive and per-client cannot exceed global"))
	}
	c.Server.ForwardedForHeader = strings.TrimSpace(c.Server.ForwardedForHeader)
	if c.Server.ForwardedForHeader == "" {
		c.Server.ForwardedForHeader = "X-Forwarded-For"
	}
	for _, cidr := range c.Server.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			errs = append(errs, fmt.Errorf("invalid server.trusted_proxy_cidrs entry %q", cidr))
		}
	}
	if err := validateTransport(c.Server.UpstreamTransport); err != nil {
		errs = append(errs, err)
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
		if c.Admin.LogStore.FilePath != "" && (c.Admin.LogStore.MaxFileBytes <= 0 || c.Admin.LogStore.MaxBackups < 0) {
			errs = append(errs, errors.New("file logging requires positive max_file_bytes and non-negative max_backups"))
		}
		if c.Admin.Connectivity.Enabled {
			if c.Admin.Connectivity.CheckInterval.Duration < time.Second || c.Admin.Connectivity.CheckInterval.Duration > time.Hour {
				errs = append(errs, errors.New("admin.connectivity.check_interval must be between 1s and 1h"))
			}
			if c.Admin.Connectivity.Timeout.Duration <= 0 || c.Admin.Connectivity.Timeout.Duration > c.Admin.Connectivity.CheckInterval.Duration {
				errs = append(errs, errors.New("admin.connectivity.timeout must be positive and cannot exceed check_interval"))
			}
			if c.Admin.Connectivity.StaleAfter.Duration < c.Admin.Connectivity.CheckInterval.Duration {
				errs = append(errs, errors.New("admin.connectivity.stale_after cannot be shorter than check_interval"))
			}
			if c.Admin.Connectivity.HistoryCapacity < 1 || c.Admin.Connectivity.HistoryCapacity > 10000 {
				errs = append(errs, errors.New("admin.connectivity.history_capacity must be between 1 and 10000"))
			}
			if c.Admin.Connectivity.DNS.Enabled {
				if _, _, err := net.SplitHostPort(strings.TrimSpace(c.Admin.Connectivity.DNS.Server)); err != nil {
					errs = append(errs, errors.New("admin.connectivity.dns.server must be host:port"))
				}
				if len(c.Admin.Connectivity.DNS.Names) == 0 {
					errs = append(errs, errors.New("admin.connectivity.dns.names must contain at least one domain when DNS probing is enabled"))
				}
				for _, address := range c.Admin.Connectivity.DNS.ExpectedAddresses {
					if net.ParseIP(strings.TrimSpace(address)) == nil {
						errs = append(errs, fmt.Errorf("invalid admin.connectivity.dns.expected_addresses entry %q", address))
					}
				}
			}
		}
		if c.Admin.MaxRequestBodyBytes <= 0 || c.Admin.MaxRequestBodyBytes > 16<<20 {
			errs = append(errs, errors.New("admin.max_request_body_bytes must be between 1 and 16777216"))
		}
		if c.Admin.AuthFailuresPerMinute <= 0 || c.Admin.AuthLockoutDuration.Duration <= 0 {
			errs = append(errs, errors.New("admin auth failure and lockout settings must be positive"))
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
	if c.WAF.MaximumMatchesPerRequest <= 0 || c.WAF.MaximumMatchesPerRequest > 256 {
		errs = append(errs, errors.New("waf.maximum_matches_per_request must be between 1 and 256"))
	}
	if err := validateCustomRules(c.WAF.CustomRules); err != nil {
		errs = append(errs, err)
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

func validateTransport(t TransportConfig) error {
	var errs []error
	for name, d := range map[string]Duration{
		"dial_timeout": t.DialTimeout, "tls_handshake_timeout": t.TLSHandshakeTimeout,
		"response_header_timeout": t.ResponseHeaderTimeout, "expect_continue_timeout": t.ExpectContinueTimeout,
		"idle_conn_timeout": t.IdleConnTimeout,
	} {
		if d.Duration <= 0 {
			errs = append(errs, fmt.Errorf("server.upstream_transport.%s must be positive", name))
		}
	}
	if t.MaxIdleConns <= 0 || t.MaxIdleConnsPerHost <= 0 || t.MaxConnsPerHost < 0 {
		errs = append(errs, errors.New("server upstream connection limits are invalid"))
	}
	return errors.Join(errs...)
}

func validateCustomRules(rules []CustomRuleConfig) error {
	var errs []error
	seen := map[string]bool{}
	validTargets := map[string]bool{"path": true, "query": true, "body": true, "headers": true, "cookies": true}
	for i := range rules {
		r := &rules[i]
		r.ID = strings.ToUpper(strings.TrimSpace(r.ID))
		r.Name = strings.TrimSpace(r.Name)
		r.Category = strings.ToLower(strings.TrimSpace(r.Category))
		if r.ID == "" || seen[r.ID] {
			errs = append(errs, fmt.Errorf("waf.custom_rules[%d].id is empty or duplicated", i))
		}
		seen[r.ID] = true
		if r.Name == "" || r.Category == "" || r.Description == "" || r.Score <= 0 || len(r.Targets) == 0 || r.Pattern == "" {
			errs = append(errs, fmt.Errorf("waf.custom_rules[%d] is incomplete", i))
		}
		for _, target := range r.Targets {
			if !validTargets[strings.ToLower(strings.TrimSpace(target))] {
				errs = append(errs, fmt.Errorf("waf.custom_rules[%d] has unsupported target %q", i, target))
			}
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			errs = append(errs, fmt.Errorf("waf.custom_rules[%d].pattern: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func validatePolicy(name string, p *Policy) error {
	var errs []error
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode != "block" && p.Mode != "log" && p.Mode != "off" {
		errs = append(errs, fmt.Errorf("%s.mode must be block, log, or off", name))
	}
	if p.AnomalyThreshold <= 0 || p.AnomalyThreshold > 1000 {
		errs = append(errs, fmt.Errorf("%s.anomaly_threshold must be between 1 and 1000", name))
	}
	if p.MaxInspectionBodyBytes < 0 || p.MaxInspectionBodyBytes > 16<<20 {
		errs = append(errs, fmt.Errorf("%s.max_inspection_body_bytes must be between 0 and 16777216", name))
	}
	if p.MaxPathBytes <= 0 || p.MaxPathBytes > 1<<20 || p.MaxQueryBytes <= 0 || p.MaxQueryBytes > 16<<20 {
		errs = append(errs, fmt.Errorf("%s path/query limits are invalid", name))
	}
	if p.MaxHeaderCount <= 0 || p.MaxHeaderCount > 10000 || p.MaxHeaderValueBytes <= 0 || p.MaxHeaderValueBytes > 16<<20 {
		errs = append(errs, fmt.Errorf("%s header limits are invalid", name))
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
		if p.RateLimit.RequestsPerSecond <= 0 || p.RateLimit.Burst <= 0 || p.RateLimit.GlobalRequestsPerSecond <= 0 || p.RateLimit.GlobalBurst <= 0 {
			errs = append(errs, fmt.Errorf("%s rate_limit rates and bursts must be positive", name))
		}
		if p.RateLimit.CleanupInterval.Duration <= 0 || p.RateLimit.IdleTTL.Duration <= 0 || p.RateLimit.MaxBuckets <= 0 {
			errs = append(errs, fmt.Errorf("%s rate_limit lifecycle settings must be positive", name))
		}
	}
	if p.AutoBan.Enabled {
		if p.AutoBan.ViolationThreshold <= 0 || p.AutoBan.Window.Duration <= 0 || p.AutoBan.BanDuration.Duration <= 0 || p.AutoBan.MaxTrackedClients <= 0 {
			errs = append(errs, fmt.Errorf("%s auto_ban settings must be positive", name))
		}
	}
	for _, list := range [][]string{p.IPAllowlist, p.IPDenylist} {
		for _, item := range list {
			if net.ParseIP(strings.TrimSpace(item)) == nil {
				if _, _, err := net.ParseCIDR(strings.TrimSpace(item)); err != nil {
					errs = append(errs, fmt.Errorf("%s contains invalid IP/CIDR %q", name, item))
				}
			}
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
