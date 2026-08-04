package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxAdminLogStoreCapacity = 100_000

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

// MaxCustomRuleScore keeps individual custom-rule contributions within the
// same documented range as policy anomaly thresholds. Besides preventing
// configuration mistakes, this bounds aggregate scoring work before the WAF's
// defensive saturation logic is needed.
const MaxCustomRuleScore = 1000

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
	ApplyEnvironmentOverrides(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ApplyEnvironmentOverrides injects runtime-only credentials without changing
// the file-backed configuration that is persisted by policy updates.
func ApplyEnvironmentOverrides(cfg *Config) {
	if cfg == nil {
		return
	}
	if v := strings.TrimSpace(os.Getenv("SECURITYEDGE_ADMIN_TOKEN")); v != "" {
		cfg.Admin.AuthToken = v
	}
	if v := strings.TrimSpace(os.Getenv("EDGEPROXY_ADMIN_TOKEN")); v != "" {
		cfg.EdgeProxy.AdminToken = v
	}
}

// LoadFile reads JSON without applying secret environment overrides. This keeps
// environment-provided secrets out of atomically persisted policy updates.
func LoadFile(path string) (Config, error) {
	data, recoveryPath, err := readConfigForLoad(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse security config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("parse security config: expected exactly one JSON value")
		}
		return Config{}, fmt.Errorf("parse security config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	if recoveryPath != "" {
		if err := os.Rename(recoveryPath, path); err != nil {
			return Config{}, fmt.Errorf("restore staged security config: %w", err)
		}
	}
	return cfg, nil
}

// readConfigForLoad recovers the backup left by an interrupted atomic update.
// Validation happens before the backup is restored, so malformed recovery data
// never replaces the configured path.
func readConfigForLoad(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, "", nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("read security config: %w", err)
	}

	recoveryPath := path + ".bak"
	data, recoveryErr := os.ReadFile(recoveryPath)
	if recoveryErr != nil {
		return nil, "", fmt.Errorf("read security config: %w", err)
	}
	return data, recoveryPath, nil
}

func (c *Config) Validate() error {
	var errs []error
	c.Server.Mode = strings.ToLower(strings.TrimSpace(c.Server.Mode))
	c.Server.ListenAddr = strings.TrimSpace(c.Server.ListenAddr)
	c.Server.UpstreamProxyURL = strings.TrimSpace(c.Server.UpstreamProxyURL)
	c.Server.ForwardedForHeader = strings.TrimSpace(c.Server.ForwardedForHeader)
	c.Admin.ListenAddr = strings.TrimSpace(c.Admin.ListenAddr)
	c.Admin.AuthToken = strings.TrimSpace(c.Admin.AuthToken)
	c.Admin.LogStore.FilePath = strings.TrimSpace(c.Admin.LogStore.FilePath)
	c.Admin.Connectivity.DNS.Server = strings.TrimSpace(c.Admin.Connectivity.DNS.Server)
	c.EdgeProxy.ConfigPath = strings.TrimSpace(c.EdgeProxy.ConfigPath)
	c.EdgeProxy.AdminURL = strings.TrimSpace(c.EdgeProxy.AdminURL)
	c.EdgeProxy.AdminToken = strings.TrimSpace(c.EdgeProxy.AdminToken)
	if c.Server.Mode != "gateway" && c.Server.Mode != "embedded" {
		errs = append(errs, errors.New("server.mode must be gateway or embedded"))
	}
	if c.Server.Mode == "gateway" {
		if err := validateListen("server.listen_addr", c.Server.ListenAddr); err != nil {
			errs = append(errs, err)
		}
		u, err := url.Parse(c.Server.UpstreamProxyURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, errors.New("server.upstream_proxy_url must be an absolute http(s) origin URL without credentials, non-root paths, queries, or fragments"))
		} else if portErr := validateURLPort("server.upstream_proxy_url", u); portErr != nil {
			errs = append(errs, portErr)
		}
	}
	if c.Server.ReadHeaderTimeout.Duration <= 0 || c.Server.ShutdownTimeout.Duration <= 0 {
		errs = append(errs, errors.New("server read_header_timeout and shutdown_timeout must be positive"))
	}
	if c.Server.ReadTimeout.Duration < 0 || c.Server.WriteTimeout.Duration < 0 || c.Server.IdleTimeout.Duration < 0 {
		errs = append(errs, errors.New("server read/write/idle timeouts cannot be negative"))
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
	if c.Server.ForwardedForHeader == "" {
		c.Server.ForwardedForHeader = "X-Forwarded-For"
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
		if c.Admin.LogStore.Capacity <= 0 || c.Admin.LogStore.Capacity > maxAdminLogStoreCapacity {
			errs = append(errs, fmt.Errorf("admin.log_store.capacity must be between 1 and %d", maxAdminLogStoreCapacity))
		}
		if c.Admin.LogStore.DefaultPageSize <= 0 || c.Admin.LogStore.MaxPageSize <= 0 {
			errs = append(errs, errors.New("admin.log_store page sizes must be positive"))
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
				if err := validateHostPort("admin.connectivity.dns.server", c.Admin.Connectivity.DNS.Server, false); err != nil {
					errs = append(errs, err)
				}
				names := make([]string, 0, len(c.Admin.Connectivity.DNS.Names))
				seenNames := map[string]struct{}{}
				for _, raw := range c.Admin.Connectivity.DNS.Names {
					name, nameErr := normalizeDNSProbeName(raw)
					if nameErr != nil {
						errs = append(errs, fmt.Errorf("invalid admin.connectivity.dns.names entry %q: %w", raw, nameErr))
						continue
					}
					if _, exists := seenNames[name]; exists {
						continue
					}
					seenNames[name] = struct{}{}
					names = append(names, name)
				}
				c.Admin.Connectivity.DNS.Names = names
				if len(names) == 0 {
					errs = append(errs, errors.New("admin.connectivity.dns.names must contain at least one domain when DNS probing is enabled"))
				}

				expected := make([]string, 0, len(c.Admin.Connectivity.DNS.ExpectedAddresses))
				seenExpected := map[string]struct{}{}
				for _, raw := range c.Admin.Connectivity.DNS.ExpectedAddresses {
					ip := net.ParseIP(strings.TrimSpace(raw))
					if ip == nil {
						errs = append(errs, fmt.Errorf("invalid admin.connectivity.dns.expected_addresses entry %q", raw))
						continue
					}
					canonical := ip.String()
					if _, exists := seenExpected[canonical]; exists {
						continue
					}
					seenExpected[canonical] = struct{}{}
					expected = append(expected, canonical)
				}
				c.Admin.Connectivity.DNS.ExpectedAddresses = expected
			}
		}
		if c.Admin.MaxRequestBodyBytes <= 0 || c.Admin.MaxRequestBodyBytes > 16<<20 {
			errs = append(errs, errors.New("admin.max_request_body_bytes must be between 1 and 16777216"))
		}
		if c.Admin.PollTimeout.Duration <= 0 || c.Admin.PollTimeout.Duration > 5*time.Minute {
			errs = append(errs, errors.New("admin.poll_timeout must be positive and no greater than 5m"))
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
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, errors.New("edgeproxy.admin_url must be an absolute http(s) URL without credentials, queries, or fragments"))
		} else if portErr := validateURLPort("edgeproxy.admin_url", u); portErr != nil {
			errs = append(errs, portErr)
		}
	}
	if c.EdgeProxy.Timeout.Duration <= 0 || c.EdgeProxy.Timeout.Duration > 5*time.Minute {
		errs = append(errs, errors.New("edgeproxy.timeout must be positive and no greater than 5m"))
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
	if c.DefaultPolicy.MaxInspectionBodyBytes > c.Server.MaxRequestBodyBytes {
		errs = append(errs, errors.New("default_policy.max_inspection_body_bytes cannot exceed server.max_request_body_bytes"))
	}
	names := make([]string, 0, len(c.RoutePolicies))
	for name := range c.RoutePolicies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := c.RoutePolicies[name]
		trimmedName := strings.TrimSpace(name)
		if trimmedName == "" {
			errs = append(errs, errors.New("route policy name cannot be empty"))
			continue
		}
		if trimmedName != name {
			errs = append(errs, fmt.Errorf("route policy name %q must not contain surrounding whitespace", name))
		}
		if err := validatePolicy("route_policies."+name, &p); err != nil {
			errs = append(errs, err)
		}
		if p.MaxInspectionBodyBytes > c.Server.MaxRequestBodyBytes {
			errs = append(errs, fmt.Errorf("route_policies.%s.max_inspection_body_bytes cannot exceed server.max_request_body_bytes", name))
		}
		if p.RateLimit.CleanupInterval != c.DefaultPolicy.RateLimit.CleanupInterval ||
			p.RateLimit.IdleTTL != c.DefaultPolicy.RateLimit.IdleTTL ||
			p.RateLimit.MaxBuckets != c.DefaultPolicy.RateLimit.MaxBuckets {
			errs = append(errs, fmt.Errorf("route_policies.%s rate_limit cleanup_interval, idle_ttl, and max_buckets must match default_policy because limiter storage is process-wide", name))
		}
		if p.AutoBan.MaxTrackedClients != c.DefaultPolicy.AutoBan.MaxTrackedClients {
			errs = append(errs, fmt.Errorf("route_policies.%s auto_ban.max_tracked_clients must match default_policy because ban tracking is process-wide", name))
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
		if r.Name == "" || r.Category == "" || r.Description == "" || len(r.Targets) == 0 || r.Pattern == "" {
			errs = append(errs, fmt.Errorf("waf.custom_rules[%d] is incomplete", i))
		}
		if r.Score <= 0 || r.Score > MaxCustomRuleScore {
			errs = append(errs, fmt.Errorf("waf.custom_rules[%d].score must be between 1 and %d", i, MaxCustomRuleScore))
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
	if p.InspectRequestBody && p.MaxInspectionBodyBytes <= 0 {
		errs = append(errs, fmt.Errorf("%s.max_inspection_body_bytes must be positive when request-body inspection is enabled", name))
	}
	bodyTypes := make([]string, 0, len(p.BodyContentTypes))
	seenBodyTypes := map[string]bool{}
	for _, raw := range p.BodyContentTypes {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(raw))
		mediaType = strings.ToLower(strings.TrimSpace(mediaType))
		if err != nil || mediaType == "" || len(params) != 0 {
			errs = append(errs, fmt.Errorf("%s.body_content_types contains invalid media type %q", name, raw))
			continue
		}
		if !seenBodyTypes[mediaType] {
			seenBodyTypes[mediaType] = true
			bodyTypes = append(bodyTypes, mediaType)
		}
	}
	p.BodyContentTypes = bodyTypes
	if p.InspectRequestBody && len(p.BodyContentTypes) == 0 {
		errs = append(errs, fmt.Errorf("%s.body_content_types cannot be empty when request-body inspection is enabled", name))
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
		if m == "" {
			continue
		}
		if !validHTTPToken(m) {
			errs = append(errs, fmt.Errorf("%s.allowed_methods contains invalid method %q", name, m))
			continue
		}
		if !seen[m] {
			methods = append(methods, m)
			seen[m] = true
		}
	}
	p.AllowedMethods = methods

	excludedPaths := make([]string, 0, len(p.ExcludedPathPrefixes))
	seenExcludedPaths := map[string]bool{}
	for _, rawPrefix := range p.ExcludedPathPrefixes {
		prefix, err := normalizePolicyPathPrefix(rawPrefix)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s.excluded_path_prefixes contains invalid path %q: %w", name, rawPrefix, err))
			continue
		}
		if prefix == "" {
			continue
		}
		if !seenExcludedPaths[prefix] {
			excludedPaths = append(excludedPaths, prefix)
			seenExcludedPaths[prefix] = true
		}
	}
	p.ExcludedPathPrefixes = excludedPaths

	disabledRules := make([]string, 0, len(p.DisabledRules))
	seenDisabledRules := map[string]bool{}
	for _, raw := range p.DisabledRules {
		id := strings.ToUpper(strings.TrimSpace(raw))
		if id != "" && !seenDisabledRules[id] {
			seenDisabledRules[id] = true
			disabledRules = append(disabledRules, id)
		}
	}
	p.DisabledRules = disabledRules

	if p.RateLimit.Enabled {
		if p.RateLimit.RequestsPerSecond <= 0 || p.RateLimit.Burst <= 0 || p.RateLimit.GlobalRequestsPerSecond <= 0 || p.RateLimit.GlobalBurst <= 0 {
			errs = append(errs, fmt.Errorf("%s rate_limit rates and bursts must be positive", name))
		}
		if p.RateLimit.CleanupInterval.Duration <= 0 || p.RateLimit.IdleTTL.Duration <= 0 || p.RateLimit.MaxBuckets < 2 {
			errs = append(errs, fmt.Errorf("%s rate_limit lifecycle settings must be positive and max_buckets must be at least 2", name))
		}
	}
	if p.AutoBan.Enabled {
		if p.AutoBan.ViolationThreshold <= 0 || p.AutoBan.Window.Duration <= 0 || p.AutoBan.BanDuration.Duration <= 0 || p.AutoBan.MaxTrackedClients <= 0 {
			errs = append(errs, fmt.Errorf("%s auto_ban settings must be positive", name))
		}
	}
	p.IPAllowlist, errs = normalizeIPList(name+".ip_allowlist", p.IPAllowlist, errs)
	p.IPDenylist, errs = normalizeIPList(name+".ip_denylist", p.IPDenylist, errs)
	denied := make(map[string]struct{}, len(p.IPDenylist))
	for _, item := range p.IPDenylist {
		denied[item] = struct{}{}
	}
	for _, item := range p.IPAllowlist {
		if _, exists := denied[item]; exists {
			errs = append(errs, fmt.Errorf("%s contains %q in both allowlist and denylist", name, item))
		}
	}
	return errors.Join(errs...)
}

func normalizeIPList(name string, values []string, errs []error) ([]string, []error) {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		canonical := ""
		if ip := net.ParseIP(value); ip != nil {
			canonical = ip.String()
		} else if _, network, err := net.ParseCIDR(value); err == nil {
			canonical = network.String()
		} else {
			errs = append(errs, fmt.Errorf("%s contains invalid IP/CIDR %q", name, raw))
			continue
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, errs
}

func normalizePolicyPathPrefix(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
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
	value = strings.TrimRight(value, "/")
	if value == "" {
		value = "/"
	}
	if path.Clean(value) != value {
		return "", errors.New("must be canonical and must not contain dot-segments or repeated slashes")
	}
	return value, nil
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

func validateListen(name, addr string) error {
	return validateHostPort(name, addr, true)
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

func normalizeDNSProbeName(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", errors.New("empty domain is not allowed")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if strings.ContainsAny(value, " \t\r\n\x00/\\?#@*:") {
		return "", errors.New("must be a hostname or IP address without whitespace, wildcards, ports, or URL syntax")
	}
	absolute := strings.HasSuffix(value, ".")
	core := strings.TrimSuffix(value, ".")
	if core == "" || len(core) > 253 {
		return "", errors.New("hostname must contain between 1 and 253 characters")
	}
	for _, label := range strings.Split(core, ".") {
		if label == "" || len(label) > 63 {
			return "", errors.New("hostname contains an empty or overlong label")
		}
		for index := 0; index < len(label); index++ {
			b := label[index]
			alnum := (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
			if !alnum && b != '-' && b != '_' {
				return "", errors.New("hostname labels may contain only ASCII letters, digits, hyphens, and underscores")
			}
		}
	}
	if absolute {
		return core + ".", nil
	}
	return core, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
