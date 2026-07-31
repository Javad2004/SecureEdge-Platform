package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	Server ServerConfig  `json:"server"`
	Admin  AdminConfig   `json:"admin"`
	Routes []RouteConfig `json:"routes"`
}

type ServerConfig struct {
	ListenAddr        string    `json:"listen_addr"`
	ReadHeaderTimeout Duration  `json:"read_header_timeout"`
	ReadTimeout       Duration  `json:"read_timeout"`
	WriteTimeout      Duration  `json:"write_timeout"`
	IdleTimeout       Duration  `json:"idle_timeout"`
	ShutdownTimeout   Duration  `json:"shutdown_timeout"`
	MaxHeaderBytes    int       `json:"max_header_bytes"`
	TLS               TLSConfig `json:"tls"`
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
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr:        ":8080",
			ReadHeaderTimeout: Duration{5 * time.Second},
			ReadTimeout:       Duration{30 * time.Second},
			WriteTimeout:      Duration{60 * time.Second},
			IdleTimeout:       Duration{90 * time.Second},
			ShutdownTimeout:   Duration{10 * time.Second},
			MaxHeaderBytes:    1 << 20,
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

func (c Config) Validate() error {
	var errs []error
	if strings.TrimSpace(c.Server.ListenAddr) == "" {
		errs = append(errs, errors.New("server.listen_addr is required"))
	} else if _, _, err := net.SplitHostPort(c.Server.ListenAddr); err != nil {
		errs = append(errs, fmt.Errorf("invalid server.listen_addr: %w", err))
	}
	if c.Server.TLS.Enabled && (c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "") {
		errs = append(errs, errors.New("server.tls.cert_file and key_file are required when TLS is enabled"))
	}
	if c.Admin.Enabled {
		if _, _, err := net.SplitHostPort(c.Admin.ListenAddr); err != nil {
			errs = append(errs, fmt.Errorf("invalid admin.listen_addr: %w", err))
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
	for i := range c.Routes {
		r := &c.Routes[i]
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
		if r.PathPrefix == "" {
			r.PathPrefix = "/"
		}
		if !strings.HasPrefix(r.PathPrefix, "/") {
			errs = append(errs, fmt.Errorf("route %q path_prefix must start with /", r.Name))
		}
		if len(r.Upstreams) == 0 {
			errs = append(errs, fmt.Errorf("route %q requires at least one upstream", r.Name))
		}
		for j, up := range r.Upstreams {
			parsed, err := url.Parse(up.URL)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] has invalid URL %q", r.Name, j, up.URL))
				continue
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				errs = append(errs, fmt.Errorf("route %q upstream[%d] scheme must be http or https", r.Name, j))
			}
		}
		if r.Proxy.RetryCount < 0 {
			errs = append(errs, fmt.Errorf("route %q retry_count cannot be negative", r.Name))
		}
		if r.Cache.Enabled {
			if r.Cache.DefaultTTL.Duration <= 0 {
				errs = append(errs, fmt.Errorf("route %q cache.default_ttl must be positive", r.Name))
			}
			if r.Cache.MaxEntries <= 0 || r.Cache.MaxBytes <= 0 || r.Cache.MaxObjectBytes <= 0 {
				errs = append(errs, fmt.Errorf("route %q cache limits must be positive", r.Name))
			}
			if r.Cache.MaxObjectBytes > r.Cache.MaxBytes {
				errs = append(errs, fmt.Errorf("route %q max_object_bytes cannot exceed max_bytes", r.Name))
			}
		}
		if r.HealthCheck.Enabled {
			if r.HealthCheck.Path == "" || !strings.HasPrefix(r.HealthCheck.Path, "/") {
				errs = append(errs, fmt.Errorf("route %q health_check.path must start with /", r.Name))
			}
			if r.HealthCheck.Interval.Duration <= 0 || r.HealthCheck.Timeout.Duration <= 0 {
				errs = append(errs, fmt.Errorf("route %q health-check durations must be positive", r.Name))
			}
		}
	}
	return errors.Join(errs...)
}
