package connectivity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/routes"
)

const (
	StatusHealthy       = "healthy"
	StatusDegraded      = "degraded"
	StatusDown          = "down"
	StatusUnknown       = "unknown"
	StatusNotApplicable = "not_applicable"
)

type Source interface {
	Config() config.Config
	Routes() []routes.Route
	EdgeJSON(context.Context, string, string, url.Values, any) (json.RawMessage, int, error)
}

type Component struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	Layer                string         `json:"layer"`
	Status               string         `json:"status"`
	Critical             bool           `json:"critical"`
	Endpoint             string         `json:"endpoint,omitempty"`
	Message              string         `json:"message"`
	Error                string         `json:"error,omitempty"`
	HTTPStatus           int            `json:"http_status,omitempty"`
	LatencyMS            float64        `json:"latency_ms,omitempty"`
	LastCheckedAt        string         `json:"last_checked_at"`
	LastSuccessAt        string         `json:"last_success_at,omitempty"`
	LastFailureAt        string         `json:"last_failure_at,omitempty"`
	ConsecutiveSuccesses int            `json:"consecutive_successes"`
	ConsecutiveFailures  int            `json:"consecutive_failures"`
	Checks               uint64         `json:"checks"`
	SuccessfulChecks     uint64         `json:"successful_checks"`
	AvailabilityPercent  float64        `json:"availability_percent"`
	Details              map[string]any `json:"details,omitempty"`
}

type Origin struct {
	URL     string `json:"url"`
	Healthy bool   `json:"healthy"`
	Status  string `json:"status"`
}

type Route struct {
	Name           string   `json:"name"`
	Ready          bool     `json:"ready"`
	Status         string   `json:"status"`
	HealthyOrigins int      `json:"healthy_origins"`
	TotalOrigins   int      `json:"total_origins"`
	Origins        []Origin `json:"origins"`
}

type Counts struct {
	ComponentsHealthy  int `json:"components_healthy"`
	ComponentsDegraded int `json:"components_degraded"`
	ComponentsDown     int `json:"components_down"`
	ReadyRoutes        int `json:"ready_routes"`
	TotalRoutes        int `json:"total_routes"`
	HealthyOrigins     int `json:"healthy_origins"`
	TotalOrigins       int `json:"total_origins"`
}

type Transition struct {
	Timestamp string `json:"timestamp"`
	Component string `json:"component"`
	From      string `json:"from"`
	To        string `json:"to"`
	Message   string `json:"message"`
}

type Snapshot struct {
	GeneratedAt               string       `json:"generated_at"`
	FreshUntil                string       `json:"fresh_until"`
	CheckIntervalSeconds      float64      `json:"check_interval_seconds"`
	StaleAfterSeconds         float64      `json:"stale_after_seconds"`
	OverallStatus             string       `json:"overall_status"`
	TrafficPathStatus         string       `json:"traffic_path_status"`
	ObservabilityStatus       string       `json:"observability_status"`
	EdgeProxyConnectionStatus string       `json:"edgeproxy_connection_status"`
	Summary                   string       `json:"summary"`
	Components                []Component  `json:"components"`
	Routes                    []Route      `json:"routes"`
	Counts                    Counts       `json:"counts"`
	History                   []Transition `json:"history"`
}

type probeResult struct {
	id         string
	name       string
	layer      string
	status     string
	critical   bool
	endpoint   string
	message    string
	err        string
	httpStatus int
	latency    time.Duration
	details    map[string]any
	routes     []Route
}

type Monitor struct {
	source Source

	mu         sync.RWMutex
	checkMu    sync.Mutex
	components map[string]Component
	history    []Transition
	last       Snapshot
}

func New(source Source) *Monitor {
	return &Monitor{source: source, components: map[string]Component{}}
}

func (m *Monitor) Snapshot(ctx context.Context, force bool) Snapshot {
	cfg := m.source.Config().Admin.Connectivity
	if !cfg.Enabled {
		return Snapshot{
			GeneratedAt:               timestamp(time.Now()),
			OverallStatus:             StatusNotApplicable,
			TrafficPathStatus:         StatusNotApplicable,
			ObservabilityStatus:       StatusNotApplicable,
			EdgeProxyConnectionStatus: StatusNotApplicable,
			Summary:                   "connectivity monitoring is disabled",
		}
	}

	m.mu.RLock()
	cached := cloneSnapshot(m.last)
	m.mu.RUnlock()
	if !force && cached.GeneratedAt != "" {
		if checked, err := time.Parse(time.RFC3339Nano, cached.GeneratedAt); err == nil && time.Since(checked) < cfg.CheckInterval.Duration {
			return cached
		}
	}

	m.checkMu.Lock()
	defer m.checkMu.Unlock()

	m.mu.RLock()
	cached = cloneSnapshot(m.last)
	m.mu.RUnlock()
	if !force && cached.GeneratedAt != "" {
		if checked, err := time.Parse(time.RFC3339Nano, cached.GeneratedAt); err == nil && time.Since(checked) < cfg.CheckInterval.Duration {
			return cached
		}
	}

	// Connectivity is shared operational state, so an individual dashboard or API
	// caller disconnecting must not turn a healthy path into a cached DOWN result.
	// Preserve request-scoped values while making the configured probe timeout the
	// sole cancellation boundary for this check.
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.Timeout.Duration)
	defer cancel()
	return m.run(checkCtx, cfg)
}

func (m *Monitor) Cached() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneSnapshot(m.last)
}

func (m *Monitor) run(ctx context.Context, monitorCfg config.ConnectivityConfig) Snapshot {
	cfg := m.source.Config()
	results := make(chan probeResult, 8)
	var wg sync.WaitGroup
	launch := func(fn func(context.Context) probeResult) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- fn(ctx)
		}()
	}

	launch(func(ctx context.Context) probeResult { return probeSecurityAdmin(cfg) })
	launch(func(ctx context.Context) probeResult { return probeGatewayListener(ctx, cfg) })
	launch(func(ctx context.Context) probeResult { return probeDataPlaneTCP(ctx, cfg) })
	launch(func(ctx context.Context) probeResult { return probeDataPlaneHTTP(ctx, cfg, m.source.Routes()) })
	launch(func(ctx context.Context) probeResult { return m.probeEdgeHealth(ctx, cfg) })
	launch(func(ctx context.Context) probeResult { return m.probeEdgeReadiness(ctx, cfg) })
	launch(func(ctx context.Context) probeResult { return m.probeEdgeStatus(ctx, cfg) })
	launch(func(ctx context.Context) probeResult { return m.probeEdgeMetrics(ctx, cfg) })
	if monitorCfg.DNS.Enabled {
		launch(func(ctx context.Context) probeResult { return probeDNS(ctx, monitorCfg.DNS) })
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	now := time.Now().UTC()
	collected := make([]probeResult, 0, 9)
	var routeState []Route
	for result := range results {
		collected = append(collected, result)
		if result.id == "edgeproxy_routes_origins" && result.routes != nil {
			routeState = result.routes
		}
	}
	sort.Slice(collected, func(i, j int) bool { return componentOrder(collected[i].id) < componentOrder(collected[j].id) })

	m.mu.Lock()
	defer m.mu.Unlock()
	components := make([]Component, 0, len(collected))
	for _, result := range collected {
		previous := m.components[result.id]
		component := updateComponent(previous, result, now)
		m.components[result.id] = component
		components = append(components, cloneComponent(component))
		if previous.Status != "" && previous.Status != component.Status {
			m.history = append(m.history, Transition{Timestamp: timestamp(now), Component: component.ID, From: previous.Status, To: component.Status, Message: component.Message})
		}
	}
	if len(m.history) > monitorCfg.HistoryCapacity {
		m.history = append([]Transition(nil), m.history[len(m.history)-monitorCfg.HistoryCapacity:]...)
	}

	snapshot := aggregate(now, monitorCfg, components, routeState, m.history)
	m.last = snapshot
	return cloneSnapshot(snapshot)
}

func probeSecurityAdmin(cfg config.Config) probeResult {
	return probeResult{
		id: "securityedge_admin", name: "SecurityEdge Admin & Dashboard", layer: "securityedge", status: StatusHealthy,
		critical: false, endpoint: cfg.Admin.ListenAddr, message: "dashboard backend is running and serving this check",
		details: map[string]any{"listen_addr": cfg.Admin.ListenAddr},
	}
}

func probeGatewayListener(ctx context.Context, cfg config.Config) probeResult {
	if cfg.Server.Mode != "gateway" {
		return probeResult{id: "securityedge_ingress", name: "SecurityEdge public ingress", layer: "securityedge", status: StatusNotApplicable, critical: true, message: "embedded mode does not use a separate public gateway listener"}
	}
	endpoint := cfg.Server.ListenAddr
	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", loopbackDialAddress(endpoint))
	latency := time.Since(started)
	if err != nil {
		return probeResult{id: "securityedge_ingress", name: "SecurityEdge public ingress", layer: "securityedge", status: StatusDown, critical: true, endpoint: endpoint, message: "configured public listener is not accepting local TCP connections", err: err.Error(), latency: latency}
	}
	_ = conn.Close()
	return probeResult{id: "securityedge_ingress", name: "SecurityEdge public ingress", layer: "securityedge", status: StatusHealthy, critical: true, endpoint: endpoint, message: "public gateway listener is accepting TCP connections", latency: latency, details: map[string]any{"external_firewall_verified": false}}
}

func probeDataPlaneTCP(ctx context.Context, cfg config.Config) probeResult {
	if cfg.Server.Mode != "gateway" {
		return probeResult{id: "edgeproxy_data_tcp", name: "EdgeProxy data-plane TCP", layer: "edgeproxy", status: StatusNotApplicable, critical: true, message: "embedded mode has no separate EdgeProxy TCP hop"}
	}
	u, err := url.Parse(cfg.Server.UpstreamProxyURL)
	if err != nil {
		return probeResult{id: "edgeproxy_data_tcp", name: "EdgeProxy data-plane TCP", layer: "edgeproxy", status: StatusDown, critical: true, endpoint: cfg.Server.UpstreamProxyURL, message: "upstream proxy URL is invalid", err: err.Error()}
	}
	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", hostPort(u))
	latency := time.Since(started)
	if err != nil {
		return probeResult{id: "edgeproxy_data_tcp", name: "EdgeProxy data-plane TCP", layer: "edgeproxy", status: StatusDown, critical: true, endpoint: cfg.Server.UpstreamProxyURL, message: "SecurityEdge cannot establish a TCP connection to EdgeProxy", err: err.Error(), latency: latency}
	}
	_ = conn.Close()
	return probeResult{id: "edgeproxy_data_tcp", name: "EdgeProxy data-plane TCP", layer: "edgeproxy", status: StatusHealthy, critical: true, endpoint: cfg.Server.UpstreamProxyURL, message: "SecurityEdge can establish a TCP connection to EdgeProxy", latency: latency}
}

func probeDataPlaneHTTP(ctx context.Context, cfg config.Config, configuredRoutes []routes.Route) probeResult {
	if cfg.Server.Mode != "gateway" {
		return probeResult{id: "edgeproxy_data_http", name: "EdgeProxy HTTP health", layer: "edgeproxy", status: StatusNotApplicable, critical: true, message: "embedded mode invokes EdgeProxy in-process"}
	}
	target := representativeDataPlaneTarget(configuredRoutes)
	u, err := url.Parse(cfg.Server.UpstreamProxyURL)
	if err != nil {
		return probeResult{id: "edgeproxy_data_http", name: "EdgeProxy HTTP health", layer: "edgeproxy", status: StatusDown, critical: true, endpoint: cfg.Server.UpstreamProxyURL, message: "upstream proxy URL is invalid", err: err.Error()}
	}
	u.Path = joinURLPath(u.Path, target.path)
	u.RawQuery = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return probeResult{id: "edgeproxy_data_http", name: "EdgeProxy HTTP health", layer: "edgeproxy", status: StatusDown, critical: true, endpoint: u.String(), message: "failed to construct EdgeProxy data-plane request", err: err.Error()}
	}
	if target.host != "" {
		req.Host = target.host
	}
	details := map[string]any{"probe_path": target.path}
	if target.host != "" {
		details["probe_host"] = target.host
	}
	if target.routeName != "" {
		details["route"] = target.routeName
	}
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		Timeout:       cfg.Admin.Connectivity.Timeout.Duration,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	started := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(started)
	if err != nil {
		return probeResult{id: "edgeproxy_data_http", name: "EdgeProxy HTTP health", layer: "edgeproxy", status: StatusDown, critical: true, endpoint: u.String(), message: "EdgeProxy data plane is unreachable over HTTP", err: err.Error(), latency: latency, details: details}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	requestID := strings.TrimSpace(resp.Header.Get("X-Request-ID"))
	if requestID == "" {
		return probeResult{id: "edgeproxy_data_http", name: "EdgeProxy HTTP health", layer: "edgeproxy", status: StatusDown, critical: true, endpoint: u.String(), message: fmt.Sprintf("EdgeProxy returned HTTP %d without matching the configured probe route", resp.StatusCode), httpStatus: resp.StatusCode, latency: latency, details: details}
	}
	details["request_id"] = requestID
	return probeResult{id: "edgeproxy_data_http", name: "EdgeProxy HTTP health", layer: "edgeproxy", status: StatusHealthy, critical: true, endpoint: u.String(), message: fmt.Sprintf("EdgeProxy accepted the configured route probe with HTTP %d", resp.StatusCode), httpStatus: resp.StatusCode, latency: latency, details: details}
}

func (m *Monitor) probeEdgeHealth(ctx context.Context, cfg config.Config) probeResult {
	return m.edgeJSONProbe(ctx, cfg, "edgeproxy_admin_health", "EdgeProxy Admin API", "observability", "/healthz", true, func(raw json.RawMessage, status int) (string, string, map[string]any) {
		if status == http.StatusOK {
			return StatusHealthy, "EdgeProxy Admin API is reachable and healthy", nil
		}
		return StatusDown, fmt.Sprintf("EdgeProxy Admin API health returned HTTP %d", status), nil
	})
}

func (m *Monitor) probeEdgeReadiness(ctx context.Context, cfg config.Config) probeResult {
	return m.edgeJSONProbe(ctx, cfg, "edgeproxy_readiness", "EdgeProxy readiness", "edgeproxy", "/readyz", true, func(raw json.RawMessage, status int) (string, string, map[string]any) {
		var payload struct {
			Status          string   `json:"status"`
			UnhealthyRoutes []string `json:"unhealthy_routes"`
		}
		_ = json.Unmarshal(raw, &payload)
		details := map[string]any{"unhealthy_routes": payload.UnhealthyRoutes}
		if status == http.StatusOK {
			return StatusHealthy, "all EdgeProxy routes have at least one healthy origin", details
		}
		if status == http.StatusServiceUnavailable {
			return StatusDegraded, "EdgeProxy is alive but one or more routes are not ready", details
		}
		return StatusDown, fmt.Sprintf("EdgeProxy readiness returned HTTP %d", status), details
	})
}

func (m *Monitor) probeEdgeStatus(ctx context.Context, cfg config.Config) probeResult {
	result := m.edgeJSONProbe(ctx, cfg, "edgeproxy_routes_origins", "Routes & origin health", "origin", "/api/v1/status", false, func(raw json.RawMessage, status int) (string, string, map[string]any) {
		if status != http.StatusOK {
			return StatusDown, fmt.Sprintf("EdgeProxy status API returned HTTP %d", status), nil
		}
		routesState, counts, err := parseRoutes(raw)
		if err != nil {
			return StatusDown, "EdgeProxy status response could not be parsed", map[string]any{"parse_error": err.Error()}
		}
		resultStatus := StatusHealthy
		message := "all routes and origins reported healthy"
		if counts.TotalRoutes == 0 {
			resultStatus = StatusDegraded
			message = "EdgeProxy returned no route status entries"
		} else if counts.ReadyRoutes < counts.TotalRoutes || counts.HealthyOrigins < counts.TotalOrigins {
			resultStatus = StatusDegraded
			message = "one or more routes or origins are unhealthy"
		}
		return resultStatus, message, map[string]any{"ready_routes": counts.ReadyRoutes, "total_routes": counts.TotalRoutes, "healthy_origins": counts.HealthyOrigins, "total_origins": counts.TotalOrigins, "routes": routesState}
	})
	if rawRoutes, ok := result.details["routes"].([]Route); ok {
		result.routes = rawRoutes
		delete(result.details, "routes")
	}
	return result
}

func (m *Monitor) probeEdgeMetrics(ctx context.Context, cfg config.Config) probeResult {
	return m.edgeJSONProbe(ctx, cfg, "edgeproxy_metrics", "EdgeProxy metrics & cache", "observability", "/api/v1/metrics", false, func(raw json.RawMessage, status int) (string, string, map[string]any) {
		if status != http.StatusOK {
			return StatusDegraded, fmt.Sprintf("EdgeProxy metrics API returned HTTP %d", status), nil
		}
		var payload struct {
			SchemaVersion string  `json:"schema_version"`
			UptimeSeconds float64 `json:"uptime_seconds"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return StatusDegraded, "EdgeProxy metrics response could not be parsed", map[string]any{"parse_error": err.Error()}
		}
		return StatusHealthy, "EdgeProxy metrics and cache telemetry are available", map[string]any{"schema_version": payload.SchemaVersion, "uptime_seconds": payload.UptimeSeconds}
	})
}

func (m *Monitor) edgeJSONProbe(ctx context.Context, cfg config.Config, id, name, layer, path string, critical bool, interpret func(json.RawMessage, int) (string, string, map[string]any)) probeResult {
	started := time.Now()
	raw, status, err := m.source.EdgeJSON(ctx, http.MethodGet, path, nil, nil)
	latency := time.Since(started)
	endpoint := strings.TrimRight(cfg.EdgeProxy.AdminURL, "/") + path
	if err != nil {
		return probeResult{id: id, name: name, layer: layer, status: StatusDown, critical: critical, endpoint: endpoint, message: "EdgeProxy dependency request failed", err: err.Error(), latency: latency}
	}
	probeStatus, message, details := interpret(raw, status)
	return probeResult{id: id, name: name, layer: layer, status: probeStatus, critical: critical, endpoint: endpoint, message: message, httpStatus: status, latency: latency, details: details}
}

// dnsDialer preserves the transport requested by net.Resolver. DNS starts on
// UDP, but truncated responses must be retried over TCP; forcing every request
// onto UDP breaks that standards-defined fallback for larger answers.
func dnsDialer(endpoint string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}
}

func probeDNS(ctx context.Context, cfg config.DNSProbeConfig) probeResult {
	endpoint := cfg.Server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial:     dnsDialer(endpoint),
	}
	started := time.Now()
	resolved := map[string][]string{}
	allExpected := true
	for _, name := range cfg.Names {
		addresses, err := resolver.LookupHost(ctx, name)
		if err != nil {
			return probeResult{id: "dns_resolution", name: "DNS resolution", layer: "dns", status: StatusDown, critical: cfg.Critical, endpoint: endpoint, message: fmt.Sprintf("DNS lookup failed for %s", name), err: err.Error(), latency: time.Since(started), details: map[string]any{"resolved": resolved}}
		}
		sort.Strings(addresses)
		resolved[name] = addresses
		if len(cfg.ExpectedAddresses) > 0 && !containsAny(addresses, cfg.ExpectedAddresses) {
			allExpected = false
		}
	}
	status := StatusHealthy
	message := "The configured DNS resolver resolved all monitored hostnames"
	if !allExpected {
		status = StatusDegraded
		message = "The DNS resolver responded, but one or more monitored hostnames did not resolve to an expected ingress address"
	}
	return probeResult{id: "dns_resolution", name: "DNS resolution", layer: "dns", status: status, critical: cfg.Critical, endpoint: endpoint, message: message, latency: time.Since(started), details: map[string]any{"resolved": resolved, "expected_addresses": cfg.ExpectedAddresses, "probe_scope": "server-side DNS resolution"}}
}

func updateComponent(previous Component, result probeResult, now time.Time) Component {
	component := Component{
		ID: result.id, Name: result.name, Layer: result.layer, Status: result.status, Critical: result.critical,
		Endpoint: result.endpoint, Message: result.message, Error: result.err, HTTPStatus: result.httpStatus,
		LatencyMS: durationMS(result.latency), LastCheckedAt: timestamp(now), Details: cloneMap(result.details),
		LastSuccessAt: previous.LastSuccessAt, LastFailureAt: previous.LastFailureAt,
		Checks: previous.Checks + 1, SuccessfulChecks: previous.SuccessfulChecks,
	}
	if successfulStatus(result.status) {
		component.SuccessfulChecks++
		component.ConsecutiveSuccesses = previous.ConsecutiveSuccesses + 1
		component.ConsecutiveFailures = 0
		component.LastSuccessAt = timestamp(now)
	} else if result.status == StatusNotApplicable || result.status == StatusUnknown {
		component.ConsecutiveSuccesses = previous.ConsecutiveSuccesses
		component.ConsecutiveFailures = previous.ConsecutiveFailures
	} else {
		component.ConsecutiveFailures = previous.ConsecutiveFailures + 1
		component.ConsecutiveSuccesses = 0
		component.LastFailureAt = timestamp(now)
	}
	if component.Checks > 0 {
		component.AvailabilityPercent = float64(component.SuccessfulChecks) / float64(component.Checks) * 100
	}
	return component
}

func aggregate(now time.Time, cfg config.ConnectivityConfig, components []Component, routesState []Route, history []Transition) Snapshot {
	byID := map[string]Component{}
	counts := Counts{}
	for _, component := range components {
		byID[component.ID] = component
		switch component.Status {
		case StatusHealthy:
			counts.ComponentsHealthy++
		case StatusDegraded:
			counts.ComponentsDegraded++
		case StatusDown:
			counts.ComponentsDown++
		}
	}
	for _, route := range routesState {
		counts.TotalRoutes++
		if route.Ready {
			counts.ReadyRoutes++
		}
		counts.HealthyOrigins += route.HealthyOrigins
		counts.TotalOrigins += route.TotalOrigins
	}

	traffic := StatusHealthy
	for _, id := range []string{"securityedge_ingress", "edgeproxy_data_tcp", "edgeproxy_data_http"} {
		if component, ok := byID[id]; ok && component.Status == StatusDown {
			traffic = StatusDown
		}
	}
	if traffic != StatusDown {
		if readiness, ok := byID["edgeproxy_readiness"]; ok {
			if readiness.Status == StatusDown {
				traffic = StatusDown
			} else if readiness.Status == StatusDegraded {
				traffic = StatusDegraded
			}
		}
		if dns, ok := byID["dns_resolution"]; ok && dns.Critical {
			if dns.Status == StatusDown {
				traffic = StatusDown
			} else if dns.Status == StatusDegraded {
				traffic = StatusDegraded
			}
		}
		if counts.TotalRoutes > 0 && counts.ReadyRoutes == 0 {
			traffic = StatusDown
		} else if counts.ReadyRoutes < counts.TotalRoutes || counts.HealthyOrigins < counts.TotalOrigins {
			traffic = StatusDegraded
		}
	}

	observability := StatusHealthy
	for _, id := range []string{"securityedge_admin", "edgeproxy_admin_health", "edgeproxy_metrics"} {
		component, ok := byID[id]
		if !ok || component.Status == StatusDown {
			observability = StatusDown
			break
		}
		if component.Status == StatusDegraded {
			observability = StatusDegraded
		}
	}

	edgeConnection := StatusHealthy
	for _, id := range []string{"edgeproxy_data_tcp", "edgeproxy_data_http"} {
		if component, ok := byID[id]; ok && component.Status == StatusDown {
			edgeConnection = StatusDown
		}
	}
	if edgeConnection != StatusDown {
		for _, id := range []string{"edgeproxy_admin_health", "edgeproxy_readiness", "edgeproxy_routes_origins", "edgeproxy_metrics"} {
			if component, ok := byID[id]; !ok || component.Status != StatusHealthy {
				edgeConnection = StatusDegraded
			}
		}
	}

	overall := StatusHealthy
	if traffic == StatusDown {
		overall = StatusDown
	} else if traffic == StatusDegraded || observability != StatusHealthy {
		overall = StatusDegraded
	}
	summary := "end-to-end traffic path and observability dependencies are healthy"
	switch overall {
	case StatusDown:
		summary = "end-to-end service is unavailable because a critical traffic-path dependency is down"
	case StatusDegraded:
		summary = "traffic may still be served, but one or more routes, origins, DNS, or observability dependencies require attention"
	}

	return Snapshot{
		GeneratedAt: timestamp(now), FreshUntil: timestamp(now.Add(cfg.CheckInterval.Duration)),
		CheckIntervalSeconds: cfg.CheckInterval.Duration.Seconds(), StaleAfterSeconds: cfg.StaleAfter.Duration.Seconds(),
		OverallStatus: overall, TrafficPathStatus: traffic, ObservabilityStatus: observability,
		EdgeProxyConnectionStatus: edgeConnection, Summary: summary, Components: components,
		Routes: append([]Route(nil), routesState...), Counts: counts, History: append([]Transition(nil), history...),
	}
}

func parseRoutes(raw json.RawMessage) ([]Route, Counts, error) {
	var payload struct {
		Routes []struct {
			Name      string `json:"name"`
			Ready     bool   `json:"ready"`
			Upstreams []struct {
				URL      string `json:"url"`
				Upstream string `json:"upstream"`
				Healthy  bool   `json:"healthy"`
			} `json:"upstreams"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, Counts{}, err
	}
	out := make([]Route, 0, len(payload.Routes))
	counts := Counts{TotalRoutes: len(payload.Routes)}
	for _, item := range payload.Routes {
		route := Route{Name: item.Name, Ready: item.Ready, Status: StatusDown, TotalOrigins: len(item.Upstreams)}
		if item.Ready {
			route.Status = StatusHealthy
			counts.ReadyRoutes++
		}
		for _, upstream := range item.Upstreams {
			address := upstream.URL
			if address == "" {
				address = upstream.Upstream
			}
			origin := Origin{URL: address, Healthy: upstream.Healthy, Status: StatusDown}
			if upstream.Healthy {
				origin.Status = StatusHealthy
				route.HealthyOrigins++
				counts.HealthyOrigins++
			}
			route.Origins = append(route.Origins, origin)
			counts.TotalOrigins++
		}
		if route.Ready && route.HealthyOrigins < route.TotalOrigins {
			route.Status = StatusDegraded
		}
		out = append(out, route)
	}
	return out, counts, nil
}

func componentOrder(id string) int {
	order := map[string]int{
		"dns_resolution": 10, "securityedge_admin": 20, "securityedge_ingress": 30,
		"edgeproxy_data_tcp": 40, "edgeproxy_data_http": 50, "edgeproxy_admin_health": 60,
		"edgeproxy_readiness": 70, "edgeproxy_routes_origins": 80, "edgeproxy_metrics": 90,
	}
	if value, ok := order[id]; ok {
		return value
	}
	return 1000
}

type dataPlaneProbeTarget struct {
	routeName string
	host      string
	path      string
}

func representativeDataPlaneTarget(configured []routes.Route) dataPlaneProbeTarget {
	var wildcard *dataPlaneProbeTarget
	var catchAll *dataPlaneProbeTarget
	for _, route := range configured {
		probePath := route.PathPrefix
		if probePath == "" {
			probePath = "/"
		}
		for _, rawHost := range route.Hosts {
			host := strings.TrimSpace(rawHost)
			switch {
			case host == "*":
				if catchAll == nil {
					candidate := dataPlaneProbeTarget{routeName: route.Name, path: probePath}
					catchAll = &candidate
				}
			case strings.HasPrefix(host, "*."):
				if wildcard == nil {
					candidate := dataPlaneProbeTarget{
						routeName: route.Name,
						host:      "connectivity-probe." + strings.TrimPrefix(host, "*."),
						path:      probePath,
					}
					wildcard = &candidate
				}
			default:
				if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
					host = "[" + ip.String() + "]"
				}
				return dataPlaneProbeTarget{routeName: route.Name, host: host, path: probePath}
			}
		}
	}
	if wildcard != nil {
		return *wildcard
	}
	if catchAll != nil {
		return *catchAll
	}
	return dataPlaneProbeTarget{path: "/"}
}

func loopbackDialAddress(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::", "[::]":
		// Preserve the listener address family. An IPv6 wildcard may be bound
		// with IPV6_V6ONLY, in which case probing 127.0.0.1 is a false failure.
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return net.JoinHostPort(u.Hostname(), u.Port())
	}
	port := "80"
	if strings.EqualFold(u.Scheme, "https") {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func joinURLPath(base, suffix string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(suffix, "/")
}

func containsAny(values, expected []string) bool {
	set := map[string]bool{}
	for _, value := range values {
		canonical := strings.TrimSpace(value)
		if ip := net.ParseIP(canonical); ip != nil {
			canonical = ip.String()
		}
		set[canonical] = true
	}
	for _, value := range expected {
		canonical := strings.TrimSpace(value)
		if ip := net.ParseIP(canonical); ip != nil {
			canonical = ip.String()
		}
		if set[canonical] {
			return true
		}
	}
	return false
}

func successfulStatus(status string) bool { return status == StatusHealthy || status == StatusDegraded }
func durationMS(value time.Duration) float64 {
	if value <= 0 {
		return 0
	}
	return float64(value.Microseconds()) / 1000
}
func timestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	data, _ := json.Marshal(input)
	var output map[string]any
	_ = json.Unmarshal(data, &output)
	return output
}
func cloneComponent(input Component) Component {
	input.Details = cloneMap(input.Details)
	return input
}
func cloneSnapshot(input Snapshot) Snapshot {
	data, _ := json.Marshal(input)
	var output Snapshot
	_ = json.Unmarshal(data, &output)
	return output
}
