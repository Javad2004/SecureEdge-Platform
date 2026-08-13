package connectivity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/edgeprobe"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/routes"
)

type fakeSource struct {
	cfg        config.Config
	edgeDown   bool
	metricsRaw json.RawMessage
}

func (f *fakeSource) Config() config.Config { return f.cfg }
func (f *fakeSource) Routes() []routes.Route {
	return []routes.Route{{Name: "demo-app", Hosts: []string{"project.test"}, PathPrefix: "/"}}
}
func (f *fakeSource) EdgeJSON(_ context.Context, _ string, path string, _ url.Values, _ any) (json.RawMessage, int, error) {
	if f.edgeDown {
		return nil, 0, errors.New("connection refused")
	}
	switch path {
	case "/healthz":
		return json.RawMessage(`{"status":"ok"}`), http.StatusOK, nil
	case "/readyz":
		return json.RawMessage(`{"status":"ready","unhealthy_routes":[]}`), http.StatusOK, nil
	case "/api/v1/status":
		return json.RawMessage(`{"routes":[{"name":"demo-app","ready":true,"upstreams":[{"url":"http://origin:9000","healthy":true}]}]}`), http.StatusOK, nil
	case "/api/v1/metrics":
		if f.metricsRaw != nil {
			return f.metricsRaw, http.StatusOK, nil
		}
		return json.RawMessage(`{"schema_version":"2.0","uptime_seconds":42}`), http.StatusOK, nil
	default:
		return json.RawMessage(`{"status":"ok"}`), http.StatusOK, nil
	}
}

func healthyConfig(t *testing.T, dataPlane *httptest.Server) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.ListenAddr = dataPlane.Listener.Addr().String()
	cfg.Server.UpstreamProxyURL = dataPlane.URL
	cfg.Admin.Connectivity.Enabled = true
	cfg.Admin.Connectivity.CheckInterval = config.Duration{Duration: time.Second}
	cfg.Admin.Connectivity.Timeout = config.Duration{Duration: 500 * time.Millisecond}
	cfg.Admin.Connectivity.StaleAfter = config.Duration{Duration: 3 * time.Second}
	cfg.Admin.Connectivity.HistoryCapacity = 10
	cfg.Admin.Connectivity.DNS.Enabled = false
	cfg.EdgeProxy.AdminURL = "http://127.0.0.1:9090"
	return cfg
}

func TestUpdateComponentExcludesUnknownAndNotApplicableFromAvailability(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	previous := Component{
		ID: "edgeproxy_data_http", Status: StatusDown, Checks: 4, SuccessfulChecks: 3, AvailabilityPercent: 75,
		ConsecutiveFailures: 1, LastSuccessAt: "2026-08-13T09:58:00Z", LastFailureAt: "2026-08-13T09:59:00Z",
	}

	unknown := updateComponent(previous, probeResult{id: previous.ID, status: StatusUnknown}, now)
	if unknown.Checks != 4 || unknown.SuccessfulChecks != 3 || unknown.AvailabilityPercent != 75 {
		t.Fatalf("unknown status changed availability denominator: %#v", unknown)
	}
	if unknown.ConsecutiveSuccesses != 0 || unknown.ConsecutiveFailures != 0 {
		t.Fatalf("unknown status should interrupt current streaks: %#v", unknown)
	}
	if unknown.LastSuccessAt != previous.LastSuccessAt || unknown.LastFailureAt != previous.LastFailureAt {
		t.Fatalf("unknown status changed historical outcome timestamps: %#v", unknown)
	}

	notApplicable := updateComponent(unknown, probeResult{id: previous.ID, status: StatusNotApplicable}, now.Add(time.Second))
	if notApplicable.Checks != 4 || notApplicable.SuccessfulChecks != 3 || notApplicable.AvailabilityPercent != 75 {
		t.Fatalf("N/A status changed availability denominator: %#v", notApplicable)
	}

	healthy := updateComponent(notApplicable, probeResult{id: previous.ID, status: StatusHealthy}, now.Add(2*time.Second))
	if healthy.Checks != 5 || healthy.SuccessfulChecks != 4 || healthy.AvailabilityPercent != 80 {
		t.Fatalf("next evaluable check used the wrong denominator: %#v", healthy)
	}
	if healthy.ConsecutiveSuccesses != 1 || healthy.ConsecutiveFailures != 0 {
		t.Fatalf("non-evaluable gap should break success streak continuity: %#v", healthy)
	}
}

func TestMonitorHealthySnapshot(t *testing.T) {
	dataPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/" || r.Host != "project.test" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Request-ID", "connectivity-test")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer dataPlane.Close()

	source := &fakeSource{cfg: healthyConfig(t, dataPlane)}
	snapshot := New(source).Snapshot(context.Background(), true)
	if snapshot.OverallStatus != StatusHealthy {
		t.Fatalf("overall=%s components=%#v", snapshot.OverallStatus, snapshot.Components)
	}
	if snapshot.EdgeProxyConnectionStatus != StatusHealthy {
		t.Fatalf("edge connection=%s", snapshot.EdgeProxyConnectionStatus)
	}
	if snapshot.Counts.ReadyRoutes != 1 || snapshot.Counts.HealthyOrigins != 1 {
		t.Fatalf("counts=%#v", snapshot.Counts)
	}
	if len(snapshot.Components) != 8 {
		t.Fatalf("components=%d", len(snapshot.Components))
	}
	for _, component := range snapshot.Components {
		if component.Status != StatusHealthy {
			t.Fatalf("component %s=%s error=%s", component.ID, component.Status, component.Error)
		}
	}
}

func TestMonitorDegradesMetricsWithoutDeclaredSchema(t *testing.T) {
	dataPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/" || r.Host != "project.test" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Request-ID", "connectivity-test")
		w.WriteHeader(http.StatusOK)
	}))
	defer dataPlane.Close()

	source := &fakeSource{
		cfg:        healthyConfig(t, dataPlane),
		metricsRaw: json.RawMessage(`{"uptime_seconds":42}`),
	}
	snapshot := New(source).Snapshot(context.Background(), true)

	var metricsComponent Component
	for _, component := range snapshot.Components {
		if component.ID == "edgeproxy_metrics" {
			metricsComponent = component
			break
		}
	}
	if metricsComponent.ID == "" {
		t.Fatal("EdgeProxy metrics component missing")
	}
	if metricsComponent.Status != StatusDegraded || !strings.Contains(metricsComponent.Message, "schema version") {
		t.Fatalf("metrics component=%#v, want degraded schema error", metricsComponent)
	}
	if snapshot.ObservabilityStatus != StatusDegraded || snapshot.EdgeProxyConnectionStatus != StatusDegraded {
		t.Fatalf("invalid metrics schema was reported healthy: observability=%s edge=%s", snapshot.ObservabilityStatus, snapshot.EdgeProxyConnectionStatus)
	}
}

func TestMonitorDetectsEdgeProxyFailureAndRecordsRecovery(t *testing.T) {
	dataPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-ID", "connectivity-test")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	cfg := healthyConfig(t, dataPlane)
	source := &fakeSource{cfg: cfg}
	monitor := New(source)
	first := monitor.Snapshot(context.Background(), true)
	if first.OverallStatus != StatusHealthy {
		t.Fatalf("first overall=%s", first.OverallStatus)
	}

	dataPlane.Close()
	source.edgeDown = true
	second := monitor.Snapshot(context.Background(), true)
	if second.OverallStatus != StatusDown {
		t.Fatalf("second overall=%s", second.OverallStatus)
	}
	if second.EdgeProxyConnectionStatus != StatusDown {
		t.Fatalf("edge connection=%s", second.EdgeProxyConnectionStatus)
	}
	if len(second.History) == 0 {
		t.Fatal("expected status transitions")
	}
	var found bool
	for _, transition := range second.History {
		if transition.Component == "edgeproxy_data_http" && transition.From == StatusHealthy && transition.To == StatusDown {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing data-plane transition: %#v", second.History)
	}
}

func TestRepresentativeDataPlaneTargetPrefersExactRoute(t *testing.T) {
	target := representativeDataPlaneTarget([]routes.Route{
		{Name: "catch-all", Hosts: []string{"*"}, PathPrefix: "/"},
		{Name: "wildcard", Hosts: []string{"*.example.com"}, PathPrefix: "/api"},
		{Name: "exact", Hosts: []string{"2001:db8::1"}, PathPrefix: "/private"},
	})
	if target.routeName != "exact" || target.host != "[2001:db8::1]" || target.path != "/private" {
		t.Fatalf("target=%#v", target)
	}
}

func TestRepresentativeDataPlaneTargetBuildsWildcardHost(t *testing.T) {
	target := representativeDataPlaneTarget([]routes.Route{{
		Name:       "wildcard",
		Hosts:      []string{"*.example.com"},
		PathPrefix: "/api",
	}})
	if target.routeName != "wildcard" || target.host != "connectivity-probe.example.com" || target.path != "/api" {
		t.Fatalf("target=%#v", target)
	}
}

func TestProbeGatewayListenerReportsTLSProtocol(t *testing.T) {
	var serverErrors bytes.Buffer
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(&serverErrors, "", 0)
	server.StartTLS()

	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.ListenAddr = server.Listener.Addr().String()
	cfg.Server.TLS.Enabled = true
	result := probeGatewayListener(context.Background(), cfg)
	if result.status != StatusHealthy {
		t.Fatalf("result=%#v", result)
	}
	if result.details["protocol"] != "https" || result.details["tls"] != true {
		t.Fatalf("TLS details=%#v", result.details)
	}
	if result.details["tls_version"] == "" {
		t.Fatalf("TLS version missing from details=%#v", result.details)
	}
	if result.message != "public HTTPS gateway listener completed a local TLS handshake" {
		t.Fatalf("message=%q", result.message)
	}
	server.Close()
	if strings.Contains(serverErrors.String(), "TLS handshake error") {
		t.Fatalf("TLS listener probe polluted server logs: %s", serverErrors.String())
	}
}

func TestProbeGatewayListenerRejectsPlainTCPWhenTLSConfigured(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()

	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.ListenAddr = listener.Addr().String()
	cfg.Server.TLS.Enabled = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := probeGatewayListener(ctx, cfg)
	<-accepted
	if result.status != StatusDown {
		t.Fatalf("result=%#v", result)
	}
	if !strings.Contains(result.message, "TLS handshake") {
		t.Fatalf("message=%q", result.message)
	}
}

func TestProbeDataPlaneHTTPUsesConfiguredWildcardRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.Host != "connectivity-probe.example.com" || r.URL.Path != "/api" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get(edgeprobe.HeaderName) != edgeprobe.HeaderValue || r.UserAgent() != edgeprobe.UserAgent {
			t.Errorf("probe identity headers=%#v", r.Header)
		}
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
			t.Errorf("probe cache policy=%#v", r.Header)
		}
		w.Header().Set("X-Request-ID", "matched-route")
		w.Header().Set("Location", "/must-not-follow")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.UpstreamProxyURL = server.URL
	cfg.Admin.Connectivity.Timeout = config.Duration{Duration: time.Second}
	result := probeDataPlaneHTTP(context.Background(), cfg, []routes.Route{{
		Name:       "api",
		Hosts:      []string{"*.example.com"},
		PathPrefix: "/api",
	}})
	if result.status != StatusHealthy || result.httpStatus != http.StatusFound {
		t.Fatalf("result=%#v", result)
	}
	if result.details["request_id"] != "matched-route" || result.details["route"] != "api" {
		t.Fatalf("details=%#v", result.details)
	}
	if result.details["protocol"] != "http" || result.details["tls"] != false {
		t.Fatalf("protocol details=%#v", result.details)
	}
}

func TestProbeDataPlaneTCPReportsHTTPSProtocol(t *testing.T) {
	var serverErrors bytes.Buffer
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(&serverErrors, "", 0)
	server.StartTLS()

	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.UpstreamProxyURL = server.URL
	result := probeDataPlaneTCP(context.Background(), cfg)
	if result.status != StatusHealthy {
		t.Fatalf("result=%#v", result)
	}
	if result.details["protocol"] != "https" || result.details["tls"] != true {
		t.Fatalf("TLS protocol details=%#v", result.details)
	}
	if result.details["tls_version"] == "" {
		t.Fatalf("TLS version missing from details=%#v", result.details)
	}
	if result.message != "SecurityEdge can complete a TLS handshake with EdgeProxy" {
		t.Fatalf("message=%q", result.message)
	}
	server.Close()
	if strings.Contains(serverErrors.String(), "TLS handshake error") {
		t.Fatalf("TLS data-plane probe polluted server logs: %s", serverErrors.String())
	}
}

func TestProbeDataPlaneTCPRejectsPlainTCPWhenHTTPSConfigured(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()

	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.UpstreamProxyURL = "https://" + listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := probeDataPlaneTCP(ctx, cfg)
	<-accepted
	if result.status != StatusDown {
		t.Fatalf("result=%#v", result)
	}
	if !strings.Contains(result.message, "TLS handshake") {
		t.Fatalf("message=%q", result.message)
	}
}

func TestProbeDataPlaneHTTPSReportsTLSProtocol(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.UpstreamProxyURL = "https://127.0.0.1:1"
	cfg.Admin.Connectivity.Timeout = config.Duration{Duration: 100 * time.Millisecond}
	result := probeDataPlaneHTTP(context.Background(), cfg, []routes.Route{{
		Name: "api", Hosts: []string{"project.test"}, PathPrefix: "/",
	}})
	if result.status != StatusDown {
		t.Fatalf("result=%#v", result)
	}
	if result.details["protocol"] != "https" || result.details["tls"] != true {
		t.Fatalf("TLS protocol details=%#v", result.details)
	}
	if !strings.Contains(result.message, "HTTPS") {
		t.Fatalf("message=%q", result.message)
	}
}

func TestProbeDataPlaneHTTPRejectsUnmatchedResponse(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	cfg := config.Default()
	cfg.Server.Mode = "gateway"
	cfg.Server.UpstreamProxyURL = server.URL
	cfg.Admin.Connectivity.Timeout = config.Duration{Duration: time.Second}
	result := probeDataPlaneHTTP(context.Background(), cfg, []routes.Route{{
		Name:       "api",
		Hosts:      []string{"project.test"},
		PathPrefix: "/api",
	}})
	if result.status != StatusDown || result.httpStatus != http.StatusNotFound {
		t.Fatalf("result=%#v", result)
	}
}

func TestCanceledCallerDoesNotPoisonConnectivitySnapshot(t *testing.T) {
	dataPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != "/" || r.Host != "project.test" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Request-ID", "connectivity-test")
		w.WriteHeader(http.StatusOK)
	}))
	defer dataPlane.Close()

	source := &fakeSource{cfg: healthyConfig(t, dataPlane)}
	monitor := New(source)
	first := monitor.Snapshot(context.Background(), true)
	if first.OverallStatus != StatusHealthy {
		t.Fatalf("initial overall=%s components=%#v", first.OverallStatus, first.Components)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	second := monitor.Snapshot(canceled, true)
	if second.OverallStatus != StatusHealthy || second.EdgeProxyConnectionStatus != StatusHealthy {
		t.Fatalf("canceled caller poisoned snapshot: overall=%s edge=%s components=%#v", second.OverallStatus, second.EdgeProxyConnectionStatus, second.Components)
	}
	if len(second.History) != 0 {
		t.Fatalf("unexpected transitions from canceled caller: %#v", second.History)
	}
}

func TestContainsAnyCanonicalizesIPAddressForms(t *testing.T) {
	if !containsAny([]string{"2001:db8::1"}, []string{" 2001:0db8:0:0:0:0:0:1 "}) {
		t.Fatal("equivalent IPv6 address forms should match")
	}
}

func TestDNSDialerUsesResolverRequestedTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dnsDialer(listener.Addr().String())(ctx, "tcp", "ignored:53")
	if err != nil {
		t.Fatalf("TCP DNS fallback dial failed: %v", err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("TCP DNS fallback was not accepted: %v", err)
	}
}

func TestLoopbackDialAddressPreservesWildcardAddressFamily(t *testing.T) {
	if got := loopbackDialAddress("0.0.0.0:8081"); got != "127.0.0.1:8081" {
		t.Fatalf("IPv4 wildcard probe address=%q", got)
	}
	if got := loopbackDialAddress("[::]:8081"); got != "[::1]:8081" {
		t.Fatalf("IPv6 wildcard probe address=%q", got)
	}
}
