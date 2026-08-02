package connectivity

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/routes"
)

type fakeSource struct {
	cfg      config.Config
	edgeDown bool
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

func TestProbeDataPlaneHTTPUsesConfiguredWildcardRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.Host != "connectivity-probe.example.com" || r.URL.Path != "/api" {
			http.NotFound(w, r)
			return
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
