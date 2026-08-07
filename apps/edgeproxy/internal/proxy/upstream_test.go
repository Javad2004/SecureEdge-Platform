package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

func TestHealthChecksUseBoundedConcurrency(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	var completed atomic.Int32
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		<-release
		active.Add(-1)
		completed.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	upstreamCount := maxConcurrentHealthChecks + 4
	upstreams := make([]config.UpstreamConfig, 0, upstreamCount)
	for i := 0; i < upstreamCount; i++ {
		upstreams = append(upstreams, config.UpstreamConfig{URL: origin.URL, Name: fmt.Sprintf("origin-%d", i+1), Weight: 1, Priority: i + 1})
	}
	route := config.RouteConfig{
		Name: "many-origins", Upstreams: upstreams,
		Proxy: config.ProxyConfig{DialTimeout: config.Duration{Duration: time.Second}, ResponseHeaderTimeout: config.Duration{Duration: time.Second}, MaxIdleConns: upstreamCount, MaxIdleConnsPerHost: upstreamCount},
	}
	pool, err := newUpstreamPool(route)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.closeIdleConnections()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pool.runHealthChecks(ctx, config.HealthCheckConfig{Enabled: true, Path: "/healthz", Interval: config.Duration{Duration: 10 * time.Second}, Timeout: config.Duration{Duration: time.Second}, HealthyStatuses: []int{http.StatusOK}}, nil)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for maximum.Load() < maxConcurrentHealthChecks && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := maximum.Load(); got != maxConcurrentHealthChecks {
		close(release)
		cancel()
		<-done
		t.Fatalf("maximum concurrent health checks=%d, want %d", got, maxConcurrentHealthChecks)
	}
	close(release)

	deadline = time.Now().Add(2 * time.Second)
	for completed.Load() < int32(upstreamCount) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := completed.Load(); got != int32(upstreamCount) {
		cancel()
		<-done
		t.Fatalf("completed health checks=%d, want %d", got, upstreamCount)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health-check loop did not stop after context cancellation")
	}
}

func TestHealthCheckDoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHits atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer origin.Close()

	route := config.RouteConfig{
		Name:      "redirecting-origin",
		Upstreams: []config.UpstreamConfig{{URL: origin.URL}},
		Proxy: config.ProxyConfig{
			DialTimeout:            config.Duration{Duration: time.Second},
			ResponseHeaderTimeout:  config.Duration{Duration: time.Second},
			IdleConnTimeout:        config.Duration{Duration: time.Minute},
			MaxIdleConns:           8,
			MaxIdleConnsPerHost:    4,
			MaxResponseHeaderBytes: 1 << 20,
		},
		HealthCheck: config.HealthCheckConfig{
			Enabled:  true,
			Path:     "/healthz",
			Interval: config.Duration{Duration: time.Hour},
			Timeout:  config.Duration{Duration: time.Second},
		},
	}
	pool, err := newUpstreamPool(route)
	if err != nil {
		t.Fatalf("newUpstreamPool: %v", err)
	}
	defer pool.closeIdleConnections()

	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan healthChange, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.runHealthChecks(ctx, route.HealthCheck, func(change healthChange) {
			changes <- change
		})
	}()

	select {
	case change := <-changes:
		if !change.Healthy || change.Status != http.StatusFound {
			t.Fatalf("unexpected health change: %#v", change)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for health-check result")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("health-check worker did not stop")
	}

	if got := redirectTargetHits.Load(); got != 0 {
		t.Fatalf("health check followed redirect target %d time(s)", got)
	}
	if !pool.nodes[0].healthy.Load() {
		t.Fatal("redirect response should be evaluated at the configured origin")
	}
}

func TestHealthCheckUsesRepresentativePreservedHost(t *testing.T) {
	const expectedHost = "app.example.test"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if r.Host != expectedHost {
			http.Error(w, "wrong virtual host", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	route := config.RouteConfig{
		Name:         "virtual-host-origin",
		Hosts:        []string{expectedHost},
		PreserveHost: true,
		Upstreams:    []config.UpstreamConfig{{URL: origin.URL}},
		Proxy: config.ProxyConfig{
			DialTimeout:            config.Duration{Duration: time.Second},
			ResponseHeaderTimeout:  config.Duration{Duration: time.Second},
			IdleConnTimeout:        config.Duration{Duration: time.Minute},
			MaxIdleConns:           8,
			MaxIdleConnsPerHost:    4,
			MaxResponseHeaderBytes: 1 << 20,
		},
		HealthCheck: config.HealthCheckConfig{
			Enabled:         true,
			Path:            "/healthz",
			Interval:        config.Duration{Duration: time.Hour},
			Timeout:         config.Duration{Duration: time.Second},
			HealthyStatuses: []int{http.StatusNoContent},
		},
	}
	pool, err := newUpstreamPool(route)
	if err != nil {
		t.Fatalf("newUpstreamPool: %v", err)
	}
	defer pool.closeIdleConnections()

	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan healthChange, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.runHealthChecks(ctx, route.HealthCheck, func(change healthChange) {
			changes <- change
		})
	}()

	select {
	case change := <-changes:
		if !change.Healthy || change.Status != http.StatusNoContent {
			t.Fatalf("unexpected health change: %#v", change)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for virtual-host health-check result")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("health-check worker did not stop")
	}

	if !pool.nodes[0].healthy.Load() {
		t.Fatal("virtual-hosted origin should be healthy when the route Host is preserved")
	}
}

func TestHealthCheckHostSelection(t *testing.T) {
	tests := []struct {
		name  string
		route config.RouteConfig
		want  string
	}{
		{name: "preserve disabled", route: config.RouteConfig{Hosts: []string{"app.example.test"}}, want: ""},
		{name: "exact preferred", route: config.RouteConfig{PreserveHost: true, Hosts: []string{"*.example.test", "api.example.test"}}, want: "api.example.test"},
		{name: "wildcard synthesized", route: config.RouteConfig{PreserveHost: true, Hosts: []string{"*.example.test"}}, want: "health-probe.example.test"},
		{name: "catch all", route: config.RouteConfig{PreserveHost: true, Hosts: []string{"*"}}, want: ""},
		{name: "IPv6 bracketed", route: config.RouteConfig{PreserveHost: true, Hosts: []string{"2001:db8::1"}}, want: "[2001:db8::1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := healthCheckHost(tc.route); got != tc.want {
				t.Fatalf("healthCheckHost() = %q, want %q", got, tc.want)
			}
		})
	}
}

func loadBalancingRoute(algorithm string, upstreams ...config.UpstreamConfig) config.RouteConfig {
	return config.RouteConfig{
		Name:      "load-balancing-test",
		Upstreams: upstreams,
		LoadBalancing: config.LoadBalancingConfig{
			Algorithm: algorithm, LatencySensitivity: 1, EWMAAlpha: 0.25,
		},
		Proxy: config.ProxyConfig{
			DialTimeout: config.Duration{Duration: time.Second}, ResponseHeaderTimeout: config.Duration{Duration: time.Second},
			IdleConnTimeout: config.Duration{Duration: time.Minute}, MaxIdleConns: 8, MaxIdleConnsPerHost: 4,
			MaxResponseHeaderBytes: 1 << 20,
		},
	}
}

func TestWeightedRoundRobinDistribution(t *testing.T) {
	pool, err := newUpstreamPool(loadBalancingRoute("weighted_round_robin",
		config.UpstreamConfig{Name: "one", URL: "http://127.0.0.1:9001", Weight: 1, Priority: 1},
		config.UpstreamConfig{Name: "three", URL: "http://127.0.0.1:9002", Weight: 3, Priority: 1},
	))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.closeIdleConnections()
	counts := map[string]int{}
	for range 400 {
		node := pool.pick(nil)
		counts[node.name]++
		pool.release(node, 10*time.Millisecond)
	}
	if counts["one"] != 100 || counts["three"] != 300 {
		t.Fatalf("unexpected smooth weighted distribution: %#v", counts)
	}
}

func TestPriorityFailoverAndRecovery(t *testing.T) {
	pool, err := newUpstreamPool(loadBalancingRoute("priority_failover",
		config.UpstreamConfig{Name: "primary", URL: "http://127.0.0.1:9001", Weight: 1, Priority: 1},
		config.UpstreamConfig{Name: "secondary", URL: "http://127.0.0.1:9002", Weight: 1, Priority: 2},
	))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.closeIdleConnections()

	first := pool.pick(nil)
	pool.release(first, 10*time.Millisecond)
	if first.name != "primary" {
		t.Fatalf("selected %q, want primary", first.name)
	}
	pool.nodes[0].healthy.Store(false)
	failover := pool.pick(nil)
	pool.release(failover, 10*time.Millisecond)
	if failover.name != "secondary" {
		t.Fatalf("selected %q, want secondary", failover.name)
	}
	pool.nodes[0].healthy.Store(true)
	recovered := pool.pick(nil)
	pool.release(recovered, 10*time.Millisecond)
	if recovered.name != "primary" {
		t.Fatalf("selected %q after recovery, want primary", recovered.name)
	}
}

func TestLeastConnectionsUsesWeightedLoad(t *testing.T) {
	pool, err := newUpstreamPool(loadBalancingRoute("least_connections",
		config.UpstreamConfig{Name: "busy", URL: "http://127.0.0.1:9001", Weight: 1, Priority: 1},
		config.UpstreamConfig{Name: "idle", URL: "http://127.0.0.1:9002", Weight: 1, Priority: 1},
	))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.closeIdleConnections()
	pool.nodes[0].active.Store(8)
	node := pool.pick(nil)
	pool.release(node, 5*time.Millisecond)
	if node.name != "idle" {
		t.Fatalf("selected %q, want idle", node.name)
	}
}

func TestAdaptiveLatencyPrefersFastHealthyOrigin(t *testing.T) {
	pool, err := newUpstreamPool(loadBalancingRoute("adaptive_latency",
		config.UpstreamConfig{Name: "fast", URL: "http://127.0.0.1:9001", Weight: 1, Priority: 1},
		config.UpstreamConfig{Name: "slow", URL: "http://127.0.0.1:9002", Weight: 1, Priority: 1},
	))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.closeIdleConnections()
	pool.nodes[0].observeLatency(10*time.Millisecond, 1)
	pool.nodes[1].observeLatency(100*time.Millisecond, 1)
	counts := map[string]int{}
	for range 220 {
		node := pool.pick(nil)
		counts[node.name]++
		if node.name == "fast" {
			pool.release(node, 10*time.Millisecond)
		} else {
			pool.release(node, 100*time.Millisecond)
		}
	}
	if counts["fast"] < 190 || counts["slow"] > 30 {
		t.Fatalf("adaptive distribution did not sufficiently prefer the faster origin: %#v", counts)
	}
}

func TestRandomWeightedDistributionIsBounded(t *testing.T) {
	pool, err := newUpstreamPool(loadBalancingRoute("random_weighted",
		config.UpstreamConfig{Name: "one", URL: "http://127.0.0.1:9001", Weight: 1, Priority: 1},
		config.UpstreamConfig{Name: "three", URL: "http://127.0.0.1:9002", Weight: 3, Priority: 1},
	))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.closeIdleConnections()
	pool.randomState.Store(1)
	counts := map[string]int{}
	for range 4000 {
		node := pool.pick(nil)
		counts[node.name]++
		pool.release(node, 10*time.Millisecond)
	}
	ratio := float64(counts["three"]) / float64(counts["one"])
	if ratio < 2.6 || ratio > 3.4 {
		t.Fatalf("unexpected weighted random ratio %.3f from %#v", ratio, counts)
	}
}

func TestHealthTransitionCountersIncludeDataPlaneChanges(t *testing.T) {
	pool, err := newUpstreamPool(loadBalancingRoute("round_robin",
		config.UpstreamConfig{Name: "origin", URL: "http://127.0.0.1:9001", Weight: 1, Priority: 1},
	))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.closeIdleConnections()
	node := pool.nodes[0]
	setNodeHealth(node, false, healthChange{}, nil)
	setNodeHealth(node, true, healthChange{}, nil)
	setNodeHealth(node, true, healthChange{}, nil)
	if got := node.healthFailures.Load(); got != 1 {
		t.Fatalf("health failures=%d, want 1", got)
	}
	if got := node.healthRecoveries.Load(); got != 1 {
		t.Fatalf("health recoveries=%d, want 1", got)
	}
}
