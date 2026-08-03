package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

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
