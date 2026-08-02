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
