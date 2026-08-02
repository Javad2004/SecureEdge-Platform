package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

type upstream struct {
	url       *url.URL
	healthy   atomic.Bool
	transport *http.Transport
}

type upstreamPool struct {
	nodes []*upstream
	next  atomic.Uint64
}

type healthChange struct {
	Upstream string
	Healthy  bool
	Status   int
	Duration time.Duration
	Error    string
}

func newUpstreamPool(route config.RouteConfig) (*upstreamPool, error) {
	pool := &upstreamPool{}
	for _, raw := range route.Upstreams {
		parsed, err := url.Parse(raw.URL)
		if err != nil {
			return nil, fmt.Errorf("parse upstream %q: %w", raw.URL, err)
		}
		tr := &http.Transport{
			// Origin traffic is an internal data-plane hop; never inherit ambient proxy settings.
			Proxy:                  nil,
			DialContext:            (&netDialer{timeout: route.Proxy.DialTimeout.Duration}).DialContext,
			ForceAttemptHTTP2:      true,
			MaxIdleConns:           route.Proxy.MaxIdleConns,
			MaxIdleConnsPerHost:    route.Proxy.MaxIdleConnsPerHost,
			IdleConnTimeout:        route.Proxy.IdleConnTimeout.Duration,
			ResponseHeaderTimeout:  route.Proxy.ResponseHeaderTimeout.Duration,
			MaxResponseHeaderBytes: route.Proxy.MaxResponseHeaderBytes,
			DisableCompression:     true,
			TLSClientConfig:        &tls.Config{InsecureSkipVerify: raw.InsecureSkipVerify}, //nolint:gosec -- explicit per-upstream demo option
		}
		node := &upstream{url: parsed, transport: tr}
		// With active health checks enabled, begin in an unknown/not-ready state
		// until the immediate first probe succeeds. Routes without health checks
		// remain optimistic and recover through real request attempts.
		node.healthy.Store(!route.HealthCheck.Enabled)
		pool.nodes = append(pool.nodes, node)
	}
	return pool, nil
}

func (p *upstreamPool) pick(exclude map[*upstream]bool) *upstream {
	n := len(p.nodes)
	if n == 0 {
		return nil
	}
	start := int(p.next.Add(1)-1) % n
	for i := 0; i < n; i++ {
		node := p.nodes[(start+i)%n]
		if exclude[node] {
			continue
		}
		if node.healthy.Load() {
			return node
		}
	}
	// If every non-excluded origin is currently marked unhealthy, still attempt one.
	// This allows automatic recovery even between active health-check intervals.
	for i := 0; i < n; i++ {
		node := p.nodes[(start+i)%n]
		if !exclude[node] {
			return node
		}
	}
	// All origins have already been attempted. When retry_count exceeds the number
	// of origins (or only one origin exists), cycle again rather than abandoning
	// a configured retry.
	for i := 0; i < n; i++ {
		node := p.nodes[(start+i)%n]
		if node.healthy.Load() {
			return node
		}
	}
	return p.nodes[start]
}

func (p *upstreamPool) hasHealthy() bool {
	for _, node := range p.nodes {
		if node.healthy.Load() {
			return true
		}
	}
	return false
}

func (p *upstreamPool) closeIdleConnections() {
	for _, node := range p.nodes {
		node.transport.CloseIdleConnections()
	}
}

func (p *upstreamPool) healthSnapshot() []map[string]any {
	out := make([]map[string]any, 0, len(p.nodes))
	for _, node := range p.nodes {
		out = append(out, map[string]any{"url": node.url.String(), "healthy": node.healthy.Load()})
	}
	return out
}

func (p *upstreamPool) runHealthChecks(ctx context.Context, cfg config.HealthCheckConfig, onChange func(healthChange)) {
	if !cfg.Enabled {
		return
	}
	statuses := make(map[int]bool)
	for _, status := range cfg.HealthyStatuses {
		statuses[status] = true
	}
	check := func() {
		for _, node := range p.nodes {
			target := *node.url
			target.Path = joinPath(node.url.Path, cfg.Path)
			started := time.Now()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
			if err != nil {
				setNodeHealth(node, false, healthChange{Upstream: node.url.String(), Healthy: false, Duration: time.Since(started), Error: err.Error()}, onChange)
				continue
			}
			client := &http.Client{
				Transport: node.transport,
				Timeout:   cfg.Timeout.Duration,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			elapsed := time.Since(started)
			if err != nil {
				setNodeHealth(node, false, healthChange{Upstream: node.url.String(), Healthy: false, Duration: elapsed, Error: err.Error()}, onChange)
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			healthy := resp.StatusCode >= 200 && resp.StatusCode < 400
			if len(statuses) > 0 {
				healthy = statuses[resp.StatusCode]
			}
			setNodeHealth(node, healthy, healthChange{Upstream: node.url.String(), Healthy: healthy, Status: resp.StatusCode, Duration: elapsed}, onChange)
		}
	}
	check()
	ticker := time.NewTicker(cfg.Interval.Duration)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func setNodeHealth(node *upstream, healthy bool, change healthChange, onChange func(healthChange)) {
	previous := node.healthy.Swap(healthy)
	if previous != healthy && onChange != nil {
		onChange(change)
	}
}
