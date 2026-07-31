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

	"github.com/bachelor-project/edgeproxy/internal/config"
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

func newUpstreamPool(route config.RouteConfig) (*upstreamPool, error) {
	pool := &upstreamPool{}
	for _, raw := range route.Upstreams {
		parsed, err := url.Parse(raw.URL)
		if err != nil {
			return nil, fmt.Errorf("parse upstream %q: %w", raw.URL, err)
		}
		tr := &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
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
		node.healthy.Store(true)
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
	for i := 0; i < n; i++ {
		node := p.nodes[(start+i)%n]
		if !exclude[node] {
			return node
		}
	}
	return nil
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

func (p *upstreamPool) runHealthChecks(ctx context.Context, cfg config.HealthCheckConfig) {
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
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
			if err != nil {
				node.healthy.Store(false)
				continue
			}
			client := &http.Client{Transport: node.transport, Timeout: cfg.Timeout.Duration}
			resp, err := client.Do(req)
			if err != nil {
				node.healthy.Store(false)
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			healthy := resp.StatusCode >= 200 && resp.StatusCode < 400
			if len(statuses) > 0 {
				healthy = statuses[resp.StatusCode]
			}
			node.healthy.Store(healthy)
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
