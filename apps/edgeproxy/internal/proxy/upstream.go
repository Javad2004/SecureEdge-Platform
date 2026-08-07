package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

const maxConcurrentHealthChecks = 16

type upstream struct {
	name             string
	url              *url.URL
	weight           int
	priority         int
	healthy          atomic.Bool
	active           atomic.Int64
	selections       atomic.Uint64
	healthFailures   atomic.Uint64
	healthRecoveries atomic.Uint64
	ewmaBits         atomic.Uint64
	currentWeight    int64
	transport        *http.Transport
}

func (u *upstream) ewmaMS() float64 { return math.Float64frombits(u.ewmaBits.Load()) }
func (u *upstream) observeLatency(duration time.Duration, alpha float64) {
	value := float64(duration) / float64(time.Millisecond)
	for {
		oldBits := u.ewmaBits.Load()
		old := math.Float64frombits(oldBits)
		next := value
		if old > 0 {
			next = alpha*value + (1-alpha)*old
		}
		if u.ewmaBits.CompareAndSwap(oldBits, math.Float64bits(next)) {
			return
		}
	}
}

type upstreamPool struct {
	nodes       []*upstream
	next        atomic.Uint64
	randomState atomic.Uint64
	mu          sync.Mutex
	healthHost  string
	algorithm   string
	sensitivity float64
	ewmaAlpha   float64
}

type healthChange struct {
	Upstream string
	Healthy  bool
	Status   int
	Duration time.Duration
	Error    string
}

func newUpstreamPool(route config.RouteConfig) (*upstreamPool, error) {
	pool := &upstreamPool{
		healthHost:  healthCheckHost(route),
		algorithm:   route.LoadBalancing.Algorithm,
		sensitivity: route.LoadBalancing.LatencySensitivity,
		ewmaAlpha:   route.LoadBalancing.EWMAAlpha,
	}
	pool.randomState.Store(uint64(time.Now().UnixNano()) ^ uint64(len(route.Name))*0x9e3779b97f4a7c15)
	for _, raw := range route.Upstreams {
		parsed, err := url.Parse(raw.URL)
		if err != nil {
			return nil, fmt.Errorf("parse upstream %q: %w", raw.URL, err)
		}
		tr := &http.Transport{
			Proxy:                  nil,
			DialContext:            (&netDialer{timeout: route.Proxy.DialTimeout.Duration}).DialContext,
			ForceAttemptHTTP2:      true,
			MaxIdleConns:           route.Proxy.MaxIdleConns,
			MaxIdleConnsPerHost:    route.Proxy.MaxIdleConnsPerHost,
			IdleConnTimeout:        route.Proxy.IdleConnTimeout.Duration,
			ResponseHeaderTimeout:  route.Proxy.ResponseHeaderTimeout.Duration,
			MaxResponseHeaderBytes: route.Proxy.MaxResponseHeaderBytes,
			DisableCompression:     true,
			TLSClientConfig:        &tls.Config{InsecureSkipVerify: raw.InsecureSkipVerify}, //nolint:gosec -- explicit per-upstream option
		}
		node := &upstream{name: raw.Name, url: parsed, weight: raw.Weight, priority: raw.Priority, transport: tr}
		node.healthy.Store(!route.HealthCheck.Enabled)
		pool.nodes = append(pool.nodes, node)
	}
	return pool, nil
}

func (p *upstreamPool) pick(exclude map[*upstream]bool) *upstream {
	candidates := p.eligible(exclude, true)
	if len(candidates) == 0 {
		candidates = p.eligible(exclude, false)
	}
	if len(candidates) == 0 {
		// Every origin may have been attempted already. Preserve configured retry
		// semantics by allowing another cycle through currently healthy origins.
		candidates = p.eligible(nil, true)
		if len(candidates) == 0 {
			candidates = append(candidates, p.nodes...)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	var selected *upstream
	switch p.algorithm {
	case "weighted_round_robin":
		selected = p.pickSmoothWeighted(candidates, false)
	case "least_connections":
		selected = p.pickLeastConnections(candidates)
	case "priority_failover":
		selected = p.pickPriority(candidates)
	case "adaptive_latency":
		selected = p.pickAdaptive(candidates)
	case "random_weighted":
		selected = p.pickRandomWeighted(candidates)
	default:
		selected = p.pickRoundRobin(candidates)
	}
	if selected != nil {
		selected.selections.Add(1)
		selected.active.Add(1)
	}
	return selected
}

func (p *upstreamPool) observe(node *upstream, duration time.Duration) {
	if node == nil {
		return
	}
	node.observeLatency(duration, p.ewmaAlpha)
}

func (p *upstreamPool) releaseActive(node *upstream) {
	if node == nil {
		return
	}
	node.active.Add(-1)
}

func (p *upstreamPool) release(node *upstream, duration time.Duration) {
	p.observe(node, duration)
	p.releaseActive(node)
}

func (p *upstreamPool) eligible(exclude map[*upstream]bool, healthyOnly bool) []*upstream {
	out := make([]*upstream, 0, len(p.nodes))
	for _, node := range p.nodes {
		if exclude != nil && exclude[node] {
			continue
		}
		if healthyOnly && !node.healthy.Load() {
			continue
		}
		out = append(out, node)
	}
	return out
}

func (p *upstreamPool) pickRoundRobin(candidates []*upstream) *upstream {
	return candidates[int(p.next.Add(1)-1)%len(candidates)]
}

func (p *upstreamPool) pickSmoothWeighted(candidates []*upstream, latencyAdjusted bool) *upstream {
	p.mu.Lock()
	defer p.mu.Unlock()
	var selected *upstream
	var total int64
	for _, node := range candidates {
		weight := int64(node.weight)
		if latencyAdjusted {
			latency := math.Max(node.ewmaMS(), 0.25)
			penalty := math.Pow(latency, p.sensitivity) * float64(node.active.Load()+1)
			weight = int64(math.Max(1, float64(node.weight)*1_000_000/penalty))
		}
		node.currentWeight += weight
		total += weight
		if selected == nil || node.currentWeight > selected.currentWeight {
			selected = node
		}
	}
	if selected != nil {
		selected.currentWeight -= total
	}
	return selected
}

func (p *upstreamPool) pickLeastConnections(candidates []*upstream) *upstream {
	best := candidates[0]
	for _, node := range candidates[1:] {
		left := float64(node.active.Load()+1) / float64(node.weight)
		right := float64(best.active.Load()+1) / float64(best.weight)
		if left < right || (left == right && node.priority < best.priority) {
			best = node
		}
	}
	return best
}

func (p *upstreamPool) pickPriority(candidates []*upstream) *upstream {
	minimum := candidates[0].priority
	for _, node := range candidates[1:] {
		if node.priority < minimum {
			minimum = node.priority
		}
	}
	group := make([]*upstream, 0, len(candidates))
	for _, node := range candidates {
		if node.priority == minimum {
			group = append(group, node)
		}
	}
	if len(group) == 1 {
		return group[0]
	}
	return p.pickSmoothWeighted(group, false)
}

func (p *upstreamPool) pickAdaptive(candidates []*upstream) *upstream {
	// Smooth weighted selection keeps the configured traffic ratio while the
	// dynamic weight penalizes slow and busy origins using EWMA latency.
	return p.pickSmoothWeighted(candidates, true)
}

func (p *upstreamPool) pickRandomWeighted(candidates []*upstream) *upstream {
	total := uint64(0)
	for _, node := range candidates {
		total += uint64(node.weight)
	}
	if total == 0 {
		return candidates[0]
	}
	x := p.randomState.Add(0x9e3779b97f4a7c15)
	x ^= bits.RotateLeft64(x, 17)
	x *= 0xbf58476d1ce4e5b9
	pick := x % total
	for _, node := range candidates {
		w := uint64(node.weight)
		if pick < w {
			return node
		}
		pick -= w
	}
	return candidates[len(candidates)-1]
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
		out = append(out, map[string]any{
			"name": node.name, "url": node.url.String(), "healthy": node.healthy.Load(),
			"weight": node.weight, "priority": node.priority, "active_requests": node.active.Load(),
			"scheduler_selections": node.selections.Load(), "health_failures": node.healthFailures.Load(),
			"health_recoveries": node.healthRecoveries.Load(), "ewma_latency_ms": node.ewmaMS(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["url"].(string) < out[j]["url"].(string) })
	return out
}

func (p *upstreamPool) schedulerSnapshot() map[string]any {
	return map[string]any{
		"algorithm": p.algorithm, "latency_sensitivity": p.sensitivity, "ewma_alpha": p.ewmaAlpha,
	}
}

func (p *upstreamPool) runHealthChecks(ctx context.Context, cfg config.HealthCheckConfig, onChange func(healthChange)) {
	if !cfg.Enabled {
		return
	}
	statuses := make(map[int]bool)
	for _, status := range cfg.HealthyStatuses {
		statuses[status] = true
	}
	checkNode := func(node *upstream) {
		target := *node.url
		target.Path = joinPath(node.url.Path, cfg.Path)
		started := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			setNodeHealth(node, false, healthChange{Upstream: node.url.String(), Healthy: false, Duration: time.Since(started), Error: err.Error()}, onChange)
			return
		}
		if p.healthHost != "" {
			req.Host = p.healthHost
		}
		client := &http.Client{Transport: node.transport, Timeout: cfg.Timeout.Duration, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		elapsed := time.Since(started)
		if err != nil {
			setNodeHealth(node, false, healthChange{Upstream: node.url.String(), Healthy: false, Duration: elapsed, Error: err.Error()}, onChange)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		healthy := resp.StatusCode >= 200 && resp.StatusCode < 400
		if len(statuses) > 0 {
			healthy = statuses[resp.StatusCode]
		}
		setNodeHealth(node, healthy, healthChange{Upstream: node.url.String(), Healthy: healthy, Status: resp.StatusCode, Duration: elapsed}, onChange)
	}
	check := func() {
		workerCount := min(maxConcurrentHealthChecks, len(p.nodes))
		if workerCount == 0 {
			return
		}
		jobs := make(chan *upstream)
		var workers sync.WaitGroup
		workers.Add(workerCount)
		for range workerCount {
			go func() {
				defer workers.Done()
				for node := range jobs {
					checkNode(node)
				}
			}()
		}
		for _, node := range p.nodes {
			select {
			case jobs <- node:
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				return
			}
		}
		close(jobs)
		workers.Wait()
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

func healthCheckHost(route config.RouteConfig) string {
	if !route.PreserveHost {
		return ""
	}
	var wildcard string
	for _, raw := range route.Hosts {
		host := strings.TrimSpace(raw)
		switch {
		case host == "*":
			continue
		case strings.HasPrefix(host, "*."):
			if wildcard == "" {
				wildcard = "health-probe." + strings.TrimPrefix(host, "*.")
			}
		default:
			if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
				return "[" + ip.String() + "]"
			}
			return host
		}
	}
	return wildcard
}

func setNodeHealth(node *upstream, healthy bool, change healthChange, onChange func(healthChange)) {
	previous := node.healthy.Swap(healthy)
	if previous != healthy {
		if healthy {
			node.healthRecoveries.Add(1)
		} else {
			node.healthFailures.Add(1)
		}
		if onChange != nil {
			onChange(change)
		}
	}
}
