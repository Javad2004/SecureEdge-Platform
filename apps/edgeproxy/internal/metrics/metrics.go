package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

type routeCounters struct {
	Requests           uint64 `json:"requests"`
	Success            uint64 `json:"success"`
	ClientErrors       uint64 `json:"client_errors"`
	ServerErrors       uint64 `json:"server_errors"`
	ProxyErrors        uint64 `json:"proxy_errors"`
	UpstreamCalls      uint64 `json:"upstream_calls"`
	Retries            uint64 `json:"retries"`
	BytesIn            uint64 `json:"bytes_in"`
	BytesOut           uint64 `json:"bytes_out"`
	CacheHits          uint64 `json:"cache_hits"`
	CacheMisses        uint64 `json:"cache_misses"`
	CacheStale         uint64 `json:"cache_stale"`
	CacheBypasses      uint64 `json:"cache_bypasses"`
	CacheStores        uint64 `json:"cache_stores"`
	TotalDurationNS    uint64 `json:"-"`
	UpstreamDurationNS uint64 `json:"-"`
}

type Counters struct {
	requests           atomic.Uint64
	success            atomic.Uint64
	clientErrors       atomic.Uint64
	serverErrors       atomic.Uint64
	proxyErrors        atomic.Uint64
	upstreamCalls      atomic.Uint64
	retries            atomic.Uint64
	bytesIn            atomic.Uint64
	bytesOut           atomic.Uint64
	cacheHits          atomic.Uint64
	cacheMisses        atomic.Uint64
	cacheStale         atomic.Uint64
	cacheBypasses      atomic.Uint64
	cacheStores        atomic.Uint64
	totalDurationNS    atomic.Uint64
	upstreamDurationNS atomic.Uint64
}

type Registry struct {
	startedAt time.Time
	inflight  atomic.Int64
	total     Counters
	mu        sync.RWMutex
	routes    map[string]*Counters
}

type Snapshot struct {
	StartedAt     string                     `json:"started_at"`
	UptimeSeconds int64                      `json:"uptime_seconds"`
	Inflight      int64                      `json:"inflight"`
	Total         CounterSnapshot            `json:"total"`
	Routes        map[string]CounterSnapshot `json:"routes"`
}

type CounterSnapshot struct {
	Requests              uint64  `json:"requests"`
	Success               uint64  `json:"success"`
	ClientErrors          uint64  `json:"client_errors"`
	ServerErrors          uint64  `json:"server_errors"`
	ProxyErrors           uint64  `json:"proxy_errors"`
	UpstreamCalls         uint64  `json:"upstream_calls"`
	Retries               uint64  `json:"retries"`
	BytesIn               uint64  `json:"bytes_in"`
	BytesOut              uint64  `json:"bytes_out"`
	CacheHits             uint64  `json:"cache_hits"`
	CacheMisses           uint64  `json:"cache_misses"`
	CacheStale            uint64  `json:"cache_stale"`
	CacheBypasses         uint64  `json:"cache_bypasses"`
	CacheStores           uint64  `json:"cache_stores"`
	AverageResponseTimeMS float64 `json:"average_response_time_ms"`
	AverageUpstreamTimeMS float64 `json:"average_upstream_time_ms"`
	CacheHitRatio         float64 `json:"cache_hit_ratio"`
}

func New() *Registry {
	return &Registry{startedAt: time.Now(), routes: make(map[string]*Counters)}
}

func (r *Registry) Begin(route string, bytesIn uint64) func(status int, bytesOut uint64, totalDuration, upstreamDuration time.Duration, proxyErr bool, upstreamCalls, retries uint64, cacheStatus string) {
	r.inflight.Add(1)
	c := r.route(route)
	r.total.requests.Add(1)
	c.requests.Add(1)
	r.total.bytesIn.Add(bytesIn)
	c.bytesIn.Add(bytesIn)
	return func(status int, bytesOut uint64, totalDuration, upstreamDuration time.Duration, proxyErr bool, upstreamCalls, retries uint64, cacheStatus string) {
		defer r.inflight.Add(-1)
		for _, target := range []*Counters{&r.total, c} {
			target.bytesOut.Add(bytesOut)
			target.totalDurationNS.Add(uint64(max(totalDuration, 0)))
			target.upstreamDurationNS.Add(uint64(max(upstreamDuration, 0)))
			target.upstreamCalls.Add(upstreamCalls)
			target.retries.Add(retries)
			if proxyErr {
				target.proxyErrors.Add(1)
			}
			switch {
			case status >= 200 && status < 400:
				target.success.Add(1)
			case status >= 400 && status < 500:
				target.clientErrors.Add(1)
			case status >= 500:
				target.serverErrors.Add(1)
			}
			switch cacheStatus {
			case "HIT":
				target.cacheHits.Add(1)
			case "MISS":
				target.cacheMisses.Add(1)
			case "STALE":
				target.cacheStale.Add(1)
			case "BYPASS":
				target.cacheBypasses.Add(1)
			case "STORE":
				target.cacheStores.Add(1)
			}
		}
	}
}

func (r *Registry) RecordCacheStore(route string) {
	r.total.cacheStores.Add(1)
	r.route(route).cacheStores.Add(1)
}

func (r *Registry) route(name string) *Counters {
	r.mu.RLock()
	c := r.routes[name]
	r.mu.RUnlock()
	if c != nil {
		return c
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c = r.routes[name]; c == nil {
		c = &Counters{}
		r.routes[name] = c
	}
	return c
}

func (r *Registry) Snapshot() Snapshot {
	out := Snapshot{
		StartedAt:     r.startedAt.UTC().Format(time.RFC3339),
		UptimeSeconds: int64(time.Since(r.startedAt).Seconds()),
		Inflight:      r.inflight.Load(),
		Total:         snapshotCounters(&r.total),
		Routes:        make(map[string]CounterSnapshot),
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for name, c := range r.routes {
		out.Routes[name] = snapshotCounters(c)
	}
	return out
}

func snapshotCounters(c *Counters) CounterSnapshot {
	requests := c.requests.Load()
	upstreamCalls := c.upstreamCalls.Load()
	hits := c.cacheHits.Load()
	misses := c.cacheMisses.Load()
	s := CounterSnapshot{
		Requests: requests,
		Success:  c.success.Load(), ClientErrors: c.clientErrors.Load(), ServerErrors: c.serverErrors.Load(),
		ProxyErrors: c.proxyErrors.Load(), UpstreamCalls: upstreamCalls, Retries: c.retries.Load(),
		BytesIn: c.bytesIn.Load(), BytesOut: c.bytesOut.Load(), CacheHits: hits, CacheMisses: misses,
		CacheStale: c.cacheStale.Load(), CacheBypasses: c.cacheBypasses.Load(), CacheStores: c.cacheStores.Load(),
	}
	if requests > 0 {
		s.AverageResponseTimeMS = float64(c.totalDurationNS.Load()) / float64(requests) / 1e6
	}
	if upstreamCalls > 0 {
		s.AverageUpstreamTimeMS = float64(c.upstreamDurationNS.Load()) / float64(upstreamCalls) / 1e6
	}
	if hits+misses > 0 {
		s.CacheHitRatio = float64(hits) / float64(hits+misses)
	}
	return s
}

func max(d time.Duration, min time.Duration) time.Duration {
	if d < min {
		return min
	}
	return d
}
