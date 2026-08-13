package metrics

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var latencyBounds = [...]time.Duration{
	1 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2_500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

type stringCounters struct {
	values sync.Map // map[string]*atomic.Uint64
}

func (c *stringCounters) Add(key string, delta uint64) {
	if key == "" || delta == 0 {
		return
	}
	value, _ := c.values.LoadOrStore(key, &atomic.Uint64{})
	value.(*atomic.Uint64).Add(delta)
}

func (c *stringCounters) Snapshot() map[string]uint64 {
	out := make(map[string]uint64)
	c.values.Range(func(key, value any) bool {
		out[key.(string)] = value.(*atomic.Uint64).Load()
		return true
	})
	return out
}

type histogram struct {
	count atomic.Uint64
	sumNS atomic.Uint64
	// minNS stores duration nanoseconds plus one so zero remains the unset
	// sentinel while a real zero-duration sample is still representable.
	minNS   atomic.Uint64
	maxNS   atomic.Uint64
	buckets [len(latencyBounds) + 1]atomic.Uint64
}

func (h *histogram) Observe(duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	ns := uint64(duration)
	h.count.Add(1)
	h.sumNS.Add(ns)
	updateMin(&h.minNS, ns+1)
	updateMax(&h.maxNS, ns)
	index := len(latencyBounds)
	for i, bound := range latencyBounds {
		if duration <= bound {
			index = i
			break
		}
	}
	h.buckets[index].Add(1)
}

func updateMin(target *atomic.Uint64, value uint64) {
	for {
		current := target.Load()
		if current != 0 && current <= value {
			return
		}
		if target.CompareAndSwap(current, value) {
			return
		}
	}
}

func updateMax(target *atomic.Uint64, value uint64) {
	for {
		current := target.Load()
		if current >= value {
			return
		}
		if target.CompareAndSwap(current, value) {
			return
		}
	}
}

type Counters struct {
	requests            atomic.Uint64
	canceledRequests    atomic.Uint64
	success             atomic.Uint64
	clientErrors        atomic.Uint64
	serverErrors        atomic.Uint64
	proxyErrors         atomic.Uint64
	upstreamCalls       atomic.Uint64
	upstreamSuccess     atomic.Uint64
	upstreamFailures    atomic.Uint64
	upstreamCanceled    atomic.Uint64
	upstreamTimeouts    atomic.Uint64
	retries             atomic.Uint64
	bytesIn             atomic.Uint64
	bytesOut            atomic.Uint64
	cacheHits           atomic.Uint64
	cacheMisses         atomic.Uint64
	cacheStale          atomic.Uint64
	cacheBypasses       atomic.Uint64
	cacheStores         atomic.Uint64
	methods             stringCounters
	statusCodes         stringCounters
	upstreamStatusCodes stringCounters
	responseLatency     histogram
	upstreamLatency     histogram
}

type UpstreamCounters struct {
	calls       atomic.Uint64
	success     atomic.Uint64
	failures    atomic.Uint64
	canceled    atomic.Uint64
	timeouts    atomic.Uint64
	retries     atomic.Uint64
	statusCodes stringCounters
	latency     histogram
}

type routeMetrics struct {
	counters  Counters
	upstreams sync.Map // map[string]*UpstreamCounters
}

type Registry struct {
	startedAt time.Time
	inflight  atomic.Int64
	total     Counters
	mu        sync.RWMutex
	routes    map[string]*routeMetrics
	upstreams sync.Map // global map[string]*UpstreamCounters
}

// RequestObservation finalizes one client request. Canceled marks a request that
// terminated without a complete client-facing HTTP outcome.
type RequestObservation struct {
	Status      int
	Canceled    bool
	BytesIn     uint64
	BytesOut    uint64
	Duration    time.Duration
	ProxyError  bool
	Retries     uint64
	CacheStatus string
}

// UpstreamObservation records one concrete attempt against one origin.
type UpstreamObservation struct {
	Status   int
	Duration time.Duration
	Failed   bool
	Canceled bool
	Timeout  bool
	Retry    bool
}

type Snapshot struct {
	SchemaVersion     string                      `json:"schema_version"`
	GeneratedAt       string                      `json:"generated_at"`
	StartedAt         string                      `json:"started_at"`
	UptimeSeconds     int64                       `json:"uptime_seconds"`
	Inflight          int64                       `json:"inflight"`
	RequestsPerSecond float64                     `json:"requests_per_second"`
	Total             CounterSnapshot             `json:"total"`
	Upstreams         map[string]UpstreamSnapshot `json:"upstreams"`
	Routes            map[string]RouteSnapshot    `json:"routes"`
}

type RouteSnapshot struct {
	CounterSnapshot
	Upstreams map[string]UpstreamSnapshot `json:"upstreams"`
}

type CounterSnapshot struct {
	Requests              uint64            `json:"requests"`
	CanceledRequests      uint64            `json:"canceled_requests"`
	Success               uint64            `json:"success"`
	ClientErrors          uint64            `json:"client_errors"`
	ServerErrors          uint64            `json:"server_errors"`
	ProxyErrors           uint64            `json:"proxy_errors"`
	UpstreamCalls         uint64            `json:"upstream_calls"`
	Retries               uint64            `json:"retries"`
	BytesIn               uint64            `json:"bytes_in"`
	BytesOut              uint64            `json:"bytes_out"`
	CacheHits             uint64            `json:"cache_hits"`
	CacheMisses           uint64            `json:"cache_misses"`
	CacheStale            uint64            `json:"cache_stale"`
	CacheBypasses         uint64            `json:"cache_bypasses"`
	CacheStores           uint64            `json:"cache_stores"`
	AverageResponseTimeMS float64           `json:"average_response_time_ms"`
	AverageUpstreamTimeMS float64           `json:"average_upstream_time_ms"`
	CacheHitRatio         float64           `json:"cache_hit_ratio"`
	SuccessRate           float64           `json:"success_rate"`
	ErrorRate             float64           `json:"error_rate"`
	Methods               map[string]uint64 `json:"methods"`
	StatusCodes           map[string]uint64 `json:"status_codes"`
	Traffic               TrafficSnapshot   `json:"traffic"`
	Cache                 CacheSnapshot     `json:"cache"`
	ResponseLatencyMS     LatencySnapshot   `json:"response_latency_ms"`
	Upstream              UpstreamAggregate `json:"upstream"`
}

type TrafficSnapshot struct {
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

type CacheSnapshot struct {
	Hits     uint64  `json:"hits"`
	Misses   uint64  `json:"misses"`
	Stale    uint64  `json:"stale"`
	Bypasses uint64  `json:"bypasses"`
	Stores   uint64  `json:"stores"`
	HitRatio float64 `json:"hit_ratio"`
}

type UpstreamAggregate struct {
	Calls       uint64            `json:"calls"`
	Success     uint64            `json:"success"`
	Failures    uint64            `json:"failures"`
	Canceled    uint64            `json:"canceled"`
	Timeouts    uint64            `json:"timeouts"`
	Retries     uint64            `json:"retries"`
	StatusCodes map[string]uint64 `json:"status_codes"`
	LatencyMS   LatencySnapshot   `json:"latency_ms"`
}

type UpstreamSnapshot struct {
	Calls       uint64            `json:"calls"`
	Success     uint64            `json:"success"`
	Failures    uint64            `json:"failures"`
	Canceled    uint64            `json:"canceled"`
	Timeouts    uint64            `json:"timeouts"`
	Retries     uint64            `json:"retries"`
	SuccessRate float64           `json:"success_rate"`
	ErrorRate   float64           `json:"error_rate"`
	StatusCodes map[string]uint64 `json:"status_codes"`
	LatencyMS   LatencySnapshot   `json:"latency_ms"`
}

type LatencySnapshot struct {
	Count        uint64          `json:"count"`
	Average      float64         `json:"average"`
	Minimum      float64         `json:"minimum"`
	Maximum      float64         `json:"maximum"`
	P50          float64         `json:"p50"`
	P95          float64         `json:"p95"`
	P99          float64         `json:"p99"`
	Distribution []LatencyBucket `json:"distribution"`
}

type LatencyBucket struct {
	UpperBoundMS *float64 `json:"upper_bound_ms"`
	Count        uint64   `json:"count"`
	Cumulative   uint64   `json:"cumulative_count"`
}

func New() *Registry {
	return &Registry{startedAt: time.Now(), routes: make(map[string]*routeMetrics)}
}

// Begin starts accounting for one client request. The returned callback must be
// called exactly once when request processing terminates, including cancellation.
func (r *Registry) Begin(route, method string) func(RequestObservation) {
	method = metricMethod(method)
	r.inflight.Add(1)
	routeMetrics := r.route(route)
	for _, target := range []*Counters{&r.total, &routeMetrics.counters} {
		target.requests.Add(1)
		target.methods.Add(method, 1)
	}
	return func(observation RequestObservation) {
		defer r.inflight.Add(-1)
		for _, target := range []*Counters{&r.total, &routeMetrics.counters} {
			target.bytesIn.Add(observation.BytesIn)
			target.bytesOut.Add(observation.BytesOut)
			target.retries.Add(observation.Retries)
			switch observation.CacheStatus {
			case "HIT":
				target.cacheHits.Add(1)
			case "MISS":
				target.cacheMisses.Add(1)
			case "STALE":
				target.cacheStale.Add(1)
			case "BYPASS":
				target.cacheBypasses.Add(1)
			}

			// A client-canceled request is physical traffic, so request/method,
			// byte, retry, and cache-activity counters remain meaningful. It is
			// not, however, a completed client-facing HTTP outcome. Exclude it
			// from response status, latency, proxy-error, and reliability data.
			if observation.Canceled {
				target.canceledRequests.Add(1)
				continue
			}

			target.responseLatency.Observe(observation.Duration)
			if observation.ProxyError {
				target.proxyErrors.Add(1)
			}
			target.statusCodes.Add(strconv.Itoa(observation.Status), 1)
			switch {
			case observation.Status == http.StatusSwitchingProtocols || observation.Status >= 200 && observation.Status < 400:
				target.success.Add(1)
			case observation.Status >= 400 && observation.Status < 500:
				target.clientErrors.Add(1)
			case observation.Status >= 500:
				target.serverErrors.Add(1)
			}
		}
	}
}

// RecordUpstream accounts for one physical request to one upstream origin.
func (r *Registry) RecordUpstream(route, upstream string, observation UpstreamObservation) {
	routeMetrics := r.route(route)
	globalUpstream := upstreamCounter(&r.upstreams, upstream)
	routeUpstream := upstreamCounter(&routeMetrics.upstreams, upstream)

	for _, target := range []*Counters{&r.total, &routeMetrics.counters} {
		target.upstreamCalls.Add(1)
		if observation.Canceled {
			target.upstreamCanceled.Add(1)
			continue
		}
		target.upstreamLatency.Observe(observation.Duration)
		if observation.Status > 0 {
			target.upstreamStatusCodes.Add(strconv.Itoa(observation.Status), 1)
		}
		if observation.Failed {
			target.upstreamFailures.Add(1)
		} else {
			target.upstreamSuccess.Add(1)
		}
		if observation.Timeout {
			target.upstreamTimeouts.Add(1)
		}
	}
	for _, target := range []*UpstreamCounters{globalUpstream, routeUpstream} {
		target.calls.Add(1)
		if observation.Retry {
			target.retries.Add(1)
		}
		if observation.Canceled {
			target.canceled.Add(1)
			continue
		}
		target.latency.Observe(observation.Duration)
		if observation.Status > 0 {
			target.statusCodes.Add(strconv.Itoa(observation.Status), 1)
		}
		if observation.Failed {
			target.failures.Add(1)
		} else {
			target.success.Add(1)
		}
		if observation.Timeout {
			target.timeouts.Add(1)
		}
	}
}

func (r *Registry) RecordCacheStore(route string) {
	r.total.cacheStores.Add(1)
	r.route(route).counters.cacheStores.Add(1)
}

func (r *Registry) route(name string) *routeMetrics {
	r.mu.RLock()
	value := r.routes[name]
	r.mu.RUnlock()
	if value != nil {
		return value
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if value = r.routes[name]; value == nil {
		value = &routeMetrics{}
		r.routes[name] = value
	}
	return value
}

func upstreamCounter(container *sync.Map, name string) *UpstreamCounters {
	value, _ := container.LoadOrStore(name, &UpstreamCounters{})
	return value.(*UpstreamCounters)
}

func (r *Registry) Snapshot() Snapshot {
	uptime := time.Since(r.startedAt)
	out := Snapshot{
		SchemaVersion: "2.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		StartedAt:     r.startedAt.UTC().Format(time.RFC3339Nano),
		UptimeSeconds: int64(uptime.Seconds()),
		Inflight:      r.inflight.Load(),
		Total:         snapshotCounters(&r.total),
		Upstreams:     snapshotUpstreamMap(&r.upstreams),
		Routes:        make(map[string]RouteSnapshot),
	}
	if uptime > 0 {
		out.RequestsPerSecond = float64(out.Total.Requests) / uptime.Seconds()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	for name, route := range r.routes {
		out.Routes[name] = RouteSnapshot{
			CounterSnapshot: snapshotCounters(&route.counters),
			Upstreams:       snapshotUpstreamMap(&route.upstreams),
		}
	}
	return out
}

func snapshotCounters(c *Counters) CounterSnapshot {
	requests := c.requests.Load()
	hits := c.cacheHits.Load()
	misses := c.cacheMisses.Load()
	success := c.success.Load()
	clientErrors := c.clientErrors.Load()
	serverErrors := c.serverErrors.Load()
	responseLatency := c.responseLatency.Snapshot()
	upstreamLatency := c.upstreamLatency.Snapshot()
	upstreamCalls := c.upstreamCalls.Load()
	upstreamFailures := c.upstreamFailures.Load()
	upstreamSuccess := c.upstreamSuccess.Load()

	snapshot := CounterSnapshot{
		Requests:              requests,
		CanceledRequests:      c.canceledRequests.Load(),
		Success:               success,
		ClientErrors:          clientErrors,
		ServerErrors:          serverErrors,
		ProxyErrors:           c.proxyErrors.Load(),
		UpstreamCalls:         upstreamCalls,
		Retries:               c.retries.Load(),
		BytesIn:               c.bytesIn.Load(),
		BytesOut:              c.bytesOut.Load(),
		CacheHits:             hits,
		CacheMisses:           misses,
		CacheStale:            c.cacheStale.Load(),
		CacheBypasses:         c.cacheBypasses.Load(),
		CacheStores:           c.cacheStores.Load(),
		AverageResponseTimeMS: responseLatency.Average,
		AverageUpstreamTimeMS: upstreamLatency.Average,
		Methods:               sortedCounterMap(c.methods.Snapshot()),
		StatusCodes:           sortedCounterMap(c.statusCodes.Snapshot()),
		ResponseLatencyMS:     responseLatency,
	}
	// Request volume includes client cancellations, while success/error rates
	// describe only completed, evaluable HTTP outcomes.
	evaluated := success + clientErrors + serverErrors
	if evaluated > 0 {
		snapshot.SuccessRate = float64(success) / float64(evaluated)
		snapshot.ErrorRate = float64(clientErrors+serverErrors) / float64(evaluated)
	}
	if hits+misses > 0 {
		snapshot.CacheHitRatio = float64(hits) / float64(hits+misses)
	}
	snapshot.Traffic = TrafficSnapshot{BytesIn: snapshot.BytesIn, BytesOut: snapshot.BytesOut}
	snapshot.Cache = CacheSnapshot{
		Hits: hits, Misses: misses, Stale: snapshot.CacheStale,
		Bypasses: snapshot.CacheBypasses, Stores: snapshot.CacheStores,
		HitRatio: snapshot.CacheHitRatio,
	}
	snapshot.Upstream = UpstreamAggregate{
		Calls:       upstreamCalls,
		Success:     upstreamSuccess,
		Failures:    upstreamFailures,
		Canceled:    c.upstreamCanceled.Load(),
		Timeouts:    c.upstreamTimeouts.Load(),
		Retries:     snapshot.Retries,
		StatusCodes: sortedCounterMap(c.upstreamStatusCodes.Snapshot()),
		LatencyMS:   upstreamLatency,
	}
	return snapshot
}

func snapshotUpstreamMap(container *sync.Map) map[string]UpstreamSnapshot {
	out := make(map[string]UpstreamSnapshot)
	container.Range(func(key, value any) bool {
		out[key.(string)] = snapshotUpstream(value.(*UpstreamCounters))
		return true
	})
	return out
}

func snapshotUpstream(c *UpstreamCounters) UpstreamSnapshot {
	calls := c.calls.Load()
	success := c.success.Load()
	failures := c.failures.Load()
	out := UpstreamSnapshot{
		Calls:       calls,
		Success:     success,
		Failures:    failures,
		Canceled:    c.canceled.Load(),
		Timeouts:    c.timeouts.Load(),
		Retries:     c.retries.Load(),
		StatusCodes: sortedCounterMap(c.statusCodes.Snapshot()),
		LatencyMS:   c.latency.Snapshot(),
	}
	// Client-canceled attempts are real physical calls, but they are not evidence
	// about Origin reliability. Derive rates only from evaluated Origin outcomes.
	evaluated := success + failures
	if evaluated > 0 {
		out.SuccessRate = float64(success) / float64(evaluated)
		out.ErrorRate = float64(failures) / float64(evaluated)
	}
	return out
}

func (h *histogram) Snapshot() LatencySnapshot {
	count := h.count.Load()
	out := LatencySnapshot{Count: count, Distribution: make([]LatencyBucket, 0, len(latencyBounds)+1)}
	if count == 0 {
		return out
	}
	out.Average = nsToMS(h.sumNS.Load() / count)
	out.Minimum = nsToMS(h.minNS.Load() - 1)
	out.Maximum = nsToMS(h.maxNS.Load())

	var cumulative uint64
	bucketCounts := make([]uint64, len(latencyBounds)+1)
	for i := range bucketCounts {
		bucketCounts[i] = h.buckets[i].Load()
		cumulative += bucketCounts[i]
		var upper *float64
		if i < len(latencyBounds) {
			value := durationToMS(latencyBounds[i])
			upper = &value
		}
		out.Distribution = append(out.Distribution, LatencyBucket{UpperBoundMS: upper, Count: bucketCounts[i], Cumulative: cumulative})
	}
	out.P50 = percentileUpperBound(bucketCounts, count, 0.50, out.Maximum)
	out.P95 = percentileUpperBound(bucketCounts, count, 0.95, out.Maximum)
	out.P99 = percentileUpperBound(bucketCounts, count, 0.99, out.Maximum)
	return out
}

func percentileUpperBound(buckets []uint64, count uint64, quantile float64, maximum float64) float64 {
	if count == 0 {
		return 0
	}
	target := uint64(float64(count)*quantile + 0.999999999)
	if target == 0 {
		target = 1
	}
	var cumulative uint64
	for i, bucketCount := range buckets {
		cumulative += bucketCount
		if cumulative >= target {
			if i < len(latencyBounds) {
				return durationToMS(latencyBounds[i])
			}
			return maximum
		}
	}
	return maximum
}

func durationToMS(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

func nsToMS(value uint64) float64 {
	return float64(value) / float64(time.Millisecond)
}

func metricMethod(method string) string {
	normalized := strings.ToUpper(strings.TrimSpace(method))
	switch normalized {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return normalized
	default:
		return "OTHER"
	}
}

func sortedCounterMap(values map[string]uint64) map[string]uint64 {
	if len(values) == 0 {
		return map[string]uint64{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]uint64, len(values))
	for _, key := range keys {
		out[key] = values[key]
	}
	return out
}
