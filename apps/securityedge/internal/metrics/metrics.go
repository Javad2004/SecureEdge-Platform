package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var latencyBounds = []time.Duration{
	100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond,
	1 * time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond,
	25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond,
	500 * time.Millisecond, time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second,
}

type counters struct {
	requests          atomic.Uint64
	allowed           atomic.Uint64
	blocked           atomic.Uint64
	logged            atomic.Uint64
	rateLimited       atomic.Uint64
	globalRateLimited atomic.Uint64
	clientRateLimited atomic.Uint64
	overloadRejected  atomic.Uint64
	bodyTooLarge      atomic.Uint64
	bannedRejected    atomic.Uint64
	autoBans          atomic.Uint64
	inspectedBodies   atomic.Uint64
	truncatedBodies   atomic.Uint64
	detections        atomic.Uint64
	errors            atomic.Uint64
	scoreTotal        atomic.Uint64
	durationNS        atomic.Uint64
	maxDurationNS     atomic.Uint64
	latencyBuckets    [17]atomic.Uint64
	rules             sync.Map
	categories        sync.Map
	methods           sync.Map
	actions           sync.Map
	reasons           sync.Map
}

type Registry struct {
	startedAt time.Time
	inflight  atomic.Int64
	total     counters
	routes    sync.Map
}

type Observation struct {
	Route, Method, Action, Reason string
	Duration                      time.Duration
	Score                         int
	RuleIDs, Categories           []string
	BodyInspected, BodyTruncated  bool
	Error                         bool
	AutoBan                       bool
}

type Snapshot struct {
	SchemaVersion     string                     `json:"schema_version"`
	GeneratedAt       string                     `json:"generated_at"`
	StartedAt         string                     `json:"started_at"`
	UptimeSeconds     int64                      `json:"uptime_seconds"`
	Inflight          int64                      `json:"inflight"`
	RequestsPerSecond float64                    `json:"requests_per_second"`
	Total             CounterSnapshot            `json:"total"`
	Routes            map[string]CounterSnapshot `json:"routes"`
}

type LatencySnapshot struct {
	AverageMS float64 `json:"average_ms"`
	MaximumMS float64 `json:"maximum_ms"`
	P50MS     float64 `json:"p50_ms"`
	P95MS     float64 `json:"p95_ms"`
	P99MS     float64 `json:"p99_ms"`
}

type CounterSnapshot struct {
	Requests          uint64            `json:"requests"`
	Allowed           uint64            `json:"allowed"`
	Blocked           uint64            `json:"blocked"`
	Logged            uint64            `json:"logged"`
	RateLimited       uint64            `json:"rate_limited"`
	GlobalRateLimited uint64            `json:"global_rate_limited"`
	ClientRateLimited uint64            `json:"client_rate_limited"`
	OverloadRejected  uint64            `json:"overload_rejected"`
	BodyTooLarge      uint64            `json:"body_too_large"`
	BannedRejected    uint64            `json:"banned_rejected"`
	AutoBans          uint64            `json:"auto_bans"`
	Detections        uint64            `json:"detections"`
	Errors            uint64            `json:"errors"`
	InspectedBodies   uint64            `json:"inspected_bodies"`
	TruncatedBodies   uint64            `json:"truncated_bodies"`
	BlockRate         float64           `json:"block_rate"`
	DetectionRate     float64           `json:"detection_rate"`
	AverageScore      float64           `json:"average_score"`
	Latency           LatencySnapshot   `json:"latency"`
	Rules             map[string]uint64 `json:"rules"`
	Categories        map[string]uint64 `json:"categories"`
	Methods           map[string]uint64 `json:"methods"`
	Actions           map[string]uint64 `json:"actions"`
	Reasons           map[string]uint64 `json:"reasons"`
}

func New() *Registry { return &Registry{startedAt: time.Now()} }

func (r *Registry) Begin() func(Observation) {
	r.inflight.Add(1)
	return func(o Observation) {
		defer r.inflight.Add(-1)
		r.record(&r.total, o)
		value, _ := r.routes.LoadOrStore(o.Route, &counters{})
		r.record(value.(*counters), o)
	}
}

func (r *Registry) record(c *counters, o Observation) {
	c.requests.Add(1)
	add(&c.methods, metricMethod(o.Method), 1)
	add(&c.actions, o.Action, 1)
	add(&c.reasons, o.Reason, 1)
	switch o.Action {
	case "ALLOW":
		c.allowed.Add(1)
	case "BLOCK":
		c.blocked.Add(1)
	case "LOG":
		c.logged.Add(1)
	case "RATE_LIMIT":
		c.rateLimited.Add(1)
		if o.Reason == "global_rate_limit" {
			c.globalRateLimited.Add(1)
		} else {
			c.clientRateLimited.Add(1)
		}
	case "OVERLOAD":
		c.overloadRejected.Add(1)
	case "BANNED":
		c.bannedRejected.Add(1)
	}
	if o.Reason == "body_too_large" {
		c.bodyTooLarge.Add(1)
	}
	if o.AutoBan {
		c.autoBans.Add(1)
	}
	if len(o.RuleIDs) > 0 {
		c.detections.Add(1)
	}
	if o.BodyInspected {
		c.inspectedBodies.Add(1)
	}
	if o.BodyTruncated {
		c.truncatedBodies.Add(1)
	}
	if o.Error {
		c.errors.Add(1)
	}
	if o.Score > 0 {
		c.scoreTotal.Add(uint64(o.Score))
	}
	ns := uint64(maxDuration(o.Duration))
	c.durationNS.Add(ns)
	updateMax(&c.maxDurationNS, ns)
	c.latencyBuckets[latencyBucket(o.Duration)].Add(1)
	for _, id := range o.RuleIDs {
		add(&c.rules, id, 1)
	}
	for _, cat := range o.Categories {
		add(&c.categories, cat, 1)
	}
}

func (r *Registry) Snapshot() Snapshot {
	up := time.Since(r.startedAt)
	out := Snapshot{
		SchemaVersion: "2.0", GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		StartedAt: r.startedAt.UTC().Format(time.RFC3339Nano), UptimeSeconds: int64(up.Seconds()),
		Inflight: r.inflight.Load(), Total: snap(&r.total), Routes: map[string]CounterSnapshot{},
	}
	if up > 0 {
		out.RequestsPerSecond = float64(out.Total.Requests) / up.Seconds()
	}
	r.routes.Range(func(k, v any) bool {
		out.Routes[k.(string)] = snap(v.(*counters))
		return true
	})
	return out
}

func snap(c *counters) CounterSnapshot {
	requests := c.requests.Load()
	detections := c.detections.Load()
	out := CounterSnapshot{
		Requests: requests, Allowed: c.allowed.Load(), Blocked: c.blocked.Load(), Logged: c.logged.Load(),
		RateLimited: c.rateLimited.Load(), GlobalRateLimited: c.globalRateLimited.Load(), ClientRateLimited: c.clientRateLimited.Load(),
		OverloadRejected: c.overloadRejected.Load(), BodyTooLarge: c.bodyTooLarge.Load(), BannedRejected: c.bannedRejected.Load(), AutoBans: c.autoBans.Load(),
		Detections: detections, Errors: c.errors.Load(), InspectedBodies: c.inspectedBodies.Load(), TruncatedBodies: c.truncatedBodies.Load(),
		Rules: snapshotMap(&c.rules), Categories: snapshotMap(&c.categories), Methods: snapshotMap(&c.methods), Actions: snapshotMap(&c.actions), Reasons: snapshotMap(&c.reasons),
	}
	if requests > 0 {
		out.BlockRate = float64(out.Blocked+out.RateLimited+out.OverloadRejected+out.BannedRejected) / float64(requests)
		out.DetectionRate = float64(detections) / float64(requests)
		out.AverageScore = float64(c.scoreTotal.Load()) / float64(requests)
		out.Latency.AverageMS = float64(c.durationNS.Load()) / float64(requests) / float64(time.Millisecond)
	}
	out.Latency.MaximumMS = float64(c.maxDurationNS.Load()) / float64(time.Millisecond)
	out.Latency.P50MS = percentile(c, requests, 0.50)
	out.Latency.P95MS = percentile(c, requests, 0.95)
	out.Latency.P99MS = percentile(c, requests, 0.99)
	return out
}

func (r *Registry) Prometheus() string {
	s := r.Snapshot()
	var b strings.Builder
	b.WriteString("# HELP securityedge_uptime_seconds Process uptime.\n# TYPE securityedge_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "securityedge_uptime_seconds %d\n", s.UptimeSeconds)
	b.WriteString("# HELP securityedge_inflight_requests Current requests being processed.\n# TYPE securityedge_inflight_requests gauge\n")
	fmt.Fprintf(&b, "securityedge_inflight_requests %d\n", s.Inflight)
	writePromCounters(&b, "", s.Total)
	routes := make([]string, 0, len(s.Routes))
	for route := range s.Routes {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	for _, route := range routes {
		writePromCounters(&b, `route="`+escapeLabel(route)+`"`, s.Routes[route])
	}
	return b.String()
}

func writePromCounters(b *strings.Builder, labels string, c CounterSnapshot) {
	if labels != "" {
		labels = "{" + labels + "}"
	}
	values := map[string]uint64{
		"requests_total": c.Requests, "allowed_total": c.Allowed, "blocked_total": c.Blocked,
		"rate_limited_total": c.RateLimited, "overload_rejected_total": c.OverloadRejected,
		"banned_rejected_total": c.BannedRejected, "detections_total": c.Detections, "errors_total": c.Errors,
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(b, "securityedge_%s%s %d\n", key, labels, values[key])
	}
}

func latencyBucket(d time.Duration) int {
	for i, bound := range latencyBounds {
		if d <= bound {
			return i
		}
	}
	return len(latencyBounds)
}

func percentile(c *counters, total uint64, q float64) float64 {
	if total == 0 {
		return 0
	}
	target := uint64(float64(total)*q + 0.999999)
	var cumulative uint64
	for i := 0; i < len(c.latencyBuckets); i++ {
		cumulative += c.latencyBuckets[i].Load()
		if cumulative >= target {
			if i < len(latencyBounds) {
				return float64(latencyBounds[i]) / float64(time.Millisecond)
			}
			return float64(c.maxDurationNS.Load()) / float64(time.Millisecond)
		}
	}
	return float64(c.maxDurationNS.Load()) / float64(time.Millisecond)
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

func add(m *sync.Map, key string, n uint64) {
	if key == "" || n == 0 {
		return
	}
	v, _ := m.LoadOrStore(key, &atomic.Uint64{})
	v.(*atomic.Uint64).Add(n)
}

func snapshotMap(m *sync.Map) map[string]uint64 {
	keys := []string{}
	vals := map[string]uint64{}
	m.Range(func(k, v any) bool {
		key := k.(string)
		keys = append(keys, key)
		vals[key] = v.(*atomic.Uint64).Load()
		return true
	})
	sort.Strings(keys)
	out := map[string]uint64{}
	for _, k := range keys {
		out[k] = vals[k]
	}
	return out
}

func updateMax(v *atomic.Uint64, n uint64) {
	for {
		old := v.Load()
		if old >= n || v.CompareAndSwap(old, n) {
			return
		}
	}
}

func maxDuration(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}
func escapeLabel(v string) string {
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n").Replace(v)
}
