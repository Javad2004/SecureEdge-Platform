package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type counters struct {
	requests        atomic.Uint64
	allowed         atomic.Uint64
	blocked         atomic.Uint64
	logged          atomic.Uint64
	rateLimited     atomic.Uint64
	inspectedBodies atomic.Uint64
	truncatedBodies atomic.Uint64
	detections      atomic.Uint64
	errors          atomic.Uint64
	scoreTotal      atomic.Uint64
	durationNS      atomic.Uint64
	maxDurationNS   atomic.Uint64
	rules           sync.Map
	categories      sync.Map
	methods         sync.Map
	actions         sync.Map
}
type Registry struct {
	startedAt time.Time
	inflight  atomic.Int64
	total     counters
	routes    sync.Map
}
type Observation struct {
	Route, Method, Action        string
	Duration                     time.Duration
	Score                        int
	RuleIDs, Categories          []string
	BodyInspected, BodyTruncated bool
	Error                        bool
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
type CounterSnapshot struct {
	Requests                uint64            `json:"requests"`
	Allowed                 uint64            `json:"allowed"`
	Blocked                 uint64            `json:"blocked"`
	Logged                  uint64            `json:"logged"`
	RateLimited             uint64            `json:"rate_limited"`
	Detections              uint64            `json:"detections"`
	Errors                  uint64            `json:"errors"`
	InspectedBodies         uint64            `json:"inspected_bodies"`
	TruncatedBodies         uint64            `json:"truncated_bodies"`
	BlockRate               float64           `json:"block_rate"`
	DetectionRate           float64           `json:"detection_rate"`
	AverageScore            float64           `json:"average_score"`
	AverageInspectionTimeMS float64           `json:"average_inspection_time_ms"`
	MaximumInspectionTimeMS float64           `json:"maximum_inspection_time_ms"`
	Rules                   map[string]uint64 `json:"rules"`
	Categories              map[string]uint64 `json:"categories"`
	Methods                 map[string]uint64 `json:"methods"`
	Actions                 map[string]uint64 `json:"actions"`
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
	add(&c.methods, o.Method, 1)
	add(&c.actions, o.Action, 1)
	switch o.Action {
	case "ALLOW":
		c.allowed.Add(1)
	case "BLOCK":
		c.blocked.Add(1)
	case "LOG":
		c.logged.Add(1)
	case "RATE_LIMIT":
		c.rateLimited.Add(1)
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
	for _, id := range o.RuleIDs {
		add(&c.rules, id, 1)
	}
	for _, cat := range o.Categories {
		add(&c.categories, cat, 1)
	}
}
func (r *Registry) Snapshot() Snapshot {
	up := time.Since(r.startedAt)
	out := Snapshot{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), StartedAt: r.startedAt.UTC().Format(time.RFC3339Nano), UptimeSeconds: int64(up.Seconds()), Inflight: r.inflight.Load(), Total: snap(&r.total), Routes: map[string]CounterSnapshot{}}
	if up > 0 {
		out.RequestsPerSecond = float64(out.Total.Requests) / up.Seconds()
	}
	r.routes.Range(func(k, v any) bool { out.Routes[k.(string)] = snap(v.(*counters)); return true })
	return out
}
func snap(c *counters) CounterSnapshot {
	requests := c.requests.Load()
	detections := c.detections.Load()
	out := CounterSnapshot{Requests: requests, Allowed: c.allowed.Load(), Blocked: c.blocked.Load(), Logged: c.logged.Load(), RateLimited: c.rateLimited.Load(), Detections: detections, Errors: c.errors.Load(), InspectedBodies: c.inspectedBodies.Load(), TruncatedBodies: c.truncatedBodies.Load(), Rules: snapshotMap(&c.rules), Categories: snapshotMap(&c.categories), Methods: snapshotMap(&c.methods), Actions: snapshotMap(&c.actions)}
	if requests > 0 {
		out.BlockRate = float64(out.Blocked+out.RateLimited) / float64(requests)
		out.DetectionRate = float64(detections) / float64(requests)
		out.AverageScore = float64(c.scoreTotal.Load()) / float64(requests)
		out.AverageInspectionTimeMS = float64(c.durationNS.Load()) / float64(requests) / float64(time.Millisecond)
	}
	out.MaximumInspectionTimeMS = float64(c.maxDurationNS.Load()) / float64(time.Millisecond)
	return out
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
		if old >= n {
			return
		}
		if v.CompareAndSwap(old, n) {
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
