package ratelimit

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

type bucket struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

type Decision struct {
	Allowed    bool          `json:"allowed"`
	RetryAfter time.Duration `json:"-"`
	Scope      string        `json:"scope,omitempty"`
	Reason     string        `json:"reason,omitempty"`
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	cancel  context.CancelFunc
	done    chan struct{}
}

func New(cleanupInterval, idleTTL time.Duration) *Limiter {
	if cleanupInterval <= 0 {
		cleanupInterval = time.Minute
	}
	if idleTTL <= 0 {
		idleTTL = 10 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Limiter{buckets: make(map[string]*bucket), cancel: cancel, done: make(chan struct{})}
	go l.cleanup(ctx, cleanupInterval, idleTTL)
	return l
}

// Allow enforces a route-wide bucket before the per-client bucket. This closes
// the common gap where a distributed botnet remains under every individual IP
// limit while still overwhelming the service in aggregate.
func (l *Limiter) Allow(route, client string, cfg config.RateLimitConfig, now time.Time) Decision {
	if !cfg.Enabled {
		return Decision{Allowed: true}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	globalKey := "global|" + route
	if ok, retry, reason := l.allowLocked(globalKey, cfg.GlobalRequestsPerSecond, cfg.GlobalBurst, cfg.MaxBuckets, now); !ok {
		return Decision{Allowed: false, RetryAfter: retry, Scope: "global", Reason: reason}
	}
	clientKey := "client|" + route + "|" + client
	if ok, retry, reason := l.allowLocked(clientKey, cfg.RequestsPerSecond, cfg.Burst, cfg.MaxBuckets, now); !ok {
		// Return the global token when the client-level decision rejects. Without
		// this rollback, abusive clients could drain the route-wide allowance.
		if b := l.buckets[globalKey]; b != nil && b.tokens < float64(cfg.GlobalBurst) {
			b.tokens++
		}
		return Decision{Allowed: false, RetryAfter: retry, Scope: "client", Reason: reason}
	}
	return Decision{Allowed: true}
}

func (l *Limiter) allowLocked(key string, rate float64, burst, maxBuckets int, now time.Time) (bool, time.Duration, string) {
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			return false, time.Second, "bucket_capacity"
		}
		b = &bucket{tokens: float64(burst), last: now, seen: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens += elapsed * rate
	if max := float64(burst); b.tokens > max {
		b.tokens = max
	}
	b.last, b.seen = now, now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0, ""
	}
	missing := 1 - b.tokens
	retry := time.Duration((missing / rate) * float64(time.Second))
	if retry < time.Millisecond {
		retry = time.Millisecond
	}
	return false, retry, "rate_exceeded"
}

func (l *Limiter) Close() { l.cancel(); <-l.done }

func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) cleanup(ctx context.Context, interval, idleTTL time.Duration) {
	defer close(l.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.mu.Lock()
			for key, b := range l.buckets {
				if now.Sub(b.seen) > idleTTL {
					delete(l.buckets, key)
				}
			}
			l.mu.Unlock()
		}
	}
}

type violation struct {
	times         []time.Time
	bannedUntil   time.Time
	banViolations int
	seen          time.Time
}

type Ban struct {
	Client      string `json:"client"`
	BannedUntil string `json:"banned_until"`
	Violations  int    `json:"violations"`
}

type BanManager struct {
	mu      sync.Mutex
	clients map[string]*violation
}

func NewBanManager() *BanManager { return &BanManager{clients: map[string]*violation{}} }

func (m *BanManager) IsBanned(client string, now time.Time) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.clients[client]
	if v == nil || !now.Before(v.bannedUntil) {
		return false, 0
	}
	v.seen = now
	return true, v.bannedUntil.Sub(now)
}

// RecordViolation tracks rate-limit, WAF-block, and overload violations in a
// bounded time window. Repeated abusive behavior results in a temporary ban.
func (m *BanManager) RecordViolation(client string, cfg config.AutoBanConfig, now time.Time) (bool, time.Duration) {
	if !cfg.Enabled || client == "" {
		return false, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.clients[client]
	if v == nil {
		if len(m.clients) >= cfg.MaxTrackedClients {
			m.evictOldestLocked()
		}
		v = &violation{}
		m.clients[client] = v
	}
	v.seen = now
	cutoff := now.Add(-cfg.Window.Duration)
	kept := v.times[:0]
	for _, t := range v.times {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	v.times = append(kept, now)
	if len(v.times) >= cfg.ViolationThreshold {
		v.bannedUntil = now.Add(cfg.BanDuration.Duration)
		v.banViolations = len(v.times)
		v.times = nil
		return true, cfg.BanDuration.Duration
	}
	return false, 0
}

func (m *BanManager) List(now time.Time) []Ban {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Ban{}
	for client, v := range m.clients {
		if now.Before(v.bannedUntil) {
			out = append(out, Ban{Client: client, BannedUntil: v.bannedUntil.UTC().Format(time.RFC3339Nano), Violations: v.banViolations})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Client < out[j].Client })
	return out
}

func (m *BanManager) Remove(client string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.clients[client]
	delete(m.clients, client)
	return ok
}

func (m *BanManager) Clear() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.clients)
	clear(m.clients)
	return n
}

func (m *BanManager) ActiveCount(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, v := range m.clients {
		if now.Before(v.bannedUntil) {
			n++
		}
	}
	return n
}

func (m *BanManager) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, v := range m.clients {
		if oldestKey == "" || v.seen.Before(oldest) {
			oldestKey, oldest = key, v.seen
		}
	}
	if oldestKey != "" {
		delete(m.clients, oldestKey)
	}
}
