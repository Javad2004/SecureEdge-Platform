package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/config"
)

type bucket struct {
	tokens float64
	last   time.Time
	seen   time.Time
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

func (l *Limiter) Allow(key string, cfg config.RateLimitConfig, now time.Time) (bool, time.Duration) {
	if !cfg.Enabled {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: float64(cfg.Burst), last: now, seen: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens += elapsed * cfg.RequestsPerSecond
	if max := float64(cfg.Burst); b.tokens > max {
		b.tokens = max
	}
	b.last, b.seen = now, now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	missing := 1 - b.tokens
	retry := time.Duration((missing / cfg.RequestsPerSecond) * float64(time.Second))
	if retry < time.Millisecond {
		retry = time.Millisecond
	}
	return false, retry
}

func (l *Limiter) Close()    { l.cancel(); <-l.done }
func (l *Limiter) Size() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.buckets) }
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
