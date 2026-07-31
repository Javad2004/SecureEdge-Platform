package ratelimit

import (
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	l := New(time.Hour, time.Hour)
	defer l.Close()
	cfg := config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 2}
	now := time.Unix(0, 0)
	if ok, _ := l.Allow("a", cfg, now); !ok {
		t.Fatal("first request denied")
	}
	if ok, _ := l.Allow("a", cfg, now); !ok {
		t.Fatal("second request denied")
	}
	if ok, _ := l.Allow("a", cfg, now); ok {
		t.Fatal("third request should be denied")
	}
	if ok, _ := l.Allow("a", cfg, now.Add(time.Second)); !ok {
		t.Fatal("token did not refill")
	}
}
