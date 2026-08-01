package ratelimit

import (
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func testConfig() config.RateLimitConfig {
	return config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 2, GlobalRequestsPerSecond: 100, GlobalBurst: 100, CleanupInterval: config.Duration{Duration: time.Hour}, IdleTTL: config.Duration{Duration: time.Hour}, MaxBuckets: 100}
}

func TestHierarchicalTokenBucket(t *testing.T) {
	l := New(time.Hour, time.Hour)
	defer l.Close()
	cfg := testConfig()
	now := time.Unix(0, 0)
	if d := l.Allow("route", "client", cfg, now); !d.Allowed {
		t.Fatal("first request denied")
	}
	if d := l.Allow("route", "client", cfg, now); !d.Allowed {
		t.Fatal("second request denied")
	}
	if d := l.Allow("route", "client", cfg, now); d.Allowed || d.Scope != "client" {
		t.Fatalf("third request=%+v", d)
	}
	if d := l.Allow("route", "client", cfg, now.Add(time.Second)); !d.Allowed {
		t.Fatal("token did not refill")
	}
}

func TestGlobalLimitProtectsRoute(t *testing.T) {
	l := New(time.Hour, time.Hour)
	defer l.Close()
	cfg := testConfig()
	cfg.GlobalRequestsPerSecond = 1
	cfg.GlobalBurst = 2
	cfg.RequestsPerSecond = 100
	cfg.Burst = 100
	now := time.Unix(0, 0)
	if !l.Allow("route", "a", cfg, now).Allowed || !l.Allow("route", "b", cfg, now).Allowed {
		t.Fatal("initial global burst denied")
	}
	if d := l.Allow("route", "c", cfg, now); d.Allowed || d.Scope != "global" {
		t.Fatalf("expected global rejection: %+v", d)
	}
}

func TestBucketCapacityIsBounded(t *testing.T) {
	l := New(time.Hour, time.Hour)
	defer l.Close()
	cfg := testConfig()
	cfg.MaxBuckets = 2
	now := time.Unix(0, 0)
	_ = l.Allow("route", "a", cfg, now)
	if d := l.Allow("route", "b", cfg, now); d.Allowed || d.Reason != "bucket_capacity" {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestAutoBan(t *testing.T) {
	m := NewBanManager()
	cfg := config.AutoBanConfig{Enabled: true, ViolationThreshold: 3, Window: config.Duration{Duration: time.Minute}, BanDuration: config.Duration{Duration: 10 * time.Minute}, MaxTrackedClients: 100}
	now := time.Unix(0, 0)
	for i := 0; i < 2; i++ {
		if banned, _ := m.RecordViolation("1.2.3.4", cfg, now.Add(time.Duration(i)*time.Second)); banned {
			t.Fatal("banned too early")
		}
	}
	if banned, _ := m.RecordViolation("1.2.3.4", cfg, now.Add(2*time.Second)); !banned {
		t.Fatal("expected ban")
	}
	if banned, _ := m.IsBanned("1.2.3.4", now.Add(3*time.Second)); !banned {
		t.Fatal("ban not active")
	}
}
