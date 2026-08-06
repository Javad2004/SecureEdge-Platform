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
	bans := m.List(now.Add(3 * time.Second))
	if len(bans) != 1 || bans[0].Violations != cfg.ViolationThreshold {
		t.Fatalf("unexpected active ban details: %+v", bans)
	}
}

func TestAutoBanCapacityPreservesActiveBan(t *testing.T) {
	m := NewBanManager()
	cfg := config.AutoBanConfig{Enabled: true, ViolationThreshold: 2, Window: config.Duration{Duration: time.Minute}, BanDuration: config.Duration{Duration: 10 * time.Minute}, MaxTrackedClients: 2}
	now := time.Unix(0, 0)

	_, _ = m.RecordViolation("active", cfg, now)
	if banned, _ := m.RecordViolation("active", cfg, now.Add(time.Second)); !banned {
		t.Fatal("expected active client to be banned")
	}
	_, _ = m.RecordViolation("inactive", cfg, now.Add(2*time.Second))
	_, _ = m.RecordViolation("new", cfg, now.Add(3*time.Second))

	if banned, _ := m.IsBanned("active", now.Add(4*time.Second)); !banned {
		t.Fatal("capacity pressure evicted an active ban")
	}
	if banned, _ := m.RecordViolation("new", cfg, now.Add(4*time.Second)); !banned {
		t.Fatal("new client was not tracked after inactive entry eviction")
	}
	bans := m.List(now.Add(5 * time.Second))
	if len(bans) != 2 || bans[0].Client != "active" || bans[1].Client != "new" {
		t.Fatalf("unexpected bans after capacity eviction: %+v", bans)
	}
}

func TestAutoBanCapacityNeverEvictsWhenAllEntriesAreActive(t *testing.T) {
	m := NewBanManager()
	cfg := config.AutoBanConfig{Enabled: true, ViolationThreshold: 1, Window: config.Duration{Duration: time.Minute}, BanDuration: config.Duration{Duration: 10 * time.Minute}, MaxTrackedClients: 2}
	now := time.Unix(0, 0)

	for _, client := range []string{"a", "b"} {
		if banned, _ := m.RecordViolation(client, cfg, now); !banned {
			t.Fatalf("expected %s to be banned", client)
		}
	}
	if banned, _ := m.RecordViolation("c", cfg, now.Add(time.Second)); banned {
		t.Fatal("new client should not replace an active ban when tracking is full")
	}
	for _, client := range []string{"a", "b"} {
		if banned, _ := m.IsBanned(client, now.Add(2*time.Second)); !banned {
			t.Fatalf("active ban for %s was evicted", client)
		}
	}
	if banned, _ := m.IsBanned("c", now.Add(2*time.Second)); banned {
		t.Fatal("untracked client unexpectedly appears banned")
	}
}

func TestRetryAfterSaturatesWithoutOverflow(t *testing.T) {
	l := New(time.Hour, time.Hour)
	defer l.Close()
	now := time.Unix(0, 0)
	l.mu.Lock()
	l.buckets["tiny"] = &bucket{tokens: 0, last: now, seen: now}
	allowed, retry, reason := l.allowLocked("tiny", 1e-300, 1, 10, now)
	l.mu.Unlock()
	if allowed || reason != "rate_exceeded" {
		t.Fatalf("unexpected decision: allowed=%v reason=%q", allowed, reason)
	}
	if retry != time.Duration(1<<63-1) {
		t.Fatalf("retry=%v, want saturated duration", retry)
	}
}

func TestAutoBanCleansInactiveViolationTracking(t *testing.T) {
	m := NewBanManager()
	cfg := config.AutoBanConfig{
		Enabled:            true,
		ViolationThreshold: 3,
		Window:             config.Duration{Duration: 2 * time.Second},
		BanDuration:        config.Duration{Duration: time.Minute},
		MaxTrackedClients:  100,
	}
	now := time.Unix(100, 0)
	_, _ = m.RecordViolation("stale", cfg, now)
	_, _ = m.RecordViolation("current", cfg, now.Add(3*time.Second))

	m.mu.Lock()
	_, staleExists := m.clients["stale"]
	_, currentExists := m.clients["current"]
	m.mu.Unlock()
	if staleExists {
		t.Fatal("inactive violation entry was not cleaned after its window expired")
	}
	if !currentExists {
		t.Fatal("current violation entry was removed unexpectedly")
	}
}

func TestExpiredBanIsRemovedWhenObserved(t *testing.T) {
	m := NewBanManager()
	cfg := config.AutoBanConfig{
		Enabled:            true,
		ViolationThreshold: 1,
		Window:             config.Duration{Duration: time.Minute},
		BanDuration:        config.Duration{Duration: time.Second},
		MaxTrackedClients:  10,
	}
	now := time.Unix(200, 0)
	if banned, _ := m.RecordViolation("expired", cfg, now); !banned {
		t.Fatal("expected immediate ban")
	}
	if banned, _ := m.IsBanned("expired", now.Add(2*time.Second)); banned {
		t.Fatal("expired ban still active")
	}
	m.mu.Lock()
	_, exists := m.clients["expired"]
	m.mu.Unlock()
	if exists {
		t.Fatal("expired ban entry was retained")
	}
}

func TestAutoBanCleanupUsesEachEntryWindow(t *testing.T) {
	m := NewBanManager()
	longWindow := config.AutoBanConfig{
		Enabled:            true,
		ViolationThreshold: 3,
		Window:             config.Duration{Duration: 10 * time.Second},
		BanDuration:        config.Duration{Duration: time.Minute},
		MaxTrackedClients:  100,
	}
	shortWindow := longWindow
	shortWindow.Window = config.Duration{Duration: time.Second}
	now := time.Unix(300, 0)
	_, _ = m.RecordViolation("long-window", longWindow, now)
	_, _ = m.RecordViolation("short-window", shortWindow, now.Add(2*time.Second))

	m.mu.Lock()
	entry := m.clients["long-window"]
	m.mu.Unlock()
	if entry == nil || len(entry.times) != 1 {
		t.Fatal("cleanup for a short-window policy removed another client's longer-window history")
	}
}
