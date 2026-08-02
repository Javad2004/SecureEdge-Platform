package cache

import (
	"net/http"
	"testing"
	"time"
)

func TestCacheFreshStaleExpired(t *testing.T) {
	c := New(10, 1024)
	now := time.Now()
	entry := Entry{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("hello"), StoredAt: now, ExpiresAt: now.Add(time.Second), StaleUntil: now.Add(2 * time.Second)}
	if !c.Set("k", entry) {
		t.Fatal("expected set to succeed")
	}
	if _, fresh, stale := c.Get("k", now.Add(500*time.Millisecond)); !fresh || stale {
		t.Fatalf("expected fresh")
	}
	if _, fresh, stale := c.Get("k", now.Add(1500*time.Millisecond)); fresh || !stale {
		t.Fatalf("expected stale")
	}
	if _, fresh, stale := c.Get("k", now.Add(3*time.Second)); fresh || stale {
		t.Fatalf("expected expired")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	c := New(2, 1024)
	now := time.Now()
	makeEntry := func(body string) Entry {
		return Entry{StatusCode: 200, Header: make(http.Header), Body: []byte(body), StoredAt: now, ExpiresAt: now.Add(time.Hour), StaleUntil: now.Add(time.Hour)}
	}
	c.Set("a", makeEntry("a"))
	c.Set("b", makeEntry("b"))
	c.Get("a", now)
	c.Set("c", makeEntry("c"))
	if _, fresh, _ := c.Get("b", now); fresh {
		t.Fatal("expected b to be evicted")
	}
	if stats := c.Stats(); stats.Entries != 2 || stats.Evictions != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestPurgePathMatchesCanonicalRequestPath(t *testing.T) {
	if !purgePathMatches("/api/../admin/settings?view=full", "/admin") {
		t.Fatal("canonical /admin prefix should match a route-equivalent request URI")
	}
}
