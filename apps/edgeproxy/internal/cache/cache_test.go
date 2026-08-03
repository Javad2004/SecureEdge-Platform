package cache

import (
	"net/http"
	"strings"
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

func TestPurgeRequestRemovesAllExactVariants(t *testing.T) {
	c := New(10, 4096)
	now := time.Now()
	entry := Entry{StatusCode: http.StatusOK, Header: make(http.Header), Body: []byte("value"), StoredAt: now, ExpiresAt: now.Add(time.Hour), StaleUntil: now.Add(time.Hour)}
	for _, key := range []string{
		"proxy.test|/item?id=1|accept=text/plain",
		"proxy.test|/item?id=1|accept=application/json",
		"proxy.test|/item?id=2|accept=text/plain",
		"other.test|/item?id=1|accept=text/plain",
	} {
		if !c.Set(key, entry) {
			t.Fatalf("failed to store %q", key)
		}
	}
	parse := func(key string) (string, string, bool) {
		parts := strings.Split(key, "|")
		if len(parts) < 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}
	if removed := c.PurgeRequest("proxy.test", "/item?id=1", parse); removed != 2 {
		t.Fatalf("removed=%d, want 2", removed)
	}
	if stats := c.Stats(); stats.Entries != 2 {
		t.Fatalf("remaining entries=%d, want 2", stats.Entries)
	}
}

func TestCacheByteLimitIncludesKey(t *testing.T) {
	now := time.Now()
	entry := Entry{StatusCode: http.StatusOK, Header: make(http.Header), Body: []byte("x"), StoredAt: now, ExpiresAt: now.Add(time.Hour), StaleUntil: now.Add(time.Hour)}
	c := New(10, 8)
	if c.Set(strings.Repeat("k", 8), entry) {
		t.Fatal("entry whose key and value exceed maxBytes must be rejected")
	}
	if !c.Set("k", entry) {
		t.Fatal("small key and value should fit within maxBytes")
	}
	stats := c.Stats()
	if stats.Bytes != 2 {
		t.Fatalf("accounted bytes=%d, want 2 for one-byte key plus one-byte body", stats.Bytes)
	}
}
