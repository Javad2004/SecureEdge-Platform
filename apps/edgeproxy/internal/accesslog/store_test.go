package accesslog

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestStoreIsBoundedAndNewestFirst(t *testing.T) {
	store := New(2)
	store.Append(Entry{Event: "request_completed", RequestID: "one"})
	store.Append(Entry{Event: "request_completed", RequestID: "two"})
	store.Append(Entry{Event: "request_completed", RequestID: "three"})

	result := store.Query(Filter{Limit: 10})
	if result.Retained != 2 || result.Dropped != 1 {
		t.Fatalf("unexpected stats: retained=%d dropped=%d", result.Retained, result.Dropped)
	}
	if len(result.Entries) != 2 || result.Entries[0].RequestID != "three" || result.Entries[1].RequestID != "two" {
		t.Fatalf("unexpected order: %#v", result.Entries)
	}
}

func TestQueryFiltersAndCursor(t *testing.T) {
	store := New(10)
	for i := 0; i < 4; i++ {
		store.Append(Entry{Event: "upstream_attempt", Route: "demo", Upstream: "http://a", Status: 200, DurationMS: float64(i + 1)})
	}
	store.Append(Entry{Event: "request_completed", Route: "other", Status: 502})

	first := store.Query(Filter{Route: "demo", Event: "upstream_attempt", Limit: 2})
	if len(first.Entries) != 2 || !first.HasMore || first.NextBeforeSequence == 0 {
		t.Fatalf("unexpected first page: %#v", first)
	}
	second := store.Query(Filter{Route: "demo", Event: "upstream_attempt", Limit: 2, BeforeSequence: first.NextBeforeSequence})
	if len(second.Entries) != 2 || second.HasMore {
		t.Fatalf("unexpected second page: %#v", second)
	}
}

func TestTimeAndStatusClassFilters(t *testing.T) {
	store := New(10)
	now := time.Now().UTC()
	store.Append(Entry{Timestamp: now.Add(-time.Minute).Format(time.RFC3339Nano), Event: "request_completed", Status: 200})
	store.Append(Entry{Timestamp: now.Format(time.RFC3339Nano), Event: "request_completed", Status: 503})
	result := store.Query(Filter{StatusClass: "5xx", Since: now.Add(-time.Second), Limit: 10})
	if len(result.Entries) != 1 || result.Entries[0].Status != 503 {
		t.Fatalf("unexpected result: %#v", result.Entries)
	}
}

func TestQueryFiltersExactClientIP(t *testing.T) {
	store := New(10)
	store.Append(Entry{Event: "request_completed", ClientIP: "203.0.113.10", Status: 200})
	store.Append(Entry{Event: "request_completed", ClientIP: "203.0.113.11", Status: 200})

	result := store.Query(Filter{ClientIP: "203.0.113.10", Event: "request_completed", Limit: 10})
	if len(result.Entries) != 1 || result.Entries[0].ClientIP != "203.0.113.10" {
		t.Fatalf("unexpected client IP filter result: %#v", result.Entries)
	}
	if result.AppliedFilters["client_ip"] != "203.0.113.10" {
		t.Fatalf("client IP filter missing from applied filters: %#v", result.AppliedFilters)
	}
}

func TestStorePreservesValidUTF8WhenBoundingTextFields(t *testing.T) {
	store := New(2)
	entry := store.Append(Entry{
		Host:        strings.Repeat("€", 171), // 513 bytes; the 512-byte bound falls inside the final rune.
		UserAgent:   "ok" + string([]byte{0xff}) + "agent",
		Method:      strings.Repeat("ȿ", 16), // 32 bytes before ToUpper, 48 bytes after ToUpper.
		CacheStatus: strings.Repeat("ȿ", 16),
	})
	if !utf8.ValidString(entry.Host) {
		t.Fatalf("bounded host is not valid UTF-8: %q", entry.Host)
	}
	if len(entry.Host) > 512 {
		t.Fatalf("bounded host length=%d, want <=512 bytes", len(entry.Host))
	}
	if entry.Host != strings.Repeat("€", 170) {
		t.Fatalf("bounded host split a rune or changed valid prefix: %q", entry.Host)
	}
	if !utf8.ValidString(entry.UserAgent) || strings.ContainsRune(entry.UserAgent, utf8.RuneError) == false {
		t.Fatalf("invalid UTF-8 user agent was not normalized safely: %q", entry.UserAgent)
	}
	if !utf8.ValidString(entry.Method) || len(entry.Method) > 32 || entry.Method != strings.Repeat("Ȿ", 10) {
		t.Fatalf("case-normalized method escaped its 32-byte bound: %q (%d bytes)", entry.Method, len(entry.Method))
	}
	if !utf8.ValidString(entry.CacheStatus) || len(entry.CacheStatus) > 32 || entry.CacheStatus != strings.Repeat("Ȿ", 10) {
		t.Fatalf("case-normalized cache status escaped its 32-byte bound: %q (%d bytes)", entry.CacheStatus, len(entry.CacheStatus))
	}
}

func TestStoreBoundsAndCanonicalizesEntryMetadata(t *testing.T) {
	store := New(2)
	tags := make([]string, 40)
	for i := range tags {
		tags[i] = string(rune('!'+i)) + strings.Repeat("x", 80)
	}

	before := time.Now().UTC().Add(-time.Second)
	entry := store.Append(Entry{
		Timestamp:   "not-an-rfc3339-timestamp" + strings.Repeat("x", 256),
		Level:       strings.Repeat("ȿ", 16), // Upper-casing expands each rune from 2 to 3 bytes.
		Status:      200,
		StatusClass: strings.Repeat("bogus", 100),
		Tags:        tags,
	})
	after := time.Now().UTC().Add(time.Second)

	parsedTimestamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err != nil || parsedTimestamp.Before(before) || parsedTimestamp.After(after) || len(entry.Timestamp) > 64 {
		t.Fatalf("timestamp was not normalized to a bounded RFC3339 value: %q (%v)", entry.Timestamp, err)
	}
	if !utf8.ValidString(entry.Level) || len(entry.Level) > 16 || entry.Level != strings.Repeat("Ȿ", 5) {
		t.Fatalf("level escaped its normalized 16-byte bound: %q (%d bytes)", entry.Level, len(entry.Level))
	}
	if entry.StatusClass != "2xx" {
		t.Fatalf("status class was not derived from status: %q", entry.StatusClass)
	}
	if len(entry.Tags) != maxEntryTags {
		t.Fatalf("tag count=%d, want %d", len(entry.Tags), maxEntryTags)
	}
	for _, tag := range entry.Tags {
		if !utf8.ValidString(tag) || len(tag) > 64 {
			t.Fatalf("bounded tag is invalid: %q (%d bytes)", tag, len(tag))
		}
	}

	result := store.Query(Filter{Since: before, Until: after, Limit: 10})
	if len(result.Entries) != 1 || result.Entries[0].Sequence != entry.Sequence {
		t.Fatalf("normalized timestamp did not remain queryable: %#v", result.Entries)
	}
}
