package securitylog

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/waf"
)

func TestRingAndFilter(t *testing.T) {
	s := New(2)
	s.Append(Entry{Event: "waf_detected", RuleIDs: []string{"XSS-001"}})
	s.Append(Entry{Event: "rate_limited"})
	s.Append(Entry{Event: "waf_blocked", RuleIDs: []string{"SQLI-001"}})
	q := s.Query(Filter{RuleID: "sqli-001", Limit: 10})
	if q.Returned != 1 || q.Dropped != 1 {
		t.Fatalf("%#v", q)
	}
}

func TestExportBatchPaginatesWithinBound(t *testing.T) {
	s := New(1000)
	for i := 0; i < 700; i++ {
		s.Append(Entry{Event: "event"})
	}
	filter := Filter{Limit: 700}
	searchLower := ""
	first := s.exportBatch(filter, searchLower, 700, 0, exportBatchSize)
	if len(first) != exportBatchSize || first[0].Sequence != 700 || first[len(first)-1].Sequence != 445 {
		t.Fatalf("unexpected first batch: len=%d first=%d last=%d", len(first), first[0].Sequence, first[len(first)-1].Sequence)
	}
	second := s.exportBatch(filter, searchLower, 700, first[len(first)-1].Sequence, exportBatchSize)
	if len(second) != exportBatchSize || second[0].Sequence != 444 || second[len(second)-1].Sequence != 189 {
		t.Fatalf("unexpected second batch: len=%d first=%d last=%d", len(second), second[0].Sequence, second[len(second)-1].Sequence)
	}
	third := s.exportBatch(filter, searchLower, 700, second[len(second)-1].Sequence, exportBatchSize)
	if len(third) != 188 || third[0].Sequence != 188 || third[len(third)-1].Sequence != 1 {
		t.Fatalf("unexpected third batch: len=%d first=%d last=%d", len(third), third[0].Sequence, third[len(third)-1].Sequence)
	}
}

func TestStorePreservesValidUTF8WhenBoundingTextFields(t *testing.T) {
	s := New(2)
	entry := s.Append(Entry{
		Host:    strings.Repeat("€", 171), // 513 bytes; the 512-byte bound falls inside the final rune.
		Error:   "ok" + string([]byte{0xff}) + "error",
		Method:  strings.Repeat("ȿ", 16), // 32 bytes before ToUpper, 48 bytes after ToUpper.
		Action:  strings.Repeat("ȿ", 16),
		Reason:  strings.Repeat("Ⱥ", 64), // 128 bytes before ToLower, 192 bytes after ToLower.
		RuleIDs: []string{strings.Repeat("ȿ", 64)},
		Tags:    []string{strings.Repeat("Ⱥ", 32)},
		Matches: []waf.Match{{
			RuleID:   strings.Repeat("ȿ", 64),
			Category: strings.Repeat("Ⱥ", 64),
		}},
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
	if !utf8.ValidString(entry.Error) || strings.ContainsRune(entry.Error, utf8.RuneError) == false {
		t.Fatalf("invalid UTF-8 error text was not normalized safely: %q", entry.Error)
	}
	checks := []struct {
		name  string
		value string
		want  string
		limit int
	}{
		{name: "method", value: entry.Method, want: strings.Repeat("Ȿ", 10), limit: 32},
		{name: "action", value: entry.Action, want: strings.Repeat("Ȿ", 10), limit: 32},
		{name: "reason", value: entry.Reason, want: strings.Repeat("ⱥ", 42), limit: 128},
		{name: "rule id", value: entry.RuleIDs[0], want: strings.Repeat("Ȿ", 42), limit: 128},
		{name: "tag", value: entry.Tags[0], want: strings.Repeat("ⱥ", 21), limit: 64},
		{name: "match rule id", value: entry.Matches[0].RuleID, want: strings.Repeat("Ȿ", 42), limit: 128},
		{name: "match category", value: entry.Matches[0].Category, want: strings.Repeat("ⱥ", 42), limit: 128},
	}
	for _, check := range checks {
		if !utf8.ValidString(check.value) || len(check.value) > check.limit || check.value != check.want {
			t.Fatalf("case-normalized %s escaped its %d-byte bound or changed normalization: %q (%d bytes)", check.name, check.limit, check.value, len(check.value))
		}
	}
}
