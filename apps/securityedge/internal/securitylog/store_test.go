package securitylog

import "testing"

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
