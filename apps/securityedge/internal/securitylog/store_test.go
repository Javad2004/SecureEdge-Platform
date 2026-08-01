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
