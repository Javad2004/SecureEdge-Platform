package metrics

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSnapshotAndPrometheus(t *testing.T) {
	r := New()
	done := r.Begin()
	done(Observation{Route: "demo", Method: "GET", Action: "RATE_LIMIT", Reason: "global_rate_limit", Duration: 12 * time.Millisecond})
	s := r.Snapshot()
	if s.Total.GlobalRateLimited != 1 || s.Total.Latency.P50MS <= 0 {
		t.Fatalf("unexpected snapshot: %#v", s.Total)
	}
	if text := r.Prometheus(); !strings.Contains(text, "securityedge_rate_limited_total") || !strings.Contains(text, `route="demo"`) {
		t.Fatalf("unexpected prometheus: %s", text)
	}
}

func TestDerivedMetricsRemainInternallyConsistent(t *testing.T) {
	r := New()
	observations := []Observation{
		{Route: "demo", Method: "GET", Action: "ALLOW", Duration: 1 * time.Millisecond},
		{Route: "demo", Method: "GET", Action: "LOG", Duration: 2 * time.Millisecond},
		{Route: "demo", Method: "GET", Action: "BLOCK", Duration: 3 * time.Millisecond, RuleIDs: []string{"rule-a"}, Categories: []string{"injection"}},
		{Route: "demo", Method: "GET", Action: "RATE_LIMIT", Reason: "client_rate_limit", Duration: 4 * time.Millisecond},
		{Route: "demo", Method: "GET", Action: "OVERLOAD", Duration: 5 * time.Millisecond},
		{Route: "demo", Method: "GET", Action: "BANNED", Duration: 6 * time.Millisecond, Error: true},
	}
	for _, observation := range observations {
		done := r.Begin()
		done(observation)
	}

	s := r.Snapshot().Total
	outcomes := s.Allowed + s.Logged + s.Blocked + s.RateLimited + s.OverloadRejected + s.BannedRejected
	if s.Requests != outcomes {
		t.Fatalf("security action counters do not partition requests: requests=%d outcomes=%d snapshot=%#v", s.Requests, outcomes, s)
	}
	if s.Requests != 6 || s.Allowed != 1 || s.Logged != 1 || s.Blocked != 1 ||
		s.RateLimited != 1 || s.ClientRateLimited != 1 || s.OverloadRejected != 1 || s.BannedRejected != 1 {
		t.Fatalf("unexpected security outcome counters: %#v", s)
	}
	rejected := s.Blocked + s.RateLimited + s.OverloadRejected + s.BannedRejected
	if s.BlockRate != float64(rejected)/float64(s.Requests) {
		t.Fatalf("rejection rate=%v, want %v", s.BlockRate, float64(rejected)/float64(s.Requests))
	}
	if s.Detections != 1 || s.DetectionRate != 1.0/6.0 {
		t.Fatalf("detection counters/rate are inconsistent: %#v", s)
	}
	if s.Errors != 1 {
		t.Fatalf("processing error count=%d, want 1", s.Errors)
	}
	if s.Latency.AverageMS <= 0 || s.Latency.P95MS <= 0 || s.Latency.MaximumMS <= 0 {
		t.Fatalf("latency summary missing for completed requests: %#v", s.Latency)
	}
}

func TestUnknownMethodsUseBoundedMetricLabel(t *testing.T) {
	r := New()
	for i := 0; i < 1000; i++ {
		done := r.Begin()
		done(Observation{Route: "demo", Method: fmt.Sprintf("X-CUSTOM-%d", i), Action: "BLOCK"})
	}
	methods := r.Snapshot().Total.Methods
	if len(methods) != 1 || methods["OTHER"] != 1000 {
		t.Fatalf("unbounded method labels: %#v", methods)
	}
}
