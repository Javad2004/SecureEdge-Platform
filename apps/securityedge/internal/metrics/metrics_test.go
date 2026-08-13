package metrics

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnapshotAndPrometheus(t *testing.T) {
	r := New()
	done := r.Begin()
	done(Observation{Route: "demo", Method: "GET", Action: "RATE_LIMIT", Reason: "rate_limit_capacity", RateLimitScope: "global", Duration: 12 * time.Millisecond})
	s := r.Snapshot()
	if s.Total.GlobalRateLimited != 1 || s.Total.ClientRateLimited != 0 || s.Total.Latency.P50MS <= 0 {
		t.Fatalf("unexpected snapshot: %#v", s.Total)
	}
	text := r.Prometheus()
	for _, metric := range []string{
		"securityedge_requests_total", "securityedge_canceled_requests_total", "securityedge_allowed_total", "securityedge_blocked_total",
		"securityedge_logged_total", "securityedge_rate_limited_total", "securityedge_global_rate_limited_total", "securityedge_client_rate_limited_total",
		"securityedge_overload_rejected_total", "securityedge_body_too_large_total", "securityedge_banned_rejected_total", "securityedge_auto_bans_total",
		"securityedge_detections_total", "securityedge_errors_total", "securityedge_inspected_bodies_total", "securityedge_truncated_bodies_total",
	} {
		if !strings.Contains(text, metric) {
			t.Fatalf("Prometheus output missing %s: %s", metric, text)
		}
	}
	if !strings.Contains(text, `securityedge_global_rate_limited_total 1`) || !strings.Contains(text, `securityedge_global_rate_limited_total{route="demo"} 1`) || !strings.Contains(text, `route="demo"`) {
		t.Fatalf("Prometheus rate-limit scope or route labels are inconsistent: %s", text)
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
		{Route: "demo", Method: "GET", Action: "CANCELED", Reason: "client_canceled", Duration: 99 * time.Millisecond, Error: true, Canceled: true},
	}
	for _, observation := range observations {
		done := r.Begin()
		done(observation)
	}

	s := r.Snapshot().Total
	outcomes := s.Allowed + s.Logged + s.Blocked + s.RateLimited + s.OverloadRejected + s.BannedRejected
	if s.Requests != outcomes+s.CanceledRequests {
		t.Fatalf("security action/cancellation counters do not partition requests: requests=%d outcomes=%d canceled=%d snapshot=%#v", s.Requests, outcomes, s.CanceledRequests, s)
	}
	if s.Requests != 7 || s.CanceledRequests != 1 || s.Allowed != 1 || s.Logged != 1 || s.Blocked != 1 ||
		s.RateLimited != 1 || s.ClientRateLimited != 1 || s.OverloadRejected != 1 || s.BannedRejected != 1 {
		t.Fatalf("unexpected security outcome counters: %#v", s)
	}
	rejected := s.Blocked + s.RateLimited + s.OverloadRejected + s.BannedRejected
	evaluated := s.Requests - s.CanceledRequests
	if s.BlockRate != float64(rejected)/float64(evaluated) {
		t.Fatalf("rejection rate=%v, want %v", s.BlockRate, float64(rejected)/float64(evaluated))
	}
	if s.Detections != 1 || s.DetectionRate != 1.0/6.0 {
		t.Fatalf("detection counters/rate are inconsistent: %#v", s)
	}
	if s.Errors != 1 {
		t.Fatalf("processing error count=%d, want 1", s.Errors)
	}
	if len(s.Actions) != 6 || s.Actions["CANCELED"] != 0 || s.Reasons["client_canceled"] != 0 {
		t.Fatalf("canceled requests must not pollute evaluated action/reason counters: %#v", s)
	}
	if s.Latency.AverageMS <= 0 || s.Latency.P95MS <= 0 || s.Latency.MaximumMS <= 0 {
		t.Fatalf("latency summary missing for completed requests: %#v", s.Latency)
	}
}

func TestCanceledOnlySnapshotHasNoEvaluatedRatesOrLatency(t *testing.T) {
	r := New()
	done := r.Begin()
	done(Observation{Route: "demo", Method: "POST", Action: "CANCELED", Reason: "client_canceled", Duration: 99 * time.Millisecond, Error: true, Canceled: true})

	s := r.Snapshot().Total
	if s.Requests != 1 || s.CanceledRequests != 1 || s.Allowed != 0 || s.Blocked != 0 || s.Errors != 0 {
		t.Fatalf("unexpected canceled-only counters: %#v", s)
	}
	if s.BlockRate != 0 || s.DetectionRate != 0 || s.AverageScore != 0 || s.Latency.AverageMS != 0 || s.Latency.MaximumMS != 0 || s.Latency.P95MS != 0 {
		t.Fatalf("cancellation polluted evaluated rates/latency: %#v", s)
	}
	if len(s.Actions) != 0 || len(s.Reasons) != 0 {
		t.Fatalf("cancellation polluted action/reason dimensions: actions=%#v reasons=%#v", s.Actions, s.Reasons)
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

func TestConcurrentSnapshotsRemainInternallyConsistent(t *testing.T) {
	registry := New()
	var stop atomic.Bool
	var workers sync.WaitGroup
	actions := []string{"ALLOW", "BLOCK", "LOG", "RATE_LIMIT", "OVERLOAD", "BANNED"}
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for i := 0; i < 5000 && !stop.Load(); i++ {
				finish := registry.Begin()
				if (i+worker)%17 == 0 {
					finish(Observation{Route: "demo", Method: "GET", Canceled: true})
				} else {
					finish(Observation{Route: "demo", Method: "GET", Action: actions[(i+worker)%len(actions)], Duration: time.Microsecond})
				}
			}
		}(worker)
	}

	check := func(snapshot Snapshot) {
		total := snapshot.Total
		route := snapshot.Routes["demo"]
		outcomes := total.Allowed + total.Blocked + total.Logged + total.RateLimited + total.OverloadRejected + total.BannedRejected
		if total.Requests != outcomes+total.CanceledRequests {
			t.Fatalf("aggregate request partition came from different update generations: requests=%d outcomes=%d canceled=%d total=%#v", total.Requests, outcomes, total.CanceledRequests, total)
		}
		routeOutcomes := route.Allowed + route.Blocked + route.Logged + route.RateLimited + route.OverloadRejected + route.BannedRejected
		if route.Requests != routeOutcomes+route.CanceledRequests || route.Requests != total.Requests {
			t.Fatalf("Route and aggregate snapshots are inconsistent: total=%#v route=%#v", total, route)
		}
		if total.Methods["GET"] != total.Requests || route.Methods["GET"] != route.Requests {
			t.Fatalf("method dimensions are not coherent with request totals: total=%#v route=%#v", total.Methods, route.Methods)
		}
		actionTotal := uint64(0)
		for action, count := range total.Actions {
			actionTotal += count
			if route.Actions[action] != count {
				t.Fatalf("aggregate and Route action dimensions came from different generations: action=%q total=%d route=%d", action, count, route.Actions[action])
			}
		}
		if actionTotal != outcomes {
			t.Fatalf("action dimensions are not coherent with scalar outcomes: actions=%#v outcomes=%d", total.Actions, outcomes)
		}
		if total.Latency.P50MS < 0 || route.Latency.P50MS < 0 {
			t.Fatalf("invalid latency snapshot: total=%#v route=%#v", total.Latency, route.Latency)
		}
	}

	for i := 0; i < 10000; i++ {
		check(registry.Snapshot())
	}
	stop.Store(true)
	workers.Wait()
	check(registry.Snapshot())
}
