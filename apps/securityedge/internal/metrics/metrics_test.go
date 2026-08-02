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
