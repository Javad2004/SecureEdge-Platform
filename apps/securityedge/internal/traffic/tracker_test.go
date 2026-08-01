package traffic

import (
	"testing"
	"time"
)

func TestSnapshotReportsRecentTrafficWithoutTreatingIdleAsFailure(t *testing.T) {
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	tracker := New(4, time.Minute)
	idle := tracker.Snapshot(now)
	if idle.Status != "no_recent_traffic" || idle.LastRequest != nil {
		t.Fatalf("idle snapshot=%#v", idle)
	}
	tracker.Observe(Event{ObservedAt: now.Add(-10 * time.Second).Format(time.RFC3339Nano), ClientIP: "10.0.0.5", Action: "ALLOW", Status: 200, Route: "demo"})
	active := tracker.Snapshot(now)
	if active.Status != "traffic_observed" || active.RequestsInWindow != 1 || active.UniqueClients != 1 || active.Allowed != 1 {
		t.Fatalf("active snapshot=%#v", active)
	}
}

func TestTrackerCapacityIsBounded(t *testing.T) {
	tracker := New(2, time.Minute)
	tracker.Observe(Event{ObservedAt: "2026-07-31T00:00:00Z", RequestID: "1"})
	tracker.Observe(Event{ObservedAt: "2026-07-31T00:00:01Z", RequestID: "2"})
	tracker.Observe(Event{ObservedAt: "2026-07-31T00:00:02Z", RequestID: "3"})
	recent := tracker.Recent(10)
	if len(recent) != 2 || recent[0].RequestID != "3" || recent[1].RequestID != "2" {
		t.Fatalf("recent=%#v", recent)
	}
}
