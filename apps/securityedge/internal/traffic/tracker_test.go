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
	tracker.Observe(Event{ObservedAt: now.Add(-5 * time.Second).Format(time.RFC3339Nano), ClientIP: "10.0.0.6", Action: "CANCELED", Reason: "client_canceled", Route: "demo"})
	active := tracker.Snapshot(now)
	if active.Status != "traffic_observed" || active.RequestsInWindow != 2 || active.UniqueClients != 2 || active.Allowed != 1 || active.Rejected != 0 || active.Canceled != 1 {
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

func TestSnapshotMarksInWindowCapacityEvictionAsTruncated(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	tracker := New(2, 5*time.Minute)
	tracker.Observe(Event{ObservedAt: now.Add(-30 * time.Second).Format(time.RFC3339Nano), RequestID: "1", ClientIP: "10.0.0.1", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: now.Add(-20 * time.Second).Format(time.RFC3339Nano), RequestID: "2", ClientIP: "10.0.0.2", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: now.Add(-10 * time.Second).Format(time.RFC3339Nano), RequestID: "3", ClientIP: "10.0.0.3", Action: "ALLOW"})

	snapshot := tracker.Snapshot(now)
	if !snapshot.WindowTruncated {
		t.Fatalf("expected truncated snapshot, got %#v", snapshot)
	}
	if snapshot.RetentionCapacity != 2 || snapshot.RequestsInWindow != 2 || snapshot.MinimumRequestsInWindow != 3 {
		t.Fatalf("unexpected retained/lower-bound counts: %#v", snapshot)
	}
	if snapshot.UniqueClients != 2 || snapshot.Allowed != 2 {
		t.Fatalf("expected retained sample counts only, got %#v", snapshot)
	}
}

func TestSnapshotClearsTruncationAfterEvictedEventLeavesWindow(t *testing.T) {
	start := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	tracker := New(2, time.Minute)
	tracker.Observe(Event{ObservedAt: start.Format(time.RFC3339Nano), RequestID: "1", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: start.Add(10 * time.Second).Format(time.RFC3339Nano), RequestID: "2", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: start.Add(20 * time.Second).Format(time.RFC3339Nano), RequestID: "3", Action: "ALLOW"})

	snapshot := tracker.Snapshot(start.Add(2 * time.Minute))
	if snapshot.WindowTruncated {
		t.Fatalf("expired evicted event should not truncate current window: %#v", snapshot)
	}
	if snapshot.RequestsInWindow != 0 || snapshot.MinimumRequestsInWindow != 0 {
		t.Fatalf("expected empty current window, got %#v", snapshot)
	}
}
