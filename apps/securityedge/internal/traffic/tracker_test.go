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

func TestTrackerOrdersOutOfOrderEventsByObservedTime(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	tracker := New(3, time.Minute)
	tracker.Observe(Event{ObservedAt: now.Add(-5 * time.Second).Format(time.RFC3339Nano), RequestID: "newer", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: now.Add(-10 * time.Second).Format(time.RFC3339Nano), RequestID: "older", Action: "ALLOW"})

	snapshot := tracker.Snapshot(now)
	if snapshot.LastRequest == nil || snapshot.LastRequest.RequestID != "newer" {
		t.Fatalf("last request should be newest by observation time: %#v", snapshot.LastRequest)
	}
	recent := tracker.Recent(10)
	if len(recent) != 2 || recent[0].RequestID != "newer" || recent[1].RequestID != "older" {
		t.Fatalf("recent events are not chronologically ordered: %#v", recent)
	}
}

func TestTrackerOrdersFractionalTimestampsWithinSameSecond(t *testing.T) {
	tracker := New(3, time.Minute)
	tracker.Observe(Event{ObservedAt: "2026-08-13T12:00:00.1Z", RequestID: "later", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: "2026-08-13T12:00:00Z", RequestID: "earlier", Action: "ALLOW"})

	recent := tracker.Recent(10)
	if len(recent) != 2 || recent[0].RequestID != "later" || recent[1].RequestID != "earlier" {
		t.Fatalf("fractional timestamps are not chronologically ordered: %#v", recent)
	}
}

func TestTrackerRetainsNewestEventsWhenOlderObservationArrivesAtCapacity(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	tracker := New(2, time.Minute)
	tracker.Observe(Event{ObservedAt: now.Add(-20 * time.Second).Format(time.RFC3339Nano), RequestID: "middle", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: now.Add(-10 * time.Second).Format(time.RFC3339Nano), RequestID: "newest", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: now.Add(-30 * time.Second).Format(time.RFC3339Nano), RequestID: "delayed-oldest", Action: "ALLOW"})

	recent := tracker.Recent(10)
	if len(recent) != 2 || recent[0].RequestID != "newest" || recent[1].RequestID != "middle" {
		t.Fatalf("capacity should retain the newest observations: %#v", recent)
	}
	snapshot := tracker.Snapshot(now)
	if snapshot.LastRequest == nil || snapshot.LastRequest.RequestID != "newest" {
		t.Fatalf("unexpected last request: %#v", snapshot.LastRequest)
	}
	if !snapshot.WindowTruncated || snapshot.RequestsInWindow != 2 || snapshot.MinimumRequestsInWindow != 3 {
		t.Fatalf("discarded in-window observation must preserve a conservative lower bound: %#v", snapshot)
	}
}

func TestSnapshotDiscardsFutureDatedEventsAfterClockRollback(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	tracker := New(10, 5*time.Minute)
	tracker.Observe(Event{ObservedAt: now.Add(time.Hour).Format(time.RFC3339Nano), RequestID: "future", Action: "ALLOW"})
	tracker.Observe(Event{ObservedAt: now.Format(time.RFC3339Nano), RequestID: "current", Action: "ALLOW"})
	tracker.latestEvictedAt = now.Add(30 * time.Minute)

	snapshot := tracker.Snapshot(now)
	if snapshot.LastRequest == nil || snapshot.LastRequest.RequestID != "current" {
		t.Fatalf("future-dated event dominated current activity snapshot: %#v", snapshot)
	}
	if snapshot.RequestsInWindow != 1 || snapshot.MinimumRequestsInWindow != 1 || snapshot.WindowTruncated {
		t.Fatalf("future timeline polluted current activity counts: %#v", snapshot)
	}
	recent := tracker.Recent(10)
	if len(recent) != 1 || recent[0].RequestID != "current" {
		t.Fatalf("future-dated event was not permanently pruned: %#v", recent)
	}

	later := tracker.Snapshot(now.Add(2 * time.Hour))
	if later.RequestsInWindow != 0 || later.LastRequest != nil {
		t.Fatalf("discarded future event reappeared after wall clock caught up: %#v", later)
	}
}
