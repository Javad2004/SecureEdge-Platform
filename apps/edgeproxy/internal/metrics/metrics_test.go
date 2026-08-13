package metrics

import (
	"fmt"
	"testing"
	"time"
)

func TestRegistryCapturesRouteAndPerUpstreamMetrics(t *testing.T) {
	registry := New()
	finish := registry.Begin("demo", "GET")
	registry.RecordUpstream("demo", "http://origin-a", UpstreamObservation{Status: 503, Duration: 25 * time.Millisecond, Failed: true})
	registry.RecordUpstream("demo", "http://origin-b", UpstreamObservation{Status: 200, Duration: 5 * time.Millisecond, Retry: true})
	finish(RequestObservation{Status: 200, BytesIn: 12, BytesOut: 100, Duration: 40 * time.Millisecond, Retries: 1, CacheStatus: "MISS"})
	registry.RecordCacheStore("demo")

	snapshot := registry.Snapshot()
	if snapshot.Total.Requests != 1 || snapshot.Total.UpstreamCalls != 2 || snapshot.Total.Retries != 1 {
		t.Fatalf("unexpected total snapshot: %#v", snapshot.Total)
	}
	if snapshot.Total.Upstream.Failures != 1 || snapshot.Total.Upstream.Success != 1 {
		t.Fatalf("unexpected upstream aggregate: %#v", snapshot.Total.Upstream)
	}
	route := snapshot.Routes["demo"]
	if len(route.Upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %d", len(route.Upstreams))
	}
	if route.Upstreams["http://origin-a"].Failures != 1 {
		t.Fatalf("origin-a failure not recorded: %#v", route.Upstreams["http://origin-a"])
	}
	if route.Upstreams["http://origin-b"].Retries != 1 {
		t.Fatalf("origin-b retry not recorded: %#v", route.Upstreams["http://origin-b"])
	}
	if snapshot.Total.CacheMisses != 1 || snapshot.Total.CacheStores != 1 {
		t.Fatalf("unexpected cache metrics: %#v", snapshot.Total.Cache)
	}
	if snapshot.Total.BytesIn != 12 || snapshot.Total.BytesOut != 100 {
		t.Fatalf("unexpected traffic metrics: %#v", snapshot.Total.Traffic)
	}
	if snapshot.Total.ResponseLatencyMS.P95 <= 0 || snapshot.Total.Upstream.LatencyMS.P95 <= 0 {
		t.Fatalf("latency percentiles missing")
	}
}

func TestProxyErrorsRemainDiagnosticSubsetOfClientFacingErrors(t *testing.T) {
	registry := New()
	finish := registry.Begin("demo", "GET")
	finish(RequestObservation{Status: 502, ProxyError: true})

	snapshot := registry.Snapshot().Total
	if snapshot.Requests != 1 || snapshot.ServerErrors != 1 || snapshot.ProxyErrors != 1 {
		t.Fatalf("unexpected overlapping error counters: %#v", snapshot)
	}
	if snapshot.ErrorRate != 1 {
		t.Fatalf("error_rate=%v, want 1 based on the single client-facing request", snapshot.ErrorRate)
	}
}

func TestHistogramEmptySnapshot(t *testing.T) {
	var h histogram
	snapshot := h.Snapshot()
	if snapshot.Count != 0 || snapshot.Average != 0 || len(snapshot.Distribution) != 0 {
		t.Fatalf("unexpected empty histogram: %#v", snapshot)
	}
}

func TestUnknownMethodsUseBoundedMetricLabel(t *testing.T) {
	r := New()
	for i := 0; i < 1000; i++ {
		finish := r.Begin("demo", fmt.Sprintf("X-CUSTOM-%d", i))
		finish(RequestObservation{Status: 200})
	}
	methods := r.Snapshot().Total.Methods
	if len(methods) != 1 || methods["OTHER"] != 1000 {
		t.Fatalf("unbounded method labels: %#v", methods)
	}
}
