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

func TestDerivedMetricsRemainInternallyConsistent(t *testing.T) {
	registry := New()

	finish := registry.Begin("demo", "GET")
	finish(RequestObservation{Status: 200, Duration: 10 * time.Millisecond, CacheStatus: "HIT"})

	finish = registry.Begin("demo", "POST")
	finish(RequestObservation{Status: 404, Duration: 20 * time.Millisecond, CacheStatus: "BYPASS"})

	finish = registry.Begin("demo", "GET")
	finish(RequestObservation{Status: 502, Duration: 30 * time.Millisecond, ProxyError: true, CacheStatus: "MISS"})

	registry.RecordUpstream("demo", "origin-a", UpstreamObservation{Status: 200, Duration: 5 * time.Millisecond})
	registry.RecordUpstream("demo", "origin-a", UpstreamObservation{Status: 404, Duration: 7 * time.Millisecond})
	registry.RecordUpstream("demo", "origin-a", UpstreamObservation{Status: 500, Duration: 9 * time.Millisecond, Failed: true})

	snapshot := registry.Snapshot()
	total := snapshot.Total
	if total.Requests != total.Success+total.ClientErrors+total.ServerErrors {
		t.Fatalf("client-facing outcome counters do not partition requests: %#v", total)
	}
	if total.Requests != 3 || total.Success != 1 || total.ClientErrors != 1 || total.ServerErrors != 1 || total.ProxyErrors != 1 {
		t.Fatalf("unexpected request outcome counters: %#v", total)
	}
	if total.SuccessRate != 1.0/3.0 || total.ErrorRate != 2.0/3.0 {
		t.Fatalf("unexpected derived request rates: success=%v error=%v", total.SuccessRate, total.ErrorRate)
	}
	if total.CacheHits != 1 || total.CacheMisses != 1 || total.CacheBypasses != 1 || total.CacheHitRatio != 0.5 {
		t.Fatalf("cache counters/ratio are inconsistent: %#v", total.Cache)
	}
	if total.ResponseLatencyMS.Count != total.Requests {
		t.Fatalf("response-latency samples=%d, want one per completed request=%d", total.ResponseLatencyMS.Count, total.Requests)
	}
	if total.Upstream.Calls != total.Upstream.Success+total.Upstream.Failures+total.Upstream.Canceled {
		t.Fatalf("upstream outcomes do not partition calls: %#v", total.Upstream)
	}
	if total.Upstream.Calls != 3 || total.Upstream.Success != 2 || total.Upstream.Failures != 1 {
		t.Fatalf("unexpected upstream aggregate: %#v", total.Upstream)
	}
	if total.Upstream.LatencyMS.Count != total.Upstream.Success+total.Upstream.Failures {
		t.Fatalf("upstream-latency samples=%d, want one per evaluated call=%d", total.Upstream.LatencyMS.Count, total.Upstream.Success+total.Upstream.Failures)
	}
	origin := snapshot.Upstreams["origin-a"]
	if origin.Calls != 3 || origin.Success != 2 || origin.Failures != 1 ||
		origin.SuccessRate != 2.0/3.0 || origin.ErrorRate != 1.0/3.0 ||
		origin.LatencyMS.Count != origin.Success+origin.Failures {
		t.Fatalf("per-Origin derived metrics are inconsistent: %#v", origin)
	}
}

func TestCanceledUpstreamAttemptIsExcludedFromOriginReliabilityAndLatency(t *testing.T) {
	registry := New()
	registry.RecordUpstream("demo", "origin-a", UpstreamObservation{Duration: 17 * time.Millisecond, Failed: true, Timeout: true, Canceled: true})

	snapshot := registry.Snapshot()
	aggregate := snapshot.Total.Upstream
	if aggregate.Calls != 1 || aggregate.Canceled != 1 || aggregate.Success != 0 || aggregate.Failures != 0 || aggregate.Timeouts != 0 {
		t.Fatalf("client-canceled attempt polluted aggregate Origin outcomes: %#v", aggregate)
	}
	if aggregate.LatencyMS.Count != 0 {
		t.Fatalf("client-canceled attempt polluted aggregate Origin latency: %#v", aggregate.LatencyMS)
	}

	origin := snapshot.Upstreams["origin-a"]
	if origin.Calls != 1 || origin.Canceled != 1 || origin.Success != 0 || origin.Failures != 0 || origin.Timeouts != 0 {
		t.Fatalf("client-canceled attempt polluted per-Origin outcomes: %#v", origin)
	}
	if origin.SuccessRate != 0 || origin.ErrorRate != 0 || origin.LatencyMS.Count != 0 {
		t.Fatalf("client-canceled attempt polluted per-Origin derived metrics: %#v", origin)
	}

	registry.RecordUpstream("demo", "origin-a", UpstreamObservation{Status: 200, Duration: 5 * time.Millisecond})
	origin = registry.Snapshot().Upstreams["origin-a"]
	if origin.Calls != 2 || origin.Canceled != 1 || origin.Success != 1 || origin.Failures != 0 || origin.SuccessRate != 1 || origin.ErrorRate != 0 || origin.LatencyMS.Count != 1 {
		t.Fatalf("canceled call changed the evaluated Origin denominator: %#v", origin)
	}
}

func TestHistogramPreservesRealZeroMinimum(t *testing.T) {
	var h histogram
	h.Observe(0)
	h.Observe(5 * time.Millisecond)
	snapshot := h.Snapshot()
	if snapshot.Count != 2 || snapshot.Minimum != 0 || snapshot.Maximum != 5 {
		t.Fatalf("zero-duration minimum was lost: %#v", snapshot)
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
