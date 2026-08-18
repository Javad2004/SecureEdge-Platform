package metrics

import (
	"fmt"
	"sync"
	"sync/atomic"
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
	if total.Requests != total.Success+total.ClientErrors+total.ServerErrors+total.CanceledRequests {
		t.Fatalf("request outcome counters do not partition physical requests: %#v", total)
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

func TestCanceledClientRequestIsExcludedFromCompletedOutcomeMetrics(t *testing.T) {
	registry := New()
	finish := registry.Begin("demo", "GET")
	finish(RequestObservation{
		Status:      502,
		Canceled:    true,
		BytesIn:     12,
		BytesOut:    7,
		Duration:    25 * time.Millisecond,
		ProxyError:  true,
		Retries:     1,
		CacheStatus: "MISS",
	})

	snapshot := registry.Snapshot().Total
	if snapshot.Requests != 1 || snapshot.CanceledRequests != 1 {
		t.Fatalf("unexpected physical request/cancellation counters: %#v", snapshot)
	}
	if snapshot.Success != 0 || snapshot.ClientErrors != 0 || snapshot.ServerErrors != 0 || snapshot.ProxyErrors != 0 {
		t.Fatalf("client cancellation polluted completed outcomes: %#v", snapshot)
	}
	if snapshot.SuccessRate != 0 || snapshot.ErrorRate != 0 || snapshot.ResponseLatencyMS.Count != 0 || len(snapshot.StatusCodes) != 0 {
		t.Fatalf("client cancellation polluted derived response metrics: %#v", snapshot)
	}
	if snapshot.BytesIn != 12 || snapshot.BytesOut != 7 || snapshot.Retries != 1 || snapshot.CacheMisses != 1 {
		t.Fatalf("physical work from canceled request was lost: %#v", snapshot)
	}

	finish = registry.Begin("demo", "GET")
	finish(RequestObservation{Status: 200, Duration: 5 * time.Millisecond, CacheStatus: "BYPASS"})
	snapshot = registry.Snapshot().Total
	if snapshot.Requests != 2 || snapshot.CanceledRequests != 1 || snapshot.Success != 1 || snapshot.SuccessRate != 1 || snapshot.ErrorRate != 0 {
		t.Fatalf("canceled request changed completed-outcome denominator: %#v", snapshot)
	}
	if snapshot.ResponseLatencyMS.Count != 1 || snapshot.StatusCodes["200"] != 1 {
		t.Fatalf("completed response telemetry is inconsistent after cancellation: %#v", snapshot)
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

func TestHistogramPercentilesNeverExceedObservedMaximum(t *testing.T) {
	var h histogram
	h.Observe(5694970 * time.Microsecond)

	snapshot := h.Snapshot()
	if snapshot.Maximum != 5694.97 {
		t.Fatalf("maximum=%v ms, want 5694.97 ms", snapshot.Maximum)
	}
	for name, percentile := range map[string]float64{
		"p50": snapshot.P50,
		"p95": snapshot.P95,
		"p99": snapshot.P99,
	} {
		if percentile > snapshot.Maximum {
			t.Fatalf("%s=%v ms exceeds observed maximum=%v ms", name, percentile, snapshot.Maximum)
		}
		if percentile != snapshot.Maximum {
			t.Fatalf("%s=%v ms, want single-sample maximum=%v ms", name, percentile, snapshot.Maximum)
		}
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

func TestConcurrentSnapshotsRemainInternallyConsistent(t *testing.T) {
	registry := New()
	var stop atomic.Bool
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for i := 0; i < 5000 && !stop.Load(); i++ {
				finish := registry.Begin("demo", "GET")
				registry.RecordUpstream("demo", "origin-a", UpstreamObservation{Status: 200, Duration: time.Microsecond})
				if (i+worker)%5 == 0 {
					registry.RecordCacheStore("demo")
				}
				if (i+worker)%17 == 0 {
					finish(RequestObservation{Canceled: true})
				} else {
					finish(RequestObservation{Status: 200, Duration: time.Microsecond})
				}
			}
		}(worker)
	}

	check := func(snapshot Snapshot) {
		total := snapshot.Total
		route := snapshot.Routes["demo"]
		completed := total.Success + total.ClientErrors + total.ServerErrors + total.CanceledRequests
		if snapshot.Inflight < 0 || total.Requests != completed+uint64(snapshot.Inflight) {
			t.Fatalf("request/outcome snapshot is torn: requests=%d completed=%d inflight=%d total=%#v", total.Requests, completed, snapshot.Inflight, total)
		}
		if route.Requests != total.Requests {
			t.Fatalf("Route and aggregate request counts came from different generations: total=%d route=%d", total.Requests, route.Requests)
		}
		if total.Methods["GET"] != total.Requests || route.Methods["GET"] != route.Requests {
			t.Fatalf("method dimensions are not coherent with request totals: total=%#v route=%#v", total.Methods, route.Methods)
		}
		if total.ResponseLatencyMS.Count != total.Success || route.ResponseLatencyMS.Count != route.Success {
			t.Fatalf("latency samples are not coherent with completed responses: total=%#v route=%#v", total.ResponseLatencyMS, route.ResponseLatencyMS)
		}
		globalOrigin := snapshot.Upstreams["origin-a"]
		routeOrigin := route.Upstreams["origin-a"]
		if total.UpstreamCalls != route.UpstreamCalls || total.Upstream.Calls != total.UpstreamCalls || route.Upstream.Calls != route.UpstreamCalls || globalOrigin.Calls != total.UpstreamCalls || routeOrigin.Calls != route.UpstreamCalls {
			t.Fatalf("upstream aggregate/Route/origin counters came from different generations: total=%#v route=%#v global_origin=%#v route_origin=%#v", total.Upstream, route.Upstream, globalOrigin, routeOrigin)
		}
		if total.CacheStores != route.CacheStores {
			t.Fatalf("cache-store counters came from different generations: total=%d route=%d", total.CacheStores, route.CacheStores)
		}
	}

	for i := 0; i < 10000; i++ {
		check(registry.Snapshot())
	}
	stop.Store(true)
	workers.Wait()
	check(registry.Snapshot())
}
