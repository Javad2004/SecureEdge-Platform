package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/metrics"
)

func TestTelemetryHistoryDoesNotTreatCanceledOnlyOriginAsReliabilitySample(t *testing.T) {
	cfg := config.Default().Admin.TelemetryHistory
	cfg.Enabled = true
	cfg.SampleInterval = config.Duration{}
	store := newTelemetryHistoryStore(cfg)

	edge := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-13T08:00:00Z","routes":{"demo":{"upstreams":{"origin-a":{"calls":1,"success":0,"failures":0,"canceled":1,"success_rate":0,"latency_ms":{"count":0}}}}}}`)
	store.observe(metrics.Snapshot{}, edge)
	snapshot := store.snapshot(10)
	if len(snapshot.Samples) != 1 {
		t.Fatalf("samples=%d, want 1", len(snapshot.Samples))
	}
	origin := snapshot.Samples[0].Routes["demo"].Origins["origin-a"]
	if origin.Calls != 1 || origin.Canceled != 1 || origin.Failures != 0 || origin.Timeouts != 0 {
		t.Fatalf("canceled-only Origin counters were not preserved in history: %#v", origin)
	}
	if origin.SuccessRateAvailable || origin.P95LatencyAvailable {
		t.Fatalf("canceled-only Origin attempt became a reliability/latency sample: %#v", origin)
	}
}

func TestTelemetryHistoryPersistsBoundsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry", "history.json")
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled:        true,
		Capacity:       2,
		SampleInterval: config.Duration{Duration: time.Second},
		FilePath:       path,
	})

	for requestCount := uint64(1); requestCount <= 3; requestCount++ {
		store.mu.Lock()
		store.lastObserved = time.Time{}
		store.mu.Unlock()
		security := metrics.Snapshot{
			GeneratedAt:       time.Now().UTC().Format(time.RFC3339Nano),
			RequestsPerSecond: float64(requestCount),
			Total: metrics.CounterSnapshot{
				Requests: requestCount,
				Blocked:  requestCount - 1,
				Latency:  metrics.LatencySnapshot{P95MS: 2.5},
			},
		}
		edge := json.RawMessage(`{"schema_version":"2.0","inflight":1,"total":{"requests":` + uintString(requestCount) + `,"cache_hits":1,"cache_misses":1,"cache_hit_ratio":0.5,"response_latency_ms":{"count":` + uintString(requestCount) + `,"p95":4.5}},"routes":{"demo":{"requests":` + uintString(requestCount) + `,"cache_hits":1,"cache_misses":1,"cache_hit_ratio":0.5,"response_latency_ms":{"count":` + uintString(requestCount) + `,"p95":4.5},"upstreams":{"origin-a":{"calls":` + uintString(requestCount) + `,"success_rate":1,"latency_ms":{"count":` + uintString(requestCount) + `,"p95":3.5}}}}}}`)
		store.observe(security, edge)
	}

	snapshot := store.snapshot(10)
	if len(snapshot.Samples) != 2 {
		t.Fatalf("expected bounded history with 2 samples, got %d", len(snapshot.Samples))
	}
	if !snapshot.Persistent || snapshot.LastError != "" {
		t.Fatalf("unexpected persistence status: %#v", snapshot)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected persisted history file: %v", err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document telemetryHistoryDocument
	if err := json.Unmarshal(persisted, &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != "1.5" {
		t.Fatalf("telemetry history schema=%q, want 1.5", document.SchemaVersion)
	}

	reloaded := newTelemetryHistoryStore(store.cfg)
	reloadedSnapshot := reloaded.snapshot(10)
	if len(reloadedSnapshot.Samples) != 2 {
		t.Fatalf("expected 2 reloaded samples, got %d", len(reloadedSnapshot.Samples))
	}
	if got := reloadedSnapshot.Samples[1].Routes["demo"].Origins["origin-a"].Calls; got != 3 {
		t.Fatalf("unexpected reloaded origin calls: %d", got)
	}
	last := reloadedSnapshot.Samples[1]
	if !last.Security.P95LatencyAvailable || !last.EdgeProxy.CacheHitRatioAvailable || !last.EdgeProxy.P95LatencyAvailable {
		t.Fatalf("current aggregate derived-metric availability was not persisted: %#v", last)
	}
	route := last.Routes["demo"]
	origin := route.Origins["origin-a"]
	if !route.CacheHitRatioAvailable || !route.P95LatencyAvailable || !origin.SuccessRateAvailable || !origin.P95LatencyAvailable {
		t.Fatalf("current Route/Origin derived-metric availability was not persisted: route=%#v origin=%#v", route, origin)
	}
}

func TestTelemetryHistoryMarksUndefinedDerivedMetricsUnavailable(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	edge := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-13T08:00:00Z","total":{"requests":0,"cache_hits":0,"cache_misses":0,"cache_hit_ratio":0.99,"response_latency_ms":{"count":0,"p95":99}},"routes":{"demo":{"requests":0,"cache_hits":0,"cache_misses":0,"cache_hit_ratio":0.99,"response_latency_ms":{"count":0,"p95":99},"upstreams":{"origin-a":{"calls":0,"success_rate":1,"latency_ms":{"count":0,"p95":99}}}}}}`)
	store.observe(metrics.Snapshot{
		StartedAt: "2026-08-13T08:00:00Z",
		Total: metrics.CounterSnapshot{
			Requests: 0,
			Latency:  metrics.LatencySnapshot{P95MS: 99},
		},
	}, edge)

	samples := store.snapshot(10).Samples
	if len(samples) != 1 {
		t.Fatalf("history samples=%d, want 1", len(samples))
	}
	point := samples[0]
	if point.Security.P95LatencyAvailable || point.EdgeProxy.CacheHitRatioAvailable || point.EdgeProxy.P95LatencyAvailable {
		t.Fatalf("zero-sample aggregate derived metrics must remain unavailable: %#v", point)
	}
	route := point.Routes["demo"]
	origin := route.Origins["origin-a"]
	if route.CacheHitRatioAvailable || route.P95LatencyAvailable || origin.SuccessRateAvailable || origin.P95LatencyAvailable {
		t.Fatalf("zero-sample Route/Origin derived metrics must remain unavailable: route=%#v origin=%#v", route, origin)
	}
}

func TestTelemetryHistoryCanceledOnlySecurityRequestHasNoLatencySample(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	store.observe(metrics.Snapshot{
		StartedAt: "2026-08-13T08:00:00Z",
		Total: metrics.CounterSnapshot{
			Requests: 1, CanceledRequests: 1,
			Latency: metrics.LatencySnapshot{AverageMS: 99, MaximumMS: 99, P50MS: 99, P95MS: 99, P99MS: 99},
		},
	}, nil)

	point := store.snapshot(10).Samples[0].Security
	if point.Requests != 1 || point.Canceled != 1 || point.Rejected != 0 || point.Errors != 0 {
		t.Fatalf("unexpected canceled-only history point: %#v", point)
	}
	if point.P95LatencyAvailable || point.P95LatencyMS != 99 {
		t.Fatalf("canceled-only security traffic must not make latency evaluable: %#v", point)
	}
}

func TestTelemetryHistoryLoadsV14WithoutSecurityCanceledField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	document := telemetryHistoryDocument{
		SchemaVersion: "1.4",
		Samples: []telemetryHistoryPoint{{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Security:    telemetrySecurityHistoryPoint{Requests: 20, P95LatencyMS: 9, P95LatencyAvailable: true},
		}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second}, FilePath: path,
	})
	loaded := store.snapshot(10).Samples
	if len(loaded) != 1 || loaded[0].Security.Canceled != 0 || !loaded[0].Security.P95LatencyAvailable {
		t.Fatalf("schema 1.4 compatibility failed: %#v", loaded)
	}
}

func TestTelemetryHistoryRejectsEdgeProxyPayloadWithoutMetricsSchema(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled:        true,
		Capacity:       10,
		SampleInterval: config.Duration{Duration: time.Second},
	})

	store.observe(
		metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 1}},
		json.RawMessage(`{"total":{"requests":0},"error":{"message":"unauthorized"}}`),
	)

	snapshot := store.snapshot(10)
	if len(snapshot.Samples) != 1 {
		t.Fatalf("history samples=%d, want 1", len(snapshot.Samples))
	}
	if snapshot.Samples[0].EdgeProxy.Available {
		t.Fatal("EdgeProxy payload without metrics schema must remain unavailable")
	}
}

func TestTelemetryHistoryDoesNotDoubleCountProxyErrors(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})

	edge := json.RawMessage(`{"schema_version":"2.0","total":{"requests":10,"client_errors":2,"server_errors":3,"proxy_errors":3},"routes":{"demo":{"requests":5,"client_errors":1,"server_errors":2,"proxy_errors":2}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 1}}, edge)

	samples := store.snapshot(10).Samples
	if len(samples) != 1 {
		t.Fatalf("history samples=%d, want 1", len(samples))
	}
	if got := samples[0].EdgeProxy.Errors; got != 5 {
		t.Fatalf("EdgeProxy client-facing errors=%d, want 5 without overlapping proxy-error causes", got)
	}
	if !samples[0].EdgeProxy.ErrorCountAvailable {
		t.Fatal("new EdgeProxy history sample must mark corrected error counts as available")
	}
	if got := samples[0].Routes["demo"].Errors; got != 3 {
		t.Fatalf("Route client-facing errors=%d, want 3 without overlapping proxy-error causes", got)
	}
	if !samples[0].Routes["demo"].ErrorCountAvailable {
		t.Fatal("new Route history sample must mark corrected error counts as available")
	}
}

func TestTelemetryHistoryLoadsLegacyErrorCountsAsUnverified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	document := telemetryHistoryDocument{
		SchemaVersion: "1.1",
		Samples: []telemetryHistoryPoint{{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
			EdgeProxy:   telemetryEdgeHistoryPoint{Available: true, Errors: 99, ErrorCountAvailable: true},
			Routes: map[string]telemetryRouteHistory{
				"demo": {Errors: 88, ErrorCountAvailable: true},
			},
		}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second}, FilePath: path,
	})
	samples := store.snapshot(10).Samples
	if len(samples) != 1 {
		t.Fatalf("legacy history samples=%d, want 1", len(samples))
	}
	if samples[0].EdgeProxy.ErrorCountAvailable || samples[0].Routes["demo"].ErrorCountAvailable {
		t.Fatalf("legacy error counts must remain explicitly unverified: %#v", samples[0])
	}
}

func TestTelemetryHistoryRecoversInterruptedWindowsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	document := telemetryHistoryDocument{
		SchemaVersion: "1.0",
		Samples: []telemetryHistoryPoint{{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Security:    telemetrySecurityHistoryPoint{Requests: 11},
		}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
		t.Fatal(err)
	}

	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second}, FilePath: path,
	})
	snapshot := store.snapshot(10)
	if snapshot.LastError != "" || len(snapshot.Samples) != 1 || snapshot.Samples[0].Security.Requests != 11 {
		t.Fatalf("unexpected recovered history: %#v", snapshot)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("restored history file is missing: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("staged history backup still exists: %v", err)
	}
}

func TestTelemetryHistoryDoesNotRestoreInvalidStagingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(path+".bak", []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second}, FilePath: path,
	})
	if store.snapshot(10).LastError == "" {
		t.Fatal("expected invalid staging file to be reported")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid staging file was restored: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("invalid staging file should remain for diagnosis: %v", err)
	}
}

func TestTelemetryHistoryCorruptionDoesNotPreventRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled:        true,
		Capacity:       5,
		SampleInterval: config.Duration{Duration: time.Second},
		FilePath:       path,
	})
	if store.snapshot(5).LastError == "" {
		t.Fatal("expected corrupt history to be reported")
	}
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 1}}, nil)
	if got := store.snapshot(5); got.LastError != "" || len(got.Samples) != 1 {
		t.Fatalf("expected history to recover after a valid sample: %#v", got)
	}
}

func TestTelemetryHistoryBoundsRetainedSerializedBytes(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled:        true,
		Capacity:       100,
		SampleInterval: config.Duration{Duration: time.Second},
	})
	store.maxRetainedBytes = 1800

	for i := 0; i < 20; i++ {
		point := telemetryHistoryPoint{
			GeneratedAt: time.Now().UTC().Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
			Security:    telemetrySecurityHistoryPoint{Requests: uint64(i + 1)},
			Routes: map[string]telemetryRouteHistory{
				"route-" + strconv.Itoa(i): {
					Requests: uint64(i + 1),
					Origins: map[string]telemetryOriginHistory{
						strings.Repeat("origin-", 40) + strconv.Itoa(i): {Calls: uint64(i + 1)},
					},
				},
			},
		}
		store.appendPointLocked(point)
	}

	if store.retainedBytes > store.maxRetainedBytes {
		t.Fatalf("retained history exceeded byte budget: %d > %d", store.retainedBytes, store.maxRetainedBytes)
	}
	if len(store.samples) >= 20 {
		t.Fatalf("expected byte budget to evict old samples, retained %d", len(store.samples))
	}
	if len(store.samples) != len(store.sampleBytes) {
		t.Fatalf("sample size accounting mismatch: %d samples, %d sizes", len(store.samples), len(store.sampleBytes))
	}
	snapshot := store.snapshot(100)
	if snapshot.RetainedBytes != store.retainedBytes || snapshot.RetainedLimitBytes != store.maxRetainedBytes {
		t.Fatalf("unexpected retained-byte status: %#v", snapshot)
	}
}

func TestTelemetryHistoryTruncatesOversizedRouteDetails(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled:        true,
		Capacity:       10,
		SampleInterval: config.Duration{Duration: time.Second},
	})
	store.maxRetainedBytes = 600

	origins := make(map[string]telemetryOriginHistory, 20)
	for i := 0; i < 20; i++ {
		origins[strings.Repeat("large-origin-name-", 4)+strconv.Itoa(i)] = telemetryOriginHistory{Calls: uint64(i + 1)}
	}
	store.appendPointLocked(telemetryHistoryPoint{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Security:    telemetrySecurityHistoryPoint{Requests: 1},
		Routes: map[string]telemetryRouteHistory{
			"large-route": {Requests: 1, Origins: origins},
		},
	})

	if len(store.samples) != 1 {
		t.Fatalf("expected aggregate sample to be retained, got %d", len(store.samples))
	}
	point := store.samples[0]
	if !point.RouteDetailsTruncated {
		t.Fatal("expected oversized route details to be marked as truncated")
	}
	if len(point.Routes) != 0 {
		t.Fatalf("expected oversized route details to be omitted, got %d routes", len(point.Routes))
	}
	if store.retainedBytes > store.maxRetainedBytes {
		t.Fatalf("retained history exceeded byte budget: %d > %d", store.retainedBytes, store.maxRetainedBytes)
	}
}

func TestTelemetryHistoryDoesNotInventRateAcrossUnavailableGap(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})

	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 1}}, nil)
	store.mu.Lock()
	store.samples[0].GeneratedAt = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	store.lastObserved = time.Time{}
	store.mu.Unlock()

	edge := json.RawMessage(`{"schema_version":"2.0","total":{"requests":100},"routes":{"demo":{"requests":40}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 2}}, edge)

	samples := store.snapshot(10).Samples
	if len(samples) != 2 {
		t.Fatalf("history samples=%d, want 2", len(samples))
	}
	recovered := samples[1]
	if !recovered.EdgeProxy.Available {
		t.Fatal("recovered EdgeProxy sample should be available")
	}
	if recovered.EdgeProxy.RequestRateAvailable || recovered.EdgeProxy.RequestsPerSecond != 0 {
		t.Fatalf("recovery rate=%v available=%v, want an explicit rate gap", recovered.EdgeProxy.RequestsPerSecond, recovered.EdgeProxy.RequestRateAvailable)
	}
	if route := recovered.Routes["demo"]; route.RequestRateAvailable || route.RequestsPerSecond != 0 {
		t.Fatalf("recovered Route rate=%v available=%v, want an explicit rate gap", route.RequestsPerSecond, route.RequestRateAvailable)
	}
}

func TestTelemetryHistoryMarksRatesAvailableOnlyForContiguousCounters(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	first := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-12T20:00:00Z","total":{"requests":100},"routes":{"demo":{"requests":40}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 1}}, first)
	store.mu.Lock()
	store.samples[0].GeneratedAt = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	store.lastObserved = time.Time{}
	store.mu.Unlock()

	second := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-12T20:00:00Z","total":{"requests":150},"routes":{"demo":{"requests":70}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 2}}, second)

	samples := store.snapshot(10).Samples
	current := samples[1]
	if !current.EdgeProxy.RequestRateAvailable || current.EdgeProxy.RequestsPerSecond < 4.9 || current.EdgeProxy.RequestsPerSecond > 5.1 {
		t.Fatalf("EdgeProxy contiguous rate=%v available=%v, want about 5 req/s", current.EdgeProxy.RequestsPerSecond, current.EdgeProxy.RequestRateAvailable)
	}
	route := current.Routes["demo"]
	if !route.RequestRateAvailable || route.RequestsPerSecond < 2.9 || route.RequestsPerSecond > 3.1 {
		t.Fatalf("Route contiguous rate=%v available=%v, want about 3 req/s", route.RequestsPerSecond, route.RequestRateAvailable)
	}
}

func TestTelemetryHistoryTreatsCounterResetAsRateGap(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	first := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-12T20:00:00Z","total":{"requests":100},"routes":{"demo":{"requests":40}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 1}}, first)
	store.mu.Lock()
	store.samples[0].GeneratedAt = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	store.lastObserved = time.Time{}
	store.mu.Unlock()

	reset := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-12T20:00:00Z","total":{"requests":3},"routes":{"demo":{"requests":2}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 2}}, reset)

	current := store.snapshot(10).Samples[1]
	if current.EdgeProxy.RequestRateAvailable || current.EdgeProxy.RequestsPerSecond != 0 {
		t.Fatalf("counter reset produced EdgeProxy rate=%v available=%v", current.EdgeProxy.RequestsPerSecond, current.EdgeProxy.RequestRateAvailable)
	}
	if route := current.Routes["demo"]; route.RequestRateAvailable || route.RequestsPerSecond != 0 {
		t.Fatalf("counter reset produced Route rate=%v available=%v", route.RequestsPerSecond, route.RequestRateAvailable)
	}
}

func TestTelemetryHistoryTreatsEdgeProxyRestartAsRateGap(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	first := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-12T20:00:00Z","total":{"requests":100},"routes":{"demo":{"requests":40}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 1}}, first)
	store.mu.Lock()
	store.samples[0].GeneratedAt = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	store.lastObserved = time.Time{}
	store.mu.Unlock()

	restarted := json.RawMessage(`{"schema_version":"2.0","started_at":"2026-08-12T20:05:00Z","total":{"requests":150},"routes":{"demo":{"requests":70}}}`)
	store.observe(metrics.Snapshot{Total: metrics.CounterSnapshot{Requests: 2}}, restarted)

	current := store.snapshot(10).Samples[1]
	if current.EdgeProxy.RequestRateAvailable || current.EdgeProxy.RequestsPerSecond != 0 {
		t.Fatalf("EdgeProxy restart produced rate=%v available=%v", current.EdgeProxy.RequestsPerSecond, current.EdgeProxy.RequestRateAvailable)
	}
	if route := current.Routes["demo"]; route.RequestRateAvailable || route.RequestsPerSecond != 0 {
		t.Fatalf("EdgeProxy restart produced Route rate=%v available=%v", route.RequestsPerSecond, route.RequestRateAvailable)
	}
}

func TestTelemetryHistoryLoadsV1RatesConservatively(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	base := time.Now().UTC().Add(-20 * time.Second)
	document := telemetryHistoryDocument{
		SchemaVersion: "1.0",
		Samples: []telemetryHistoryPoint{
			{GeneratedAt: base.Format(time.RFC3339Nano), EdgeProxy: telemetryEdgeHistoryPoint{Available: true, Requests: 10}, Routes: map[string]telemetryRouteHistory{"demo": {Requests: 4}}},
			{GeneratedAt: base.Add(10 * time.Second).Format(time.RFC3339Nano), EdgeProxy: telemetryEdgeHistoryPoint{Available: true, Requests: 30, RequestsPerSecond: 2}, Routes: map[string]telemetryRouteHistory{"demo": {Requests: 14, RequestsPerSecond: 1}}},
		},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second}, FilePath: path,
	})
	samples := store.snapshot(10).Samples
	if len(samples) != 2 {
		t.Fatalf("history samples=%d, want 2", len(samples))
	}
	for i, sample := range samples {
		if sample.EdgeProxy.RequestRateAvailable || sample.Routes["demo"].RequestRateAvailable {
			t.Fatalf("legacy sample %d has no rate-validity metadata and must remain a gap: %#v", i, sample)
		}
	}
}

func TestTelemetryHistoryMarksSecurityRatesAvailableOnlyForContiguousProcess(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	startedAt := "2026-08-13T08:00:00Z"
	store.observe(metrics.Snapshot{StartedAt: startedAt, Total: metrics.CounterSnapshot{Requests: 100, Blocked: 10}}, nil)
	store.mu.Lock()
	store.samples[0].GeneratedAt = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	store.lastObserved = time.Time{}
	store.mu.Unlock()

	store.observe(metrics.Snapshot{StartedAt: startedAt, Total: metrics.CounterSnapshot{Requests: 150, Blocked: 15}}, nil)

	current := store.snapshot(10).Samples[1].Security
	if !current.RequestRateAvailable || current.RequestsPerSecond < 4.9 || current.RequestsPerSecond > 5.1 {
		t.Fatalf("SecurityEdge contiguous request rate=%v available=%v, want about 5 req/s", current.RequestsPerSecond, current.RequestRateAvailable)
	}
	if !current.RejectedRateAvailable || current.RejectedPerSecond < 0.49 || current.RejectedPerSecond > 0.51 {
		t.Fatalf("SecurityEdge contiguous rejection rate=%v available=%v, want about 0.5 req/s", current.RejectedPerSecond, current.RejectedRateAvailable)
	}
}

func TestTelemetryHistoryTreatsSecurityEdgeRestartAsRateGap(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	store.observe(metrics.Snapshot{StartedAt: "2026-08-13T08:00:00Z", Total: metrics.CounterSnapshot{Requests: 100, Blocked: 10}}, nil)
	store.mu.Lock()
	store.samples[0].GeneratedAt = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	store.lastObserved = time.Time{}
	store.mu.Unlock()

	store.observe(metrics.Snapshot{StartedAt: "2026-08-13T08:05:00Z", Total: metrics.CounterSnapshot{Requests: 150, Blocked: 15}}, nil)

	current := store.snapshot(10).Samples[1].Security
	if current.RequestRateAvailable || current.RequestsPerSecond != 0 || current.RejectedRateAvailable || current.RejectedPerSecond != 0 {
		t.Fatalf("SecurityEdge restart produced synthetic rates: %#v", current)
	}
}

func TestTelemetryHistoryTreatsSecurityCounterResetAsRateGap(t *testing.T) {
	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second},
	})
	startedAt := "2026-08-13T08:00:00Z"
	store.observe(metrics.Snapshot{StartedAt: startedAt, Total: metrics.CounterSnapshot{Requests: 100, Blocked: 10}}, nil)
	store.mu.Lock()
	store.samples[0].GeneratedAt = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano)
	store.lastObserved = time.Time{}
	store.mu.Unlock()

	store.observe(metrics.Snapshot{StartedAt: startedAt, Total: metrics.CounterSnapshot{Requests: 3, Blocked: 1}}, nil)

	current := store.snapshot(10).Samples[1].Security
	if current.RequestRateAvailable || current.RequestsPerSecond != 0 || current.RejectedRateAvailable || current.RejectedPerSecond != 0 {
		t.Fatalf("SecurityEdge counter reset produced synthetic rates: %#v", current)
	}
}

func TestTelemetryHistoryLoadsV13WithoutCanceledField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	document := telemetryHistoryDocument{
		SchemaVersion: "1.3",
		Samples: []telemetryHistoryPoint{{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Security: telemetrySecurityHistoryPoint{
				Requests: 20, P95LatencyMS: 9, P95LatencyAvailable: true,
			},
			EdgeProxy: telemetryEdgeHistoryPoint{
				Available: true, ErrorCountAvailable: true,
				CacheHitRatio: 0.5, CacheHitRatioAvailable: true, P95LatencyMS: 7, P95LatencyAvailable: true,
			},
			Routes: map[string]telemetryRouteHistory{
				"demo": {
					CacheHitRatio: 0.5, CacheHitRatioAvailable: true, P95LatencyMS: 6, P95LatencyAvailable: true,
					Origins: map[string]telemetryOriginHistory{
						"origin-a": {Calls: 10, SuccessRate: 1, SuccessRateAvailable: true, P95LatencyMS: 5, P95LatencyAvailable: true},
					},
				},
			},
		}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second}, FilePath: path,
	})
	loaded := store.snapshot(10).Samples
	if len(loaded) != 1 {
		t.Fatalf("history samples=%d, want 1", len(loaded))
	}
	origin := loaded[0].Routes["demo"].Origins["origin-a"]
	if origin.Canceled != 0 {
		t.Fatalf("schema 1.3 history unexpectedly synthesized canceled attempts: %#v", origin)
	}
	if !loaded[0].Security.P95LatencyAvailable || !loaded[0].EdgeProxy.CacheHitRatioAvailable ||
		!loaded[0].EdgeProxy.P95LatencyAvailable || !origin.SuccessRateAvailable || !origin.P95LatencyAvailable {
		t.Fatalf("schema 1.3 derived-metric validity must remain trusted: %#v", loaded[0])
	}
}

func TestTelemetryHistoryLoadsPreV13SecurityRatesConservatively(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	document := telemetryHistoryDocument{
		SchemaVersion: "1.2",
		Samples: []telemetryHistoryPoint{{
			GeneratedAt: time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339Nano),
			Security: telemetrySecurityHistoryPoint{
				InstanceStartedAt: "2026-08-13T08:00:00Z", Requests: 20, Rejected: 4,
				RequestsPerSecond: 2, RequestRateAvailable: true, RejectedPerSecond: 0.4, RejectedRateAvailable: true,
				P95LatencyMS: 9, P95LatencyAvailable: true,
			},
			EdgeProxy: telemetryEdgeHistoryPoint{
				Available: true, ErrorCountAvailable: true,
				CacheHitRatio: 0.5, CacheHitRatioAvailable: true, P95LatencyMS: 7, P95LatencyAvailable: true,
			},
			Routes: map[string]telemetryRouteHistory{
				"demo": {
					CacheHitRatio: 0.5, CacheHitRatioAvailable: true, P95LatencyMS: 6, P95LatencyAvailable: true,
					Origins: map[string]telemetryOriginHistory{
						"origin-a": {Calls: 10, SuccessRate: 1, SuccessRateAvailable: true, P95LatencyMS: 5, P95LatencyAvailable: true},
					},
				},
			},
		}},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	store := newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled: true, Capacity: 10, SampleInterval: config.Duration{Duration: time.Second}, FilePath: path,
	})
	loaded := store.snapshot(10).Samples
	if len(loaded) != 1 {
		t.Fatalf("history samples=%d, want 1", len(loaded))
	}
	security := loaded[0].Security
	if security.RequestRateAvailable || security.RejectedRateAvailable || security.P95LatencyAvailable {
		t.Fatalf("pre-1.3 SecurityEdge derived-metric validity must be treated as unknown: %#v", security)
	}
	edge := loaded[0].EdgeProxy
	route := loaded[0].Routes["demo"]
	origin := route.Origins["origin-a"]
	if edge.CacheHitRatioAvailable || edge.P95LatencyAvailable || route.CacheHitRatioAvailable || route.P95LatencyAvailable ||
		origin.SuccessRateAvailable || origin.P95LatencyAvailable {
		t.Fatalf("pre-1.3 derived-metric validity must be treated as unknown: edge=%#v route=%#v origin=%#v", edge, route, origin)
	}
	if !edge.ErrorCountAvailable {
		t.Fatal("schema 1.2 corrected EdgeProxy error-count validity must remain trusted")
	}
}

func TestTelemetryHistoryEndpointValidatesLimit(t *testing.T) {
	server := &Server{history: newTelemetryHistoryStore(config.TelemetryHistoryConfig{
		Enabled:        true,
		Capacity:       10,
		SampleInterval: config.Duration{Duration: time.Second},
	})}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/history?limit=invalid", nil)
	response := httptest.NewRecorder()
	server.telemetryHistory(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/history?limit=2", nil)
	response = httptest.NewRecorder()
	server.telemetryHistory(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}
}

func uintString(value uint64) string { return strconv.FormatUint(value, 10) }
