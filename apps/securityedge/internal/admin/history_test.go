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
		edge := json.RawMessage(`{"schema_version":"2.0","inflight":1,"total":{"requests":` + uintString(requestCount) + `,"cache_hit_ratio":0.5,"response_latency_ms":{"p95":4.5}},"routes":{"demo":{"requests":` + uintString(requestCount) + `,"cache_hit_ratio":0.5,"response_latency_ms":{"p95":4.5},"upstreams":{"origin-a":{"calls":` + uintString(requestCount) + `,"success_rate":1,"latency_ms":{"p95":3.5}}}}}}`)
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

	reloaded := newTelemetryHistoryStore(store.cfg)
	reloadedSnapshot := reloaded.snapshot(10)
	if len(reloadedSnapshot.Samples) != 2 {
		t.Fatalf("expected 2 reloaded samples, got %d", len(reloadedSnapshot.Samples))
	}
	if got := reloadedSnapshot.Samples[1].Routes["demo"].Origins["origin-a"].Calls; got != 3 {
		t.Fatalf("unexpected reloaded origin calls: %d", got)
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
