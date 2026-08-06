package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
		edge := json.RawMessage(`{"inflight":1,"total":{"requests":` + uintString(requestCount) + `,"cache_hit_ratio":0.5,"response_latency_ms":{"p95":4.5}},"routes":{"demo":{"requests":` + uintString(requestCount) + `,"cache_hit_ratio":0.5,"response_latency_ms":{"p95":4.5},"upstreams":{"origin-a":{"calls":` + uintString(requestCount) + `,"success_rate":1,"latency_ms":{"p95":3.5}}}}}}`)
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
