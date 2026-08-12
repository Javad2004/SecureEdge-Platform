package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/metrics"
)

const (
	maxTelemetryHistoryFileBytes     int64 = 32 << 20
	maxTelemetryHistoryRetainedBytes int64 = 16 << 20
)

type telemetryHistoryPoint struct {
	GeneratedAt           string                           `json:"generated_at"`
	Security              telemetrySecurityHistoryPoint    `json:"security"`
	EdgeProxy             telemetryEdgeHistoryPoint        `json:"edgeproxy"`
	Routes                map[string]telemetryRouteHistory `json:"routes,omitempty"`
	RouteDetailsTruncated bool                             `json:"route_details_truncated,omitempty"`
}

type telemetrySecurityHistoryPoint struct {
	Requests          uint64  `json:"requests"`
	Rejected          uint64  `json:"rejected"`
	Detections        uint64  `json:"detections"`
	Errors            uint64  `json:"errors"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	RejectedPerSecond float64 `json:"rejected_per_second"`
	P95LatencyMS      float64 `json:"p95_latency_ms"`
	Inflight          int64   `json:"inflight"`
}

type telemetryEdgeHistoryPoint struct {
	Available         bool    `json:"available"`
	Requests          uint64  `json:"requests"`
	Errors            uint64  `json:"errors"`
	CacheHitRatio     float64 `json:"cache_hit_ratio"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	P95LatencyMS      float64 `json:"p95_latency_ms"`
	Inflight          int64   `json:"inflight"`
}

type telemetryRouteHistory struct {
	Requests          uint64                            `json:"requests"`
	Errors            uint64                            `json:"errors"`
	CacheHitRatio     float64                           `json:"cache_hit_ratio"`
	RequestsPerSecond float64                           `json:"requests_per_second"`
	P95LatencyMS      float64                           `json:"p95_latency_ms"`
	Origins           map[string]telemetryOriginHistory `json:"origins,omitempty"`
}

type telemetryOriginHistory struct {
	Calls        uint64  `json:"calls"`
	Failures     uint64  `json:"failures"`
	Timeouts     uint64  `json:"timeouts"`
	SuccessRate  float64 `json:"success_rate"`
	P95LatencyMS float64 `json:"p95_latency_ms"`
}

type edgeMetricsHistoryInput struct {
	SchemaVersion string                           `json:"schema_version"`
	Inflight      int64                            `json:"inflight"`
	Total         edgeCounterHistoryInput          `json:"total"`
	Routes        map[string]edgeRouteHistoryInput `json:"routes"`
}

type edgeCounterHistoryInput struct {
	Requests          uint64  `json:"requests"`
	ClientErrors      uint64  `json:"client_errors"`
	ServerErrors      uint64  `json:"server_errors"`
	ProxyErrors       uint64  `json:"proxy_errors"`
	CacheHitRatio     float64 `json:"cache_hit_ratio"`
	ResponseLatencyMS struct {
		P95 float64 `json:"p95"`
	} `json:"response_latency_ms"`
}

type edgeRouteHistoryInput struct {
	edgeCounterHistoryInput
	Upstreams map[string]edgeOriginHistoryInput `json:"upstreams"`
}

type edgeOriginHistoryInput struct {
	Calls       uint64  `json:"calls"`
	Failures    uint64  `json:"failures"`
	Timeouts    uint64  `json:"timeouts"`
	SuccessRate float64 `json:"success_rate"`
	LatencyMS   struct {
		P95 float64 `json:"p95"`
	} `json:"latency_ms"`
}

type telemetryHistoryDocument struct {
	SchemaVersion string                  `json:"schema_version"`
	Samples       []telemetryHistoryPoint `json:"samples"`
}

type telemetryHistorySnapshot struct {
	Enabled            bool                    `json:"enabled"`
	Persistent         bool                    `json:"persistent"`
	Capacity           int                     `json:"capacity"`
	SampleInterval     string                  `json:"sample_interval"`
	FilePath           string                  `json:"file_path,omitempty"`
	LastError          string                  `json:"last_error,omitempty"`
	RetainedBytes      int64                   `json:"retained_bytes"`
	RetainedLimitBytes int64                   `json:"retained_limit_bytes"`
	Samples            []telemetryHistoryPoint `json:"samples"`
}

type telemetryHistoryStore struct {
	mu               sync.Mutex
	cfg              config.TelemetryHistoryConfig
	samples          []telemetryHistoryPoint
	sampleBytes      []int64
	retainedBytes    int64
	maxRetainedBytes int64
	lastObserved     time.Time
	lastError        string
}

func newTelemetryHistoryStore(cfg config.TelemetryHistoryConfig) *telemetryHistoryStore {
	store := &telemetryHistoryStore{cfg: cfg, maxRetainedBytes: maxTelemetryHistoryRetainedBytes}
	if !cfg.Enabled || strings.TrimSpace(cfg.FilePath) == "" {
		return store
	}
	if err := store.load(); err != nil {
		store.lastError = err.Error()
	}
	return store
}

func (s *telemetryHistoryStore) observe(security metrics.Snapshot, edgeRaw json.RawMessage) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	nowTime := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastObserved.IsZero() && nowTime.Sub(s.lastObserved) < s.cfg.SampleInterval.Duration {
		return
	}

	point := telemetryHistoryPoint{
		GeneratedAt: nowTime.Format(time.RFC3339Nano),
		Security: telemetrySecurityHistoryPoint{
			Requests:          security.Total.Requests,
			Rejected:          rejectedSecurityRequests(security.Total),
			Detections:        security.Total.Detections,
			Errors:            security.Total.Errors,
			RequestsPerSecond: security.RequestsPerSecond,
			P95LatencyMS:      security.Total.Latency.P95MS,
			Inflight:          security.Inflight,
		},
		Routes: map[string]telemetryRouteHistory{},
	}

	var edge edgeMetricsHistoryInput
	if len(edgeRaw) > 0 && json.Unmarshal(edgeRaw, &edge) == nil && strings.TrimSpace(edge.SchemaVersion) != "" {
		point.EdgeProxy = telemetryEdgeHistoryPoint{
			Available:     true,
			Requests:      edge.Total.Requests,
			Errors:        edge.Total.ClientErrors + edge.Total.ServerErrors + edge.Total.ProxyErrors,
			CacheHitRatio: edge.Total.CacheHitRatio,
			P95LatencyMS:  edge.Total.ResponseLatencyMS.P95,
			Inflight:      edge.Inflight,
		}
		for routeName, route := range edge.Routes {
			routePoint := telemetryRouteHistory{
				Requests:      route.Requests,
				Errors:        route.ClientErrors + route.ServerErrors + route.ProxyErrors,
				CacheHitRatio: route.CacheHitRatio,
				P95LatencyMS:  route.ResponseLatencyMS.P95,
				Origins:       map[string]telemetryOriginHistory{},
			}
			for originName, origin := range route.Upstreams {
				routePoint.Origins[originName] = telemetryOriginHistory{
					Calls:        origin.Calls,
					Failures:     origin.Failures,
					Timeouts:     origin.Timeouts,
					SuccessRate:  origin.SuccessRate,
					P95LatencyMS: origin.LatencyMS.P95,
				}
			}
			point.Routes[routeName] = routePoint
		}
	}

	if len(s.samples) > 0 {
		previous := s.samples[len(s.samples)-1]
		if previousTime, err := time.Parse(time.RFC3339Nano, previous.GeneratedAt); err == nil {
			seconds := nowTime.Sub(previousTime).Seconds()
			if seconds > 0 {
				point.Security.RequestsPerSecond = counterRate(previous.Security.Requests, point.Security.Requests, seconds, point.Security.RequestsPerSecond)
				point.Security.RejectedPerSecond = counterRate(previous.Security.Rejected, point.Security.Rejected, seconds, 0)
				if point.EdgeProxy.Available {
					fallback := point.EdgeProxy.RequestsPerSecond
					point.EdgeProxy.RequestsPerSecond = counterRate(previous.EdgeProxy.Requests, point.EdgeProxy.Requests, seconds, fallback)
				}
				for routeName, routePoint := range point.Routes {
					previousRoute, ok := previous.Routes[routeName]
					if ok {
						routePoint.RequestsPerSecond = counterRate(previousRoute.Requests, routePoint.Requests, seconds, 0)
						point.Routes[routeName] = routePoint
					}
				}
			}
		}
	}

	s.appendPointLocked(point)
	s.lastObserved = nowTime
	if s.cfg.FilePath != "" {
		if err := s.persistLocked(); err != nil {
			s.lastError = err.Error()
		} else {
			s.lastError = ""
		}
	}
}

func (s *telemetryHistoryStore) appendPointLocked(point telemetryHistoryPoint) {
	limit := s.maxRetainedBytes
	if limit <= 0 {
		limit = maxTelemetryHistoryRetainedBytes
	}
	size := telemetryHistoryPointSize(point)
	if size > limit && len(point.Routes) > 0 {
		point.Routes = nil
		point.RouteDetailsTruncated = true
		size = telemetryHistoryPointSize(point)
	}
	if size > limit {
		return
	}

	s.samples = append(s.samples, point)
	s.sampleBytes = append(s.sampleBytes, size)
	s.retainedBytes += size
	for len(s.samples) > 0 && (len(s.samples) > s.cfg.Capacity || s.retainedBytes > limit) {
		s.retainedBytes -= s.sampleBytes[0]
		s.samples[0] = telemetryHistoryPoint{}
		s.samples = s.samples[1:]
		s.sampleBytes = s.sampleBytes[1:]
	}
	if len(s.samples) == 0 {
		s.samples = nil
		s.sampleBytes = nil
		s.retainedBytes = 0
	}
}

func telemetryHistoryPointSize(point telemetryHistoryPoint) int64 {
	data, err := json.Marshal(point)
	if err != nil {
		return maxTelemetryHistoryRetainedBytes + 1
	}
	return int64(len(data))
}

func (s *telemetryHistoryStore) snapshot(limit int) telemetryHistorySnapshot {
	if s == nil {
		return telemetryHistorySnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > s.cfg.Capacity {
		limit = s.cfg.Capacity
	}
	start := len(s.samples) - limit
	if start < 0 {
		start = 0
	}
	retainedLimit := s.maxRetainedBytes
	if retainedLimit <= 0 {
		retainedLimit = maxTelemetryHistoryRetainedBytes
	}
	return telemetryHistorySnapshot{
		Enabled:            s.cfg.Enabled,
		Persistent:         s.cfg.Enabled && s.cfg.FilePath != "",
		Capacity:           s.cfg.Capacity,
		SampleInterval:     s.cfg.SampleInterval.String(),
		FilePath:           s.cfg.FilePath,
		LastError:          s.lastError,
		RetainedBytes:      s.retainedBytes,
		RetainedLimitBytes: retainedLimit,
		Samples:            append([]telemetryHistoryPoint(nil), s.samples[start:]...),
	}
}

func (s *telemetryHistoryStore) load() error {
	data, recoveryPath, err := readTelemetryHistoryForLoad(s.cfg.FilePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document telemetryHistoryDocument
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode telemetry history: %w", err)
	}
	if document.SchemaVersion != "1.0" {
		return fmt.Errorf("unsupported telemetry history schema %q", document.SchemaVersion)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode telemetry history: %w", err)
	}
	valid := document.Samples[:0]
	for _, sample := range document.Samples {
		if _, err := time.Parse(time.RFC3339Nano, sample.GeneratedAt); err == nil {
			valid = append(valid, sample)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool { return valid[i].GeneratedAt < valid[j].GeneratedAt })
	for _, sample := range valid {
		s.appendPointLocked(sample)
	}
	if len(s.samples) > 0 {
		s.lastObserved, _ = time.Parse(time.RFC3339Nano, s.samples[len(s.samples)-1].GeneratedAt)
	}
	if recoveryPath != "" {
		if err := os.Rename(recoveryPath, s.cfg.FilePath); err != nil {
			return fmt.Errorf("restore staged telemetry history: %w", err)
		}
	}
	return nil
}

func readTelemetryHistoryForLoad(path string) ([]byte, string, error) {
	data, err := readBoundedTelemetryHistoryFile(path)
	if err == nil {
		return data, "", nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("read telemetry history: %w", err)
	}

	recoveryPath := path + ".bak"
	data, recoveryErr := readBoundedTelemetryHistoryFile(recoveryPath)
	if recoveryErr != nil {
		if errors.Is(recoveryErr, os.ErrNotExist) {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("read staged telemetry history recovery %q: %w", recoveryPath, recoveryErr)
	}
	return data, recoveryPath, nil
}

func readBoundedTelemetryHistoryFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("telemetry history path is not a regular file")
	}
	if info.Size() > maxTelemetryHistoryFileBytes {
		return nil, fmt.Errorf("telemetry history exceeds %d bytes", maxTelemetryHistoryFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxTelemetryHistoryFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxTelemetryHistoryFileBytes {
		return nil, fmt.Errorf("telemetry history exceeds %d bytes", maxTelemetryHistoryFileBytes)
	}
	return data, nil
}

func (s *telemetryHistoryStore) persistLocked() error {
	document := telemetryHistoryDocument{SchemaVersion: "1.0", Samples: s.samples}
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode telemetry history: %w", err)
	}
	data = append(data, '\n')
	if int64(len(data)) > maxTelemetryHistoryFileBytes {
		return fmt.Errorf("encoded telemetry history exceeds %d bytes", maxTelemetryHistoryFileBytes)
	}
	path := s.cfg.FilePath
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create telemetry history directory: %w", err)
	}
	mode := os.FileMode(0o600)
	exists := false
	if info, statErr := os.Stat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return errors.New("telemetry history path is not a regular file")
		}
		exists = true
		mode = info.Mode().Perm()
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("stat telemetry history: %w", statErr)
	}
	tmp, err := os.CreateTemp(dir, ".telemetry-history-*.tmp")
	if err != nil {
		return fmt.Errorf("create telemetry history temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set telemetry history permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write telemetry history: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync telemetry history: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close telemetry history: %w", err)
	}
	staging := path + ".bak"
	if runtime.GOOS == "windows" && exists {
		_ = os.Remove(staging)
		if err := os.Rename(path, staging); err != nil {
			return fmt.Errorf("stage telemetry history: %w", err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		if runtime.GOOS == "windows" && exists {
			_ = os.Rename(staging, path)
		}
		return fmt.Errorf("replace telemetry history: %w", err)
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(staging)
	}
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}

func rejectedSecurityRequests(counter metrics.CounterSnapshot) uint64 {
	return counter.Blocked + counter.RateLimited + counter.OverloadRejected + counter.BannedRejected
}

func counterRate(previous, current uint64, seconds, fallback float64) float64 {
	if seconds <= 0 {
		return fallback
	}
	if current < previous {
		return fallback
	}
	return float64(current-previous) / seconds
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values are not allowed")
}
