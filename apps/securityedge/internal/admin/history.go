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
	InstanceStartedAt     string  `json:"instance_started_at,omitempty"`
	Requests              uint64  `json:"requests"`
	Canceled              uint64  `json:"canceled"`
	Rejected              uint64  `json:"rejected"`
	Detections            uint64  `json:"detections"`
	Errors                uint64  `json:"errors"`
	RequestsPerSecond     float64 `json:"requests_per_second"`
	RequestRateAvailable  bool    `json:"request_rate_available"`
	RejectedPerSecond     float64 `json:"rejected_per_second"`
	RejectedRateAvailable bool    `json:"rejected_rate_available"`
	P95LatencyMS          float64 `json:"p95_latency_ms"`
	P95LatencyAvailable   bool    `json:"p95_latency_available"`
	Inflight              int64   `json:"inflight"`
}

type telemetryEdgeHistoryPoint struct {
	Available              bool    `json:"available"`
	InstanceStartedAt      string  `json:"instance_started_at,omitempty"`
	Requests               uint64  `json:"requests"`
	Errors                 uint64  `json:"errors"`
	ErrorCountAvailable    bool    `json:"error_count_available"`
	CacheHitRatio          float64 `json:"cache_hit_ratio"`
	CacheHitRatioAvailable bool    `json:"cache_hit_ratio_available"`
	RequestsPerSecond      float64 `json:"requests_per_second"`
	RequestRateAvailable   bool    `json:"request_rate_available"`
	P95LatencyMS           float64 `json:"p95_latency_ms"`
	P95LatencyAvailable    bool    `json:"p95_latency_available"`
	Inflight               int64   `json:"inflight"`
}

type telemetryRouteHistory struct {
	Requests               uint64                            `json:"requests"`
	Errors                 uint64                            `json:"errors"`
	ErrorCountAvailable    bool                              `json:"error_count_available"`
	CacheHitRatio          float64                           `json:"cache_hit_ratio"`
	CacheHitRatioAvailable bool                              `json:"cache_hit_ratio_available"`
	RequestsPerSecond      float64                           `json:"requests_per_second"`
	RequestRateAvailable   bool                              `json:"request_rate_available"`
	P95LatencyMS           float64                           `json:"p95_latency_ms"`
	P95LatencyAvailable    bool                              `json:"p95_latency_available"`
	Origins                map[string]telemetryOriginHistory `json:"origins,omitempty"`
}

type telemetryOriginHistory struct {
	Calls                uint64  `json:"calls"`
	Canceled             uint64  `json:"canceled"`
	Failures             uint64  `json:"failures"`
	Timeouts             uint64  `json:"timeouts"`
	SuccessRate          float64 `json:"success_rate"`
	SuccessRateAvailable bool    `json:"success_rate_available"`
	P95LatencyMS         float64 `json:"p95_latency_ms"`
	P95LatencyAvailable  bool    `json:"p95_latency_available"`
}

type edgeMetricsHistoryInput struct {
	SchemaVersion string                           `json:"schema_version"`
	StartedAt     string                           `json:"started_at"`
	Inflight      int64                            `json:"inflight"`
	Total         edgeCounterHistoryInput          `json:"total"`
	Routes        map[string]edgeRouteHistoryInput `json:"routes"`
}

type edgeCounterHistoryInput struct {
	Requests          uint64  `json:"requests"`
	ClientErrors      uint64  `json:"client_errors"`
	ServerErrors      uint64  `json:"server_errors"`
	ProxyErrors       uint64  `json:"proxy_errors"`
	CacheHits         uint64  `json:"cache_hits"`
	CacheMisses       uint64  `json:"cache_misses"`
	CacheHitRatio     float64 `json:"cache_hit_ratio"`
	ResponseLatencyMS struct {
		Count uint64  `json:"count"`
		P95   float64 `json:"p95"`
	} `json:"response_latency_ms"`
}

type edgeRouteHistoryInput struct {
	edgeCounterHistoryInput
	Upstreams map[string]edgeOriginHistoryInput `json:"upstreams"`
}

type edgeOriginHistoryInput struct {
	Calls       uint64  `json:"calls"`
	Canceled    uint64  `json:"canceled"`
	Failures    uint64  `json:"failures"`
	Timeouts    uint64  `json:"timeouts"`
	SuccessRate float64 `json:"success_rate"`
	LatencyMS   struct {
		Count uint64  `json:"count"`
		P95   float64 `json:"p95"`
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
	rateGapPending   bool
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
	if !s.lastObserved.IsZero() && nowTime.Before(s.lastObserved) {
		// A wall-clock rollback (or a future-dated persisted sample) must not
		// freeze collection until the clock catches up. Future samples cannot
		// be ordered truthfully against the current wall clock, so discard
		// them and force one explicit rate gap before resuming normal sampling.
		s.discardSamplesAfterLocked(nowTime)
		s.rateGapPending = true
	}
	if !s.lastObserved.IsZero() && nowTime.Sub(s.lastObserved) < s.cfg.SampleInterval.Duration {
		return
	}

	point := telemetryHistoryPoint{
		GeneratedAt: nowTime.Format(time.RFC3339Nano),
		Security: telemetrySecurityHistoryPoint{
			InstanceStartedAt:   strings.TrimSpace(security.StartedAt),
			Requests:            security.Total.Requests,
			Canceled:            security.Total.CanceledRequests,
			Rejected:            rejectedSecurityRequests(security.Total),
			Detections:          security.Total.Detections,
			Errors:              security.Total.Errors,
			P95LatencyMS:        security.Total.Latency.P95MS,
			P95LatencyAvailable: security.Total.Requests > security.Total.CanceledRequests,
			Inflight:            security.Inflight,
		},
		Routes: map[string]telemetryRouteHistory{},
	}

	var edge edgeMetricsHistoryInput
	if len(edgeRaw) > 0 && json.Unmarshal(edgeRaw, &edge) == nil && strings.TrimSpace(edge.SchemaVersion) != "" {
		point.EdgeProxy = telemetryEdgeHistoryPoint{
			Available:              true,
			InstanceStartedAt:      strings.TrimSpace(edge.StartedAt),
			Requests:               edge.Total.Requests,
			Errors:                 edge.Total.ClientErrors + edge.Total.ServerErrors,
			ErrorCountAvailable:    true,
			CacheHitRatio:          edge.Total.CacheHitRatio,
			CacheHitRatioAvailable: edge.Total.CacheHits+edge.Total.CacheMisses > 0,
			P95LatencyMS:           edge.Total.ResponseLatencyMS.P95,
			P95LatencyAvailable:    edge.Total.ResponseLatencyMS.Count > 0,
			Inflight:               edge.Inflight,
		}
		for routeName, route := range edge.Routes {
			routePoint := telemetryRouteHistory{
				Requests:               route.Requests,
				Errors:                 route.ClientErrors + route.ServerErrors,
				ErrorCountAvailable:    true,
				CacheHitRatio:          route.CacheHitRatio,
				CacheHitRatioAvailable: route.CacheHits+route.CacheMisses > 0,
				P95LatencyMS:           route.ResponseLatencyMS.P95,
				P95LatencyAvailable:    route.ResponseLatencyMS.Count > 0,
				Origins:                map[string]telemetryOriginHistory{},
			}
			for originName, origin := range route.Upstreams {
				routePoint.Origins[originName] = telemetryOriginHistory{
					Calls:                origin.Calls,
					Canceled:             origin.Canceled,
					Failures:             origin.Failures,
					Timeouts:             origin.Timeouts,
					SuccessRate:          origin.SuccessRate,
					SuccessRateAvailable: origin.LatencyMS.Count > 0,
					P95LatencyMS:         origin.LatencyMS.P95,
					P95LatencyAvailable:  origin.LatencyMS.Count > 0,
				}
			}
			point.Routes[routeName] = routePoint
		}
	}

	if len(s.samples) > 0 && !s.rateGapPending {
		previous := s.samples[len(s.samples)-1]
		if previousTime, err := time.Parse(time.RFC3339Nano, previous.GeneratedAt); err == nil {
			seconds := nowTime.Sub(previousTime).Seconds()
			if seconds > 0 {
				sameSecurityEdgeInstance := point.Security.InstanceStartedAt != "" &&
					point.Security.InstanceStartedAt == previous.Security.InstanceStartedAt
				if sameSecurityEdgeInstance && point.Security.Requests >= previous.Security.Requests {
					point.Security.RequestsPerSecond = float64(point.Security.Requests-previous.Security.Requests) / seconds
					point.Security.RequestRateAvailable = true
				}
				if sameSecurityEdgeInstance && point.Security.Rejected >= previous.Security.Rejected {
					point.Security.RejectedPerSecond = float64(point.Security.Rejected-previous.Security.Rejected) / seconds
					point.Security.RejectedRateAvailable = true
				}
				sameEdgeProxyInstance := point.EdgeProxy.Available && previous.EdgeProxy.Available &&
					point.EdgeProxy.InstanceStartedAt != "" && point.EdgeProxy.InstanceStartedAt == previous.EdgeProxy.InstanceStartedAt
				if sameEdgeProxyInstance && point.EdgeProxy.Requests >= previous.EdgeProxy.Requests {
					point.EdgeProxy.RequestsPerSecond = float64(point.EdgeProxy.Requests-previous.EdgeProxy.Requests) / seconds
					point.EdgeProxy.RequestRateAvailable = true
				}
				if sameEdgeProxyInstance {
					for routeName, routePoint := range point.Routes {
						previousRoute, ok := previous.Routes[routeName]
						if ok && routePoint.Requests >= previousRoute.Requests {
							routePoint.RequestsPerSecond = float64(routePoint.Requests-previousRoute.Requests) / seconds
							routePoint.RequestRateAvailable = true
							point.Routes[routeName] = routePoint
						}
					}
				}
			}
		}
	}

	s.appendPointLocked(point)
	s.lastObserved = nowTime
	s.rateGapPending = false
	if s.cfg.FilePath != "" {
		if err := s.persistLocked(); err != nil {
			s.lastError = err.Error()
		} else {
			s.lastError = ""
		}
	}
}

func (s *telemetryHistoryStore) discardSamplesAfterLocked(cutoff time.Time) int {
	if len(s.samples) == 0 {
		s.lastObserved = time.Time{}
		return 0
	}

	keptSamples := make([]telemetryHistoryPoint, 0, len(s.samples))
	keptBytes := make([]int64, 0, len(s.sampleBytes))
	var retained int64
	dropped := 0
	for i, sample := range s.samples {
		observedAt, err := time.Parse(time.RFC3339Nano, sample.GeneratedAt)
		if err == nil && observedAt.After(cutoff) {
			dropped++
			continue
		}
		keptSamples = append(keptSamples, sample)
		if i < len(s.sampleBytes) {
			keptBytes = append(keptBytes, s.sampleBytes[i])
			retained += s.sampleBytes[i]
		}
	}
	s.samples = keptSamples
	s.sampleBytes = keptBytes
	s.retainedBytes = retained
	s.lastObserved = time.Time{}
	if len(s.samples) > 0 {
		s.lastObserved, _ = time.Parse(time.RFC3339Nano, s.samples[len(s.samples)-1].GeneratedAt)
	}
	return dropped
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
	if document.SchemaVersion != "1.0" && document.SchemaVersion != "1.1" && document.SchemaVersion != "1.2" && document.SchemaVersion != "1.3" && document.SchemaVersion != "1.4" && document.SchemaVersion != "1.5" {
		return fmt.Errorf("unsupported telemetry history schema %q", document.SchemaVersion)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode telemetry history: %w", err)
	}
	for i := range document.Samples {
		if document.SchemaVersion != "1.3" && document.SchemaVersion != "1.4" && document.SchemaVersion != "1.5" {
			document.Samples[i].Security.RequestRateAvailable = false
			document.Samples[i].Security.RejectedRateAvailable = false
			document.Samples[i].Security.P95LatencyAvailable = false
			document.Samples[i].EdgeProxy.CacheHitRatioAvailable = false
			document.Samples[i].EdgeProxy.P95LatencyAvailable = false
			for name, route := range document.Samples[i].Routes {
				route.CacheHitRatioAvailable = false
				route.P95LatencyAvailable = false
				for originName, origin := range route.Origins {
					origin.SuccessRateAvailable = false
					origin.P95LatencyAvailable = false
					route.Origins[originName] = origin
				}
				document.Samples[i].Routes[name] = route
			}
		}
		if document.SchemaVersion == "1.0" || document.SchemaVersion == "1.1" {
			document.Samples[i].EdgeProxy.ErrorCountAvailable = false
			for name, route := range document.Samples[i].Routes {
				route.ErrorCountAvailable = false
				document.Samples[i].Routes[name] = route
			}
		}
	}
	valid := document.Samples[:0]
	loadedAt := time.Now().UTC()
	futureSamples := 0
	for _, sample := range document.Samples {
		observedAt, err := time.Parse(time.RFC3339Nano, sample.GeneratedAt)
		if err != nil {
			continue
		}
		if observedAt.After(loadedAt) {
			futureSamples++
			continue
		}
		valid = append(valid, sample)
	}
	if futureSamples > 0 {
		s.rateGapPending = true
		s.lastError = fmt.Sprintf("ignored %d future-dated telemetry history sample(s) after a wall-clock rollback or clock correction", futureSamples)
	}
	sort.SliceStable(valid, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, valid[i].GeneratedAt)
		right, _ := time.Parse(time.RFC3339Nano, valid[j].GeneratedAt)
		return left.Before(right)
	})
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
	document := telemetryHistoryDocument{SchemaVersion: "1.5", Samples: s.samples}
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

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values are not allowed")
}
