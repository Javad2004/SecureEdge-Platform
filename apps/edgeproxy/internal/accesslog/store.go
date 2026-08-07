package accesslog

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxTextLength = 2048
)

// Entry is a structured operational event retained by the in-memory log store.
// Request bodies and authorization/cookie headers are intentionally never stored.
type Entry struct {
	Sequence           uint64   `json:"sequence"`
	Timestamp          string   `json:"timestamp"`
	Level              string   `json:"level"`
	Event              string   `json:"event"`
	Message            string   `json:"message,omitempty"`
	RequestID          string   `json:"request_id,omitempty"`
	ClientIP           string   `json:"client_ip,omitempty"`
	Method             string   `json:"method,omitempty"`
	Host               string   `json:"host,omitempty"`
	Path               string   `json:"path,omitempty"`
	Query              string   `json:"query,omitempty"`
	Route              string   `json:"route,omitempty"`
	Status             int      `json:"status,omitempty"`
	StatusClass        string   `json:"status_class,omitempty"`
	BytesIn            uint64   `json:"bytes_in,omitempty"`
	BytesOut           uint64   `json:"bytes_out,omitempty"`
	DurationMS         float64  `json:"duration_ms,omitempty"`
	CacheStatus        string   `json:"cache_status,omitempty"`
	Upstream           string   `json:"upstream,omitempty"`
	UpstreamStatus     int      `json:"upstream_status,omitempty"`
	UpstreamDurationMS float64  `json:"upstream_duration_ms,omitempty"`
	UpstreamCalls      uint64   `json:"upstream_calls,omitempty"`
	Attempt            int      `json:"attempt,omitempty"`
	Retries            uint64   `json:"retries,omitempty"`
	Retry              bool     `json:"retry,omitempty"`
	ProxyError         bool     `json:"proxy_error,omitempty"`
	Timeout            bool     `json:"timeout,omitempty"`
	Healthy            *bool    `json:"healthy,omitempty"`
	Error              string   `json:"error,omitempty"`
	UserAgent          string   `json:"user_agent,omitempty"`
	Tags               []string `json:"tags,omitempty"`
}

// Filter selects entries from the bounded log store.
type Filter struct {
	Route          string
	Upstream       string
	RequestID      string
	Method         string
	Event          string
	Level          string
	CacheStatus    string
	Status         int
	StatusClass    string
	MinDurationMS  float64
	Since          time.Time
	Until          time.Time
	BeforeSequence uint64
	Search         string
	Limit          int
}

// QueryResult is returned by Store.Query and contains cursor metadata.
type QueryResult struct {
	GeneratedAt        string         `json:"generated_at"`
	Capacity           int            `json:"capacity"`
	Retained           int            `json:"retained"`
	Dropped            uint64         `json:"dropped"`
	OldestSequence     uint64         `json:"oldest_sequence,omitempty"`
	NewestSequence     uint64         `json:"newest_sequence,omitempty"`
	Returned           int            `json:"returned"`
	HasMore            bool           `json:"has_more"`
	NextBeforeSequence uint64         `json:"next_before_sequence,omitempty"`
	AppliedFilters     map[string]any `json:"applied_filters,omitempty"`
	Entries            []Entry        `json:"entries"`
}

// Stats describes current log-store utilization.
type Stats struct {
	Enabled        bool   `json:"enabled"`
	Capacity       int    `json:"capacity"`
	Retained       int    `json:"retained"`
	Dropped        uint64 `json:"dropped"`
	OldestSequence uint64 `json:"oldest_sequence,omitempty"`
	NewestSequence uint64 `json:"newest_sequence,omitempty"`
}

// Store is a concurrency-safe, bounded ring buffer. It deliberately keeps only
// recent operational events so an admin endpoint cannot cause unbounded memory use.
type Store struct {
	mu       sync.RWMutex
	entries  []Entry
	capacity int
	head     int
	count    int
	nextSeq  uint64
	dropped  uint64
}

func New(capacity int) *Store {
	if capacity <= 0 {
		capacity = 1
	}
	return &Store{entries: make([]Entry, capacity), capacity: capacity, nextSeq: 1}
}

// Append stores one event and returns the normalized entry including sequence
// number and timestamp.
func (s *Store) Append(entry Entry) Entry {
	if s == nil {
		return entry
	}
	entry = normalize(entry)

	s.mu.Lock()
	defer s.mu.Unlock()
	entry.Sequence = s.nextSeq
	s.nextSeq++

	if s.count < s.capacity {
		index := (s.head + s.count) % s.capacity
		s.entries[index] = entry
		s.count++
		return entry
	}

	s.entries[s.head] = entry
	s.head = (s.head + 1) % s.capacity
	s.dropped++
	return entry
}

func (s *Store) Query(filter Filter) QueryResult {
	if s == nil {
		return QueryResult{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Entries: []Entry{}}
	}
	if filter.Limit <= 0 {
		filter.Limit = 100
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	result := QueryResult{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Capacity:       s.capacity,
		Retained:       s.count,
		Dropped:        s.dropped,
		Entries:        make([]Entry, 0, min(filter.Limit, s.count)),
		AppliedFilters: appliedFilters(filter),
	}
	if s.count > 0 {
		result.OldestSequence = s.entries[s.head].Sequence
		newestIndex := (s.head + s.count - 1) % s.capacity
		result.NewestSequence = s.entries[newestIndex].Sequence
	}

	searchLower := strings.ToLower(strings.TrimSpace(filter.Search))
	statusClassLower := strings.ToLower(strings.TrimSpace(filter.StatusClass))
	for logical := s.count - 1; logical >= 0; logical-- {
		index := (s.head + logical) % s.capacity
		entry := s.entries[index]
		if filter.BeforeSequence > 0 && entry.Sequence >= filter.BeforeSequence {
			continue
		}
		if !matches(entry, filter, searchLower, statusClassLower) {
			continue
		}
		if len(result.Entries) < filter.Limit {
			result.Entries = append(result.Entries, cloneEntry(entry))
			continue
		}
		result.HasMore = true
		break
	}
	result.Returned = len(result.Entries)
	if result.HasMore && result.Returned > 0 {
		result.NextBeforeSequence = result.Entries[result.Returned-1].Sequence
	}
	return result
}

func (s *Store) Clear() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := s.count
	clear(s.entries)
	s.head = 0
	s.count = 0
	return removed
}

func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{Enabled: false}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := Stats{Enabled: true, Capacity: s.capacity, Retained: s.count, Dropped: s.dropped}
	if s.count > 0 {
		stats.OldestSequence = s.entries[s.head].Sequence
		stats.NewestSequence = s.entries[(s.head+s.count-1)%s.capacity].Sequence
	}
	return stats
}

func normalize(entry Entry) Entry {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	entry.Level = strings.ToUpper(strings.TrimSpace(entry.Level))
	if entry.Level == "" {
		entry.Level = "INFO"
	}
	entry.Event = truncate(strings.TrimSpace(entry.Event), 128)
	entry.Message = truncate(strings.TrimSpace(entry.Message), defaultMaxTextLength)
	entry.RequestID = truncate(strings.TrimSpace(entry.RequestID), 256)
	entry.ClientIP = truncate(strings.TrimSpace(entry.ClientIP), 256)
	entry.Method = strings.ToUpper(truncate(strings.TrimSpace(entry.Method), 32))
	entry.Host = truncate(strings.TrimSpace(entry.Host), 512)
	entry.Path = truncate(strings.TrimSpace(entry.Path), defaultMaxTextLength)
	entry.Query = truncate(strings.TrimSpace(entry.Query), defaultMaxTextLength)
	entry.Route = truncate(strings.TrimSpace(entry.Route), 256)
	entry.CacheStatus = strings.ToUpper(truncate(strings.TrimSpace(entry.CacheStatus), 32))
	entry.Upstream = truncate(strings.TrimSpace(entry.Upstream), defaultMaxTextLength)
	entry.Error = truncate(strings.TrimSpace(entry.Error), defaultMaxTextLength)
	entry.UserAgent = truncate(strings.TrimSpace(entry.UserAgent), 512)
	if entry.StatusClass == "" {
		status := entry.Status
		if status == 0 {
			status = entry.UpstreamStatus
		}
		entry.StatusClass = statusClass(status)
	}
	if entry.DurationMS < 0 {
		entry.DurationMS = 0
	}
	if entry.UpstreamDurationMS < 0 {
		entry.UpstreamDurationMS = 0
	}
	if len(entry.Tags) > 0 {
		tags := make([]string, 0, len(entry.Tags))
		seen := make(map[string]struct{}, len(entry.Tags))
		for _, raw := range entry.Tags {
			tag := truncate(strings.ToLower(strings.TrimSpace(raw)), 64)
			if tag == "" {
				continue
			}
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		entry.Tags = tags
	}
	return entry
}

func matches(entry Entry, filter Filter, searchLower, statusClassLower string) bool {
	if filter.Route != "" && !strings.EqualFold(entry.Route, filter.Route) {
		return false
	}
	if filter.Upstream != "" && entry.Upstream != filter.Upstream {
		return false
	}
	if filter.RequestID != "" && entry.RequestID != filter.RequestID {
		return false
	}
	if filter.Method != "" && !strings.EqualFold(entry.Method, filter.Method) {
		return false
	}
	if filter.Event != "" && !strings.EqualFold(entry.Event, filter.Event) {
		return false
	}
	if filter.Level != "" && !strings.EqualFold(entry.Level, filter.Level) {
		return false
	}
	if filter.CacheStatus != "" && !strings.EqualFold(entry.CacheStatus, filter.CacheStatus) {
		return false
	}
	if filter.Status > 0 && entry.Status != filter.Status && entry.UpstreamStatus != filter.Status {
		return false
	}
	if statusClassLower != "" && entry.StatusClass != statusClassLower && statusClass(entry.UpstreamStatus) != statusClassLower {
		return false
	}
	if filter.MinDurationMS > 0 && entry.DurationMS < filter.MinDurationMS && entry.UpstreamDurationMS < filter.MinDurationMS {
		return false
	}
	entryTime, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err == nil {
		if !filter.Since.IsZero() && entryTime.Before(filter.Since) {
			return false
		}
		if !filter.Until.IsZero() && entryTime.After(filter.Until) {
			return false
		}
	}
	if searchLower != "" {
		haystack := strings.ToLower(strings.Join([]string{
			entry.Event, entry.Message, entry.RequestID, entry.ClientIP, entry.Method,
			entry.Host, entry.Path, entry.Query, entry.Route, entry.CacheStatus,
			entry.Upstream, entry.Error, entry.UserAgent,
		}, " "))
		if !strings.Contains(haystack, searchLower) {
			return false
		}
	}
	return true
}

func appliedFilters(filter Filter) map[string]any {
	out := map[string]any{"limit": filter.Limit}
	if filter.Route != "" {
		out["route"] = filter.Route
	}
	if filter.Upstream != "" {
		out["upstream"] = filter.Upstream
	}
	if filter.RequestID != "" {
		out["request_id"] = filter.RequestID
	}
	if filter.Method != "" {
		out["method"] = strings.ToUpper(filter.Method)
	}
	if filter.Event != "" {
		out["event"] = filter.Event
	}
	if filter.Level != "" {
		out["level"] = strings.ToUpper(filter.Level)
	}
	if filter.CacheStatus != "" {
		out["cache"] = strings.ToUpper(filter.CacheStatus)
	}
	if filter.Status > 0 {
		out["status"] = filter.Status
	}
	if filter.StatusClass != "" {
		out["status_class"] = strings.ToLower(filter.StatusClass)
	}
	if filter.MinDurationMS > 0 {
		out["min_duration_ms"] = filter.MinDurationMS
	}
	if !filter.Since.IsZero() {
		out["since"] = filter.Since.UTC().Format(time.RFC3339Nano)
	}
	if !filter.Until.IsZero() {
		out["until"] = filter.Until.UTC().Format(time.RFC3339Nano)
	}
	if filter.BeforeSequence > 0 {
		out["before_sequence"] = filter.BeforeSequence
	}
	if filter.Search != "" {
		out["q"] = filter.Search
	}
	return out
}

func cloneEntry(entry Entry) Entry {
	entry.Tags = append([]string(nil), entry.Tags...)
	if entry.Healthy != nil {
		value := *entry.Healthy
		entry.Healthy = &value
	}
	return entry
}

func statusClass(status int) string {
	if status < 100 || status > 599 {
		return ""
	}
	return string(rune('0'+status/100)) + "xx"
}

func truncate(value string, maxLength int) string {
	if len(value) <= maxLength {
		return value
	}
	return value[:maxLength]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
