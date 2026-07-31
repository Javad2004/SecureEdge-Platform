package securitylog

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bachelor-project/edgeproxy-security/internal/waf"
)

type Entry struct {
	Sequence     uint64      `json:"sequence"`
	Timestamp    string      `json:"timestamp"`
	Level        string      `json:"level"`
	Event        string      `json:"event"`
	Message      string      `json:"message,omitempty"`
	RequestID    string      `json:"request_id,omitempty"`
	ClientIP     string      `json:"client_ip,omitempty"`
	Method       string      `json:"method,omitempty"`
	Host         string      `json:"host,omitempty"`
	Path         string      `json:"path,omitempty"`
	Route        string      `json:"route,omitempty"`
	Status       int         `json:"status,omitempty"`
	DurationMS   float64     `json:"duration_ms,omitempty"`
	Action       string      `json:"action,omitempty"`
	Score        int         `json:"score,omitempty"`
	RuleIDs      []string    `json:"rule_ids,omitempty"`
	Matches      []waf.Match `json:"matches,omitempty"`
	RateLimitKey string      `json:"rate_limit_key,omitempty"`
	RetryAfterMS int64       `json:"retry_after_ms,omitempty"`
	UserAgent    string      `json:"user_agent,omitempty"`
	Error        string      `json:"error,omitempty"`
	Tags         []string    `json:"tags,omitempty"`
}

type Filter struct {
	Route, RequestID, Method, Event, Level, Action, RuleID, Search string
	Status                                                         int
	Since, Until                                                   time.Time
	BeforeSequence                                                 uint64
	Limit                                                          int
}
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
type Stats struct {
	Enabled        bool   `json:"enabled"`
	Capacity       int    `json:"capacity"`
	Retained       int    `json:"retained"`
	Dropped        uint64 `json:"dropped"`
	OldestSequence uint64 `json:"oldest_sequence,omitempty"`
	NewestSequence uint64 `json:"newest_sequence,omitempty"`
}

type Store struct {
	mu                    sync.RWMutex
	entries               []Entry
	capacity, head, count int
	nextSeq, dropped      uint64
}

func New(capacity int) *Store {
	if capacity <= 0 {
		capacity = 1
	}
	return &Store{entries: make([]Entry, capacity), capacity: capacity, nextSeq: 1}
}
func (s *Store) Append(e Entry) Entry {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	e.Level = strings.ToUpper(strings.TrimSpace(e.Level))
	if e.Level == "" {
		e.Level = "INFO"
	}
	e.Event = trim(e.Event, 128)
	e.Message = trim(e.Message, 2048)
	e.RequestID = trim(e.RequestID, 256)
	e.ClientIP = trim(e.ClientIP, 256)
	e.Method = strings.ToUpper(trim(e.Method, 32))
	e.Host = trim(e.Host, 512)
	e.Path = trim(e.Path, 2048)
	e.Route = trim(e.Route, 256)
	e.Action = strings.ToUpper(trim(e.Action, 32))
	e.UserAgent = trim(e.UserAgent, 512)
	e.Error = trim(e.Error, 2048)
	e.RuleIDs = uniqueUpper(e.RuleIDs)
	e.Tags = uniqueLower(e.Tags)
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Sequence = s.nextSeq
	s.nextSeq++
	if s.count < s.capacity {
		idx := (s.head + s.count) % s.capacity
		s.entries[idx] = e
		s.count++
		return e
	}
	s.entries[s.head] = e
	s.head = (s.head + 1) % s.capacity
	s.dropped++
	return e
}
func (s *Store) Query(f Filter) QueryResult {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := QueryResult{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Capacity: s.capacity, Retained: s.count, Dropped: s.dropped, Entries: make([]Entry, 0, min(f.Limit, s.count)), AppliedFilters: filters(f)}
	if s.count > 0 {
		r.OldestSequence = s.entries[s.head].Sequence
		r.NewestSequence = s.entries[(s.head+s.count-1)%s.capacity].Sequence
	}
	for logical := s.count - 1; logical >= 0; logical-- {
		idx := (s.head + logical) % s.capacity
		e := s.entries[idx]
		if f.BeforeSequence > 0 && e.Sequence >= f.BeforeSequence {
			continue
		}
		if !matches(e, f) {
			continue
		}
		if len(r.Entries) < f.Limit {
			r.Entries = append(r.Entries, clone(e))
			continue
		}
		r.HasMore = true
		break
	}
	r.Returned = len(r.Entries)
	if r.HasMore && r.Returned > 0 {
		r.NextBeforeSequence = r.Entries[r.Returned-1].Sequence
	}
	return r
}
func (s *Store) Clear() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.count
	clear(s.entries)
	s.head = 0
	s.count = 0
	return n
}
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := Stats{Enabled: true, Capacity: s.capacity, Retained: s.count, Dropped: s.dropped}
	if s.count > 0 {
		r.OldestSequence = s.entries[s.head].Sequence
		r.NewestSequence = s.entries[(s.head+s.count-1)%s.capacity].Sequence
	}
	return r
}
func matches(e Entry, f Filter) bool {
	if f.Route != "" && !strings.EqualFold(e.Route, f.Route) {
		return false
	}
	if f.RequestID != "" && e.RequestID != f.RequestID {
		return false
	}
	if f.Method != "" && !strings.EqualFold(e.Method, f.Method) {
		return false
	}
	if f.Event != "" && !strings.EqualFold(e.Event, f.Event) {
		return false
	}
	if f.Level != "" && !strings.EqualFold(e.Level, f.Level) {
		return false
	}
	if f.Action != "" && !strings.EqualFold(e.Action, f.Action) {
		return false
	}
	if f.Status > 0 && e.Status != f.Status {
		return false
	}
	if f.RuleID != "" && !containsFold(e.RuleIDs, f.RuleID) {
		return false
	}
	ts, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err == nil {
		if !f.Since.IsZero() && ts.Before(f.Since) {
			return false
		}
		if !f.Until.IsZero() && ts.After(f.Until) {
			return false
		}
	}
	if f.Search != "" {
		h := strings.ToLower(strings.Join([]string{e.Event, e.Message, e.RequestID, e.ClientIP, e.Method, e.Host, e.Path, e.Route, e.Action, strings.Join(e.RuleIDs, " "), e.UserAgent, e.Error}, " "))
		if !strings.Contains(h, strings.ToLower(f.Search)) {
			return false
		}
	}
	return true
}
func filters(f Filter) map[string]any {
	m := map[string]any{"limit": f.Limit}
	if f.Route != "" {
		m["route"] = f.Route
	}
	if f.RequestID != "" {
		m["request_id"] = f.RequestID
	}
	if f.Method != "" {
		m["method"] = strings.ToUpper(f.Method)
	}
	if f.Event != "" {
		m["event"] = f.Event
	}
	if f.Level != "" {
		m["level"] = strings.ToUpper(f.Level)
	}
	if f.Action != "" {
		m["action"] = strings.ToUpper(f.Action)
	}
	if f.RuleID != "" {
		m["rule_id"] = strings.ToUpper(f.RuleID)
	}
	if f.Status > 0 {
		m["status"] = f.Status
	}
	if f.BeforeSequence > 0 {
		m["before_sequence"] = f.BeforeSequence
	}
	if f.Search != "" {
		m["q"] = f.Search
	}
	return m
}
func clone(e Entry) Entry {
	e.RuleIDs = append([]string(nil), e.RuleIDs...)
	e.Tags = append([]string(nil), e.Tags...)
	e.Matches = append([]waf.Match(nil), e.Matches...)
	return e
}
func uniqueUpper(v []string) []string {
	set := map[string]bool{}
	out := []string{}
	for _, x := range v {
		x = strings.ToUpper(strings.TrimSpace(x))
		if x != "" && !set[x] {
			set[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
func uniqueLower(v []string) []string {
	set := map[string]bool{}
	out := []string{}
	for _, x := range v {
		x = strings.ToLower(strings.TrimSpace(x))
		if x != "" && !set[x] {
			set[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
func containsFold(v []string, x string) bool {
	for _, item := range v {
		if strings.EqualFold(item, x) {
			return true
		}
	}
	return false
}
func trim(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) > n {
		return v[:n]
	}
	return v
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
