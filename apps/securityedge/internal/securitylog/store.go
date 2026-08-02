package securitylog

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/waf"
)

type Entry struct {
	Sequence             uint64      `json:"sequence"`
	Timestamp            string      `json:"timestamp"`
	Level                string      `json:"level"`
	Event                string      `json:"event"`
	Message              string      `json:"message,omitempty"`
	RequestID            string      `json:"request_id,omitempty"`
	ClientIP             string      `json:"client_ip,omitempty"`
	Method               string      `json:"method,omitempty"`
	Host                 string      `json:"host,omitempty"`
	Path                 string      `json:"path,omitempty"`
	PathFingerprint      string      `json:"path_fingerprint,omitempty"`
	Route                string      `json:"route,omitempty"`
	Status               int         `json:"status,omitempty"`
	DurationMS           float64     `json:"duration_ms,omitempty"`
	Action               string      `json:"action,omitempty"`
	Reason               string      `json:"reason,omitempty"`
	Score                int         `json:"score,omitempty"`
	RuleIDs              []string    `json:"rule_ids,omitempty"`
	Matches              []waf.Match `json:"matches,omitempty"`
	RetryAfterMS         int64       `json:"retry_after_ms,omitempty"`
	UserAgentFingerprint string      `json:"user_agent_fingerprint,omitempty"`
	Error                string      `json:"error,omitempty"`
	AutoBanned           bool        `json:"auto_banned,omitempty"`
	MatchLimitReached    bool        `json:"match_limit_reached,omitempty"`
	Tags                 []string    `json:"tags,omitempty"`
}

type Filter struct {
	Route, RequestID, ClientIP, Method, Event, Level, Action, Reason, RuleID, Search string
	Status                                                                           int
	Since, Until                                                                     time.Time
	BeforeSequence                                                                   uint64
	Limit                                                                            int
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
	FileEnabled    bool   `json:"file_enabled"`
	FilePath       string `json:"file_path,omitempty"`
	FileBytes      int64  `json:"file_bytes,omitempty"`
	FileErrors     uint64 `json:"file_errors"`
}

type Store struct {
	mu                    sync.RWMutex
	entries               []Entry
	capacity, head, count int
	nextSeq, dropped      uint64
	file                  *os.File
	filePath              string
	fileBytes             int64
	maxFileBytes          int64
	maxBackups            int
	fileErrors            uint64
}

func New(capacity int) *Store {
	s, _ := NewWithConfig(config.LogStoreConfig{Capacity: capacity})
	return s
}

func NewWithConfig(cfg config.LogStoreConfig) (*Store, error) {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 1
	}
	s := &Store{entries: make([]Entry, cfg.Capacity), capacity: cfg.Capacity, nextSeq: 1, filePath: strings.TrimSpace(cfg.FilePath), maxFileBytes: cfg.MaxFileBytes, maxBackups: cfg.MaxBackups}
	if s.filePath == "" {
		return s, nil
	}
	if s.maxFileBytes <= 0 {
		s.maxFileBytes = 20 << 20
	}
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0o750); err != nil {
		return nil, fmt.Errorf("create security log directory: %w", err)
	}
	file, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open security log file: %w", err)
	}
	info, _ := file.Stat()
	if info != nil {
		s.fileBytes = info.Size()
	}
	s.file = file
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
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
	e.PathFingerprint = trim(e.PathFingerprint, 128)
	e.Route = trim(e.Route, 256)
	e.Action = strings.ToUpper(trim(e.Action, 32))
	e.Reason = strings.ToLower(trim(e.Reason, 128))
	e.UserAgentFingerprint = trim(e.UserAgentFingerprint, 128)
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
	} else {
		s.entries[s.head] = e
		s.head = (s.head + 1) % s.capacity
		s.dropped++
	}
	s.writeFileLocked(e)
	return e
}

func (s *Store) writeFileLocked(e Entry) {
	if s.file == nil {
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		s.fileErrors++
		return
	}
	data = append(data, '\n')
	if s.fileBytes+int64(len(data)) > s.maxFileBytes {
		if err := s.rotateLocked(); err != nil {
			s.fileErrors++
			return
		}
	}
	n, err := s.file.Write(data)
	if err != nil {
		s.fileErrors++
		return
	}
	s.fileBytes += int64(n)
}

func (s *Store) rotateLocked() error {
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			s.file = nil
			return fmt.Errorf("close security log before rotation: %w", err)
		}
		s.file = nil
	}

	var rotationErr error
	if s.maxBackups > 0 {
		oldest := fmt.Sprintf("%s.%d", s.filePath, s.maxBackups)
		if err := removeIfExists(oldest); err != nil {
			rotationErr = fmt.Errorf("remove oldest security log backup: %w", err)
		}
		for i := s.maxBackups - 1; rotationErr == nil && i >= 1; i-- {
			src := fmt.Sprintf("%s.%d", s.filePath, i)
			dst := fmt.Sprintf("%s.%d", s.filePath, i+1)
			if err := replaceRename(src, dst); err != nil {
				rotationErr = fmt.Errorf("rotate security log backup %q to %q: %w", src, dst, err)
			}
		}
		if rotationErr == nil {
			if err := replaceRename(s.filePath, s.filePath+".1"); err != nil {
				rotationErr = fmt.Errorf("rotate active security log: %w", err)
			}
		}
	} else if err := removeIfExists(s.filePath); err != nil {
		rotationErr = fmt.Errorf("remove active security log: %w", err)
	}

	if rotationErr != nil {
		reopenErr := s.reopenAppendLocked()
		return errors.Join(rotationErr, reopenErr)
	}

	file, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		reopenErr := s.reopenAppendLocked()
		return errors.Join(fmt.Errorf("open new security log after rotation: %w", err), reopenErr)
	}
	s.file, s.fileBytes = file, 0
	return nil
}

func (s *Store) reopenAppendLocked() error {
	file, err := os.OpenFile(s.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("reopen security log after rotation failure: %w", err)
	}
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return fmt.Errorf("stat security log after rotation failure: %w", statErr)
	}
	s.file = file
	s.fileBytes = info.Size()
	return nil
}

func replaceRename(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := removeIfExists(dst); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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

func (s *Store) Export(w io.Writer, f Filter, format string) error {
	if f.Limit <= 0 || f.Limit > s.capacity {
		f.Limit = s.capacity
	}
	entries := s.Query(f).Entries
	switch strings.ToLower(format) {
	case "csv":
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"sequence", "timestamp", "level", "event", "request_id", "client_ip", "method", "host", "path", "path_fingerprint", "route", "status", "action", "reason", "score", "rule_ids", "duration_ms", "auto_banned"}); err != nil {
			return err
		}
		for _, e := range entries {
			row := []string{strconv.FormatUint(e.Sequence, 10), e.Timestamp, e.Level, e.Event, e.RequestID, e.ClientIP, e.Method, e.Host, e.Path, e.PathFingerprint, e.Route, strconv.Itoa(e.Status), e.Action, e.Reason, strconv.Itoa(e.Score), strings.Join(e.RuleIDs, "|"), strconv.FormatFloat(e.DurationMS, 'f', 3, 64), strconv.FormatBool(e.AutoBanned)}
			for i := range row {
				row[i] = safeCSVCell(row[i])
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	case "ndjson", "jsonl":
		bw := bufio.NewWriter(w)
		enc := json.NewEncoder(bw)
		for _, e := range entries {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return bw.Flush()
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func (s *Store) Clear() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.count
	clear(s.entries)
	s.head = 0
	s.count = 0

	var errs []error
	if s.file != nil {
		if err := s.file.Truncate(0); err != nil {
			errs = append(errs, fmt.Errorf("truncate security log: %w", err))
		} else {
			s.fileBytes = 0
		}
	}
	if s.filePath != "" {
		for i := 1; i <= s.maxBackups; i++ {
			backup := fmt.Sprintf("%s.%d", s.filePath, i)
			if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove security log backup %q: %w", backup, err))
			}
		}
	}
	return n, errors.Join(errs...)
}
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := Stats{Enabled: true, Capacity: s.capacity, Retained: s.count, Dropped: s.dropped, FileEnabled: s.filePath != "", FilePath: s.filePath, FileBytes: s.fileBytes, FileErrors: s.fileErrors}
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
	if f.ClientIP != "" && !strings.EqualFold(e.ClientIP, f.ClientIP) {
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
	if f.Reason != "" && !strings.EqualFold(e.Reason, f.Reason) {
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
		h := strings.ToLower(strings.Join([]string{e.Event, e.Message, e.RequestID, e.ClientIP, e.Method, e.Host, e.Path, e.Route, e.Action, e.Reason, strings.Join(e.RuleIDs, " "), e.PathFingerprint, e.UserAgentFingerprint, e.Error}, " "))
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
	if f.ClientIP != "" {
		m["client_ip"] = f.ClientIP
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
	if f.Reason != "" {
		m["reason"] = strings.ToLower(f.Reason)
	}
	if f.RuleID != "" {
		m["rule_id"] = strings.ToUpper(f.RuleID)
	}
	if f.Status > 0 {
		m["status"] = f.Status
	}
	if !f.Since.IsZero() {
		m["since"] = f.Since.UTC().Format(time.RFC3339Nano)
	}
	if !f.Until.IsZero() {
		m["until"] = f.Until.UTC().Format(time.RFC3339Nano)
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
func safeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
