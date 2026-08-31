package securitylog

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/waf"
)

func TestPersistentLogRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 220, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		s.Append(Entry{Event: "test", Message: "0123456789012345678901234567890123456789", ClientIP: "10.0.0.1"})
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
}

func TestPersistentLogSkipsInvalidUTF8Records(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	invalid := []byte(`{"sequence":1,"event":"bad","route":"route`)
	invalid = append(invalid, 0xff)
	invalid = append(invalid, []byte(`name"}`)...)
	valid, err := json.Marshal(Entry{Sequence: 2, Event: "good", Route: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	data := append(append(append([]byte{}, invalid...), '\n'), valid...)
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}

	store, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	stats := store.Stats()
	if stats.FileErrors != 1 {
		t.Fatalf("file_errors=%d, want 1 invalid UTF-8 record", stats.FileErrors)
	}
	result := store.Query(Filter{Limit: 10})
	if len(result.Entries) != 1 || result.Entries[0].Event != "good" || result.Entries[0].Route != "demo" {
		t.Fatalf("invalid UTF-8 record was restored or valid record was lost: %#v", result.Entries)
	}
}

func TestClearRemovesPersistentLogAndBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 220, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 20; i++ {
		s.Append(Entry{Event: "test", Message: "0123456789012345678901234567890123456789"})
	}
	removed, err := s.Clear()
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 {
		t.Fatal("expected in-memory entries to be removed")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected active log file to be truncated, size=%d", info.Size())
	}
	for i := 1; i <= 2; i++ {
		if _, err := os.Stat(path + "." + strconv.Itoa(i)); !os.IsNotExist(err) {
			t.Fatalf("expected backup %d to be removed, err=%v", i, err)
		}
	}
}

func TestClearRewindsRotatedActiveLogBeforeNextAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1 << 20, MaxBackups: 1})
	if err != nil {
		t.Fatal(err)
	}

	// Rotation reopens the active file without O_APPEND. Write one entry so its
	// current offset is non-zero, then clear and append again.
	if err := s.rotateLocked(); err != nil {
		t.Fatal(err)
	}
	s.Append(Entry{Event: "before-clear"})
	if _, err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	s.Append(Entry{Event: "after-clear"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		t.Fatalf("cleared log contains a sparse NUL-filled gap: %q", data)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("expected one NDJSON entry after clear, got %d: %q", len(lines), data)
	}
	var entry Entry
	if err := json.Unmarshal(lines[0], &entry); err != nil {
		t.Fatalf("active log is not valid NDJSON after clear: %v; data=%q", err, data)
	}
	if entry.Event != "after-clear" {
		t.Fatalf("event=%q, want after-clear", entry.Event)
	}
}

func TestCSVExportNeutralizesSpreadsheetFormulas(t *testing.T) {
	s := New(10)
	s.Append(Entry{Event: "waf_blocked", Host: "=HYPERLINK(\"https://example.test\")", Path: " +SUM(1,1)"})

	var output bytes.Buffer
	if err := s.Export(&output, Filter{Limit: 10}, "csv"); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header and one data row, got %d records", len(records))
	}
	if got := records[1][7]; !strings.HasPrefix(got, "'") {
		t.Fatalf("host formula was not neutralized: %q", got)
	}
	if got := records[1][8]; !strings.HasPrefix(got, "'") {
		t.Fatalf("path formula was not neutralized: %q", got)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced write failure")
}

func TestCSVExportReturnsFlushError(t *testing.T) {
	s := New(10)
	s.Append(Entry{Event: "test"})
	if err := s.Export(failingWriter{}, Filter{Limit: 10}, "csv"); err == nil {
		t.Fatal("expected CSV writer flush error")
	}
}

func TestClearWithoutFileLoggingDoesNotRemoveRelativeBackups(t *testing.T) {
	dir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	for _, name := range []string{".1", ".2"} {
		if err := os.WriteFile(name, []byte("unrelated"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	s.Append(Entry{Event: "test"})
	if _, err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".1", ".2"} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("unrelated file %s was removed: %v", name, err)
		}
	}
}

func TestNDJSONExportReturnsFlushError(t *testing.T) {
	s := New(10)
	s.Append(Entry{Event: "test"})
	if err := s.Export(failingWriter{}, Filter{Limit: 10}, "ndjson"); err == nil {
		t.Fatal("expected buffered writer flush error")
	}
}

func TestRotationReplacesExistingBackupDestinations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1024, MaxBackups: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.file.WriteString("current\n"); err != nil {
		t.Fatal(err)
	}
	s.fileBytes = int64(len("current\n"))
	if err := os.WriteFile(path+".1", []byte("previous\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".2", []byte("oldest\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := s.rotateLocked(); err != nil {
		t.Fatal(err)
	}
	backup1, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	backup2, err := os.ReadFile(path + ".2")
	if err != nil {
		t.Fatal(err)
	}
	if string(backup1) != "current\n" {
		t.Fatalf("unexpected first backup: %q", backup1)
	}
	if string(backup2) != "previous\n" {
		t.Fatalf("unexpected second backup: %q", backup2)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("expected a fresh active log, size=%d", info.Size())
	}
}

func TestPersistentLogRestoresEntriesAndContinuesSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	writeEntries := func(name string, entries ...Entry) {
		t.Helper()
		var data bytes.Buffer
		encoder := json.NewEncoder(&data)
		for _, entry := range entries {
			if err := encoder.Encode(entry); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(name, data.Bytes(), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	writeEntries(path+".1",
		Entry{Sequence: 7, Timestamp: "2026-08-01T00:00:00Z", Event: "oldest"},
		Entry{Sequence: 8, Timestamp: "2026-08-01T00:00:01Z", Event: "older"},
	)
	// Simulate a file produced by an older process that restarted its sequence
	// counter at one. Startup must repair that duplicate in memory.
	writeEntries(path, Entry{Sequence: 1, Timestamp: "2026-08-01T00:00:02Z", Event: "active"})

	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1 << 20, MaxBackups: 1})
	if err != nil {
		t.Fatal(err)
	}
	query := s.Query(Filter{Limit: 10})
	if query.Returned != 3 {
		t.Fatalf("expected three restored entries, got %#v", query)
	}
	if got := []uint64{query.Entries[0].Sequence, query.Entries[1].Sequence, query.Entries[2].Sequence}; !equalUint64s(got, []uint64{9, 8, 7}) {
		t.Fatalf("unexpected restored sequences: %v", got)
	}
	appended := s.Append(Entry{Event: "new"})
	if appended.Sequence != 10 {
		t.Fatalf("expected next sequence 10, got %d", appended.Sequence)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1 << 20, MaxBackups: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	appended = reopened.Append(Entry{Event: "newer"})
	if appended.Sequence != 11 {
		t.Fatalf("expected stable sequence 11 after a second restart, got %d", appended.Sequence)
	}
}

func TestPersistentLogRestoresOnlyNewestCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	for i := 1; i <= 5; i++ {
		if err := encoder.Encode(Entry{Sequence: uint64(i), Event: "event-" + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 3, FilePath: path, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	query := s.Query(Filter{Limit: 10})
	if query.Returned != 3 || query.Dropped != 2 {
		t.Fatalf("unexpected restored ring stats: %#v", query)
	}
	if got := []uint64{query.Entries[0].Sequence, query.Entries[1].Sequence, query.Entries[2].Sequence}; !equalUint64s(got, []uint64{5, 4, 3}) {
		t.Fatalf("unexpected retained sequences: %v", got)
	}
}

func TestPersistentLogSeparatesPartialTailBeforeAppending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	valid, err := json.Marshal(Entry{Sequence: 3, Event: "valid"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append(valid, '\n'), []byte(`{"sequence":4,"event":"partial"`)...), 0o640); err != nil {
		t.Fatal(err)
	}

	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if stats := s.Stats(); stats.FileErrors != 1 {
		t.Fatalf("expected one malformed-tail error, got %#v", stats)
	}
	appended := s.Append(Entry{Event: "after-restart"})
	if appended.Sequence != 4 {
		t.Fatalf("expected sequence 4 after ignoring partial tail, got %d", appended.Sequence)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("partial\"\n{\"sequence\":4")) {
		t.Fatalf("new entry was not separated from partial tail: %q", data)
	}
}

func equalUint64s(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPersistentLogBoundsRestoredEntryData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	ruleIDs := make([]string, maxEntryRuleIDs+1)
	tags := make([]string, maxEntryTags+1)
	matches := make([]waf.Match, maxEntryMatches+1)
	for i := range ruleIDs {
		ruleIDs[i] = strings.Repeat("r", 140) + strconv.Itoa(i)
	}
	for i := range tags {
		tags[i] = strings.Repeat("t", 70) + strconv.Itoa(i)
	}
	for i := range matches {
		matches[i] = waf.Match{
			RuleID: strings.Repeat("i", 140), RuleName: strings.Repeat("n", 300),
			Category: strings.Repeat("c", 140), Target: strings.Repeat("x", 140),
			Location: strings.Repeat("l", 600), Fingerprint: strings.Repeat("f", 140),
		}
	}
	entry := Entry{
		Sequence: 1, Timestamp: strings.Repeat("invalid", 100), Level: strings.Repeat("warn", 20),
		Event: "restored", RuleIDs: ruleIDs, Tags: tags, Matches: matches,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}

	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	result := s.Query(Filter{Limit: 10})
	if result.Returned != 1 {
		t.Fatalf("expected one restored entry, got %#v", result)
	}
	got := result.Entries[0]
	if _, err := time.Parse(time.RFC3339Nano, got.Timestamp); err != nil {
		t.Fatalf("timestamp was not repaired: %q", got.Timestamp)
	}
	if len(got.Level) > 16 || len(got.RuleIDs) > maxEntryRuleIDs || len(got.Tags) > maxEntryTags || len(got.Matches) > maxEntryMatches {
		t.Fatalf("restored entry was not bounded: level=%d rules=%d tags=%d matches=%d", len(got.Level), len(got.RuleIDs), len(got.Tags), len(got.Matches))
	}
	if len(got.RuleIDs[0]) > 128 || len(got.Tags[0]) > 64 || len(got.Matches[0].RuleName) > 256 || len(got.Matches[0].Location) > 512 {
		t.Fatalf("restored nested values were not bounded: %#v", got.Matches[0])
	}
}

func TestPersistentLogRejectsOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	oversized := append([]byte(`{"event":"`), bytes.Repeat([]byte{'x'}, maxPersistentLogLineBytes)...)
	oversized = append(oversized, []byte("\"}\n")...)
	if err := os.WriteFile(path, oversized, 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if stats := s.Stats(); stats.FileErrors == 0 || stats.Retained != 0 {
		t.Fatalf("oversized persistent line was not rejected: %#v", stats)
	}
}

func TestPersistentLogSkipsOversizedLineAndContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	valid, err := json.Marshal(Entry{Sequence: 7, Event: "valid-after-oversized"})
	if err != nil {
		t.Fatal(err)
	}
	oversized := append([]byte(`{"event":"`), bytes.Repeat([]byte{'x'}, maxPersistentLogLineBytes)...)
	oversized = append(oversized, []byte("\"}\n")...)
	data := append(oversized, append(valid, '\n')...)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}

	s, err := NewWithConfig(config.LogStoreConfig{Capacity: 10, FilePath: path, MaxFileBytes: 2 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	stats := s.Stats()
	if stats.FileErrors != 1 || stats.Retained != 1 {
		t.Fatalf("expected one rejected line and one restored event, got %#v", stats)
	}
	result := s.Query(Filter{Limit: 10})
	if result.Returned != 1 || result.Entries[0].Event != "valid-after-oversized" || result.Entries[0].Sequence != 7 {
		t.Fatalf("valid event after oversized line was not restored: %#v", result)
	}
	appended := s.Append(Entry{Event: "new-event"})
	if appended.Sequence != 8 {
		t.Fatalf("sequence did not continue after recovered line: %d", appended.Sequence)
	}
}
