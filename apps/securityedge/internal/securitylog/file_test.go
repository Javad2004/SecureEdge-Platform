package securitylog

import (
	"bytes"
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
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
