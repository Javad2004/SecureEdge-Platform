package securitylog

import (
	"bytes"
	"encoding/csv"
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
