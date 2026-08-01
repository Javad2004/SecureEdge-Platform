package securitylog

import (
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"os"
	"path/filepath"
	"testing"
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
