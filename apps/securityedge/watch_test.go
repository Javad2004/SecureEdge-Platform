package securityedge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileDigestRejectsOversizedWatchedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxWatchedFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := FileDigest(path); err == nil {
		t.Fatal("expected oversized watched file to be rejected")
	}
}

func TestRecordWatchChangeDeduplicatesUnchangedFailure(t *testing.T) {
	runtime := &Runtime{}
	failure := os.ErrNotExist
	runtime.RecordWatchChange("security.json", false, false, failure)
	first := runtime.WatchStatus()
	runtime.RecordWatchChange("security.json", false, false, failure)
	second := runtime.WatchStatus()
	if second.Revision != first.Revision {
		t.Fatalf("duplicate failure advanced revision from %d to %d", first.Revision, second.Revision)
	}
	if second.LastChangeAt != first.LastChangeAt {
		t.Fatalf("duplicate failure changed timestamp: first=%q second=%q", first.LastChangeAt, second.LastChangeAt)
	}
}
