package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validPersistenceTestConfig() Config {
	cfg := Default()
	cfg.Server.Mode = "embedded"
	cfg.EdgeProxy.ConfigPath = "edge.json"
	return cfg
}

func TestLoadFileRecoversInterruptedAtomicUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "securityedge.json")
	cfg := validPersistenceTestConfig()
	cfg.DefaultPolicy.AnomalyThreshold = 9

	stagingPath := filepath.Join(dir, "staged.json")
	if err := Save(stagingPath, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(stagingPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("recover staged configuration: %v", err)
	}
	if loaded.DefaultPolicy.AnomalyThreshold != 9 {
		t.Fatalf("recovered threshold=%d, want 9", loaded.DefaultPolicy.AnomalyThreshold)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("restored configuration is missing: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("staged backup still exists after recovery: %v", err)
	}
}

func TestLoadFileDoesNotRestoreInvalidBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "securityedge.json")
	backup := path + ".bak"
	if err := os.WriteFile(backup, []byte(`{"server":`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "parse security config") {
		t.Fatalf("expected parse error, got %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("invalid backup was restored to the configured path: %v", statErr)
	}
	if _, statErr := os.Stat(backup); statErr != nil {
		t.Fatalf("invalid backup should remain available for diagnosis: %v", statErr)
	}
}

func TestSaveRetainsBoundedTimestampedBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "securityedge.json")
	cfg := validPersistenceTestConfig()
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxConfigBackups+3; i++ {
		cfg.DefaultPolicy.AnomalyThreshold = 5 + i
		if err := Save(path, cfg); err != nil {
			t.Fatal(err)
		}
	}
	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != maxConfigBackups {
		t.Fatalf("backup count=%d, want %d", len(backups), maxConfigBackups)
	}
}

func TestLoadFileRejectsOversizedConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securityedge.json")
	if err := os.WriteFile(path, make([]byte, maxConfigFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestSaveRejectsOversizedExistingConfigWithoutBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "securityedge.json")
	original := make([]byte, maxConfigFileBytes+1)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	err := Save(path, validPersistenceTestConfig())
	if err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || info.Size() != int64(len(original)) {
		t.Fatalf("oversized source was modified: info=%v err=%v", info, statErr)
	}
	backups, globErr := filepath.Glob(path + ".bak-*")
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(backups) != 0 {
		t.Fatalf("unexpected partial backups: %v", backups)
	}
}
