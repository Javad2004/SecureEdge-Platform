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
