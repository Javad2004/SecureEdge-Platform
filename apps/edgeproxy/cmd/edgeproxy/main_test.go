package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigPathUsesCLIThenDotenvThenExistingDefault(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if got := resolveConfigPath("cli.json", "env.json", envPath, true, "default.json"); got != "cli.json" {
		t.Fatalf("CLI path lost precedence: %q", got)
	}
	wantEnv := filepath.Join(dir, "configs", "edge.json")
	if got := resolveConfigPath("", "configs/edge.json", envPath, true, "default.json"); got != wantEnv {
		t.Fatalf("relative environment path=%q, want %q", got, wantEnv)
	}

	defaultPath := filepath.Join(dir, "default.json")
	if err := os.WriteFile(defaultPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveConfigPath("", "", "", false, defaultPath, "fallback.json"); got != defaultPath {
		t.Fatalf("existing default was not selected: %q", got)
	}
}

func TestResolveConfigPathKeepsProcessEnvironmentRelativeToWorkingDirectory(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), ".env")
	if got := resolveConfigPath("", "configs/process.json", envPath, false, "fallback.json"); got != "configs/process.json" {
		t.Fatalf("process environment path was rebased to dotenv directory: %q", got)
	}
}

func TestFirstNonEmptyTrimsValues(t *testing.T) {
	if got := firstNonEmpty("  ", " value ", "fallback"); got != "value" {
		t.Fatalf("got %q", got)
	}
}
