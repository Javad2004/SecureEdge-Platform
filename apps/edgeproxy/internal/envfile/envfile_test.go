package envfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsesFirstExistingCandidateWithoutOverwritingProcessEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("FROM_FILE=file-value\nEXISTING=file-value\nQUOTED=\"hello world\" # comment\nSINGLE='literal # value'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXISTING", "process-value")
	loaded, err := Load("", filepath.Join(dir, "missing"), path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != path {
		t.Fatalf("expected %q, got %q", path, loaded)
	}
	if got := os.Getenv("FROM_FILE"); got != "file-value" {
		t.Fatalf("unexpected file value %q", got)
	}
	if got := os.Getenv("EXISTING"); got != "process-value" {
		t.Fatalf("process environment was overwritten: %q", got)
	}
	if got := os.Getenv("QUOTED"); got != "hello world" {
		t.Fatalf("unexpected quoted value %q", got)
	}
	if got := os.Getenv("SINGLE"); got != "literal # value" {
		t.Fatalf("unexpected single-quoted value %q", got)
	}
}

func TestLoadMissingAutoDiscoveredFileIsOptional(t *testing.T) {
	loaded, err := Load("", filepath.Join(t.TempDir(), ".env"))
	if err != nil || loaded != "" {
		t.Fatalf("expected optional missing file, path=%q err=%v", loaded, err)
	}
}

func TestLoadExplicitMissingFileFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.env")); err == nil {
		t.Fatal("expected explicit missing environment file to fail")
	}
}

func TestLoadRejectsMalformedFileWithoutPartialApplication(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("VALID_BEFORE_ERROR=value\nINVALID LINE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected malformed environment file to fail")
	}
	if _, exists := os.LookupEnv("VALID_BEFORE_ERROR"); exists {
		t.Fatal("malformed file was partially applied")
	}
}

func TestLoadRejectsNonRegularExplicitPath(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("expected an explicit directory to be rejected")
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	data := make([]byte, int(maxFileBytes)+1)
	for i := range data {
		data[i] = '#'
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected oversized environment file to fail")
	}
}

func TestLoadRejectsInvalidUTF8WithoutPartialApplication(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	data := append([]byte("VALID_BEFORE_UTF8_ERROR=value\nINVALID_UTF8="), 0xff, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid UTF-8 environment file to fail")
	}
	if _, exists := os.LookupEnv("VALID_BEFORE_UTF8_ERROR"); exists {
		t.Fatal("invalid UTF-8 file was partially applied")
	}
}
