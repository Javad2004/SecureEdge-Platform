package envfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDoubleQuotedValuesUsesJSONCompatibleEscapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "escaped slash", raw: `"https:\/\/example.test\/api"`, want: "https://example.test/api"},
		{name: "unicode escape", raw: `"token-\u0031"`, want: "token-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseValue(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}

	if _, err := parseValue(`"\x41"`); err == nil {
		t.Fatal("expected a Go-only hexadecimal escape to be rejected")
	}
}

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

func TestLoadAcceptsFileAtExactSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	data := make([]byte, int(maxFileBytes))
	for i := range data {
		data[i] = '#'
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("expected an environment file at the documented size limit to load: %v", err)
	}
	if loaded != path {
		t.Fatalf("expected %q, got %q", path, loaded)
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

func TestApplicationCandidatesKeepDotenvApplicationScoped(t *testing.T) {
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if got := ApplicationCandidates("apps/application/.env"); len(got) != 1 || got[0] != "apps/application/.env" {
		t.Fatalf("repository root must not discover generic .env: %#v", got)
	}

	if err := os.WriteFile("go.mod", []byte("module "+applicationModulePath+"\n\ngo 1.26.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ApplicationCandidates("apps/application/.env")
	if len(got) != 2 || got[0] != "apps/application/.env" || got[1] != ".env" {
		t.Fatalf("application directory must discover local .env: %#v", got)
	}
}

func TestReloadValidatedRollsBackEnvironmentOnValidationFailure(t *testing.T) {
	key := "EDGEPROXY_ENVFILE_TRANSACTION_TEST"
	_ = os.Unsetenv(key)
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(key+"=healthy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(path, nil, 0o600)
		_ = Reload(path)
		_ = os.Unsetenv(key)
	})
	if err := os.WriteFile(path, []byte(key+"=rejected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validationErr := errors.New("referenced config is invalid")
	if err := ReloadValidated(path, func() error { return validationErr }); !errors.Is(err, validationErr) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if got := os.Getenv(key); got != "healthy" {
		t.Fatalf("expected previous environment value after rollback, got %q", got)
	}
}

func TestManagedEnvironmentSnapshotRestoresOnlyDotenvValues(t *testing.T) {
	initial := SnapshotManagedEnvironment()
	t.Cleanup(func() {
		if err := RestoreManagedEnvironment(initial); err != nil {
			t.Errorf("restore initial managed environment: %v", err)
		}
		_ = os.Unsetenv("EDGEPROXY_DOTENV_A")
		_ = os.Unsetenv("EDGEPROXY_DOTENV_B")
		_ = os.Unsetenv("EDGEPROXY_DOTENV_C")
	})
	t.Setenv("EDGEPROXY_DEPLOYMENT_OWNED_VALUE", "parent")
	dir := t.TempDir()
	first := filepath.Join(dir, "first.env")
	second := filepath.Join(dir, "second.env")
	if err := os.WriteFile(first, []byte("EDGEPROXY_DOTENV_A=one\nEDGEPROXY_DOTENV_B=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("EDGEPROXY_DOTENV_A=changed\nEDGEPROXY_DOTENV_C=three\nEDGEPROXY_DEPLOYMENT_OWNED_VALUE=ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(first); err != nil {
		t.Fatal(err)
	}
	snapshot := SnapshotManagedEnvironment()
	if err := Reload(second); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("EDGEPROXY_DOTENV_C"); got != "three" {
		t.Fatalf("candidate environment was not applied: %q", got)
	}
	if err := RestoreManagedEnvironment(snapshot); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("EDGEPROXY_DOTENV_A"); got != "one" {
		t.Fatalf("EDGEPROXY_DOTENV_A=%q", got)
	}
	if got := os.Getenv("EDGEPROXY_DOTENV_B"); got != "two" {
		t.Fatalf("EDGEPROXY_DOTENV_B=%q", got)
	}
	if _, exists := os.LookupEnv("EDGEPROXY_DOTENV_C"); exists {
		t.Fatal("candidate-only managed variable was not removed")
	}
	if got := os.Getenv("EDGEPROXY_DEPLOYMENT_OWNED_VALUE"); got != "parent" {
		t.Fatalf("deployment variable changed: %q", got)
	}
}
