package envfile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	maxFileBytes          int64 = 1 << 20
	applicationModulePath       = "github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy"
)

var (
	keyPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	managedMu     sync.Mutex
	managedValues = map[string]string{}
)

// ManagedSnapshot captures only values owned by this dotenv loader. Process
// variables supplied by a service manager or parent process are deliberately
// excluded and therefore remain authoritative during rollback.
type ManagedSnapshot struct {
	values map[string]string
}

// SnapshotManagedEnvironment records the currently applied dotenv-owned
// variables so the managed-generation supervisor can recover after a
// post-preflight startup failure.
func SnapshotManagedEnvironment() ManagedSnapshot {
	managedMu.Lock()
	defer managedMu.Unlock()
	values := make(map[string]string, len(managedValues))
	for key, value := range managedValues {
		values[key] = value
	}
	return ManagedSnapshot{values: values}
}

// RestoreManagedEnvironment restores a prior dotenv-owned environment without
// touching deployment-level variables that the loader never managed.
func RestoreManagedEnvironment(snapshot ManagedSnapshot) error {
	managedMu.Lock()
	defer managedMu.Unlock()

	for key := range managedValues {
		if _, keep := snapshot.values[key]; keep {
			continue
		}
		if err := os.Unsetenv(key); err != nil {
			return fmt.Errorf("unset %s while restoring managed environment: %w", key, err)
		}
	}
	for key, value := range snapshot.values {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s while restoring managed environment: %w", key, err)
		}
	}
	managedValues = make(map[string]string, len(snapshot.values))
	for key, value := range snapshot.values {
		managedValues[key] = value
	}
	return nil
}

func ApplicationCandidates(repositoryPath string) []string {
	candidates := []string{repositoryPath}
	if currentModulePath() == applicationModulePath {
		candidates = append(candidates, ".env")
	}
	return candidates
}

func currentModulePath() string {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	return ""
}

// Load loads the selected dotenv file without overriding deployment-provided
// process variables. Values set by this package are tracked so Reload can
// transactionally replace them when the watched file changes.
func Load(explicit string, candidates ...string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		if err := loadFile(explicit, false, nil); err != nil {
			return "", fmt.Errorf("load environment file %q: %w", explicit, err)
		}
		return explicit, nil
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("stat environment file %q: %w", candidate, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("environment path %q is not a regular file", candidate)
		}
		if err := loadFile(candidate, false, nil); err != nil {
			return "", fmt.Errorf("load environment file %q: %w", candidate, err)
		}
		return candidate, nil
	}
	return "", nil
}

// Reload atomically replaces only variables previously managed by this
// package. Deployment-level environment variables remain authoritative.
func Reload(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := loadFile(path, true, nil); err != nil {
		return fmt.Errorf("reload environment file %q: %w", path, err)
	}
	return nil
}

// ReloadValidated applies a dotenv revision and runs validation while the
// previous managed environment is still available for rollback. This makes
// runtime file watching transactional across parsing, environment overrides,
// referenced configuration files, and hot-apply preparation.
func ReloadValidated(path string, validate func() error) error {
	if strings.TrimSpace(path) == "" {
		if validate != nil {
			return validate()
		}
		return nil
	}
	if err := loadFile(path, true, validate); err != nil {
		return fmt.Errorf("reload environment file %q: %w", path, err)
	}
	return nil
}

func loadFile(path string, reload bool, validate func() error) error {
	values, err := readValues(path)
	if err != nil {
		return err
	}
	managedMu.Lock()
	defer managedMu.Unlock()

	previousManaged := make(map[string]string, len(managedValues))
	for key, value := range managedValues {
		previousManaged[key] = value
	}
	previousEnv := map[string]*string{}
	record := func(key string) {
		if _, exists := previousEnv[key]; exists {
			return
		}
		if value, exists := os.LookupEnv(key); exists {
			v := value
			previousEnv[key] = &v
		} else {
			previousEnv[key] = nil
		}
	}
	rollback := func() {
		for key, value := range previousEnv {
			if value == nil {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, *value)
			}
		}
		managedValues = previousManaged
	}

	if reload {
		for key := range managedValues {
			if _, keep := values[key]; keep {
				continue
			}
			record(key)
			if err := os.Unsetenv(key); err != nil {
				rollback()
				return fmt.Errorf("unset %s: %w", key, err)
			}
			delete(managedValues, key)
		}
	}
	for key, value := range values {
		_, alreadyManaged := managedValues[key]
		if !alreadyManaged {
			if _, exists := os.LookupEnv(key); exists {
				continue
			}
		}
		record(key)
		if err := os.Setenv(key, value); err != nil {
			rollback()
			return fmt.Errorf("set %s: %w", key, err)
		}
		managedValues[key] = value
	}
	if validate != nil {
		if err := validate(); err != nil {
			rollback()
			return fmt.Errorf("validation failed: %w", err)
		}
	}
	return nil
}

func readValues(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("environment path is not a regular file")
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("environment file exceeds the %d-byte safety limit", maxFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if int64(len(data)) > maxFileBytes {
		return nil, fmt.Errorf("environment file exceeds the %d-byte safety limit", maxFileBytes)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("environment file must be valid UTF-8")
	}
	values := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), int(maxFileBytes)+1)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		key, value, ok, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if ok {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func parseLine(raw string) (key, value string, ok bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, nil
	}
	if strings.HasPrefix(line, "export ") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	}
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return "", "", false, errors.New("expected KEY=VALUE")
	}
	key = strings.TrimSpace(line[:idx])
	if !keyPattern.MatchString(key) {
		return "", "", false, fmt.Errorf("invalid variable name %q", key)
	}
	value, err = parseValue(strings.TrimSpace(line[idx+1:]))
	if err != nil {
		return "", "", false, err
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", "", false, errors.New("environment values cannot contain NUL bytes")
	}
	return key, value, true, nil
}

func parseValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '\'':
		end := strings.IndexByte(raw[1:], '\'')
		if end < 0 {
			return "", errors.New("unterminated single-quoted value")
		}
		end++
		if err := validateTrailing(raw[end+1:]); err != nil {
			return "", err
		}
		return raw[1:end], nil
	case '"':
		end, err := closingDoubleQuote(raw)
		if err != nil {
			return "", err
		}
		if err := validateTrailing(raw[end+1:]); err != nil {
			return "", err
		}
		var value string
		if err := json.Unmarshal([]byte(raw[:end+1]), &value); err != nil {
			return "", fmt.Errorf("invalid double-quoted value: %w", err)
		}
		return value, nil
	default:
		for i := 1; i < len(raw); i++ {
			if raw[i] == '#' && (raw[i-1] == ' ' || raw[i-1] == '\t') {
				raw = raw[:i]
				break
			}
		}
		return strings.TrimSpace(raw), nil
	}
}

func closingDoubleQuote(raw string) (int, error) {
	escaped := false
	for i := 1; i < len(raw); i++ {
		if escaped {
			escaped = false
			continue
		}
		if raw[i] == '\\' {
			escaped = true
			continue
		}
		if raw[i] == '"' {
			return i, nil
		}
	}
	return -1, errors.New("unterminated double-quoted value")
}

func validateTrailing(raw string) error {
	trailing := strings.TrimSpace(raw)
	if trailing == "" || strings.HasPrefix(trailing, "#") {
		return nil
	}
	return errors.New("unexpected characters after quoted value")
}
