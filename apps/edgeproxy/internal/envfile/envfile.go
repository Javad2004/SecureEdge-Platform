package envfile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxFileBytes          int64 = 1 << 20
	applicationModulePath       = "github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy"
)

var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ApplicationCandidates returns the repository-relative application dotenv
// path and adds a local .env candidate only when the current working directory
// is the matching Go module. This keeps per-application dotenv discovery
// working from either the repository root or the application directory without
// treating an unrelated repository-root .env as shared configuration.
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

// Load loads an explicitly selected dotenv file, or the first existing file
// from candidates. Existing process environment variables are never
// overwritten, so deployment-level environment settings take precedence over
// local dotenv values. A missing auto-discovered file is not an error.
func Load(explicit string, candidates ...string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		if err := loadFile(explicit); err != nil {
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
		if err := loadFile(candidate); err != nil {
			return "", fmt.Errorf("load environment file %q: %w", candidate, err)
		}
		return candidate, nil
	}
	return "", nil
}

func loadFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("environment path is not a regular file")
	}
	if info.Size() > maxFileBytes {
		return fmt.Errorf("environment file exceeds the %d-byte safety limit", maxFileBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	if int64(len(data)) > maxFileBytes {
		return fmt.Errorf("environment file exceeds the %d-byte safety limit", maxFileBytes)
	}
	if !utf8.Valid(data) {
		return errors.New("environment file must be valid UTF-8")
	}

	values := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Scanner requires room beyond the token itself for boundary detection.
	// The file-size check already caps total input, so one extra byte lets a
	// valid file whose final line reaches the exact 1 MiB limit be accepted.
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
			return fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if ok {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	for key, value := range values {
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
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
		value, err := strconv.Unquote(raw[:end+1])
		if err != nil {
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
