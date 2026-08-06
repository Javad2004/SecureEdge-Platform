package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	maxConfigFileBytes int64 = 4 << 20
	maxConfigBackups         = 10
)

// LoadFile decodes and validates the persisted JSON document without applying
// process-environment overrides. Control-plane writes use this form so runtime
// secrets and deployment overrides are never copied into the checked-in file.
func LoadFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("config path is not a regular file")
	}
	if info.Size() > maxConfigFileBytes {
		return Config{}, fmt.Errorf("config exceeds the %d-byte safety limit", maxConfigFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if int64(len(data)) > maxConfigFileBytes {
		return Config{}, fmt.Errorf("config exceeds the %d-byte safety limit", maxConfigFileBytes)
	}
	cfg := Default()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("parse config: expected exactly one JSON value")
		}
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save validates and atomically replaces the persisted JSON document. The
// previous document is retained as a timestamped backup beside the live file.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if int64(len(data)) > maxConfigFileBytes {
		return fmt.Errorf("encoded config exceeds the %d-byte safety limit", maxConfigFileBytes)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
		backup := path + ".bak-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if err := copyFile(path, backup, mode); err != nil {
			return fmt.Errorf("backup config: %w", err)
		}
		trimConfigBackups(path, maxConfigBackups)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if runtime.GOOS == "windows" {
		// Windows does not replace an existing file with Rename. The backup above
		// makes this short remove/rename sequence recoverable.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove previous config: %w", err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

func trimConfigBackups(path string, keep int) {
	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(backups) <= keep {
		return
	}
	sort.Strings(backups)
	for _, backup := range backups[:len(backups)-keep] {
		_ = os.Remove(backup)
	}
}

func copyFile(source, destination string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, mode)
}

// Redacted returns a presentation-safe copy for APIs and dashboards.
func Redacted(cfg Config) Config {
	if strings.TrimSpace(cfg.Admin.AuthToken) != "" {
		cfg.Admin.AuthToken = "[REDACTED]"
	}
	return cfg
}
