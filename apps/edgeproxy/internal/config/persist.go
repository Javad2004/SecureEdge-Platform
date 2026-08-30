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
	"unicode/utf8"
)

const (
	maxConfigFileBytes int64 = 4 << 20
	maxConfigBackups         = 10
)

// LoadFile decodes and validates the persisted JSON document without applying
// process-environment overrides. Control-plane writes use this form so runtime
// secrets and deployment overrides are never copied into the checked-in file.
func LoadFile(path string) (Config, error) {
	data, recoveryPath, err := readConfigForLoad(path)
	if err != nil {
		return Config{}, err
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
	if recoveryPath != "" {
		if err := os.Rename(recoveryPath, path); err != nil {
			return Config{}, fmt.Errorf("restore staged config: %w", err)
		}
	}
	return cfg, nil
}

// readConfigForLoad recovers the staging file left by an interrupted Windows
// replacement. Validation completes before restoration so malformed recovery
// data never replaces the configured path.
func readConfigForLoad(path string) ([]byte, string, error) {
	data, err := readBoundedConfigFile(path)
	if err == nil {
		return data, "", nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("read config: %w", err)
	}

	recoveryPath := path + ".bak"
	data, recoveryErr := readBoundedConfigFile(recoveryPath)
	if recoveryErr != nil {
		if errors.Is(recoveryErr, os.ErrNotExist) {
			return nil, "", fmt.Errorf("read config: %w", err)
		}
		return nil, "", fmt.Errorf("read staged config recovery %q: %w", recoveryPath, recoveryErr)
	}
	return data, recoveryPath, nil
}

func readBoundedConfigFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("config path is not a regular file")
	}
	if info.Size() > maxConfigFileBytes {
		return nil, fmt.Errorf("config exceeds the %d-byte safety limit", maxConfigFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxConfigFileBytes {
		return nil, fmt.Errorf("config exceeds the %d-byte safety limit", maxConfigFileBytes)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("config must be valid UTF-8")
	}
	return data, nil
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
	exists := false
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("config path is not a regular file")
		}
		if info.Size() > maxConfigFileBytes {
			return fmt.Errorf("existing config exceeds the %d-byte safety limit", maxConfigFileBytes)
		}
		exists = true
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
	staging := path + ".bak"
	if runtime.GOOS == "windows" && exists {
		_ = os.Remove(staging)
		if err := os.Rename(path, staging); err != nil {
			return fmt.Errorf("stage existing config: %w", err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		if runtime.GOOS == "windows" && exists {
			_ = os.Rename(staging, path)
		}
		return fmt.Errorf("replace config: %w", err)
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(staging)
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
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	written, err := io.Copy(out, io.LimitReader(in, maxConfigFileBytes+1))
	if err != nil {
		return err
	}
	if written > maxConfigFileBytes {
		return fmt.Errorf("source config exceeds the %d-byte safety limit", maxConfigFileBytes)
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

// Redacted returns a presentation-safe copy for APIs and dashboards.
func Redacted(cfg Config) Config {
	if strings.TrimSpace(cfg.Admin.AuthToken) != "" {
		cfg.Admin.AuthToken = "[REDACTED]"
	}
	return cfg
}
