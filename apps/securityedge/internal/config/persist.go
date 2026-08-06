package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

const (
	maxConfigFileBytes int64 = 4 << 20
	maxConfigBackups         = 10
)

// Save validates and atomically replaces the file-backed SecurityEdge
// configuration. Timestamped backups are retained for operator rollback, while
// the short-lived .bak staging file provides crash recovery on platforms that
// cannot rename over an existing file.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode security config: %w", err)
	}
	data = append(data, '\n')
	if int64(len(data)) > maxConfigFileBytes {
		return fmt.Errorf("encoded security config exceeds the %d-byte safety limit", maxConfigFileBytes)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create security config directory: %w", err)
	}
	mode := os.FileMode(0o600)
	exists := false
	if info, statErr := os.Stat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return errors.New("security config path is not a regular file")
		}
		exists = true
		mode = info.Mode().Perm()
		backup := path + ".bak-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if err := copyConfigFile(path, backup, mode); err != nil {
			return fmt.Errorf("backup security config: %w", err)
		}
		trimConfigBackups(path, maxConfigBackups)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("stat security config: %w", statErr)
	}

	tmp, err := os.CreateTemp(dir, ".security-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
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
			return fmt.Errorf("stage existing security config: %w", err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		if runtime.GOOS == "windows" && exists {
			_ = os.Rename(staging, path)
		}
		return fmt.Errorf("replace security config: %w", err)
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

func copyConfigFile(source, destination string, mode os.FileMode) error {
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
	if _, err := io.Copy(out, io.LimitReader(in, maxConfigFileBytes+1)); err != nil {
		return err
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
