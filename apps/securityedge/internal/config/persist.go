package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode security config: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".security-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}

	backup := path + ".bak"
	_ = os.Remove(backup)
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, backup); err != nil {
			return fmt.Errorf("stage existing config: %w", err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Rename(backup, path)
		return fmt.Errorf("replace config: %w", err)
	}
	_ = os.Remove(backup)
	return nil
}
