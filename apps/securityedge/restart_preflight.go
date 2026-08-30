package securityedge

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

// validateRestartCandidate prepares every dependency and probes newly claimed
// sockets before the active generation is drained. Endpoints overlapping a
// current listener are intentionally skipped because only the current process
// prevents that bind; synchronous generation startup verifies them immediately
// after shutdown.
func (r *Runtime) validateRestartCandidate(configPath string, current, next config.Config) error {
	var errs []error

	if next.Server.Mode == "gateway" && next.Server.TLS.Enabled {
		if _, err := tls.LoadX509KeyPair(next.Server.TLS.CertFile, next.Server.TLS.KeyFile); err != nil {
			errs = append(errs, fmt.Errorf("load server TLS certificate: %w", err))
		}
	}

	prepared, err := prepareRuntimeConfig(configPath, next, r.protectedPaths...)
	if err != nil {
		errs = append(errs, err)
	} else if prepared.edge != nil {
		prepared.edge.CloseIdleConnections()
	}

	active := make([]string, 0, 2)
	if current.Server.Mode == "gateway" {
		active = append(active, current.Server.ListenAddr)
	}
	if current.Admin.Enabled {
		active = append(active, current.Admin.ListenAddr)
	}
	if next.Server.Mode == "gateway" && (current.Server.Mode != "gateway" || current.Server.ListenAddr != next.Server.ListenAddr) && !securityListenerOverlapsAny(next.Server.ListenAddr, active) {
		if err := probeSecurityListener("server.listen_addr", next.Server.ListenAddr); err != nil {
			errs = append(errs, err)
		}
	}
	if next.Admin.Enabled && (!current.Admin.Enabled || current.Admin.ListenAddr != next.Admin.ListenAddr) && !securityListenerOverlapsAny(next.Admin.ListenAddr, active) {
		if err := probeSecurityListener("admin.listen_addr", next.Admin.ListenAddr); err != nil {
			errs = append(errs, err)
		}
	}

	// Runtime.New always reopens the security log store, even when the Admin
	// listener is disabled. Probe the destination without constructing a Store:
	// NewWithConfig restores entries and normalizes the trailing newline, so using
	// it during preflight would mutate (or create) persistent data even when an
	// unrelated listener/TLS/dependency check later rejects the candidate.
	if err := probeSecurityLogDestination(next.Admin.LogStore.FilePath); err != nil {
		errs = append(errs, fmt.Errorf("prepare admin.log_store: %w", err))
	}
	// The Admin generation recreates the bounded history store on every
	// restart. Probe the destination on every enabled candidate rather than
	// only when its JSON fields changed; permissions may have changed on disk.
	if next.Admin.Enabled && next.Admin.TelemetryHistory.Enabled && next.Admin.TelemetryHistory.FilePath != "" {
		if err := probeWritableDirectory("admin.telemetry_history.file_path", next.Admin.TelemetryHistory.FilePath); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func securityListenerOverlapsAny(candidate string, active []string) bool {
	for _, address := range active {
		if config.ListenerEndpointsOverlap(candidate, address) {
			return true
		}
	}
	return false
}

func probeSecurityListener(field, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("%s cannot be activated: %w", field, err)
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("close %s preflight listener: %w", field, err)
	}
	return nil
}

func probeSecurityLogDestination(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if err := probeWritableDirectory("admin.log_store.file_path", path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat admin.log_store.file_path: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("admin.log_store.file_path is a directory")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("admin.log_store.file_path cannot be reopened: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close admin.log_store.file_path preflight: %w", err)
	}
	return nil
}

func probeWritableDirectory(field, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("prepare %s directory: %w", field, err)
	}
	file, err := os.CreateTemp(dir, ".securityedge-write-probe-*")
	if err != nil {
		return fmt.Errorf("%s directory is not writable: %w", field, err)
	}
	name := file.Name()
	if closeErr := file.Close(); closeErr != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close %s write probe: %w", field, closeErr)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove %s write probe: %w", field, err)
	}
	return nil
}
