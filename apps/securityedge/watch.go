package securityedge

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"
)

type WatchStatus struct {
	Enabled          bool   `json:"enabled"`
	SecurityConfig   string `json:"security_config"`
	EdgeProxyConfig  string `json:"edgeproxy_config"`
	EnvironmentFile  string `json:"environment_file,omitempty"`
	Revision         uint64 `json:"revision"`
	AppliedRevision  uint64 `json:"applied_revision"`
	RestartScheduled bool   `json:"restart_scheduled"`
	LastChangedFile  string `json:"last_changed_file,omitempty"`
	LastChangeAt     string `json:"last_change_at,omitempty"`
	LastAppliedAt    string `json:"last_applied_at,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

func (r *Runtime) WatchStatus() WatchStatus {
	r.watchMu.RLock()
	defer r.watchMu.RUnlock()
	return r.watch
}

func (r *Runtime) ConfigureWatcher(envPath string, previous ...WatchStatus) {
	r.watchMu.Lock()
	if len(previous) > 0 && previous[0].Enabled {
		r.watch = previous[0]
		// A newly created generation is the successful completion of any
		// previously scheduled restart. Preserve monotonic revision history while
		// marking the latest accepted revision as applied.
		r.watch.RestartScheduled = false
		r.watch.AppliedRevision = r.watch.Revision
		r.watch.LastAppliedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.watch.LastError = ""
	}
	r.watch.Enabled = true
	r.watch.SecurityConfig = r.configPath
	r.watch.EdgeProxyConfig = r.EdgeConfigPath()
	r.watch.EnvironmentFile = envPath
	if r.watch.Revision == 0 {
		r.watch.Revision = 1
		r.watch.AppliedRevision = 1
		r.watch.LastAppliedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	r.watchMu.Unlock()
}

// MarkRestartScheduled makes a Control Plane 202 response immediately reflect
// that the persisted revision is awaiting the file supervisor. The supervisor
// records the actual file change and carries the status into the next generation.
func (r *Runtime) MarkRestartScheduled(path string) {
	r.watchMu.Lock()
	r.watch.RestartScheduled = true
	r.watch.LastChangedFile = path
	r.watch.LastChangeAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.watch.LastError = ""
	r.watchMu.Unlock()
}

func (r *Runtime) RecordWatchChange(path string, applied, restart bool, err error) {
	r.watchMu.Lock()
	defer r.watchMu.Unlock()
	r.watch.Revision++
	r.watch.LastChangedFile = path
	r.watch.LastChangeAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.watch.RestartScheduled = restart
	if err != nil {
		r.watch.LastError = err.Error()
		return
	}
	r.watch.LastError = ""
	if applied {
		r.watch.AppliedRevision = r.watch.Revision
		r.watch.LastAppliedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
}

func FileDigest(path string) ([32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("read watched file %q: %w", path, err)
	}
	return sha256.Sum256(data), nil
}
