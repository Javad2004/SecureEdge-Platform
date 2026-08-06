package control

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

// validateRestartCandidate rejects listener generations that are known to be
// unusable before the healthy generation is asked to drain. It intentionally
// probes only endpoints not currently owned by EdgeProxy; an overlapping
// endpoint can be acquired only after the active generation releases it.
func validateRestartCandidate(current, next config.Config) error {
	var errs []error

	if next.Server.TLS.Enabled {
		if _, err := tls.LoadX509KeyPair(next.Server.TLS.CertFile, next.Server.TLS.KeyFile); err != nil {
			errs = append(errs, fmt.Errorf("load server TLS certificate: %w", err))
		}
	}

	active := []string{current.Server.ListenAddr}
	if current.Admin.Enabled {
		active = append(active, current.Admin.ListenAddr)
	}
	if current.Server.ListenAddr != next.Server.ListenAddr && !overlapsAnyListener(next.Server.ListenAddr, active) {
		if err := probeListener("server.listen_addr", next.Server.ListenAddr); err != nil {
			errs = append(errs, err)
		}
	}
	if next.Admin.Enabled && (!current.Admin.Enabled || current.Admin.ListenAddr != next.Admin.ListenAddr) && !overlapsAnyListener(next.Admin.ListenAddr, active) {
		if err := probeListener("admin.listen_addr", next.Admin.ListenAddr); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func overlapsAnyListener(candidate string, active []string) bool {
	for _, address := range active {
		if config.ListenerEndpointsOverlap(candidate, address) {
			return true
		}
	}
	return false
}

func probeListener(field, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("%s cannot be activated: %w", field, err)
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("close %s preflight listener: %w", field, err)
	}
	return nil
}
