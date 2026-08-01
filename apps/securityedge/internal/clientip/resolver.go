package clientip

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// Resolver returns a stable client address while only trusting forwarding
// headers supplied by explicitly configured proxy networks.
type Resolver struct {
	mu      sync.RWMutex
	trusted []*net.IPNet
	header  string
}

func New(cidrs []string, header string) (*Resolver, error) {
	r := &Resolver{}
	if err := r.Replace(cidrs, header); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Resolver) Replace(cidrs []string, header string) error {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return err
		}
		parsed = append(parsed, network)
	}
	header = strings.TrimSpace(header)
	if header == "" {
		header = "X-Forwarded-For"
	}
	r.mu.Lock()
	r.trusted, r.header = parsed, header
	r.mu.Unlock()
	return nil
}

func (r *Resolver) Resolve(req *http.Request) string {
	r.mu.RLock()
	trusted := append([]*net.IPNet(nil), r.trusted...)
	header := r.header
	r.mu.RUnlock()
	remote := remoteIP(req.RemoteAddr)
	if remote == nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	if !isTrusted(remote, trusted) {
		return remote.String()
	}
	parts := strings.Split(req.Header.Get(header), ",")
	chain := make([]net.IP, 0, len(parts)+1)
	for _, raw := range parts {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			chain = append(chain, ip)
		}
	}
	chain = append(chain, remote)
	for i := len(chain) - 1; i >= 0; i-- {
		if !isTrusted(chain[i], trusted) {
			return chain[i].String()
		}
	}
	if len(chain) > 0 {
		return chain[0].String()
	}
	return remote.String()
}

func isTrusted(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func remoteIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.TrimSpace(addr))
}
