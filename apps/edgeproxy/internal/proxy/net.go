package proxy

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

type netDialer struct{ timeout time.Duration }

func (d *netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
}

type clientResolver struct {
	trusted []*net.IPNet
	header  string
}

func newClientResolver(cidrs []string, header string) (*clientResolver, error) {
	trusted := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, network)
	}
	header = strings.TrimSpace(header)
	if header == "" {
		header = "X-Forwarded-For"
	}
	return &clientResolver{trusted: trusted, header: header}, nil
}

func (r *clientResolver) Resolve(req *http.Request) string {
	remote := remoteIP(req.RemoteAddr)
	if remote == nil {
		return strings.TrimSpace(req.RemoteAddr)
	}
	if r == nil || !trustedIP(remote, r.trusted) {
		return remote.String()
	}
	parts := strings.Split(req.Header.Get(r.header), ",")
	chain := make([]net.IP, 0, len(parts)+1)
	for _, raw := range parts {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			chain = append(chain, ip)
		}
	}
	chain = append(chain, remote)
	for i := len(chain) - 1; i >= 0; i-- {
		if !trustedIP(chain[i], r.trusted) {
			return chain[i].String()
		}
	}
	if len(chain) > 0 {
		return chain[0].String()
	}
	return remote.String()
}

func trustedIP(ip net.IP, networks []*net.IPNet) bool {
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

type resolvedClientIPKey struct{}

func withResolvedClientIP(req *http.Request, ip string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), resolvedClientIPKey{}, ip))
}

func resolvedClientIP(req *http.Request) string {
	if req == nil {
		return ""
	}
	value, _ := req.Context().Value(resolvedClientIPKey{}).(string)
	return strings.TrimSpace(value)
}
