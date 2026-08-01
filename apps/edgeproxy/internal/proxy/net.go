package proxy

import (
	"context"
	"net"
	"time"
)

type netDialer struct{ timeout time.Duration }

func (d *netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
}
