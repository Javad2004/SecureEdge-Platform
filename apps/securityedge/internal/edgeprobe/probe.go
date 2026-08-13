package edgeprobe

import "net/http"

// HeaderName and HeaderValue form the reserved internal wire contract used by
// SecurityEdge's synthetic data-plane connectivity probe. EdgeProxy only honors
// this marker from a directly connected loopback/trusted proxy peer, and
// SecurityEdge strips client-supplied copies before forwarding normal traffic.
// The marker is not a credential; trust comes from the direct peer check.
const (
	HeaderName  = "X-SecureEdge-Internal-Probe"
	HeaderValue = "connectivity-v1"
	UserAgent   = "SecurityEdge-Connectivity-Probe/1.0"
)

// Mark prepares a synthetic data-plane probe so it cannot read from or populate
// the shared application cache. The reserved marker lets a trusted EdgeProxy
// distinguish the probe from real client traffic for telemetry purposes.
func Mark(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set(HeaderName, HeaderValue)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")
}

// Strip removes the reserved marker from client traffic. This prevents an
// Internet client from hiding ordinary requests from EdgeProxy application
// telemetry by spoofing the operational-probe contract through SecurityEdge.
func Strip(header http.Header) {
	if header != nil {
		header.Del(HeaderName)
	}
}
