package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientResolverUsesAllForwardedHeaderFields(t *testing.T) {
	resolver, err := newClientResolver([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://proxy.test/", nil)
	req.RemoteAddr = "10.0.0.4:1234"
	req.Header["X-Forwarded-For"] = []string{"198.51.100.25", "203.0.113.9"}

	if got := resolver.Resolve(req); got != "203.0.113.9" {
		t.Fatalf("resolved client=%q, want nearest untrusted address", got)
	}
}

func TestClientResolverFailsClosedOnMalformedForwardedChain(t *testing.T) {
	resolver, err := newClientResolver([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://proxy.test/", nil)
	req.RemoteAddr = "10.0.0.4:1234"
	req.Header["X-Forwarded-For"] = []string{"198.51.100.25", "not-an-ip"}

	if got := resolver.Resolve(req); got != "10.0.0.4" {
		t.Fatalf("resolved client=%q, want directly connected proxy", got)
	}
}

func TestTrustedOperationalProbeRequiresTrustedDirectPeer(t *testing.T) {
	resolver, err := newClientResolver([]string{"172.30.0.10/32"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	makeProbe := func(remote string) *http.Request {
		req := httptest.NewRequest(http.MethodHead, "http://proxy.test/", nil)
		req.RemoteAddr = remote
		req.Header.Set(internalProbeHeader, internalProbeValue)
		req.Header.Set("User-Agent", internalProbeUserAgent)
		return req
	}
	for _, remote := range []string{"127.0.0.1:1234", "[::1]:1234", "172.30.0.10:1234"} {
		if !trustedOperationalProbe(makeProbe(remote), resolver) {
			t.Fatalf("trusted probe peer %q was rejected", remote)
		}
	}
	if trustedOperationalProbe(makeProbe("172.30.0.11:1234"), resolver) {
		t.Fatal("untrusted peer was allowed to mark a request as operational")
	}
	wrongMethod := makeProbe("127.0.0.1:1234")
	wrongMethod.Method = http.MethodGet
	if trustedOperationalProbe(wrongMethod, resolver) {
		t.Fatal("non-HEAD request was allowed to use the operational probe contract")
	}
	wrongAgent := makeProbe("127.0.0.1:1234")
	wrongAgent.Header.Set("User-Agent", "spoofed")
	if trustedOperationalProbe(wrongAgent, resolver) {
		t.Fatal("wrong probe user agent was trusted")
	}
}
