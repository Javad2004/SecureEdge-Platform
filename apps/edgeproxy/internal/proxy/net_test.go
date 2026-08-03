package proxy

import (
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
