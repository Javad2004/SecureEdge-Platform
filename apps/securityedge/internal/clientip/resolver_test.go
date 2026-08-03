package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestUntrustedPeerCannotSpoofXFF(t *testing.T) {
	r, _ := New([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "192.168.1.9:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := r.Resolve(req); got != "192.168.1.9" {
		t.Fatalf("got %s", got)
	}
}
func TestTrustedProxyChain(t *testing.T) {
	r, _ := New([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.3")
	if got := r.Resolve(req); got != "203.0.113.9" {
		t.Fatalf("got %s", got)
	}
}

func TestResolverUsesAllForwardedHeaderFields(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	req.RemoteAddr = "10.0.0.4:1234"
	req.Header["X-Forwarded-For"] = []string{"198.51.100.25", "203.0.113.9"}
	if got := r.Resolve(req); got != "203.0.113.9" {
		t.Fatalf("resolved client=%q, want nearest untrusted address", got)
	}
}

func TestResolverFailsClosedOnMalformedForwardedChain(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.test/", nil)
	req.RemoteAddr = "10.0.0.4:1234"
	req.Header["X-Forwarded-For"] = []string{"198.51.100.25", "unknown"}
	if got := r.Resolve(req); got != "10.0.0.4" {
		t.Fatalf("resolved client=%q, want directly connected proxy", got)
	}
}
