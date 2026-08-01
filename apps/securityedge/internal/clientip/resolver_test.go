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
