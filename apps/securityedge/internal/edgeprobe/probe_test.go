package edgeprobe

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMarkCreatesNonCacheableOperationalProbe(t *testing.T) {
	req := httptest.NewRequest(http.MethodHead, "http://edgeproxy.test/", nil)
	Mark(req)
	if req.Header.Get(HeaderName) != HeaderValue || req.UserAgent() != UserAgent {
		t.Fatalf("operational identity headers=%#v", req.Header)
	}
	if req.Header.Get("Cache-Control") != "no-store" || req.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("cache policy headers=%#v", req.Header)
	}
}

func TestStripRemovesOnlyPrivateMarker(t *testing.T) {
	header := http.Header{
		HeaderName:      []string{HeaderValue},
		"Cache-Control": []string{"no-store"},
		"User-Agent":    []string{UserAgent},
	}
	Strip(header)
	if header.Get(HeaderName) != "" {
		t.Fatalf("marker survived strip: %#v", header)
	}
	if header.Get("Cache-Control") != "no-store" || header.Get("User-Agent") != UserAgent {
		t.Fatalf("strip removed unrelated headers: %#v", header)
	}
}
