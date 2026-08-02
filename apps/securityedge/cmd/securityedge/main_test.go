package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func TestGatewayTransportIgnoresAmbientProxySettings(t *testing.T) {
	target, err := url.Parse("http://edgeproxy:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(target, config.Default().Server, slog.Default())
	transport, ok := proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", proxy.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("SecurityEdge data-plane transport must connect directly instead of honoring HTTP_PROXY/HTTPS_PROXY")
	}
}

func TestGatewayRemovesConfiguredClientIPHeader(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default().Server
	cfg.ForwardedForHeader = "X-Real-IP"
	proxy := newReverseProxy(target, cfg, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "http://securityedge.test/", nil)
	req.Header.Set("X-Real-IP", "198.51.100.25")
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}

	headers := <-seen
	if got := headers.Get("X-Real-IP"); got != "" {
		t.Fatalf("configured client-IP source header leaked downstream: %q", got)
	}
	if got := headers.Get("X-Forwarded-For"); got == "198.51.100.25" {
		t.Fatalf("unresolved client-supplied address was propagated: %q", got)
	}
}
