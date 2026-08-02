package router

import (
	"net/http/httptest"
	"testing"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
)

func TestHostAndLongestPathMatch(t *testing.T) {
	routes := []config.RouteConfig{{Name: "root", Hosts: []string{"*.example.local"}, PathPrefix: "/"}, {Name: "api", Hosts: []string{"app.example.local"}, PathPrefix: "/api"}}
	r := New(routes)
	req := httptest.NewRequest("GET", "http://app.example.local/api/items", nil)
	match, ok := r.Match(req)
	if !ok || match.Route.Name != "api" {
		t.Fatalf("expected api route, got %#v", match)
	}
}

func TestPathPrefixRequiresSegmentBoundary(t *testing.T) {
	r := New([]config.RouteConfig{{Name: "api", Hosts: []string{"app.local"}, PathPrefix: "/api"}})
	req := httptest.NewRequest("GET", "http://app.local/apix", nil)
	if _, ok := r.Match(req); ok {
		t.Fatal("/api route must not match /apix")
	}
}

func TestExactHostBeatsWildcardAtSamePath(t *testing.T) {
	r := New([]config.RouteConfig{
		{Name: "wildcard", Hosts: []string{"*.example.local"}, PathPrefix: "/"},
		{Name: "exact", Hosts: []string{"api.example.local"}, PathPrefix: "/"},
	})
	req := httptest.NewRequest("GET", "http://api.example.local/items", nil)
	match, ok := r.Match(req)
	if !ok || match.Route.Name != "exact" {
		t.Fatalf("expected exact route, got %#v", match)
	}
}

func TestLongerWildcardSuffixWinsAtSamePath(t *testing.T) {
	r := New([]config.RouteConfig{
		{Name: "broad", Hosts: []string{"*.example.local"}, PathPrefix: "/"},
		{Name: "narrow", Hosts: []string{"*.api.example.local"}, PathPrefix: "/"},
	})
	req := httptest.NewRequest("GET", "http://v1.api.example.local/items", nil)
	match, ok := r.Match(req)
	if !ok || match.Route.Name != "narrow" {
		t.Fatalf("expected narrow wildcard route, got %#v", match)
	}
}

func TestMatchUsesCanonicalRequestPath(t *testing.T) {
	r := New([]config.RouteConfig{
		{Name: "api", Hosts: []string{"app.local"}, PathPrefix: "/api"},
		{Name: "admin", Hosts: []string{"app.local"}, PathPrefix: "/admin"},
	})
	req := httptest.NewRequest("GET", "http://app.local/api/../admin/settings", nil)
	match, ok := r.Match(req)
	if !ok || match.Route.Name != "admin" {
		t.Fatalf("expected canonical /admin route, got %#v, ok=%v", match, ok)
	}
}

func TestMatchNormalizesBracketedIPv6HostWithoutPort(t *testing.T) {
	r := New([]config.RouteConfig{{Name: "ipv6", Hosts: []string{"::1"}, PathPrefix: "/"}})
	req := httptest.NewRequest("GET", "http://[::1]/healthz", nil)
	match, ok := r.Match(req)
	if !ok || match.Route.Name != "ipv6" {
		t.Fatalf("expected IPv6 route, got %#v, ok=%v", match, ok)
	}
}
