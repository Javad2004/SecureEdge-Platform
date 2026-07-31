package router

import (
	"net/http/httptest"
	"testing"

	"github.com/bachelor-project/edgeproxy/internal/config"
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
