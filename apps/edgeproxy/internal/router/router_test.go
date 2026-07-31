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
