package routes

import (
	"net/http/httptest"
	"testing"
)

func TestMatchCompatibility(t *testing.T) {
	table := &Table{routes: []Route{
		{Name: "catch", Hosts: []string{"*"}, PathPrefix: "/"},
		{Name: "wild", Hosts: []string{"*.example.com"}, PathPrefix: "/api"},
		{Name: "exact", Hosts: []string{"app.example.com"}, PathPrefix: "/api/v1"},
	}}
	req := httptest.NewRequest("GET", "http://app.example.com/api/v1/users", nil)
	got, ok := table.Match(req)
	if !ok || got.Name != "exact" {
		t.Fatalf("got %#v, %v", got, ok)
	}
}
