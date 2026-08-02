package routes

import (
	"net/http/httptest"
	"os"
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

func TestMatchUsesCanonicalRequestPath(t *testing.T) {
	table := &Table{routes: []Route{
		{Name: "api", Hosts: []string{"app.example.com"}, PathPrefix: "/api"},
		{Name: "admin", Hosts: []string{"app.example.com"}, PathPrefix: "/admin"},
	}}
	req := httptest.NewRequest("GET", "http://app.example.com/api/../admin/settings", nil)
	got, ok := table.Match(req)
	if !ok || got.Name != "admin" {
		t.Fatalf("expected canonical /admin route, got %#v, ok=%v", got, ok)
	}
}

func TestLoadNormalizesTrailingSlashAndRejectsNonCanonicalPrefix(t *testing.T) {
	validPath := t.TempDir() + "/valid.json"
	if err := os.WriteFile(validPath, []byte(`{"routes":[{"name":"api","hosts":["app.example.com"],"path_prefix":"/api/"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := Load(validPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Routes()[0].PathPrefix; got != "/api" {
		t.Fatalf("normalized prefix=%q, want /api", got)
	}

	for _, prefix := range []string{"/api/../admin", "/api//admin", "/api%2Fadmin", "/api?debug=1"} {
		path := t.TempDir() + "/invalid.json"
		payload := `{"routes":[{"name":"api","hosts":["app.example.com"],"path_prefix":"` + prefix + `"}]}`
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("expected prefix %q to be rejected", prefix)
		}
	}
}

func TestLoadRejectsInvalidHostPatterns(t *testing.T) {
	for _, host := range []string{"app.example.com:8080", "foo*bar.example", "*.127.0.0.1", "bad..example"} {
		configPath := t.TempDir() + "/edge.json"
		payload := `{"routes":[{"name":"api","hosts":["` + host + `"],"path_prefix":"/"}]}`
		if err := os.WriteFile(configPath, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(configPath); err == nil {
			t.Fatalf("expected host pattern %q to be rejected", host)
		}
	}
}

func TestLoadNormalizesValidHostPatterns(t *testing.T) {
	configPath := t.TempDir() + "/edge.json"
	payload := `{"routes":[{"name":"api","hosts":[" Example.TEST. ","*.Sub.Example.TEST.","[::1]"],"path_prefix":"/"}]}`
	if err := os.WriteFile(configPath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	got := table.Routes()[0].Hosts
	want := []string{"example.test", "*.sub.example.test", "::1"}
	if len(got) != len(want) {
		t.Fatalf("hosts=%#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hosts=%#v, want %#v", got, want)
		}
	}
}

func TestMatchNormalizesBracketedIPv6HostWithoutPort(t *testing.T) {
	table := &Table{routes: []Route{{Name: "ipv6", Hosts: []string{"::1"}, PathPrefix: "/"}}}
	req := httptest.NewRequest("GET", "http://[::1]/healthz", nil)
	got, ok := table.Match(req)
	if !ok || got.Name != "ipv6" {
		t.Fatalf("expected IPv6 route, got %#v, ok=%v", got, ok)
	}
}
