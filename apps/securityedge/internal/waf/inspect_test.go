package waf

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

func inspector(t *testing.T) *Inspector {
	t.Helper()
	i, err := NewInspector(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestDetectSQLiAndRestoreBody(t *testing.T) {
	req := httptest.NewRequest("POST", "http://project.test/login", strings.NewReader(`{"username":"admin' OR 1=1 --"}`))
	req.Header.Set("Content-Type", "application/json")
	p := config.Default().DefaultPolicy
	got, err := inspector(t).Inspect(req, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Score < p.AnomalyThreshold || len(got.Matches) == 0 {
		t.Fatalf("unexpected result: %#v", got)
	}
	data := make([]byte, 128)
	n, _ := req.Body.Read(data)
	if !strings.Contains(string(data[:n]), "username") {
		t.Fatal("body was not restored")
	}
}
func TestCleanRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "http://project.test/api/products?page=2", nil)
	got, err := inspector(t).Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if got.Score != 0 {
		t.Fatalf("false positive: %#v", got)
	}
}
func TestDetectSSRFAndXXE(t *testing.T) {
	p := config.Default().DefaultPolicy
	req := httptest.NewRequest("POST", "http://project.test/fetch?url=http://169.254.169.254/latest/meta-data", strings.NewReader(`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`))
	req.Header.Set("Content-Type", "application/xml")
	got, err := inspector(t).Inspect(req, p)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range got.Matches {
		seen[m.Category] = true
	}
	if !seen["ssrf"] || !seen["xxe"] {
		t.Fatalf("missing categories: %#v", got.Matches)
	}
}
func TestCustomRule(t *testing.T) {
	custom := []config.CustomRuleConfig{{ID: "CUSTOM-001", Name: "Secret probe", Category: "custom", Description: "test", Score: 7, Targets: []string{"query"}, Pattern: `(?i)super-secret-token`}}
	i, err := NewInspector(custom, 32)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://project.test/?q=super-secret-token", nil)
	got, err := i.Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if got.Score != 7 || got.Matches[0].RuleID != "CUSTOM-001" {
		t.Fatalf("unexpected: %#v", got)
	}
}
func TestMatchCap(t *testing.T) {
	i, err := NewInspector(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://project.test/?q=%3Cscript%3Ejavascript:alert(1)%3C/script%3E", nil)
	got, err := i.Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if !got.MatchLimitReached || len(got.Matches) != 1 {
		t.Fatalf("cap not enforced: %#v", got)
	}
}
func FuzzInspectorNeverPanics(f *testing.F) {
	f.Add("/api/products", "page=1", "hello")
	f.Add("/search", "q=%3Cscript%3Ealert(1)%3C/script%3E", "admin' OR 1=1 --")
	f.Fuzz(func(t *testing.T, path, query, body string) {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		req := httptest.NewRequest("POST", "http://project.test/", strings.NewReader(body))
		req.URL.Path = path
		req.URL.RawPath = ""
		req.URL.RawQuery = query
		req.Header.Set("Content-Type", "text/plain")
		_, _ = inspector(t).Inspect(req, config.Default().DefaultPolicy)
	})
}

func TestExcludedPathRequiresSegmentBoundary(t *testing.T) {
	custom := []config.CustomRuleConfig{{
		ID: "CUSTOM-EXCLUSION-001", Name: "Excluded path boundary", Category: "custom",
		Description: "detects the regression marker", Score: 7, Targets: []string{"path"}, Pattern: `blocked-marker`,
	}}
	i, err := NewInspector(custom, 32)
	if err != nil {
		t.Fatal(err)
	}
	policy := config.Default().DefaultPolicy
	policy.ExcludedPathPrefixes = []string{"/healthz"}

	for _, path := range []string{"/healthz", "/healthz/ready"} {
		req := httptest.NewRequest("GET", "http://project.test"+path+"/blocked-marker", nil)
		if path == "/healthz" {
			req = httptest.NewRequest("GET", "http://project.test/healthz", nil)
		}
		got, err := i.Inspect(req, policy)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Excluded {
			t.Fatalf("expected %q to be excluded", req.URL.Path)
		}
	}

	req := httptest.NewRequest("GET", "http://project.test/healthz-admin/blocked-marker", nil)
	got, err := i.Inspect(req, policy)
	if err != nil {
		t.Fatal(err)
	}
	if got.Excluded || len(got.Matches) == 0 {
		t.Fatalf("similar path must remain inspected: %#v", got)
	}
}

func TestExcludedPathCanonicalizationPreventsDotSegmentBypass(t *testing.T) {
	custom := []config.CustomRuleConfig{{
		ID: "CUSTOM-EXCLUSION-002", Name: "Excluded path traversal", Category: "custom",
		Description: "detects the regression marker", Score: 7, Targets: []string{"path"}, Pattern: `blocked-marker`,
	}}
	i, err := NewInspector(custom, 32)
	if err != nil {
		t.Fatal(err)
	}
	policy := config.Default().DefaultPolicy
	policy.ExcludedPathPrefixes = []string{"/healthz"}

	req := httptest.NewRequest("GET", "http://project.test/healthz/../admin/blocked-marker", nil)
	got, err := i.Inspect(req, policy)
	if err != nil {
		t.Fatal(err)
	}
	if got.Excluded || len(got.Matches) == 0 {
		t.Fatalf("dot-segment path must remain inspected: %#v", got)
	}
}
