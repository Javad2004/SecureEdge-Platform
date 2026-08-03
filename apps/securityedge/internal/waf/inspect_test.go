package waf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
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

func TestRepeatedHeaderValuesAreAllInspected(t *testing.T) {
	req := httptest.NewRequest("GET", "http://project.test/", nil)
	values := make([]string, 17)
	for index := 0; index < 16; index++ {
		values[index] = "safe"
	}
	values[16] = "javascript:alert(1)"
	req.Header["X-Repeated"] = values

	got, err := inspector(t).Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Matches) == 0 {
		t.Fatal("a malicious repeated header value after the sixteenth field was not inspected")
	}
}

func TestRawCookieFieldCoversValuesBeyondParsedSampleCap(t *testing.T) {
	req := httptest.NewRequest("GET", "http://project.test/", nil)
	parts := make([]string, 0, 65)
	for index := 0; index < 64; index++ {
		parts = append(parts, fmt.Sprintf("safe%d=ok", index))
	}
	parts = append(parts, "attack=%0d%0a")
	req.Header.Set("Cookie", strings.Join(parts, "; "))

	got, err := inspector(t).Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Matches) == 0 {
		t.Fatal("a malicious cookie after the parsed-cookie sample cap was not inspected")
	}
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

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestReadAndRestoreTruncatedBodyPreservesCloseSemantics(t *testing.T) {
	payload := []byte("0123456789")
	original := &closeTrackingBody{Reader: bytes.NewReader(payload)}
	req := httptest.NewRequest("POST", "http://project.test/upload", nil)
	req.Body = original

	inspected, truncated, err := readAndRestore(req, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || string(inspected) != "0123" {
		t.Fatalf("unexpected inspection result: body=%q truncated=%v", inspected, truncated)
	}

	replayed, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, payload) {
		t.Fatalf("restored body mismatch: got %q want %q", replayed, payload)
	}
	if err := req.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !original.closed {
		t.Fatal("closing the restored body did not close the original request body")
	}
}

func TestStructuredSampleExpansionIsBounded(t *testing.T) {
	pairs := make([]string, 2000)
	jsonFields := make([]string, 2000)
	for index := range pairs {
		pairs[index] = fmt.Sprintf("k%d=v%d", index, index)
		jsonFields[index] = fmt.Sprintf("%q:%q", fmt.Sprintf("k%d", index), fmt.Sprintf("v%d", index))
	}

	queryRequest := httptest.NewRequest("GET", "http://project.test/?"+strings.Join(pairs, "&"), nil)
	if samples := querySamples(queryRequest.URL); len(samples) > maxStructuredSamples {
		t.Fatalf("query expansion produced %d samples; limit is %d", len(samples), maxStructuredSamples)
	}
	if samples := bodySamples([]byte(strings.Join(pairs, "&")), "application/x-www-form-urlencoded"); len(samples) > maxStructuredSamples {
		t.Fatalf("form expansion produced %d samples; limit is %d", len(samples), maxStructuredSamples)
	}
	if samples := bodySamples([]byte("{"+strings.Join(jsonFields, ",")+"}"), "application/json"); len(samples) > maxStructuredSamples {
		t.Fatalf("JSON expansion produced %d samples; limit is %d", len(samples), maxStructuredSamples)
	}
}

func TestOversizedStructuredLocationIsFingerprinted(t *testing.T) {
	key := strings.Repeat("field", 300)
	body := fmt.Sprintf(`{%q:"\u003cscript\u003e"}`, key)
	req := httptest.NewRequest("POST", "http://project.test/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	got, err := inspector(t).Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range got.Matches {
		if match.RuleID != "XSS-001" {
			continue
		}
		if !strings.HasPrefix(match.Location, "oversized-field:") {
			t.Fatalf("oversized location was not fingerprinted: %q", match.Location)
		}
		if len(match.Location) > maxMatchLocationBytes {
			t.Fatalf("fingerprinted location is too large: %d", len(match.Location))
		}
		return
	}
	t.Fatalf("expected decoded JSON string to match XSS-001: %#v", got.Matches)
}

func TestHostHeaderIsInspectedByHeaderRules(t *testing.T) {
	custom := []config.CustomRuleConfig{{
		ID:          "CUSTOM-HOST-001",
		Name:        "Malicious virtual host",
		Category:    "protocol",
		Description: "detects an attacker-controlled Host value",
		Score:       7,
		Targets:     []string{"headers"},
		Pattern:     `(?i)attacker-marker`,
	}}
	i, err := NewInspector(custom, 32)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://project.test/", nil)
	// This is a syntactically valid hostname and can match a wildcard/catch-all
	// route, but net/http stores it in Request.Host rather than Request.Header.
	req.Host = "attacker-marker.example.test"

	got, err := i.Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Matches) != 1 || got.Matches[0].RuleID != "CUSTOM-HOST-001" {
		t.Fatalf("Host header was not inspected: %#v", got)
	}
	if got.Matches[0].Location != "header:host" {
		t.Fatalf("unexpected Host match location %q", got.Matches[0].Location)
	}
}

func TestHostCountsTowardHeaderInspectionLimit(t *testing.T) {
	req := httptest.NewRequest("GET", "http://project.test/", nil)
	req.Host = "safe.example.test"
	req.Header.Set("X-Later", "javascript:alert(1)")

	samples := headerSamples(req, 1)
	if len(samples) != 2 || samples[0].value != "Host" || samples[1].location != "header:host" {
		t.Fatalf("unexpected samples at one-field limit: %#v", samples)
	}
}

func TestTrailerValuesAreInspectedAsHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "http://project.test/upload", strings.NewReader("payload"))
	req.ContentLength = -1
	req.Trailer = http.Header{"X-Scanner": {"sqlmap"}}

	got, err := inspector(t).Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range got.Matches {
		if match.RuleID == "SCAN-001" && match.Target == "headers" && match.Location == "trailer:x-scanner" {
			return
		}
	}
	t.Fatalf("malicious trailer was not inspected as a header: %#v", got.Matches)
}
