package waf

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bachelor-project/edgeproxy-security/internal/config"
)

func TestDetectSQLiAndRestoreBody(t *testing.T) {
	req := httptest.NewRequest("POST", "http://project.test/login", strings.NewReader(`{"username":"admin' OR 1=1 --"}`))
	req.Header.Set("Content-Type", "application/json")
	p := config.Default().DefaultPolicy
	got, err := NewInspector().Inspect(req, p)
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
	got, err := NewInspector().Inspect(req, config.Default().DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if got.Score != 0 {
		t.Fatalf("false positive: %#v", got)
	}
}
