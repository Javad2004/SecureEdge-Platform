package main

import (
	"net/http/httptest"
	"testing"
)

func TestSafeLogPathExcludesQueryValues(t *testing.T) {
	req := httptest.NewRequest("GET", "http://origin.test/items?token=super-secret", nil)
	if got := safeLogPath(req); got != "/items" {
		t.Fatalf("expected query-free log path, got %q", got)
	}
}
