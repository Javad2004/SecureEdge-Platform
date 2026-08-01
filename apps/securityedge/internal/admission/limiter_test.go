package admission

import "testing"

func TestConcurrencyLimits(t *testing.T) {
	l := New()
	release, ok, _ := l.Acquire("a", 2, 1)
	if !ok {
		t.Fatal("first denied")
	}
	if _, ok, reason := l.Acquire("a", 2, 1); ok || reason != "client_concurrency" {
		t.Fatalf("unexpected %v %s", ok, reason)
	}
	release()
	if _, ok, _ := l.Acquire("a", 2, 1); !ok {
		t.Fatal("not released")
	}
}
