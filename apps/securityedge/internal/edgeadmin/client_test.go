package edgeadmin

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewRejectsUnsafeAdminURLs(t *testing.T) {
	for _, raw := range []string{
		"ftp://edgeproxy.test",
		"http://user:pass@edgeproxy.test",
		"http://edgeproxy.test?token=value",
		"http://edgeproxy.test#fragment",
		"edgeproxy.test:9090",
	} {
		if _, err := New(raw, "token", time.Second); err == nil {
			t.Fatalf("expected URL %q to be rejected", raw)
		}
	}
}

func TestClientDisablesAmbientProxyAndRedirects(t *testing.T) {
	var redirected atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("authorization leaked to redirect target: %q", got)
		}
		_, _ = w.Write([]byte(`{"status":"unexpected"}`))
	}))
	defer sink.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, sink.URL, http.StatusFound)
	}))
	defer source.Close()

	client, err := New(source.URL, "control-plane-secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("control-plane client must disable ambient proxy: %#v", client.http.Transport)
	}
	_, status, err := client.JSON(context.Background(), http.MethodGet, "/healthz", nil, nil)
	if err == nil || status != http.StatusFound {
		t.Fatalf("redirect response status=%d error=%v", status, err)
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target received %d requests", redirected.Load())
	}
}

func TestClientRejectsOversizedJSONResponse(t *testing.T) {
	const advertisedSize = maxResponseBytes + 1
	var handlerCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.FormatInt(advertisedSize, 10))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(server.URL, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, status, err := client.JSON(context.Background(), http.MethodGet, "/large", nil, nil)
	if status != http.StatusOK || err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("status=%d error=%v", status, err)
	}
	if !handlerCalled.Load() {
		t.Fatal("test server was not called")
	}
}

func TestReadJSONResponseRejectsUnknownLengthBodyAtLimit(t *testing.T) {
	data, err := readJSONResponse(bytes.NewBufferString(`{"value":"abcdef"}`), -1, 8)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("data=%q error=%v", data, err)
	}
}

func TestReadJSONResponseAcceptsBodyAtExactLimit(t *testing.T) {
	data, err := readJSONResponse(bytes.NewBufferString(`{"ok":1}`), -1, 8)
	if err != nil || string(data) != `{"ok":1}` {
		t.Fatalf("data=%q error=%v", data, err)
	}
}

func TestClientReturnsValidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer control-token" {
			t.Fatalf("authorization=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client, err := New(server.URL, "control-token", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw, status, err := client.JSON(context.Background(), http.MethodGet, "/healthz", nil, nil)
	if err != nil || status != http.StatusOK || string(raw) != `{"status":"ok"}` {
		t.Fatalf("status=%d raw=%s error=%v", status, raw, err)
	}
}
