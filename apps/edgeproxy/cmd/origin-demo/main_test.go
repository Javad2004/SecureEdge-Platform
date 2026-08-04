package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSafeLogPathExcludesQueryValues(t *testing.T) {
	req := httptest.NewRequest("GET", "http://origin.test/items?token=super-secret", nil)
	if got := safeLogPath(req); got != "/items" {
		t.Fatalf("expected query-free log path, got %q", got)
	}
}

func TestWaitForRequestStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if waitForRequest(ctx, time.Minute) {
		t.Fatal("canceled request unexpectedly completed its wait")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("canceled wait returned too slowly: %v", elapsed)
	}
}

func TestShutdownServerForceClosesAfterDeadline(t *testing.T) {
	requestStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
		close(requestCanceled)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	clientDone := make(chan error, 1)
	go func() {
		_, requestErr := http.Get("http://" + listener.Addr().String())
		clientDone <- requestErr
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not reach origin server")
	}

	shutdownErr := shutdownServer(server, 20*time.Millisecond)
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("expected shutdown deadline error, got %v", shutdownErr)
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("forced close did not cancel the active request")
	}
	select {
	case requestErr := <-clientDone:
		if requestErr == nil {
			t.Fatal("client unexpectedly received a successful response")
		}
	case <-time.After(time.Second):
		t.Fatal("client did not observe the forced close")
	}
	select {
	case serveErr := <-serveDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("unexpected serve error: %v", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop after forced close")
	}
}
