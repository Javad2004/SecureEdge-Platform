package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestShutdownServersClosesAllListenersBeforeWaitingForHandlers(t *testing.T) {
	type runningServer struct {
		server      *http.Server
		started     chan struct{}
		release     chan struct{}
		serveDone   chan error
		requestDone chan error
	}

	start := func() runningServer {
		started := make(chan struct{})
		release := make(chan struct{})
		var startedOnce sync.Once
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			startedOnce.Do(func() { close(started) })
			<-release
			w.WriteHeader(http.StatusNoContent)
		})}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve(listener) }()
		requestDone := make(chan error, 1)
		go func() {
			response, requestErr := http.Get("http://" + listener.Addr().String())
			if response != nil {
				_ = response.Body.Close()
			}
			requestDone <- requestErr
		}()
		return runningServer{server: server, started: started, release: release, serveDone: serveDone, requestDone: requestDone}
	}

	first := start()
	second := start()
	for name, started := range map[string]<-chan struct{}{"first": first.started, "second": second.started} {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s request handler did not start", name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- shutdownServers(ctx,
			namedHTTPServer{name: "first", server: first.server},
			namedHTTPServer{name: "second", server: second.server},
		)
	}()

	// Shutdown closes every listener before waiting for active handlers. Both
	// Serve calls must therefore stop even though neither handler is released yet.
	for name, done := range map[string]<-chan error{"first": first.serveDone, "second": second.serveDone} {
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("%s Serve returned %v, want http.ErrServerClosed", name, err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("%s listener remained open while another server was draining", name)
		}
	}

	close(first.release)
	close(second.release)
	for name, done := range map[string]<-chan error{"first": first.requestDone, "second": second.requestDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s request failed after handler release: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s request did not finish", name)
		}
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdownServers returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdownServers did not return")
	}
}

func TestShutdownServersForcesCloseAfterDeadline(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request handler did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	shutdownErr := shutdownServers(ctx, namedHTTPServer{name: "test", server: server})
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("shutdown error=%v, want context deadline exceeded", shutdownErr)
	}

	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("forced shutdown did not cancel the active request")
	}
	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client request remained blocked after forced shutdown")
	}
	select {
	case serveErr := <-serveDone:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Fatalf("Serve returned %v, want http.ErrServerClosed", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop accepting connections")
	}
}
