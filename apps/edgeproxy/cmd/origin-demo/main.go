package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", ":9000", "listen address")
	name := flag.String("name", "origin-a", "origin server name")
	flag.Parse()

	var total atomic.Uint64
	mux := http.NewServeMux()
	wrap := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			total.Add(1)
			w.Header().Set("X-Origin-Name", *name)
			log.Printf("origin=%s method=%s path=%s xff=%q request_id=%q", *name, r.Method, safeLogPath(r), r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Request-ID"))
			next(w, r)
		}
	}

	mux.HandleFunc("/healthz", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/", wrap(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=20")
		fmt.Fprintf(w, `<!doctype html><html><body><h1>EdgeProxy Origin Demo</h1><p>Origin: %s</p><p>Path: %s</p><p>Generated: %s</p></body></html>`, html.EscapeString(*name), html.EscapeString(r.URL.Path), time.Now().Format(time.RFC3339Nano))
	}))
	mux.HandleFunc("/api/products", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=30")
		_ = json.NewEncoder(w).Encode(map[string]any{"origin": *name, "products": []string{"keyboard", "mouse", "monitor"}, "generated_at": time.Now().UTC()})
	}))
	mux.HandleFunc("/api/time", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"origin": *name, "time": time.Now().UTC()})
	}))
	mux.HandleFunc("/api/private", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		http.SetCookie(w, &http.Cookie{Name: "demo_session", Value: "secret", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "private responses must not be cached"})
	}))
	mux.HandleFunc("/api/slow", wrap(func(w http.ResponseWriter, r *http.Request) {
		ms := 1000
		if raw := r.URL.Query().Get("ms"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 && parsed <= 15000 {
				ms = parsed
			}
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=10")
		_ = json.NewEncoder(w).Encode(map[string]any{"origin": *name, "slept_ms": ms})
	}))
	mux.HandleFunc("/api/error", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "intentional origin error", http.StatusServiceUnavailable)
	}))
	mux.HandleFunc("/api/counter", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"origin": *name, "requests": total.Load()})
	}))

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("origin demo %q listening on %s", *name, *addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-sigCtx.Done():
		log.Printf("origin demo %q shutting down", *name)
	case err := <-errCh:
		log.Fatalf("origin server failed: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("origin graceful shutdown failed: %v", err)
	}
}

func safeLogPath(r *http.Request) string {
	path := r.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}
