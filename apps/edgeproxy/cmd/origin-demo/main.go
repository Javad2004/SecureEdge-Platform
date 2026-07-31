package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
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
			log.Printf("origin=%s method=%s path=%s xff=%q request_id=%q", *name, r.Method, r.URL.RequestURI(), r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Request-ID"))
			next(w, r)
		}
	}

	mux.HandleFunc("/healthz", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	mux.HandleFunc("/", wrap(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=20")
		fmt.Fprintf(w, `<!doctype html><html><body><h1>EdgeProxy Origin Demo</h1><p>Origin: %s</p><p>Path: %s</p><p>Generated: %s</p></body></html>`, *name, r.URL.Path, time.Now().Format(time.RFC3339Nano))
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
		http.SetCookie(w, &http.Cookie{Name: "demo_session", Value: "secret", HttpOnly: true})
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "private responses must not be cached"})
	}))
	mux.HandleFunc("/api/slow", wrap(func(w http.ResponseWriter, r *http.Request) {
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		if ms < 0 || ms > 15000 {
			ms = 1000
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=10")
		_ = json.NewEncoder(w).Encode(map[string]any{"origin": *name, "slept_ms": ms})
	}))
	mux.HandleFunc("/api/error", wrap(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "intentional origin error", http.StatusServiceUnavailable)
	}))
	mux.HandleFunc("/api/counter", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"origin": *name, "requests": total.Load()})
	}))

	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("origin demo %q listening on %s", *name, *addr)
	log.Fatal(server.ListenAndServe())
}
