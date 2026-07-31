package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	securityedge "github.com/bachelor-project/edgeproxy-security"
)

func main() {
	configPath := flag.String("config", "configs/local-dev.json", "path to security configuration")
	validate := flag.Bool("validate", false, "validate configuration and exit")
	pretty := flag.Bool("pretty-logs", false, "use human-readable logs")
	flag.Parse()
	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	if *pretty {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(handler)
	runtime, err := securityedge.New(*configPath, logger)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	defer runtime.Close()
	if *validate {
		fmt.Println("configuration is valid")
		return
	}
	cfg := runtime.Config()
	adminServer, err := runtime.AdminServer()
	if err != nil {
		logger.Error("admin setup failed", "error", err)
		os.Exit(1)
	}
	errCh := make(chan error, 2)
	var gatewayServer *http.Server
	if cfg.Server.Mode == "gateway" {
		target, err := url.Parse(cfg.Server.UpstreamProxyURL)
		if err != nil {
			logger.Error("invalid upstream proxy URL", "error", err)
			os.Exit(1)
		}
		reverse := httputil.NewSingleHostReverseProxy(target)
		reverse.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("edgeproxy forwarding failed", "error", err, "request_id", r.Header.Get("X-Request-ID"))
			http.Error(w, "edge proxy unavailable", http.StatusBadGateway)
		}
		gatewayServer = &http.Server{Addr: cfg.Server.ListenAddr, Handler: runtime.Wrap(reverse), ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration, ReadTimeout: cfg.Server.ReadTimeout.Duration, WriteTimeout: cfg.Server.WriteTimeout.Duration, IdleTimeout: cfg.Server.IdleTimeout.Duration, MaxHeaderBytes: cfg.Server.MaxHeaderBytes}
		go func() {
			logger.Info("security gateway starting", "address", cfg.Server.ListenAddr, "upstream", cfg.Server.UpstreamProxyURL)
			if err := gatewayServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("security gateway: %w", err)
			}
		}()
	}
	if cfg.Admin.Enabled {
		go func() {
			logger.Info("security admin and dashboard starting", "address", cfg.Admin.ListenAddr)
			if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("security admin: %w", err)
			}
		}()
	}
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var runErr error
	select {
	case <-sigCtx.Done():
		logger.Info("shutdown signal received")
	case runErr = <-errCh:
		logger.Error("listener failed", "error", runErr)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer cancel()
	if gatewayServer != nil {
		_ = gatewayServer.Shutdown(shutdownCtx)
	}
	if cfg.Admin.Enabled {
		_ = adminServer.Shutdown(shutdownCtx)
	}
	if runErr != nil {
		os.Exit(1)
	}
}
