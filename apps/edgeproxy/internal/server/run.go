package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/admin"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

func Run(cfg config.Config, logger *slog.Logger) error {
	registry := metrics.New()
	var logStore *accesslog.Store
	if cfg.Admin.Enabled && cfg.Admin.LogStore.Enabled {
		logStore = accesslog.New(cfg.Admin.LogStore.Capacity)
	}
	handler, err := proxy.NewHandler(cfg, logger, registry, logStore)
	if err != nil {
		return err
	}
	defer handler.Close()

	mainServer := &http.Server{
		Addr: cfg.Server.ListenAddr, Handler: handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration,
		ReadTimeout:       cfg.Server.ReadTimeout.Duration,
		WriteTimeout:      cfg.Server.WriteTimeout.Duration,
		IdleTimeout:       cfg.Server.IdleTimeout.Duration,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("proxy server starting", "address", cfg.Server.ListenAddr, "tls", cfg.Server.TLS.Enabled)
		var serveErr error
		if cfg.Server.TLS.Enabled {
			serveErr = mainServer.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			serveErr = mainServer.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy server: %w", serveErr)
		}
	}()

	var adminServer *http.Server
	if cfg.Admin.Enabled {
		adminServer = admin.New(cfg.Admin, logger, registry, handler, logStore).HTTPServer()
		go func() {
			logger.Info("admin server starting", "address", cfg.Admin.ListenAddr)
			if serveErr := adminServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				errCh <- fmt.Errorf("admin server: %w", serveErr)
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
		logger.Error("listener failed; shutting down remaining servers", "error", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer cancel()
	var shutdownErrs []error
	if adminServer != nil {
		if err := adminServer.Shutdown(shutdownCtx); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("admin graceful shutdown: %w", err))
		}
	}
	if err := mainServer.Shutdown(shutdownCtx); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("proxy graceful shutdown: %w", err))
	}
	return errors.Join(append([]error{runErr}, shutdownErrs...)...)
}
