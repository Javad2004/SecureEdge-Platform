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

	"github.com/bachelor-project/edgeproxy/internal/admin"
	"github.com/bachelor-project/edgeproxy/internal/config"
	"github.com/bachelor-project/edgeproxy/internal/metrics"
	"github.com/bachelor-project/edgeproxy/internal/proxy"
)

func Run(cfg config.Config, logger *slog.Logger) error {
	registry := metrics.New()
	handler, err := proxy.NewHandler(cfg, logger, registry)
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
		adminServer = admin.New(cfg.Admin, logger, registry, handler).HTTPServer()
		go func() {
			logger.Info("admin server starting", "address", cfg.Admin.ListenAddr)
			if serveErr := adminServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				errCh <- fmt.Errorf("admin server: %w", serveErr)
			}
		}()
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-sigCtx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer cancel()
	if adminServer != nil {
		_ = adminServer.Shutdown(shutdownCtx)
	}
	if err := mainServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}
