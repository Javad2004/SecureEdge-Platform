package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/accesslog"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/admin"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/control"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/metrics"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/proxy"
)

type generation struct {
	cfg         config.Config
	handler     *proxy.Handler
	mainServer  *http.Server
	adminServer *http.Server
	errCh       chan error
}

// Run starts one immutable listener generation. RunManaged should be preferred
// by the executable because it also enables the authenticated control plane and
// automatic config-file reload/restart supervision.
func Run(cfg config.Config, logger *slog.Logger) error {
	return runLoop("", "", cfg, logger, false, false)
}

func RunManaged(configPath, envPath string, cfg config.Config, logger *slog.Logger, allowEnvironmentConfigPath ...bool) error {
	allowPath := len(allowEnvironmentConfigPath) > 0 && allowEnvironmentConfigPath[0]
	return runLoop(configPath, envPath, cfg, logger, true, allowPath)
}

func runLoop(configPath, envPath string, cfg config.Config, logger *slog.Logger, managed, allowEnvironmentConfigPath bool) error {
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var manager *control.Manager
	var err error
	if managed {
		manager, err = control.New(configPath, envPath, logger, allowEnvironmentConfigPath)
		if err != nil {
			return err
		}
	}
	watchStarted := false

	for {
		gen, err := startGeneration(cfg, logger, manager)
		if err != nil {
			return err
		}
		if manager != nil {
			manager.Attach(gen.handler, cfg)
			if !watchStarted {
				manager.Start(sigCtx)
				watchStarted = true
			}
		}

		var runErr error
		var next config.Config
		restart := false
		select {
		case <-sigCtx.Done():
			logger.Info("shutdown signal received")
		case runErr = <-gen.errCh:
			logger.Error("listener failed; shutting down generation", "error", runErr)
		case next = <-restartRequests(manager):
			restart = true
			logger.Info("configuration requires automatic listener restart")
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), gen.cfg.Server.ShutdownTimeout.Duration)
		shutdownErr := shutdownServers(shutdownCtx,
			namedHTTPServer{name: "proxy", server: gen.mainServer},
			namedHTTPServer{name: "admin", server: gen.adminServer},
		)
		cancel()
		gen.handler.Close()
		if runErr != nil || shutdownErr != nil {
			return errors.Join(runErr, shutdownErr)
		}
		if !restart {
			return nil
		}
		// Changes arriving while listeners drain are folded into the next
		// generation, avoiding an unnecessary intermediate restart.
		next = latestRestart(next, manager)
		cfg = next
	}
}

func latestRestart(current config.Config, manager *control.Manager) config.Config {
	if manager == nil {
		return current
	}
	for {
		select {
		case newer := <-manager.RestartRequests():
			current = newer
		default:
			return current
		}
	}
}

func restartRequests(manager *control.Manager) <-chan config.Config {
	if manager == nil {
		return make(chan config.Config)
	}
	return manager.RestartRequests()
}

func startGeneration(cfg config.Config, logger *slog.Logger, manager *control.Manager) (*generation, error) {
	registry := metrics.New()
	var logStore *accesslog.Store
	if cfg.Admin.Enabled && cfg.Admin.LogStore.Enabled {
		logStore = accesslog.New(cfg.Admin.LogStore.Capacity)
	}
	handler, err := proxy.NewHandler(cfg, logger, registry, logStore)
	if err != nil {
		return nil, err
	}
	gen := &generation{cfg: cfg, handler: handler, errCh: make(chan error, 2)}
	gen.mainServer = &http.Server{
		Addr: cfg.Server.ListenAddr, Handler: handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration,
		ReadTimeout:       cfg.Server.ReadTimeout.Duration,
		WriteTimeout:      cfg.Server.WriteTimeout.Duration,
		IdleTimeout:       cfg.Server.IdleTimeout.Duration,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}
	go func() {
		logger.Info("proxy server starting", "address", cfg.Server.ListenAddr, "tls", cfg.Server.TLS.Enabled)
		var serveErr error
		if cfg.Server.TLS.Enabled {
			serveErr = gen.mainServer.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			serveErr = gen.mainServer.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			gen.errCh <- fmt.Errorf("proxy server: %w", serveErr)
		}
	}()

	if cfg.Admin.Enabled {
		gen.adminServer = admin.New(cfg.Admin, logger, registry, handler, logStore, manager).HTTPServer()
		go func() {
			logger.Info("admin server starting", "address", cfg.Admin.ListenAddr)
			if serveErr := gen.adminServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				gen.errCh <- fmt.Errorf("admin server: %w", serveErr)
			}
		}()
	}
	return gen, nil
}

type namedHTTPServer struct {
	name   string
	server *http.Server
}

// shutdownServers stops independent listeners concurrently so one slow
// listener cannot consume the entire shared shutdown deadline before the
// remaining listeners receive a chance to drain.
func shutdownServers(ctx context.Context, servers ...namedHTTPServer) error {
	errCh := make(chan error, len(servers))
	var wg sync.WaitGroup
	for _, item := range servers {
		if item.server == nil {
			continue
		}
		wg.Add(1)
		go func(item namedHTTPServer) {
			defer wg.Done()
			if err := item.server.Shutdown(ctx); err != nil {
				gracefulErr := fmt.Errorf("%s graceful shutdown: %w", item.name, err)
				closeErr := item.server.Close()
				if closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
					errCh <- errors.Join(gracefulErr, fmt.Errorf("%s forced shutdown: %w", item.name, closeErr))
					return
				}
				errCh <- gracefulErr
			}
		}(item)
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
