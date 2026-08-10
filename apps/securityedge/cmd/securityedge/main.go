package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	securityedge "github.com/Javad2004/SecureEdge-Platform/apps/securityedge"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/envfile"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/gateway"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	configFlag := flag.String("config", "", "path to security configuration (overrides SECURITYEDGE_CONFIG)")
	envFlag := flag.String("env", "", "path to optional .env file (overrides SECURITYEDGE_ENV_FILE)")
	noEnv := flag.Bool("no-env", false, "disable automatic and explicit dotenv loading")
	validate := flag.Bool("validate", false, "validate configuration and exit")
	pretty := flag.Bool("pretty-logs", false, "use human-readable logs")
	logLevel := flag.String("log-level", "info", "debug, info, warn, or error")
	showVersion := flag.Bool("version", false, "print build version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return 0
	}

	if *noEnv && strings.TrimSpace(*envFlag) != "" {
		fmt.Fprintln(os.Stderr, "-env and -no-env cannot be used together")
		return 1
	}
	loadedEnv := ""
	_, configEnvironmentPreexisting := os.LookupEnv("SECURITYEDGE_CONFIG")
	var err error
	if !*noEnv {
		explicitEnv := firstNonEmpty(*envFlag, os.Getenv("SECURITYEDGE_ENV_FILE"))
		loadedEnv, err = envfile.Load(explicitEnv, envfile.ApplicationCandidates("apps/securityedge/.env")...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	configPath := resolveConfigPath(
		*configFlag,
		os.Getenv("SECURITYEDGE_CONFIG"),
		loadedEnv,
		!configEnvironmentPreexisting,
		"configs/local-dev.json",
		"apps/securityedge/configs/local-dev.json",
	)
	level, err := parseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	if *pretty {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	logger := slog.New(handler)
	if loadedEnv != "" {
		logger.Info("environment file loaded", "path", loadedEnv)
	}
	if *validate {
		if err := securityedge.Validate(configPath); err != nil {
			logger.Error("configuration failed", "error", err)
			return 1
		}
		fmt.Println("configuration is valid")
		return 0
	}
	allowEnvironmentConfigPath := strings.TrimSpace(*configFlag) == "" && !configEnvironmentPreexisting
	return runManaged(configPath, loadedEnv, logger, allowEnvironmentConfigPath)

}

type securityGeneration struct {
	runtime                *securityedge.Runtime
	cfg                    config.Config
	gatewayServer          *http.Server
	adminServer            *http.Server
	errCh                  chan error
	restartEnvironmentFrom *envfile.ManagedSnapshot
}

type securityRestartFallback struct {
	path        string
	cfg         config.Config
	watch       securityedge.WatchStatus
	environment *envfile.ManagedSnapshot
}

type securityRollbackNotice struct {
	path string
	err  error
}

func runManaged(configPath, envPath string, logger *slog.Logger, allowEnvironmentConfigPath bool) int {
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var previousWatch securityedge.WatchStatus
	defaultConfigPath := configPath
	var fallback *securityRestartFallback
	var rollbackNotice *securityRollbackNotice
	for {
		gen, err := startSecurityGeneration(configPath, envPath, previousWatch, logger)
		if err != nil {
			if fallback != nil {
				if rollbackErr := restoreSecurityFallback(*fallback, configPath); rollbackErr != nil {
					logger.Error("replacement SecurityEdge generation failed and last-known-good configuration could not be restored", "startup_error", err, "rollback_error", rollbackErr)
					return 1
				}
				logger.Error("replacement SecurityEdge generation failed after restart preflight; retrying the last healthy generation", "error", err, "config", fallback.path)
				previousWatch = fallback.watch
				rollbackNotice = &securityRollbackNotice{path: configPath, err: err}
				configPath = fallback.path
				fallback = nil
				continue
			}
			logger.Error("configuration failed", "error", err)
			return 1
		}
		fallback = nil
		if rollbackNotice != nil {
			gen.runtime.RecordWatchChange(rollbackNotice.path, false, false, fmt.Errorf("replacement generation failed; restored last healthy configuration: %w", rollbackNotice.err))
			rollbackNotice = nil
		}
		restart, nextConfigPath, runErr := superviseSecurityGeneration(sigCtx, gen, envPath, defaultConfigPath, allowEnvironmentConfigPath, logger)
		if restart {
			fallbackPath, fallbackConfig := gen.runtime.RestartFallback()
			fallback = &securityRestartFallback{path: fallbackPath, cfg: fallbackConfig, watch: gen.runtime.WatchStatus(), environment: gen.restartEnvironmentFrom}
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gen.cfg.Server.ShutdownTimeout.Duration)
		shutdownErr := shutdownServers(shutdownCtx,
			namedHTTPServer{name: "gateway", server: gen.gatewayServer},
			namedHTTPServer{name: "admin", server: gen.adminServer},
		)
		cancel()
		previousWatch = gen.runtime.WatchStatus()
		gen.runtime.Close()
		if shutdownErr != nil {
			logger.Error("graceful shutdown failed", "error", shutdownErr)
		}
		if runErr != nil || shutdownErr != nil {
			return 1
		}
		if !restart {
			return 0
		}
		configPath = nextConfigPath
		logger.Info("SecurityEdge generation restarted automatically", "config", configPath)
	}
}

func startSecurityGeneration(configPath, envPath string, previousWatch securityedge.WatchStatus, logger *slog.Logger) (*securityGeneration, error) {
	runtime, err := securityedge.New(configPath, logger)
	if err != nil {
		return nil, err
	}
	runtime.ConfigureWatcher(envPath, previousWatch)
	cfg := runtime.Config()
	gen := &securityGeneration{runtime: runtime, cfg: cfg, errCh: make(chan error, 2)}
	var gatewayListener net.Listener
	var adminListener net.Listener
	if cfg.Admin.Enabled {
		gen.adminServer, err = runtime.AdminServer()
		if err != nil {
			runtime.Close()
			return nil, fmt.Errorf("admin setup failed: %w", err)
		}
	}
	if cfg.Server.Mode == "gateway" {
		target, err := url.Parse(cfg.Server.UpstreamProxyURL)
		if err != nil {
			runtime.Close()
			return nil, fmt.Errorf("invalid upstream proxy URL: %w", err)
		}
		reverse := newReverseProxy(target, cfg.Server, logger)
		gen.gatewayServer = &http.Server{
			Addr: cfg.Server.ListenAddr, Handler: runtime.Wrap(reverse),
			ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration, ReadTimeout: cfg.Server.ReadTimeout.Duration,
			WriteTimeout: cfg.Server.WriteTimeout.Duration, IdleTimeout: cfg.Server.IdleTimeout.Duration,
			MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
		}
		if cfg.Server.TLS.Enabled {
			certificate, certErr := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
			if certErr != nil {
				runtime.Close()
				return nil, fmt.Errorf("load security gateway TLS certificate: %w", certErr)
			}
			gen.gatewayServer.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS12,
			}
		}
		gatewayListener, err = net.Listen("tcp", cfg.Server.ListenAddr)
		if err != nil {
			runtime.Close()
			return nil, fmt.Errorf("listen security gateway %q: %w", cfg.Server.ListenAddr, err)
		}
	}
	if gen.adminServer != nil {
		adminListener, err = net.Listen("tcp", cfg.Admin.ListenAddr)
		if err != nil {
			if gatewayListener != nil {
				_ = gatewayListener.Close()
			}
			runtime.Close()
			return nil, fmt.Errorf("listen security admin %q: %w", cfg.Admin.ListenAddr, err)
		}
	}
	if gen.gatewayServer != nil {
		go func() {
			logger.Info("security gateway starting", "address", cfg.Server.ListenAddr, "tls", cfg.Server.TLS.Enabled, "upstream", cfg.Server.UpstreamProxyURL, "max_concurrent", cfg.Server.MaxConcurrentRequests, "max_body_bytes", cfg.Server.MaxRequestBodyBytes)
			var serveErr error
			if cfg.Server.TLS.Enabled {
				serveErr = gen.gatewayServer.ServeTLS(gatewayListener, "", "")
			} else {
				serveErr = gen.gatewayServer.Serve(gatewayListener)
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				gen.errCh <- fmt.Errorf("security gateway: %w", serveErr)
			}
		}()
	}
	if gen.adminServer != nil {
		go func() {
			logger.Info("security admin and dashboard starting", "address", cfg.Admin.ListenAddr)
			if err := gen.adminServer.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				gen.errCh <- fmt.Errorf("security admin: %w", err)
			}
		}()
	}
	return gen, nil
}

func restoreSecurityFallback(fallback securityRestartFallback, failedPath string) error {
	if fallback.environment != nil {
		if err := envfile.RestoreManagedEnvironment(*fallback.environment); err != nil {
			return fmt.Errorf("restore last-known-good SecurityEdge environment: %w", err)
		}
	}
	// A config-path switch leaves the healthy file untouched. When the failed
	// candidate replaced the same file, restore its last successfully started
	// persisted representation before retrying the previous generation.
	if filepath.Clean(fallback.path) != filepath.Clean(failedPath) {
		return nil
	}
	if err := config.Save(fallback.path, fallback.cfg); err != nil {
		return fmt.Errorf("restore last-known-good SecurityEdge configuration %q: %w", fallback.path, err)
	}
	return nil
}

func superviseSecurityGeneration(ctx context.Context, gen *securityGeneration, envPath, defaultConfigPath string, allowEnvironmentConfigPath bool, logger *slog.Logger) (bool, string, error) {
	securityPath := gen.runtime.ConfigPath()
	edgePath := gen.runtime.EdgeConfigPath()
	securityDigest, _ := securityedge.FileDigest(securityPath)
	edgeDigest, _ := securityedge.FileDigest(edgePath)
	var envDigest [32]byte
	if envPath != "" {
		envDigest, _ = securityedge.FileDigest(envPath)
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown signal received")
			return false, securityPath, nil
		case err := <-gen.errCh:
			logger.Error("listener failed", "error", err)
			return false, securityPath, err
		case <-ticker.C:
			if envPath != "" {
				if digest, err := securityedge.FileDigest(envPath); err != nil {
					gen.runtime.RecordWatchChange(envPath, false, false, err)
				} else if digest != envDigest {
					envDigest = digest
					previousEnvironment := envfile.SnapshotManagedEnvironment()
					nextPath := securityPath
					restartRequired := false
					hotApplied := false
					err := envfile.ReloadValidated(envPath, func() error {
						nextPath = watchedConfigPath(defaultConfigPath, envPath, securityPath, allowEnvironmentConfigPath)
						if nextPath != securityPath {
							if err := gen.runtime.ValidateRestartConfig(nextPath); err != nil {
								return fmt.Errorf("validate SECURITYEDGE_CONFIG target %q: %w", nextPath, err)
							}
							restartRequired = true
							return nil
						}
						if err := gen.runtime.ReloadEnvironment(); err != nil {
							var restart interface{ RestartRequired() bool }
							if errors.As(err, &restart) && restart.RestartRequired() {
								restartRequired = true
								return nil
							}
							return err
						}
						hotApplied = true
						return nil
					})
					if err != nil {
						gen.runtime.RecordWatchChange(envPath, false, false, err)
					} else if restartRequired {
						gen.restartEnvironmentFrom = &previousEnvironment
						gen.runtime.RecordWatchChange(envPath, false, true, nil)
						return true, nextPath, nil
					} else if hotApplied {
						gen.runtime.RecordWatchChange(envPath, true, false, nil)
						edgePath = gen.runtime.EdgeConfigPath()
						edgeDigest, _ = securityedge.FileDigest(edgePath)
					}
				}
			}

			if digest, err := securityedge.FileDigest(securityPath); err != nil {
				gen.runtime.RecordWatchChange(securityPath, false, false, err)
			} else if digest != securityDigest {
				securityDigest = digest
				err := gen.runtime.Reload()
				if err != nil {
					var restart interface{ RestartRequired() bool }
					if errors.As(err, &restart) && restart.RestartRequired() {
						gen.runtime.RecordWatchChange(securityPath, false, true, nil)
						return true, securityPath, nil
					}
					gen.runtime.RecordWatchChange(securityPath, false, false, err)
				} else {
					gen.runtime.RecordWatchChange(securityPath, true, false, nil)
					edgePath = gen.runtime.EdgeConfigPath()
					edgeDigest, _ = securityedge.FileDigest(edgePath)
				}
			}

			currentEdgePath := gen.runtime.EdgeConfigPath()
			if currentEdgePath != edgePath {
				edgePath = currentEdgePath
				edgeDigest, _ = securityedge.FileDigest(edgePath)
			}
			if digest, err := securityedge.FileDigest(edgePath); err != nil {
				gen.runtime.RecordWatchChange(edgePath, false, false, err)
			} else if digest != edgeDigest {
				edgeDigest = digest
				if err := gen.runtime.ReloadEdgeRoutes(); err != nil {
					gen.runtime.RecordWatchChange(edgePath, false, false, err)
				} else {
					// This is the critical separation: an EdgeProxy route-table edit
					// updates only SecurityEdge routing metadata and never restarts its listeners.
					gen.runtime.RecordWatchChange(edgePath, true, false, nil)
					logger.Info("shared EdgeProxy route table hot-reloaded", "path", edgePath)
				}
			}
		}
	}
}

func watchedConfigPath(defaultPath, envPath, currentPath string, allowed bool) string {
	if !allowed {
		return currentPath
	}
	value := strings.TrimSpace(os.Getenv("SECURITYEDGE_CONFIG"))
	if value == "" {
		return defaultPath
	}
	if filepath.IsAbs(value) || strings.TrimSpace(envPath) == "" {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(envPath), value))
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
				// Shutdown leaves active connections open when its deadline expires.
				// Force-close them before Runtime.Close releases shared components so
				// in-flight handlers cannot continue against partially closed state.
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

func newReverseProxy(target *url.URL, cfg config.ServerConfig, logger *slog.Logger) *httputil.ReverseProxy {
	t := cfg.UpstreamTransport
	transport := &http.Transport{
		// EdgeProxy is an internal data-plane dependency; never inherit ambient proxy settings.
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: t.DialTimeout.Duration, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: t.MaxIdleConns, MaxIdleConnsPerHost: t.MaxIdleConnsPerHost,
		MaxConnsPerHost: t.MaxConnsPerHost, IdleConnTimeout: t.IdleConnTimeout.Duration,
		TLSHandshakeTimeout: t.TLSHandshakeTimeout.Duration, ResponseHeaderTimeout: t.ResponseHeaderTimeout.Duration,
		ExpectContinueTimeout:  t.ExpectContinueTimeout.Duration,
		MaxResponseHeaderBytes: t.MaxResponseHeaderBytes,
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			clientIP := gateway.ResolvedClientIP(pr.In.Context())
			removeForwardingIdentityHeaders(pr.Out.Header, cfg.ForwardedForHeader)
			pr.SetURL(target)
			pr.SetXForwarded()
			if net.ParseIP(clientIP) != nil {
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
			}
			pr.Out.Header.Set("Via", "1.1 SecurityEdge")
			if cfg.PreserveHost {
				pr.Out.Host = pr.In.Host
			} else {
				pr.Out.Host = target.Host
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Server")
			resp.Header.Set("X-Security-Gateway", "SecurityEdge")
			if resp.StatusCode == http.StatusSwitchingProtocols {
				// The gateway decision writer owns these response fields. Unlike a
				// normal response, a hijacked 101 handshake is serialized directly
				// by ReverseProxy, so remove upstream copies to avoid duplicate or
				// spoofed security-decision headers.
				for _, name := range []string{"X-Request-ID", "X-Security-Action", "X-Security-Score"} {
					resp.Header.Del(name)
				}
				if cfg.AddSecurityHeaders {
					for _, name := range []string{"X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Permissions-Policy"} {
						resp.Header.Del(name)
					}
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeProxyError(w, http.StatusRequestEntityTooLarge, "body_too_large", r.Header.Get("X-Request-ID"))
				return
			}
			logger.Error("edgeproxy forwarding failed", "error", err, "request_id", r.Header.Get("X-Request-ID"))
			writeProxyError(w, http.StatusBadGateway, "edgeproxy_unavailable", r.Header.Get("X-Request-ID"))
		},
	}
	return proxy
}

// removeForwardingIdentityHeaders ensures SecurityEdge is the only source of
// client identity metadata sent to EdgeProxy. Alternate forwarding headers are
// removed as well as the configured source header so downstream components
// cannot accidentally trust a spoofed value.
func removeForwardingIdentityHeaders(header http.Header, configured string) {
	configured = strings.TrimSpace(configured)
	for name := range header {
		lower := strings.ToLower(name)
		remove := strings.EqualFold(name, configured) || strings.HasPrefix(lower, "x-forwarded-")
		if !remove {
			switch lower {
			case "forwarded", "client-ip", "x-real-ip", "true-client-ip", "x-client-ip", "x-cluster-client-ip", "x-originating-ip", "x-original-forwarded-for", "cf-connecting-ip", "fastly-client-ip", "fly-client-ip", "x-appengine-user-ip", "x-azure-clientip", "proxy-client-ip", "wl-proxy-client-ip":
				remove = true
			}
		}
		if remove {
			header.Del(name)
		}
	}
}

func writeProxyError(w http.ResponseWriter, status int, code, id string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", id)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"message":%q,"request_id":%q}}\n`, code, http.StatusText(status), id)
}

func resolveConfigPath(cliValue, environmentValue, loadedEnv string, environmentValueFromDotenv bool, candidates ...string) string {
	if value := strings.TrimSpace(cliValue); value != "" {
		return value
	}
	if value := strings.TrimSpace(environmentValue); value != "" {
		if environmentValueFromDotenv && loadedEnv != "" && !filepath.IsAbs(value) {
			return filepath.Clean(filepath.Join(filepath.Dir(loadedEnv), value))
		}
		return value
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func parseLevel(v string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid -log-level %q: expected debug, info, warn, or error", v)
	}
}
