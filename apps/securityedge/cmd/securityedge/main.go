package main

import (
	"context"
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
	runtime, err := securityedge.New(configPath, logger)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		return 1
	}
	defer runtime.Close()
	cfg := runtime.Config()
	var adminServer *http.Server
	if cfg.Admin.Enabled {
		adminServer, err = runtime.AdminServer()
		if err != nil {
			logger.Error("admin setup failed", "error", err)
			return 1
		}
	}
	errCh := make(chan error, 2)
	var gatewayServer *http.Server
	if cfg.Server.Mode == "gateway" {
		target, err := url.Parse(cfg.Server.UpstreamProxyURL)
		if err != nil {
			logger.Error("invalid upstream proxy URL", "error", err)
			return 1
		}
		reverse := newReverseProxy(target, cfg.Server, logger)
		// Runtime.Wrap enforces the request-body limit so the same protection and
		// security-event accounting also apply when SecurityEdge is embedded or
		// used with a different downstream handler.
		wrapped := runtime.Wrap(reverse)
		gatewayServer = &http.Server{
			Addr: cfg.Server.ListenAddr, Handler: wrapped,
			ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration, ReadTimeout: cfg.Server.ReadTimeout.Duration,
			WriteTimeout: cfg.Server.WriteTimeout.Duration, IdleTimeout: cfg.Server.IdleTimeout.Duration,
			MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
		}
		go func() {
			logger.Info("security gateway starting", "address", cfg.Server.ListenAddr, "upstream", cfg.Server.UpstreamProxyURL, "max_concurrent", cfg.Server.MaxConcurrentRequests, "max_body_bytes", cfg.Server.MaxRequestBodyBytes)
			if err := gatewayServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("security gateway: %w", err)
			}
		}()
	}
	if adminServer != nil {
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
	shutdownErr := shutdownServers(shutdownCtx,
		namedHTTPServer{name: "gateway", server: gatewayServer},
		namedHTTPServer{name: "admin", server: adminServer},
	)
	if shutdownErr != nil {
		logger.Error("graceful shutdown failed", "error", shutdownErr)
	}
	if runErr != nil || shutdownErr != nil {
		return 1
	}
	return 0
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
