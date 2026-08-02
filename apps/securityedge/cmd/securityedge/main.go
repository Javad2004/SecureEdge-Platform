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
	"strings"
	"syscall"
	"time"

	securityedge "github.com/Javad2004/SecureEdge-Platform/apps/securityedge"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/gateway"
	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version"
)

func main() {
	configPath := flag.String("config", "configs/local-dev.json", "path to security configuration")
	validate := flag.Bool("validate", false, "validate configuration and exit")
	pretty := flag.Bool("pretty-logs", false, "use human-readable logs")
	logLevel := flag.String("log-level", "info", "debug, info, warn, or error")
	showVersion := flag.Bool("version", false, "print build version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	level := parseLevel(*logLevel)
	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	if *pretty {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	logger := slog.New(handler)
	if *validate {
		if err := securityedge.Validate(*configPath); err != nil {
			logger.Error("configuration failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("configuration is valid")
		return
	}
	runtime, err := securityedge.New(*configPath, logger)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	defer runtime.Close()
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
		reverse := newReverseProxy(target, cfg.Server, logger)
		wrapped := runtime.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxRequestBodyBytes)
			}
			reverse.ServeHTTP(w, r)
		}))
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
		if err := gatewayServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("gateway shutdown", "error", err)
		}
	}
	if cfg.Admin.Enabled {
		if err := adminServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("admin shutdown", "error", err)
		}
	}
	if runErr != nil {
		os.Exit(1)
	}
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
		ExpectContinueTimeout: t.ExpectContinueTimeout.Duration,
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
func parseLevel(v string) slog.Level {
	switch v {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
