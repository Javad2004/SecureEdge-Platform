package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/envfile"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/server"
)

func main() {
	configFlag := flag.String("config", "", "path to JSON configuration (overrides EDGEPROXY_CONFIG)")
	envFlag := flag.String("env", "", "path to optional .env file (overrides EDGEPROXY_ENV_FILE)")
	noEnv := flag.Bool("no-env", false, "disable automatic and explicit dotenv loading")
	prettyLogs := flag.Bool("pretty-logs", false, "use human-readable text logs instead of JSON")
	validateOnly := flag.Bool("validate", false, "validate configuration and exit")
	flag.Parse()

	if *noEnv && strings.TrimSpace(*envFlag) != "" {
		fmt.Fprintln(os.Stderr, "-env and -no-env cannot be used together")
		os.Exit(1)
	}
	loadedEnv := ""
	_, configEnvironmentPreexisting := os.LookupEnv("EDGEPROXY_CONFIG")
	var err error
	if !*noEnv {
		explicitEnv := firstNonEmpty(*envFlag, os.Getenv("EDGEPROXY_ENV_FILE"))
		loadedEnv, err = envfile.Load(explicitEnv, envfile.ApplicationCandidates("apps/edgeproxy/.env")...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	configPath := resolveConfigPath(
		*configFlag,
		os.Getenv("EDGEPROXY_CONFIG"),
		loadedEnv,
		!configEnvironmentPreexisting,
		"configs/edgeproxy.json",
		"apps/edgeproxy/configs/edgeproxy.json",
	)

	var handler slog.Handler
	if *prettyLogs {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(handler)
	if loadedEnv != "" {
		logger.Info("environment file loaded", "path", loadedEnv)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	if *validateOnly {
		fmt.Println("configuration is valid")
		return
	}
	if err := server.Run(cfg, logger); err != nil {
		logger.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
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
