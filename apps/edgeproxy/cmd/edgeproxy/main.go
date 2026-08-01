package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/server"
)

func main() {
	configPath := flag.String("config", "configs/edgeproxy.json", "path to JSON configuration")
	prettyLogs := flag.Bool("pretty-logs", false, "use human-readable text logs instead of JSON")
	validateOnly := flag.Bool("validate", false, "validate configuration and exit")
	flag.Parse()

	var handler slog.Handler
	if *prettyLogs {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	logger := slog.New(handler)

	cfg, err := config.Load(*configPath)
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
