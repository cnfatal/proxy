package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cnfatal/proxy/config"
	"github.com/cnfatal/proxy/iptables"
	"github.com/cnfatal/proxy/proxy"
	"github.com/cnfatal/proxy/rules"
)

var (
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	setupOnly  = flag.Bool("setup", false, "Only setup iptables rules and exit")
	cleanup    = flag.Bool("cleanup", false, "Only cleanup iptables rules and exit")
)

func main() {
	flag.Parse()

	// Handle cleanup mode
	if *cleanup {
		cleanupAndExit()
		return
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize logger with level
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	slog.SetDefault(slog.New(handler))

	slog.Info("Configuration loaded",
		"listen", cfg.Listen,
		"upstream", cfg.Upstream,
		"rules", len(cfg.Rules),
	)

	// Parse rules
	parsedRules, err := rules.ParseRules(cfg.Rules)
	if err != nil {
		slog.Error("Failed to parse rules", "error", err)
		os.Exit(1)
	}

	// Create rule matcher
	matcher := rules.NewMatcher(parsedRules)

	// Get listen port
	port, err := proxy.GetListenPort(cfg.Listen)
	if err != nil {
		slog.Error("Failed to get listen port", "error", err)
		os.Exit(1)
	}

	// Check prerequisites
	if err := iptables.CheckRoot(); err != nil {
		slog.Error("Permission check failed", "error", err)
		os.Exit(1)
	}

	if err := iptables.CheckAvailable(); err != nil {
		slog.Error("nftables check failed", "error", err)
		os.Exit(1)
	}

	// Setup iptables
	iptMgr := iptables.NewManager(port, iptables.DefaultPorts())
	if err := iptMgr.Setup(); err != nil {
		slog.Error("Failed to setup nftables", "error", err)
		os.Exit(1)
	}

	// Handle setup-only mode
	if *setupOnly {
		slog.Info("nftables rules configured, run with -cleanup to remove")
		return
	}

	// Setup signal handling for cleanup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Cleanup on exit
	defer func() {
		slog.Info("Shutting down...")
		iptMgr.Cleanup()
	}()

	// Create and start transparent proxy
	tp := proxy.NewTransparentProxy(cfg, matcher)

	// Start proxy in goroutine
	go func() {
		if err := tp.Start(); err != nil {
			slog.Error("Proxy error", "error", err)
			sigChan <- syscall.SIGTERM
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	slog.Info("Received signal", "signal", sig)

	// Stop the proxy
	tp.Stop()
}

func cleanupAndExit() {
	if err := iptables.CheckRoot(); err != nil {
		slog.Error("Permission check failed", "error", err)
		os.Exit(1)
	}

	// Create manager just for cleanup (port doesn't matter)
	iptMgr := iptables.NewManager(0, nil)
	iptMgr.Cleanup()
	slog.Info("Cleanup completed")
}
