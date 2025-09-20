package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/enterprise/distributed-health-monitor/internal/app"
	"github.com/enterprise/distributed-health-monitor/internal/config"
	"github.com/enterprise/distributed-health-monitor/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "Path to configuration file")
	version    = "dev"
	buildTime  = "unknown"
	gitCommit  = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "health-monitor",
		Short: "Enterprise Distributed System Health Monitor",
		Long: `An enterprise-grade distributed system health monitor with RATS-compliant 
attestation framework, ML-based anomaly detection, and multi-cloud federation support.`,
		Run: func(cmd *cobra.Command, args []string) {
			runServer()
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Build Time: %s\n", buildTime)
			fmt.Printf("Git Commit: %s\n", gitCommit)
		},
	}

	var validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration",
		Run: func(cmd *cobra.Command, args []string) {
			validateConfig()
		},
	}

	rootCmd.PersistentFlags().StringVar(configPath, "config", "configs/config.yaml", "Path to configuration file")
	rootCmd.AddCommand(versionCmd, validateCmd)

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func runServer() {
	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	log := logger.New(cfg.Logging)

	log.WithFields(logrus.Fields{
		"version":    version,
		"build_time": buildTime,
		"git_commit": gitCommit,
	}).Info("Starting Enterprise Distributed System Health Monitor")

	// Create application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize application
	application, err := app.New(ctx, cfg, log)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the application
	if err := application.Start(ctx); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}

	log.Info("Health Monitor started successfully")

	// Wait for shutdown signal
	<-sigChan
	log.Info("Shutdown signal received, initiating graceful shutdown...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop the application
	if err := application.Stop(shutdownCtx); err != nil {
		log.Errorf("Error during shutdown: %v", err)
	}

	log.Info("Health Monitor stopped")
}

func validateConfig() {
	cfg, err := config.Load(*configPath)
	if err != nil {
		logrus.Fatalf("Configuration validation failed: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		logrus.Fatalf("Configuration validation failed: %v", err)
	}

	logrus.Info("Configuration is valid")
}
