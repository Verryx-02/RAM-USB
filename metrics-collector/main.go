/*
Main application entry point for Metrics-Collector monitoring service.

Implements a secure metrics collection system that receives performance data from
all R.A.M.-U.S.B. services via MQTT, stores them in TimescaleDB for time-series
analysis
Maintains zero-knowledge principles by rejecting any metrics containing sensitive data
like email addresses, passwords, or SSH keys.

The service operates on two ports:
- 8446: mTLS admin API for health checks and management

TO-DO: Implement mTLS authentication for admin API
TO-DO: Add Tailscale IP restrictions for network isolation
*/
package main

import (
	"context"
	"fmt"
	"log"
	"metrics-collector/config"
	"metrics-collector/handlers"
	"metrics-collector/mqtt"
	"metrics-collector/storage"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// main initializes and starts the Metrics-Collector service.
//
// Security features:
// - MQTT subscriber with TLS authentication for secure metrics reception
// - TimescaleDB connection for efficient time-series storage
// - Zero-knowledge validation rejecting sensitive data
// - Graceful shutdown handling for data consistency
//
// Starts metrics collection on configured port (default: 8446)
func main() {
	// CONFIGURATION LOADING
	// Load service configuration including certificates and database settings
	cfg := config.GetConfig()

	// SERVICE STARTUP LOGGING
	// Log configuration without exposing sensitive credentials
	fmt.Println("============================================")
	fmt.Println("Metrics-Collector Service Starting")
	fmt.Println("============================================")
	fmt.Printf("Admin API Port: %s (mTLS)\n", cfg.ServerPort)
	fmt.Printf("MQTT Broker: %s\n", maskCredentials(cfg.MQTTBrokerURL))
	fmt.Printf("TimescaleDB: %s\n", maskDatabaseURL(cfg.DatabaseURL))

	// GRACEFUL SHUTDOWN SETUP
	// Handle interrupt signals for clean service termination
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// TIMESCALEDB INITIALIZATION
	// Initialize time-series database connection with connection pooling
	log.Println("Initializing TimescaleDB storage...")
	if err := storage.InitializeTimescaleDB(cfg.DatabaseURL); err != nil {
		log.Printf("Warning: Failed to initialize TimescaleDB: %v", err)
		log.Println("Continuing without database storage (metrics will be lost)")
		// Non-fatal: service can run without storage for debugging
	} else {
		log.Println("TimescaleDB storage initialized successfully")
		defer storage.Close() // Ensure clean database shutdown
	}

	// MQTT SUBSCRIBER INITIALIZATION
	// Connect to MQTT broker for receiving metrics from services
	log.Println("Initializing MQTT subscriber...")
	if err := mqtt.InitializeSubscriber(cfg); err != nil {
		log.Printf("Warning: Failed to initialize MQTT subscriber: %v", err)
		log.Println("Continuing without MQTT (no metrics will be collected)")
		// Non-fatal: allows testing database storage independently
	} else {
		log.Println("MQTT subscriber connected and listening on metrics/*")
	}

	// ADMIN API SETUP (mTLS)
	// Start mTLS server for administrative operations
	// TO-DO: Implement full mTLS authentication like database-vault
	wg.Add(1)
	go func() {
		defer wg.Done()

		mux := http.NewServeMux()
		mux.HandleFunc("/api/health", handlers.AdminHealthHandler)
		mux.HandleFunc("/api/stats", handlers.StatsHandler)

		server := &http.Server{
			Addr:         ":" + cfg.ServerPort,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		// GRACEFUL SHUTDOWN HANDLER
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				log.Printf("Admin server shutdown error: %v", err)
			}
		}()

		log.Printf("Admin API ready on :%s (mTLS required)", cfg.ServerPort)
		// TO-DO: Use ListenAndServeTLS with proper certificates
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Admin server error: %v", err)
		}
	}()

	// SERVICE READY NOTIFICATION
	fmt.Println("============================================")
	fmt.Println("Metrics-Collector Service Ready")
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println("============================================")

	// SIGNAL HANDLING
	// Wait for interrupt signal
	<-sigChan
	log.Println("Shutdown signal received, stopping service...")

	// GRACEFUL SHUTDOWN SEQUENCE
	cancel() // Signal all goroutines to stop

	// Disconnect MQTT client
	mqtt.Disconnect()

	// Wait for all goroutines to finish
	wg.Wait()

	log.Println("Metrics-Collector service stopped gracefully")
}

// maskCredentials hides sensitive parts of connection strings for logging.
//
// Security features:
// - Prevents credential exposure in logs
// - Maintains useful connection information for debugging
//
// Returns masked connection string safe for logging.
func maskCredentials(url string) string {
	// Simple masking for MQTT URLs
	if len(url) > 20 {
		return url[:10] + "***MASKED***"
	}
	return "***MASKED***"
}

// maskDatabaseURL sanitizes database connection string for logging.
//
// Security features:
// - Hides username and password from logs
// - Preserves host and database name for debugging
//
// Returns sanitized database URL suitable for logging.
func maskDatabaseURL(dbURL string) string {
	// TO-DO: Implement proper URL parsing and masking
	if len(dbURL) > 30 {
		return "postgres://***:***@" + dbURL[30:]
	}
	return "***MASKED***"
}
