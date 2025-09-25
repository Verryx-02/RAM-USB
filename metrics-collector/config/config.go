/*
Configuration management for Metrics-Collector monitoring service.

Provides centralized configuration for mTLS server operations, MQTT subscriber
settings, TimescaleDB connection parameters, and Prometheus endpoint configuration.
Uses environment variables for sensitive data with hardcoded certificate paths
following the R.A.M.-U.S.B. pattern for development environments.

TO-DO in GetConfig(): Load Tailscale IPs from environment variables
TO-DO: Add configuration validation similar to database-vault
*/
package config

import (
	"log"
	"os"
)

// Config holds Metrics-Collector configuration for monitoring operations.
//
// Security features:
// - mTLS server certificates for authenticated admin access
// - MQTT TLS certificates for secure metrics reception
// - TimescaleDB credentials isolated from main database
// - Separate ports for admin API and Prometheus scraping
// - Certificate-based authentication for all external connections
//
// Supports dual server roles: mTLS admin API and HTTP Prometheus endpoint.
type Config struct {
	// MTLS SERVER CONFIGURATION - for admin API operations
	ServerPort     string // Port for mTLS admin server (8446)
	ServerCertFile string // Server certificate for admin authentication
	ServerKeyFile  string // Server private key for TLS handshake
	CACertFile     string // CA certificate for client validation

	// PROMETHEUS ENDPOINT CONFIGURATION - for metrics exposure
	PrometheusPort string // Port for Prometheus scraping (8447)

	// MQTT SUBSCRIBER CONFIGURATION - for metrics collection
	MQTTBrokerURL  string // MQTT broker address with TLS (ssl://host:8883)
	MQTTCertFile   string // Client certificate for MQTT authentication
	MQTTKeyFile    string // Client private key for MQTT TLS
	MQTTCACertFile string // CA certificate for MQTT broker validation
	MQTTClientID   string // Unique identifier for MQTT connection

	// TIMESCALEDB CONFIGURATION - for time-series storage
	DatabaseURL string // PostgreSQL connection string with TimescaleDB extension
}

// GetConfig returns Metrics-Collector configuration with all service parameters.
//
// Security features:
// - Environment variables for sensitive connection strings
// - Hardcoded certificate paths prevent path traversal attacks
// - Default values for development with override capability
// - Validation logging without exposing credentials
//
// Returns pointer to Config struct with all monitoring service parameters.
//
// TO-DO: Load MQTT_BROKER_IP from environment variable
// TO-DO: Implement configuration validation like database-vault/config
func GetConfig() *Config {
	// MQTT BROKER CONFIGURATION
	// Load from environment with development default
	mqttBrokerURL := os.Getenv("MQTT_BROKER_URL")
	if mqttBrokerURL == "" {
		// Default for development - replace with actual Tailscale IP
		// TO-DO: Use os.Getenv("MQTT_BROKER_IP") instead of hardcoded IP
		mqttBrokerURL = "ssl://100.102.186.107:8883" // Replace with your Tailscale IP
		log.Printf("Using default MQTT broker URL (development mode)")
	}

	// TIMESCALEDB CONNECTION
	// Separate database for metrics to maintain isolation
	databaseURL := os.Getenv("METRICS_DATABASE_URL")
	if databaseURL == "" {
		// Default connection for local TimescaleDB
		// Uses different port (5433) to avoid conflict with main PostgreSQL
		databaseURL = "postgres://metrics_user:metrics_secure_2024@localhost:5433/metrics_db?sslmode=require"
		log.Printf("Using default TimescaleDB URL (development mode)")
	}

	// MQTT CLIENT ID
	// Unique identifier for MQTT broker connections
	mqttClientID := os.Getenv("MQTT_CLIENT_ID")
	if mqttClientID == "" {
		mqttClientID = "metrics-collector-subscriber"
	}

	return &Config{
		// MTLS ADMIN SERVER SETTINGS
		// Configuration for administrative operations
		ServerPort:     "8446",
		ServerCertFile: "../certificates/metrics-collector/server.crt",
		ServerKeyFile:  "../certificates/metrics-collector/server.key",
		CACertFile:     "../certificates/certification-authority/ca.crt",

		// PROMETHEUS SETTINGS
		// HTTP endpoint for metrics scraping
		PrometheusPort: "8447",

		// MQTT SUBSCRIBER SETTINGS
		// Configuration for receiving metrics from services
		MQTTBrokerURL:  mqttBrokerURL,
		MQTTCertFile:   "../certificates/metrics-collector/mqtt-subscriber.crt",
		MQTTKeyFile:    "../certificates/metrics-collector/mqtt-subscriber.key",
		MQTTCACertFile: "../certificates/certification-authority/ca.crt",
		MQTTClientID:   mqttClientID,

		// TIMESCALEDB SETTINGS
		// Time-series database for metrics storage
		DatabaseURL: databaseURL,
	}
}

// ValidateConfig performs configuration validation for secure startup.
//
// Security features:
// - Certificate file existence validation
// - Connection string format checking
// - Port availability verification
//
// Returns error if any critical configuration is invalid.
//
// TO-DO: Implement comprehensive validation like database-vault
func (c *Config) ValidateConfig() error {
	// TO-DO: Implement certificate file validation
	// TO-DO: Implement port availability checking
	// TO-DO: Validate database connection string format
	return nil
}
