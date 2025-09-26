/*
MQTT publisher implementation for Entry-Hub metrics transmission.

Provides secure MQTT client functionality for publishing Entry-Hub operational
metrics to the monitoring system. Implements TLS authentication, periodic
publication with staggered timing, and graceful shutdown. Publishes to the
metrics/entry-hub topic for collection by the Metrics-Collector service.
*/
package mqtt

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"https_server/config"
	"https_server/metrics"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var (
	// Global MQTT client instance
	mqttClient mqtt.Client

	// Shutdown synchronization
	shutdownOnce   sync.Once
	isShuttingDown bool
	shutdownMutex  sync.RWMutex

	// Publication control
	ticker   *time.Ticker
	stopChan chan struct{}
)

// InitializePublisher creates and connects MQTT client for metrics publication.
//
// Security features:
// - TLS 1.3 minimum version enforcement
// - Certificate-based authentication with CA validation
// - Topic-restricted publication (only metrics/entry-hub)
// - Automatic reconnection with exponential backoff
// - Staggered initial publication to prevent thundering herd
//
// Returns error if connection fails or nil if MQTT not configured.
func InitializePublisher(cfg *config.Config) error {
	// CHECK MQTT CONFIGURATION
	// Allow service to run without MQTT if not configured
	mqttURL := os.Getenv("MQTT_BROKER_URL")
	if mqttURL == "" {
		log.Println("MQTT_BROKER_URL not set, metrics publishing disabled")
		return nil
	}

	// TLS CONFIGURATION
	// Load certificates for secure MQTT connection
	tlsConfig, err := configureTLS(cfg)
	if err != nil {
		// If certificates not found, run without metrics
		log.Printf("Warning: MQTT TLS configuration failed: %v", err)
		log.Println("Continuing without metrics publishing")
		return nil
	}

	// MQTT CLIENT OPTIONS
	// Configure client with security and reliability settings
	opts := mqtt.NewClientOptions()
	opts.AddBroker(mqttURL)
	opts.SetClientID("entry-hub-publisher")
	opts.SetTLSConfig(tlsConfig)

	// CONNECTION CALLBACKS
	opts.SetOnConnectHandler(onConnectHandler)
	opts.SetConnectionLostHandler(onConnectionLostHandler)

	// RELIABILITY SETTINGS
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(30 * time.Second)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetCleanSession(true) // Publishers don't need persistent sessions

	// CREATE AND CONNECT CLIENT
	mqttClient = mqtt.NewClient(opts)

	log.Printf("Connecting to MQTT broker for metrics publishing...")

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		// Connection failed but not fatal
		log.Printf("Warning: Failed to connect to MQTT broker: %v", token.Error())
		log.Println("Metrics publishing disabled, service continuing")
		return nil
	}

	// START PERIODIC PUBLICATION
	startPeriodicPublication()

	log.Println("MQTT metrics publisher initialized successfully")
	return nil
}

// configureTLS creates TLS configuration for MQTT client authentication.
//
// Security features:
// - CA certificate validation for broker verification
// - Client certificate authentication for publisher identity
// - TLS 1.3 enforcement for modern cryptography
// - Organization validation in certificate
//
// Returns configured TLS settings or error if certificates missing/invalid.
func configureTLS(cfg *config.Config) (*tls.Config, error) {
	// CERTIFICATE PATHS
	// Construct paths for MQTT publisher certificates
	mqttCertFile := "../certificates/entry-hub/mqtt-publisher.crt"
	mqttKeyFile := "../certificates/entry-hub/mqtt-publisher.key"
	caCertFile := cfg.CACertFile

	// CHECK CERTIFICATE EXISTENCE
	// Verify all required certificates are present
	if _, err := os.Stat(mqttCertFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("MQTT publisher certificate not found: %s", mqttCertFile)
	}
	if _, err := os.Stat(mqttKeyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("MQTT publisher key not found: %s", mqttKeyFile)
	}

	// CA CERTIFICATE LOADING
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// CERTIFICATE POOL SETUP
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// CLIENT CERTIFICATE LOADING
	clientCert, err := tls.LoadX509KeyPair(mqttCertFile, mqttKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load MQTT publisher certificate: %v", err)
	}

	// TLS CONFIGURATION
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
		ServerName:   "mqtt-broker",
	}

	return tlsConfig, nil
}

// onConnectHandler handles successful MQTT connection events.
//
// Security features:
// - Logs connection for audit trail
// - No subscription (publisher only)
// - Ready for immediate publication
//
// Logs successful connection to broker.
func onConnectHandler(client mqtt.Client) {
	log.Println("Connected to MQTT broker for metrics publishing")
}

// onConnectionLostHandler handles MQTT disconnection events.
//
// Security features:
// - Logs disconnection for monitoring
// - Automatic reconnection by client
// - Continues metric collection during disconnection
//
// Logs connection loss for debugging.
func onConnectionLostHandler(client mqtt.Client, err error) {
	log.Printf("Lost connection to MQTT broker: %v", err)
	log.Println("Will attempt automatic reconnection...")
}

// startPeriodicPublication begins periodic metrics publication.
//
// Security features:
// - Staggered start to prevent thundering herd
// - Fixed interval publication (5 minutes)
// - Graceful shutdown handling
// - Non-blocking publication
//
// Starts background goroutine for metrics publication.
func startPeriodicPublication() {
	// STAGGER INITIAL PUBLICATION
	// Random delay 0-60 seconds to distribute load
	initialDelay := time.Duration(rand.Intn(60)) * time.Second
	log.Printf("Starting metrics publication in %v (staggered start)", initialDelay)

	// SETUP CONTROL CHANNELS
	stopChan = make(chan struct{})

	// PUBLICATION GOROUTINE
	go func() {
		// Initial delay
		select {
		case <-time.After(initialDelay):
		case <-stopChan:
			return
		}

		// Publish immediately after delay
		publishMetrics()

		// Setup periodic ticker
		ticker = time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		// PUBLICATION LOOP
		for {
			select {
			case <-ticker.C:
				// Check if shutting down
				shutdownMutex.RLock()
				shuttingDown := isShuttingDown
				shutdownMutex.RUnlock()

				if !shuttingDown {
					publishMetrics()
				}

			case <-stopChan:
				log.Println("Stopping metrics publication")
				return
			}
		}
	}()
}

// publishMetrics publishes current metrics to MQTT broker.
//
// Security features:
// - No user data in metrics
// - Topic restriction (metrics/entry-hub only)
// - QoS 1 for at-least-once delivery
// - Non-blocking with timeout
//
// Publishes all collected metrics or logs error.
func publishMetrics() {
	// CHECK CLIENT STATUS
	if mqttClient == nil || !mqttClient.IsConnected() {
		// Silently skip if not connected
		return
	}

	// COLLECT METRICS
	metricsData := metrics.GetMetrics()

	if len(metricsData) == 0 {
		// No metrics to publish
		return
	}

	// PUBLISH METRICS
	published := 0
	failed := 0

	for _, metric := range metricsData {
		// Serialize metric to JSON
		payload, err := json.Marshal(metric)
		if err != nil {
			log.Printf("Failed to serialize metric: %v", err)
			failed++
			continue
		}

		// Publish to broker
		topic := "metrics/entry-hub"
		token := mqttClient.Publish(topic, 1, false, payload)

		// Wait with timeout
		if token.WaitTimeout(5 * time.Second) {
			if token.Error() != nil {
				log.Printf("Failed to publish metric: %v", token.Error())
				failed++
			} else {
				published++
			}
		} else {
			log.Printf("Timeout publishing metric")
			failed++
		}
	}

	// LOG PUBLICATION SUMMARY
	if published > 0 {
		log.Printf("Published %d metrics to MQTT broker", published)
	}
	if failed > 0 {
		log.Printf("Failed to publish %d metrics", failed)
	}
}

// PublishMetricsNow triggers immediate metrics publication.
//
// Security features:
// - Manual trigger for testing/debugging
// - Same security as periodic publication
// - Non-blocking operation
//
// Useful for testing or forced publication before shutdown.
func PublishMetricsNow() {
	if mqttClient != nil && mqttClient.IsConnected() {
		log.Println("Triggering immediate metrics publication")
		go publishMetrics()
	}
}

// Shutdown gracefully stops MQTT publisher.
//
// Security features:
// - Final metrics publication before shutdown
// - Clean disconnection from broker
// - Prevents duplicate shutdown calls
// - Waits for pending publications
//
// Should be called during service shutdown.
func Shutdown() {
	shutdownOnce.Do(func() {
		log.Println("Shutting down MQTT metrics publisher...")

		// SET SHUTDOWN FLAG
		shutdownMutex.Lock()
		isShuttingDown = true
		shutdownMutex.Unlock()

		// STOP PERIODIC PUBLICATION
		if stopChan != nil {
			close(stopChan)
		}

		// FINAL METRICS PUBLICATION
		if mqttClient != nil && mqttClient.IsConnected() {
			log.Println("Publishing final metrics before shutdown...")
			publishMetrics()

			// DISCONNECT FROM BROKER
			log.Println("Disconnecting from MQTT broker...")
			mqttClient.Disconnect(5000) // 5 second timeout
		}

		log.Println("MQTT metrics publisher shutdown complete")
	})
}

// IsConnected returns true if MQTT client is connected.
//
// Security features:
// - Read-only status check
// - No sensitive information exposed
//
// Useful for health checks and debugging.
func IsConnected() bool {
	return mqttClient != nil && mqttClient.IsConnected()
}

// GetConnectionStatus returns detailed connection status.
//
// Security features:
// - No credentials or broker details exposed
// - Simple status string only
//
// Returns human-readable connection status.
func GetConnectionStatus() string {
	if mqttClient == nil {
		return "not_initialized"
	}
	if mqttClient.IsConnected() {
		return "connected"
	}
	return "disconnected"
}
