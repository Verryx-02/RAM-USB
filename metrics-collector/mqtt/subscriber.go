/*
MQTT subscriber implementation for Metrics-Collector service.

Provides secure MQTT client functionality for receiving metrics from all
R.A.M.-U.S.B. services. Implements TLS authentication, zero-knowledge validation,
and reliable message processing with automatic reconnection. Subscribes to
metrics/* topics and validates all incoming data before storage.
*/
package mqtt

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"metrics-collector/config"
	"metrics-collector/storage"
	"metrics-collector/types"
	"os"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var (
	// Global MQTT client instance for lifecycle management
	mqttClient mqtt.Client

	// Metrics tracking for monitoring
	metricsReceived uint64
	metricsRejected uint64
	metricsStored   uint64

	// Mutex for thread-safe counter updates
	counterMutex sync.RWMutex
)

// InitializeSubscriber creates and connects MQTT client with TLS authentication.
//
// Security features:
// - TLS 1.3 minimum version enforcement
// - Certificate-based authentication with CA validation
// - Automatic reconnection with exponential backoff
// - Zero-knowledge message validation before processing
// - Topic-based access control via certificate CN
//
// Returns error if connection or subscription fails.
func InitializeSubscriber(cfg *config.Config) error {
	// TLS CONFIGURATION
	// Load and configure certificates for secure MQTT connection
	tlsConfig, err := configureTLS(cfg)
	if err != nil {
		return fmt.Errorf("failed to configure TLS: %v", err)
	}

	// MQTT CLIENT OPTIONS
	// Configure client with security and reliability settings
	opts := mqtt.NewClientOptions()
	opts.AddBroker(cfg.MQTTBrokerURL)
	opts.SetClientID(cfg.MQTTClientID)
	opts.SetTLSConfig(tlsConfig)

	// CONNECTION CALLBACKS
	// Set up connection lifecycle handlers
	opts.SetOnConnectHandler(onConnectHandler)
	opts.SetConnectionLostHandler(onConnectionLostHandler)

	// RELIABILITY SETTINGS
	// Configure automatic reconnection and keep-alive
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(30 * time.Second)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	opts.SetCleanSession(false) // Preserve subscriptions on reconnect

	// MESSAGE ORDERING
	// Ensure message ordering for metric consistency
	opts.SetOrderMatters(true)

	// CLIENT CREATION AND CONNECTION
	// Create client and establish connection to broker
	mqttClient = mqtt.NewClient(opts)

	log.Printf("Connecting to MQTT broker at %s...", maskBrokerURL(cfg.MQTTBrokerURL))

	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to connect to MQTT broker: %v", token.Error())
	}

	return nil
}

// configureTLS creates TLS configuration for MQTT client authentication.
//
// Security features:
// - CA certificate validation for broker verification
// - Client certificate authentication for access control
// - TLS 1.3 enforcement for modern cryptography
// - Server name verification for MITM prevention
//
// Returns configured TLS settings or error if certificates are invalid.
func configureTLS(cfg *config.Config) (*tls.Config, error) {
	// CA CERTIFICATE LOADING
	// Load Certificate Authority for broker validation
	caCert, err := os.ReadFile(cfg.MQTTCACertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// CERTIFICATE POOL SETUP
	// Create pool with trusted CA certificates
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// CLIENT CERTIFICATE LOADING
	// Load subscriber certificate for authentication
	clientCert, err := tls.LoadX509KeyPair(cfg.MQTTCertFile, cfg.MQTTKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// TLS CONFIGURATION
	// Configure secure connection parameters
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
		ServerName:   "mqtt-broker", // Expected CN in broker certificate
	}

	return tlsConfig, nil
}

// onConnectHandler handles successful MQTT connection events.
//
// Security features:
// - Subscription to authorized topics only
// - QoS 1 for at-least-once delivery guarantee
// - Wildcard subscription for all service metrics
//
// Automatically subscribes to metrics topics on connection.
func onConnectHandler(client mqtt.Client) {
	log.Println("Connected to MQTT broker successfully")

	// TOPIC SUBSCRIPTION
	// Subscribe to all service metrics with QoS 1
	topic := "metrics/+"
	qos := byte(1)

	if token := client.Subscribe(topic, qos, messageHandler); token.Wait() && token.Error() != nil {
		log.Printf("Failed to subscribe to %s: %v", topic, token.Error())
	} else {
		log.Printf("Subscribed to topic: %s", topic)
	}
}

// onConnectionLostHandler handles MQTT disconnection events.
//
// Security features:
// - Logs disconnection for security monitoring
// - Preserves metric counters during disconnection
// - Automatic reconnection handled by client
//
// Logs connection loss and prepares for reconnection.
func onConnectionLostHandler(client mqtt.Client, err error) {
	log.Printf("Connection to MQTT broker lost: %v", err)
	log.Println("Attempting automatic reconnection...")
}

// messageHandler processes incoming MQTT messages with metrics data.
//
// Security features:
// - Zero-knowledge validation before processing
// - Rejection of messages with sensitive data
// - Service authentication via topic validation
// - Comprehensive error logging for security monitoring
//
// Validates and stores metrics or rejects invalid messages.
func messageHandler(client mqtt.Client, msg mqtt.Message) {
	// MESSAGE RECEPTION TRACKING
	incrementCounter(&metricsReceived)

	// TOPIC VALIDATION
	// Extract service name from topic for validation
	topicParts := strings.Split(msg.Topic(), "/")
	if len(topicParts) != 2 || topicParts[0] != "metrics" {
		log.Printf("Invalid topic format: %s", msg.Topic())
		incrementCounter(&metricsRejected)
		return
	}

	serviceName := topicParts[1]

	// MESSAGE DESERIALIZATION
	// Parse JSON payload into metric structure
	var metric types.Metric
	if err := json.Unmarshal(msg.Payload(), &metric); err != nil {
		log.Printf("Failed to parse metric from %s: %v", serviceName, err)
		incrementCounter(&metricsRejected)
		return
	}

	// SERVICE NAME VALIDATION
	// Ensure metric service matches topic service
	if metric.Service != serviceName {
		log.Printf("Service mismatch: topic=%s, metric=%s", serviceName, metric.Service)
		incrementCounter(&metricsRejected)
		return
	}

	// ZERO-KNOWLEDGE VALIDATION
	// Reject metrics containing sensitive data
	if err := validateMetric(metric); err != nil {
		log.Printf("Metric validation failed from %s: %v", serviceName, err)
		incrementCounter(&metricsRejected)
		return
	}

	// TIMESTAMP VALIDATION
	// Ensure metric timestamp is reasonable
	now := time.Now().Unix()
	if metric.Timestamp <= 0 || metric.Timestamp > now+60 {
		log.Printf("Invalid timestamp in metric from %s: %d", serviceName, metric.Timestamp)
		incrementCounter(&metricsRejected)
		return
	}

	// STORAGE OPERATION
	// Store validated metric in TimescaleDB
	if err := storage.StoreMetric(metric); err != nil {
		log.Printf("Failed to store metric from %s: %v", serviceName, err)
		// Not counting as rejected since validation passed
		return
	}

	incrementCounter(&metricsStored)
}

// validateMetric checks metric for sensitive data and format compliance.
//
// Security features:
// - Rejects metrics with forbidden label keys
// - Validates label sizes to prevent storage attacks
// - Checks metric name format and length
// - Ensures no PII or credentials in metric data
//
// Returns error if metric contains sensitive data or invalid format.
func validateMetric(m types.Metric) error {
	// METRIC NAME VALIDATION
	// Check name length and format
	if len(m.Name) == 0 || len(m.Name) > types.MaxMetricNameLength {
		return fmt.Errorf("invalid metric name length: %d", len(m.Name))
	}

	// FORBIDDEN LABEL DETECTION
	// Check for sensitive data in labels
	forbiddenKeys := []string{
		types.ForbiddenLabelEmail,
		types.ForbiddenLabelPassword,
		types.ForbiddenLabelSSHKey,
		types.ForbiddenLabelEmailHash,
		types.ForbiddenLabelUserID,
		types.ForbiddenLabelUsername,
	}

	for _, forbidden := range forbiddenKeys {
		if _, exists := m.Labels[forbidden]; exists {
			return fmt.Errorf("forbidden label key: %s", forbidden)
		}

		// Check if forbidden key is substring of any label key
		for key := range m.Labels {
			if strings.Contains(strings.ToLower(key), forbidden) {
				return fmt.Errorf("label key contains forbidden term: %s", forbidden)
			}
		}
	}

	// LABEL SIZE VALIDATION
	// Prevent oversized labels that could cause storage issues
	if len(m.Labels) > types.MaxLabelsPerMetric {
		return fmt.Errorf("too many labels: %d (max %d)", len(m.Labels), types.MaxLabelsPerMetric)
	}

	for key, value := range m.Labels {
		if len(key) > types.MaxLabelKeyLength {
			return fmt.Errorf("label key too long: %s", key)
		}
		if len(value) > types.MaxLabelValueLength {
			return fmt.Errorf("label value too long for key %s", key)
		}

		// Check for sensitive data patterns in values
		valueLower := strings.ToLower(value)
		if strings.Contains(valueLower, "@") && strings.Contains(valueLower, ".") {
			return fmt.Errorf("label value appears to contain email address")
		}
		if strings.HasPrefix(valueLower, "ssh-") {
			return fmt.Errorf("label value appears to contain SSH key")
		}
	}

	// METRIC TYPE VALIDATION
	// Ensure valid metric type for proper aggregation
	validTypes := []types.MetricType{
		types.MetricTypeCounter,
		types.MetricTypeGauge,
		types.MetricTypeHistogram,
		types.MetricTypeSummary,
	}

	typeValid := false
	for _, validType := range validTypes {
		if m.Type == validType {
			typeValid = true
			break
		}
	}

	if !typeValid {
		return fmt.Errorf("invalid metric type: %s", m.Type)
	}

	return nil
}

// Disconnect gracefully disconnects MQTT client.
//
// Security features:
// - Clean disconnection to prevent message loss
// - Unsubscribe from topics before disconnecting
// - Timeout to prevent hanging on shutdown
//
// Should be called during service shutdown.
func Disconnect() {
	if mqttClient != nil && mqttClient.IsConnected() {
		log.Println("Disconnecting from MQTT broker...")

		// UNSUBSCRIBE FROM TOPICS
		// Clean unsubscribe before disconnection
		if token := mqttClient.Unsubscribe("metrics/+"); token.Wait() && token.Error() != nil {
			log.Printf("Failed to unsubscribe: %v", token.Error())
		}

		// DISCONNECT WITH TIMEOUT
		// Graceful disconnection with 5-second timeout
		mqttClient.Disconnect(5000)
		log.Println("Disconnected from MQTT broker")
	}
}

// GetStatistics returns current MQTT subscriber statistics.
//
// Security features:
// - Read-only statistics access
// - No sensitive data in statistics
// - Thread-safe counter access
//
// Returns metrics reception and processing statistics.
func GetStatistics() (received, rejected, stored uint64) {
	counterMutex.RLock()
	defer counterMutex.RUnlock()
	return metricsReceived, metricsRejected, metricsStored
}

// incrementCounter safely increments a counter with mutex protection.
//
// Security features:
// - Thread-safe counter updates
// - Prevents race conditions in concurrent message processing
//
// Updates specified counter atomically.
func incrementCounter(counter *uint64) {
	counterMutex.Lock()
	defer counterMutex.Unlock()
	*counter++
}

// maskBrokerURL hides sensitive parts of MQTT broker URL for logging.
//
// Security features:
// - Prevents credential exposure in logs
// - Maintains useful connection information for debugging
//
// Returns masked broker URL safe for logging.
func maskBrokerURL(url string) string {
	if strings.Contains(url, "@") {
		parts := strings.Split(url, "@")
		if len(parts) == 2 {
			return "ssl://***:***@" + parts[1]
		}
	}

	// For simple SSL URLs without credentials
	if strings.HasPrefix(url, "ssl://") && len(url) > 10 {
		hostPart := strings.Split(url[6:], ":")[0]
		if len(hostPart) > 4 {
			return "ssl://" + hostPart[:4] + "***" + url[len(url)-5:]
		}
	}

	return "***MASKED***"
}
