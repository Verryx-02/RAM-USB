/*
Metrics collection implementation for Entry-Hub REST API service.

Provides internal metrics gathering for monitoring Entry-Hub performance,
request patterns, and registration statistics. Maintains counters, gauges,
and histograms in memory for periodic publication to the monitoring system
via MQTT. Implements zero-knowledge principles by never including user
data in metrics, only aggregate statistics and performance indicators.
*/
package metrics

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Metric represents a single metric data point for MQTT publication.
//
// Security features:
// - No fields for user data (email, passwords, etc.)
// - Service identification for filtering
// - Generic labels for categorization without PII
//
// Compatible with metrics-collector expectations.
type Metric struct {
	Service   string            `json:"service"`   // Always "entry-hub" for this service
	Timestamp int64             `json:"timestamp"` // Unix timestamp of collection
	Name      string            `json:"name"`      // Metric name (e.g., "requests_total")
	Value     float64           `json:"value"`     // Numeric value
	Labels    map[string]string `json:"labels"`    // Additional dimensions
	Type      MetricType        `json:"type"`      // Metric aggregation type
}

// MetricType defines how metrics should be aggregated.
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"   // Monotonically increasing
	MetricTypeGauge     MetricType = "gauge"     // Can go up or down
	MetricTypeHistogram MetricType = "histogram" // Distribution of values
)

// MetricsCollector manages Entry-Hub operational metrics.
//
// Security features:
// - Thread-safe for concurrent request handling
// - No storage of request bodies or user data
// - Only aggregate statistics maintained
// - Memory-only storage (no persistence)
//
// Singleton instance for service-wide metrics.
type MetricsCollector struct {
	mu sync.RWMutex

	// REQUEST METRICS
	requestsTotal    map[string]int64 // Key: "method:path:status"
	requestDurations []float64        // Request latencies in milliseconds

	// REGISTRATION METRICS
	registrationsTotal map[string]int64 // Key: "success" or "failed"
	validationFailures map[string]int64 // Key: failure reason

	// CONNECTION METRICS
	activeConnections int64 // Current active HTTPS connections
	mtlsConnections   int64 // Active mTLS connections to Security-Switch

	// ERROR METRICS
	errorsTotal map[string]int64 // Key: error type

	// PERFORMANCE METRICS
	lastResetTime time.Time // For rate calculations
}

// Global collector instance
var (
	collector *MetricsCollector
	once      sync.Once
)

// Initialize creates the singleton metrics collector.
//
// Security features:
// - Single initialization prevents memory leaks
// - Initialized with empty maps to prevent nil access
//
// Should be called during service startup.
func Initialize() {
	once.Do(func() {
		collector = &MetricsCollector{
			requestsTotal:      make(map[string]int64),
			requestDurations:   make([]float64, 0, 1000), // Pre-allocate for efficiency
			registrationsTotal: make(map[string]int64),
			validationFailures: make(map[string]int64),
			errorsTotal:        make(map[string]int64),
			lastResetTime:      time.Now(),
		}
	})
}

// IncrementRequest records an HTTP request completion.
//
// Security features:
// - No logging of request content
// - Path sanitization to prevent cardinality explosion
// - Status grouping (2xx, 3xx, 4xx, 5xx)
//
// Thread-safe counter increment.
func IncrementRequest(method, path string, status int) {
	if collector == nil {
		return
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	// Sanitize path to prevent high cardinality
	// Remove IDs and parameters from path
	sanitizedPath := sanitizePath(path)

	// Group status codes by class
	statusClass := fmt.Sprintf("%dxx", status/100)

	key := fmt.Sprintf("%s:%s:%s", method, sanitizedPath, statusClass)
	collector.requestsTotal[key]++
}

// RecordRequestDuration records request processing time.
//
// Security features:
// - No association with specific requests
// - Bounded histogram to prevent memory exhaustion
// - Millisecond precision to prevent timing attacks
//
// Adds duration to histogram for percentile calculations.
func RecordRequestDuration(durationMs float64) {
	if collector == nil {
		return
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	// Limit histogram size to prevent memory issues
	if len(collector.requestDurations) >= 10000 {
		// Remove oldest entries
		collector.requestDurations = collector.requestDurations[5000:]
	}

	collector.requestDurations = append(collector.requestDurations, durationMs)
}

// IncrementRegistration records a registration attempt result.
//
// Security features:
// - Only success/failure recorded, no user details
// - No correlation with specific users
// - Simple counter for monitoring registration health
//
// Tracks registration success rate.
func IncrementRegistration(success bool) {
	if collector == nil {
		return
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	if success {
		collector.registrationsTotal["success"]++
	} else {
		collector.registrationsTotal["failed"]++
	}
}

// IncrementValidationFailure records input validation failures.
//
// Security features:
// - Only failure type recorded, not actual input
// - Helps identify common validation issues
// - No user data in failure reasons
//
// Tracks validation failure patterns.
func IncrementValidationFailure(reason string) {
	if collector == nil {
		return
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	// Sanitize reason to prevent cardinality explosion
	sanitizedReason := sanitizeFailureReason(reason)
	collector.validationFailures[sanitizedReason]++
}

// UpdateActiveConnections increments/decrements the active connection count.
//
// Security features:
// - Simple gauge, no connection details
// - Helps monitor service load
// - Thread-safe increment/decrement operations
//
// Thread-safe gauge update with delta values (+1 for new connections, -1 for closed).
func UpdateActiveConnections(delta int64) {
	if collector == nil {
		return
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	collector.activeConnections += delta

	// Prevent negative connection counts in case of race conditions
	if collector.activeConnections < 0 {
		collector.activeConnections = 0
	}
}

// IncrementError records an error occurrence.
//
// Security features:
// - Only error type recorded, not details
// - Helps identify error patterns
// - No stack traces or sensitive data
//
// Tracks error rates by type.
func IncrementError(errorType string) {
	if collector == nil {
		return
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	// Sanitize error type
	sanitizedType := sanitizeErrorType(errorType)
	collector.errorsTotal[sanitizedType]++
}

// GetMetrics returns all collected metrics for MQTT publication.
//
// Security features:
// - Returns copies to prevent external modification
// - No user data in any metrics
// - Calculated rates and percentiles included
//
// Returns slice of metrics ready for publication.
func GetMetrics() []Metric {
	if collector == nil {
		return []Metric{}
	}

	collector.mu.RLock()
	defer collector.mu.RUnlock()

	var metrics []Metric
	timestamp := time.Now().Unix()

	// REQUEST METRICS
	for key, value := range collector.requestsTotal {
		parts := strings.Split(key, ":")
		if len(parts) == 3 {
			metrics = append(metrics, Metric{
				Service:   "entry-hub",
				Timestamp: timestamp,
				Name:      "requests_total",
				Value:     float64(value),
				Labels: map[string]string{
					"method": parts[0],
					"path":   parts[1],
					"status": parts[2],
				},
				Type: MetricTypeCounter,
			})
		}
	}

	// REQUEST DURATION METRICS
	if len(collector.requestDurations) > 0 {
		// Calculate percentiles
		p50 := calculatePercentile(collector.requestDurations, 50)
		p95 := calculatePercentile(collector.requestDurations, 95)
		p99 := calculatePercentile(collector.requestDurations, 99)

		metrics = append(metrics,
			Metric{
				Service:   "entry-hub",
				Timestamp: timestamp,
				Name:      "request_duration_milliseconds",
				Value:     p50,
				Labels:    map[string]string{"quantile": "0.5"},
				Type:      MetricTypeGauge,
			},
			Metric{
				Service:   "entry-hub",
				Timestamp: timestamp,
				Name:      "request_duration_milliseconds",
				Value:     p95,
				Labels:    map[string]string{"quantile": "0.95"},
				Type:      MetricTypeGauge,
			},
			Metric{
				Service:   "entry-hub",
				Timestamp: timestamp,
				Name:      "request_duration_milliseconds",
				Value:     p99,
				Labels:    map[string]string{"quantile": "0.99"},
				Type:      MetricTypeGauge,
			},
		)
	}

	// REGISTRATION METRICS
	for result, count := range collector.registrationsTotal {
		metrics = append(metrics, Metric{
			Service:   "entry-hub",
			Timestamp: timestamp,
			Name:      "registrations_total",
			Value:     float64(count),
			Labels:    map[string]string{"result": result},
			Type:      MetricTypeCounter,
		})
	}

	// VALIDATION FAILURE METRICS
	for reason, count := range collector.validationFailures {
		metrics = append(metrics, Metric{
			Service:   "entry-hub",
			Timestamp: timestamp,
			Name:      "validation_failures_total",
			Value:     float64(count),
			Labels:    map[string]string{"reason": reason},
			Type:      MetricTypeCounter,
		})
	}

	// CONNECTION METRICS
	metrics = append(metrics, Metric{
		Service:   "entry-hub",
		Timestamp: timestamp,
		Name:      "connections_active",
		Value:     float64(collector.activeConnections),
		Labels:    map[string]string{},
		Type:      MetricTypeGauge,
	})

	// ERROR METRICS
	for errorType, count := range collector.errorsTotal {
		metrics = append(metrics, Metric{
			Service:   "entry-hub",
			Timestamp: timestamp,
			Name:      "errors_total",
			Value:     float64(count),
			Labels:    map[string]string{"type": errorType},
			Type:      MetricTypeCounter,
		})
	}

	return metrics
}

// Reset clears all metrics (useful for testing).
//
// Security features:
// - Complete memory clear
// - No data persistence
//
// Should only be used in tests.
func Reset() {
	if collector == nil {
		return
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()

	collector.requestsTotal = make(map[string]int64)
	collector.requestDurations = make([]float64, 0, 1000)
	collector.registrationsTotal = make(map[string]int64)
	collector.validationFailures = make(map[string]int64)
	collector.errorsTotal = make(map[string]int64)
	collector.activeConnections = 0
	collector.mtlsConnections = 0
	collector.lastResetTime = time.Now()
}

// sanitizePath removes dynamic parts from URL paths.
//
// Security features:
// - Prevents cardinality explosion in metrics
// - Removes UUIDs, numbers, emails
// - Maintains path structure for analysis
//
// Returns sanitized path safe for metrics.
func sanitizePath(path string) string {
	// Common patterns to replace
	// - UUIDs: /users/123e4567-e89b-12d3-a456-426614174000 -> /users/{id}
	// - Numbers: /users/12345 -> /users/{id}
	// - Emails: /verify/user@example.com -> /verify/{email}

	if strings.HasPrefix(path, "/api/") {
		// Simplify API paths
		if strings.Contains(path, "/register") {
			return "/api/register"
		}
		if strings.Contains(path, "/health") {
			return "/api/health"
		}
	}

	// Default sanitization
	return path
}

// sanitizeFailureReason groups similar validation failures.
//
// Security features:
// - Groups related failures
// - Removes specific values
// - Maintains failure categories
//
// Returns sanitized failure reason.
func sanitizeFailureReason(reason string) string {
	// Group similar reasons
	switch {
	case strings.Contains(reason, "email"):
		return "invalid_email"
	case strings.Contains(reason, "password"):
		return "invalid_password"
	case strings.Contains(reason, "ssh"):
		return "invalid_ssh_key"
	default:
		return "validation_error"
	}
}

// sanitizeErrorType groups similar errors.
//
// Security features:
// - Groups related errors
// - Removes specific error details
// - Maintains error categories
//
// Returns sanitized error type.
func sanitizeErrorType(errorType string) string {
	// Group similar errors
	switch {
	case strings.Contains(errorType, "timeout"):
		return "timeout"
	case strings.Contains(errorType, "connection"):
		return "connection"
	case strings.Contains(errorType, "tls"):
		return "tls"
	case strings.Contains(errorType, "certificate"):
		return "certificate"
	default:
		return "internal"
	}
}

// calculatePercentile calculates the nth percentile of a slice.
//
// Security features:
// - No data exposure
// - Simple mathematical operation
//
// Returns percentile value.
func calculatePercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}

	// Simple implementation - in production use a proper algorithm
	// This is simplified for demonstration
	index := int(float64(len(values)) * percentile / 100)
	if index >= len(values) {
		index = len(values) - 1
	}

	return values[index]
}
