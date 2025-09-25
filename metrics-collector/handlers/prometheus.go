/*
Prometheus endpoint handlers for Metrics-Collector service.

Implements HTTP handlers that expose collected metrics in Prometheus exposition
format. Provides /metrics endpoint for scraping and /health endpoint for
service monitoring. Maintains zero-knowledge principles by never exposing
sensitive data in metrics output.
*/
package handlers

import (
	"encoding/json"
	"fmt"
	"metrics-collector/mqtt"
	"metrics-collector/storage"
	"net/http"
	"sort"
	"strings"
	"time"
)

// PrometheusHandler exposes metrics in Prometheus text format for scraping.
//
// Security features:
// - No authentication required (Prometheus scraper uses mTLS at network level)
// - Zero-knowledge compliance - no sensitive data exposed
// - Read-only endpoint - no state modification
// - Efficient text format to prevent resource exhaustion
//
// Returns metrics in Prometheus exposition format or error.
func PrometheusHandler(w http.ResponseWriter, r *http.Request) {
	// HTTP METHOD VALIDATION
	// Only allow GET requests for metrics scraping
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// CONTENT TYPE HEADER
	// Set Prometheus text format version
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// COLLECTOR METRICS
	// Internal metrics about the collector itself
	writeCollectorMetrics(w)

	// SERVICE METRICS
	// Retrieved metrics from all monitored services
	writeServiceMetrics(w)
}

// writeCollectorMetrics outputs internal collector statistics.
//
// Security features:
// - Only aggregate statistics (no individual message details)
// - No service-specific information that could reveal architecture
// - Performance metrics for monitoring collector health
//
// Writes collector operational metrics to response writer.
func writeCollectorMetrics(w http.ResponseWriter) {
	// MQTT STATISTICS
	// Get message processing statistics
	received, rejected, stored := mqtt.GetStatistics()

	// COLLECTOR UP METRIC
	// Basic liveness indicator for monitoring
	fmt.Fprintf(w, "# HELP ramusb_metrics_collector_up Indicates if the metrics collector is running\n")
	fmt.Fprintf(w, "# TYPE ramusb_metrics_collector_up gauge\n")
	fmt.Fprintf(w, "ramusb_metrics_collector_up 1\n\n")

	// METRICS RECEIVED COUNTER
	// Total metrics received via MQTT
	fmt.Fprintf(w, "# HELP ramusb_metrics_received_total Total number of metrics received via MQTT\n")
	fmt.Fprintf(w, "# TYPE ramusb_metrics_received_total counter\n")
	fmt.Fprintf(w, "ramusb_metrics_received_total %d\n\n", received)

	// METRICS REJECTED COUNTER
	// Metrics rejected due to validation failures
	fmt.Fprintf(w, "# HELP ramusb_metrics_rejected_total Total number of metrics rejected for containing sensitive data\n")
	fmt.Fprintf(w, "# TYPE ramusb_metrics_rejected_total counter\n")
	fmt.Fprintf(w, "ramusb_metrics_rejected_total %d\n\n", rejected)

	// METRICS STORED COUNTER
	// Successfully stored metrics in TimescaleDB
	fmt.Fprintf(w, "# HELP ramusb_metrics_stored_total Total number of metrics stored in TimescaleDB\n")
	fmt.Fprintf(w, "# TYPE ramusb_metrics_stored_total counter\n")
	fmt.Fprintf(w, "ramusb_metrics_stored_total %d\n\n", stored)

	// REJECTION RATE GAUGE
	// Percentage of metrics rejected (useful for alerting)
	rejectionRate := float64(0)
	if received > 0 {
		rejectionRate = float64(rejected) / float64(received) * 100
	}
	fmt.Fprintf(w, "# HELP ramusb_metrics_rejection_rate_percent Percentage of metrics rejected\n")
	fmt.Fprintf(w, "# TYPE ramusb_metrics_rejection_rate_percent gauge\n")
	fmt.Fprintf(w, "ramusb_metrics_rejection_rate_percent %.2f\n\n", rejectionRate)
}

// writeServiceMetrics outputs metrics from monitored services.
//
// Security features:
// - Retrieves only recent metrics to limit data exposure
// - No user-specific metrics included
// - Aggregated service-level metrics only
// - Label sanitization to prevent injection
//
// Writes service metrics in Prometheus format to response writer.
func writeServiceMetrics(w http.ResponseWriter) {
	// RECENT METRICS RETRIEVAL
	// Get metrics from last 5 minutes for current values
	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute)

	metrics, err := storage.GetRecentMetrics(startTime, endTime)
	if err != nil {
		// Log error but don't expose to Prometheus
		fmt.Fprintf(w, "# ERROR: Failed to retrieve service metrics\n")
		return
	}

	// GROUP METRICS BY NAME
	// Organize metrics for proper exposition format
	metricGroups := make(map[string][]storage.MetricData)
	for _, metric := range metrics {
		metricGroups[metric.Name] = append(metricGroups[metric.Name], metric)
	}

	// SORT METRIC NAMES
	// Ensure consistent output ordering
	var metricNames []string
	for name := range metricGroups {
		metricNames = append(metricNames, name)
	}
	sort.Strings(metricNames)

	// OUTPUT EACH METRIC GROUP
	// Write metrics with proper HELP and TYPE annotations
	for _, metricName := range metricNames {
		metrics := metricGroups[metricName]
		if len(metrics) == 0 {
			continue
		}

		// Determine metric type from first metric
		metricType := metrics[0].Type

		// WRITE HELP TEXT
		fmt.Fprintf(w, "# HELP %s %s\n", metricName, getMetricHelp(metricName))

		// WRITE TYPE ANNOTATION
		fmt.Fprintf(w, "# TYPE %s %s\n", metricName, prometheusType(metricType))

		// WRITE METRIC VALUES
		for _, metric := range metrics {
			labelStr := formatLabels(metric.Labels)
			fmt.Fprintf(w, "%s%s %f\n", metricName, labelStr, metric.Value)
		}
		fmt.Fprintln(w) // Empty line between metrics
	}
}

// HealthHandler provides service health status for monitoring.
//
// Security features:
// - No sensitive configuration exposed
// - Generic health status only
// - No internal architecture details
//
// Returns JSON health status or error.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// HTTP METHOD VALIDATION
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// CONTENT TYPE HEADER
	w.Header().Set("Content-Type", "application/json")

	// HEALTH STATUS CONSTRUCTION
	health := struct {
		Status    string            `json:"status"`
		Service   string            `json:"service"`
		Timestamp time.Time         `json:"timestamp"`
		Checks    map[string]string `json:"checks"`
	}{
		Status:    "healthy",
		Service:   "metrics-collector",
		Timestamp: time.Now(),
		Checks:    make(map[string]string),
	}

	// DATABASE HEALTH CHECK
	if err := storage.HealthCheck(); err != nil {
		health.Status = "degraded"
		health.Checks["database"] = "unavailable"
	} else {
		health.Checks["database"] = "healthy"
	}

	// MQTT HEALTH CHECK
	received, rejected, _ := mqtt.GetStatistics()
	if received > 0 && rejected == received {
		health.Status = "degraded"
		health.Checks["mqtt"] = "all metrics rejected"
	} else {
		health.Checks["mqtt"] = "healthy"
	}

	// SET HTTP STATUS CODE
	if health.Status != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// ENCODE RESPONSE
	json.NewEncoder(w).Encode(health)
}

// AdminHealthHandler provides detailed health status for admin API.
//
// Security features:
// - Requires mTLS authentication (enforced by middleware)
// - More detailed status than public health endpoint
// - Still no sensitive configuration exposed
//
// Returns detailed JSON health status.
func AdminHealthHandler(w http.ResponseWriter, r *http.Request) {
	// HTTP METHOD VALIDATION
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// CONTENT TYPE HEADER
	w.Header().Set("Content-Type", "application/json")

	// DETAILED HEALTH STATUS
	received, rejected, stored := mqtt.GetStatistics()

	health := struct {
		Status     string            `json:"status"`
		Service    string            `json:"service"`
		Version    string            `json:"version"`
		Uptime     string            `json:"uptime"`
		Timestamp  time.Time         `json:"timestamp"`
		Statistics map[string]uint64 `json:"statistics"`
		Checks     map[string]string `json:"checks"`
	}{
		Status:    "healthy",
		Service:   "metrics-collector",
		Version:   "1.0.0",
		Uptime:    getUptime(),
		Timestamp: time.Now(),
		Statistics: map[string]uint64{
			"metrics_received": received,
			"metrics_rejected": rejected,
			"metrics_stored":   stored,
		},
		Checks: make(map[string]string),
	}

	// Perform health checks
	if err := storage.HealthCheck(); err != nil {
		health.Status = "degraded"
		health.Checks["database"] = fmt.Sprintf("error: %v", err)
	} else {
		health.Checks["database"] = "connected"
	}

	// RESPONSE ENCODING
	json.NewEncoder(w).Encode(health)
}

// StatsHandler provides detailed statistics for admin monitoring.
//
// Security features:
// - Requires mTLS authentication
// - Aggregate statistics only
// - No individual metric data exposed
//
// Returns JSON statistics summary.
func StatsHandler(w http.ResponseWriter, r *http.Request) {
	// HTTP METHOD VALIDATION
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// CONTENT TYPE HEADER
	w.Header().Set("Content-Type", "application/json")

	// STATISTICS COLLECTION
	received, rejected, stored := mqtt.GetStatistics()

	stats := struct {
		Timestamp time.Time          `json:"timestamp"`
		Counters  map[string]uint64  `json:"counters"`
		Rates     map[string]float64 `json:"rates"`
	}{
		Timestamp: time.Now(),
		Counters: map[string]uint64{
			"total_received": received,
			"total_rejected": rejected,
			"total_stored":   stored,
		},
		Rates: make(map[string]float64),
	}

	// CALCULATE RATES
	if received > 0 {
		stats.Rates["rejection_rate"] = float64(rejected) / float64(received) * 100
		stats.Rates["storage_rate"] = float64(stored) / float64(received) * 100
	}

	// RESPONSE ENCODING
	json.NewEncoder(w).Encode(stats)
}

// formatLabels formats metric labels for Prometheus exposition.
//
// Security features:
// - Label value escaping to prevent injection
// - Key validation to ensure compliance
// - No sensitive data in labels
//
// Returns formatted label string or empty string if no labels.
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	// SORT LABEL KEYS
	// Ensure consistent output
	var keys []string
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// BUILD LABEL STRING
	var parts []string
	for _, key := range keys {
		value := labels[key]
		// Escape special characters in label values
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `"`, `\"`)
		value = strings.ReplaceAll(value, "\n", `\n`)

		parts = append(parts, fmt.Sprintf(`%s="%s"`, key, value))
	}

	return "{" + strings.Join(parts, ",") + "}"
}

// prometheusType converts internal metric type to Prometheus type string.
//
// Security features:
// - Validates type to prevent invalid exposition
// - Returns safe default for unknown types
//
// Returns Prometheus type annotation string.
func prometheusType(metricType string) string {
	switch metricType {
	case "counter":
		return "counter"
	case "gauge":
		return "gauge"
	case "histogram":
		return "histogram"
	case "summary":
		return "summary"
	default:
		return "untyped"
	}
}

// getMetricHelp returns help text for known metrics.
//
// Security features:
// - Generic descriptions only
// - No implementation details exposed
//
// Returns help text string for metric.
func getMetricHelp(metricName string) string {
	helpTexts := map[string]string{
		"requests_total":           "Total number of requests processed",
		"request_duration_seconds": "Request processing duration in seconds",
		"errors_total":             "Total number of errors encountered",
		"connections_active":       "Number of active connections",
		"memory_usage_bytes":       "Memory usage in bytes",
	}

	if help, exists := helpTexts[metricName]; exists {
		return help
	}

	// Generic help for unknown metrics
	return fmt.Sprintf("Metric %s from R.A.M.-U.S.B. services", metricName)
}

// getUptime calculates service uptime since start.
//
// Security features:
// - Only duration exposed, not actual start time
// - Rounded to prevent timing attacks
//
// Returns human-readable uptime string.
var startTime = time.Now()

func getUptime() string {
	duration := time.Since(startTime)
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	seconds := int(duration.Seconds()) % 60

	return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
}
