/*
Metrics endpoint handlers for Metrics-Collector service.

Implements HTTP handlers that expose collected metrics in standard exposition
format. Provides /metrics endpoint for monitoring tools and /health endpoint for
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
	"time"
)

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
