/*
Metrics middleware for Entry-Hub HTTP request monitoring and connection tracking.

Provides comprehensive request instrumentation including latency measurement,
HTTP method and status code tracking, and active connection counting for
operational visibility. Integrates with the metrics collector for MQTT
publication to the monitoring system following zero-knowledge principles.
*/
package middleware

import (
	"https_server/metrics"
	"net/http"
	"time"
)

// MetricsMiddleware creates middleware function for comprehensive HTTP request monitoring.
//
// Security features:
// - No user data collection (only HTTP method, path, status)
// - Request latency measurement for performance monitoring
// - Active connection tracking for load analysis
// - Thread-safe metrics collection
// - Zero-knowledge compliance (no request content logging)
//
// Integrates both request metrics and connection tracking in a single middleware.
func MetricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CONNECTION TRACKING: Increment active connections
		// Track concurrent connection load for capacity planning
		metrics.UpdateActiveConnections(1) // Increment
		defer func() {
			// CONNECTION TRACKING: Decrement when request completes
			// Ensure accurate connection count regardless of request outcome
			metrics.UpdateActiveConnections(-1) // Decrement
		}()

		// REQUEST TIMING: Start latency measurement
		// Measure total request processing time for performance analysis
		startTime := time.Now()

		// STATUS CODE CAPTURE: Wrap ResponseWriter to capture status
		// Custom wrapper to extract HTTP response status for metrics
		wrapper := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200 OK
		}

		// REQUEST PROCESSING: Execute the actual handler
		// Process request with timing and status tracking
		next(wrapper, r)

		// REQUEST METRICS: Record completion statistics
		// Calculate request duration in milliseconds for histogram
		duration := time.Since(startTime)
		durationMs := float64(duration.Nanoseconds()) / 1e6

		// METRICS COLLECTION: Record request completion
		// Thread-safe recording of request method, path, and status
		metrics.IncrementRequest(r.Method, r.URL.Path, wrapper.statusCode)
		metrics.RecordRequestDuration(durationMs)
	}
}

// responseWriter wraps http.ResponseWriter to capture status codes.
//
// Security features:
// - Minimal wrapper with only status code capture
// - No response body logging (zero-knowledge compliance)
// - Thread-safe status code recording
//
// Required for HTTP status code metrics collection.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before writing the response.
//
// Security features:
// - Only captures numeric status code
// - No header content logging
// - Required for metrics status code tracking
//
// Implements http.ResponseWriter interface.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
