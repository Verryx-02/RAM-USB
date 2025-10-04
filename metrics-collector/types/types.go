/*
Type definitions for Metrics-Collector monitoring service.

Provides structured data models for metrics collection, storage, and exposition
across the R.A.M.-U.S.B. distributed monitoring system.
Ensures consistent metric format between MQTT publishers, TimescaleDB storage
while maintaining zero-knowledge principles by excluding sensitive data.
*/
package types

import (
	"time"
)

// Metric represents a single metric data point in the monitoring system.
//
// Security features:
// - No fields for sensitive data (emails, passwords, SSH keys)
// - Generic labels map for extensibility without exposing PII
// - Service identification for access control and filtering
// - Timestamp for time-series correlation and retention policies
//
// Used for MQTT message serialization between services and collector.
type Metric struct {
	Service   string            `json:"service"`   // Service identifier (entry-hub, security-switch, etc.)
	Timestamp int64             `json:"timestamp"` // Unix timestamp for metric collection time
	Name      string            `json:"name"`      // Metric name following Prometheus naming convention
	Value     float64           `json:"value"`     // Numeric value of the metric
	Labels    map[string]string `json:"labels"`    // Additional dimensions for metric categorization
	Type      MetricType        `json:"type"`      // Metric type for proper aggregation
}

// MetricType defines the aggregation behavior for metrics.
//
// Based on Prometheus metric types for compatibility with monitoring ecosystem.
// Determines how metrics are stored, aggregated, and exposed.
type MetricType string

const (
	// COUNTER - Monotonically increasing value, resets on restart
	// Examples: requests_total, errors_total, bytes_processed
	MetricTypeCounter MetricType = "counter"

	// GAUGE - Value that can go up or down
	// Examples: temperature, memory_usage, concurrent_connections
	MetricTypeGauge MetricType = "gauge"

	// HISTOGRAM - Samples observations and counts them in buckets
	// Examples: request_duration, response_size
	MetricTypeHistogram MetricType = "histogram"

	// SUMMARY - Similar to histogram but calculates quantiles
	// Examples: request_latency_percentiles
	MetricTypeSummary MetricType = "summary"
)

// StoredMetric represents a metric persisted in TimescaleDB.
//
// Security features:
// - Immutable after creation (time-series data)
// - No user-identifiable information in any field
// - Service-level granularity only (no user-level metrics)
// - JSON labels for flexible querying without schema changes
//
// Mapped to TimescaleDB hypertable for efficient time-series operations.
type StoredMetric struct {
	Time       time.Time         `db:"time"`        // Timestamp as TimescaleDB primary key
	Service    string            `db:"service"`     // Service that generated the metric
	MetricName string            `db:"metric_name"` // Prometheus-compatible metric name (Compatible with Grafana)
	MetricType string            `db:"metric_type"` // Type for aggregation rules
	Value      float64           `db:"value"`       // Numeric metric value
	Labels     map[string]string `db:"labels"`      // JSONB column for label storage
	InsertedAt time.Time         `db:"inserted_at"` // Collector reception timestamp
}

// MetricQuery defines parameters for retrieving metrics from storage.
//
// Security features:
// - Time-based filtering prevents full table scans
// - Service filtering for access control
// - No ability to query by user or sensitive fields
//
// Used for Grafana queries.
type MetricQuery struct {
	Service    string            `json:"service,omitempty"`     // Filter by service name
	MetricName string            `json:"metric_name,omitempty"` // Filter by metric name
	StartTime  time.Time         `json:"start_time"`            // Beginning of time range
	EndTime    time.Time         `json:"end_time"`              // End of time range
	Labels     map[string]string `json:"labels,omitempty"`      // Filter by label values
	Limit      int               `json:"limit,omitempty"`       // Maximum results to return
}

// AggregatedMetric represents summarized metrics for dashboard display.
//
// Security features:
// - Pre-aggregated data prevents detailed user tracking
// - Statistical summaries only (no individual data points)
// - Time-bucketed for trend analysis without precision timing
//
// Used for Grafana dashboards and reporting.
type AggregatedMetric struct {
	TimeBucket   time.Time `json:"time_bucket"`   // Aggregation time bucket (hourly, daily)
	Service      string    `json:"service"`       // Service identifier
	MetricName   string    `json:"metric_name"`   // Metric being aggregated
	Count        int64     `json:"count"`         // Number of data points in bucket
	Sum          float64   `json:"sum"`           // Sum of all values
	Average      float64   `json:"average"`       // Average value in bucket
	Min          float64   `json:"min"`           // Minimum value in bucket
	Max          float64   `json:"max"`           // Maximum value in bucket
	Percentile95 float64   `json:"p95,omitempty"` // 95th percentile (for latency metrics)
}

// ServiceHealth represents health status of a monitored service.
//
// Security features:
// - High-level health only (no internal details)
// - No exposure of configuration or credentials
// - Generic status indicators for monitoring
//
// Used for service discovery and alerting.
type ServiceHealth struct {
	Service      string    `json:"service"`           // Service name
	Status       string    `json:"status"`            // Health status (up, down, degraded)
	LastSeen     time.Time `json:"last_seen"`         // Last metric received timestamp
	MetricsCount int64     `json:"metrics_count"`     // Total metrics received
	ErrorRate    float64   `json:"error_rate"`        // Recent error percentage
	ResponseTime float64   `json:"response_time"`     // Average response time (ms)
	Version      string    `json:"version,omitempty"` // Service version if available
}

// Constants for validation and limits
const (
	// METRIC SIZE LIMITS
	MaxLabelKeyLength   = 128 // Maximum length for label keys
	MaxLabelValueLength = 256 // Maximum length for label values
	MaxLabelsPerMetric  = 20  // Maximum number of labels per metric
	MaxMetricNameLength = 256 // Maximum length for metric names
)
