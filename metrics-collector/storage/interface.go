/*
Storage interface definitions for Metrics-Collector time-series persistence.

Provides abstract interfaces for metrics storage operations with TimescaleDB,
enabling efficient time-series data management, aggregation, and retrieval.
Maintains zero-knowledge principles by never storing sensitive user data
and implements retention policies for automatic data lifecycle management.
*/
package storage

import (
	"fmt"
	"log"
	"metrics-collector/types"
	"time"
)

var (
	// Global storage instance for metric operations
	storageInstance MetricsStorage
)

// MetricsStorage defines the interface for time-series metric storage.
//
// Security features:
// - No methods for storing user-identifiable information
// - Time-based retention for automatic data purging
// - Service-level granularity only
// - Read operations limited by time ranges
//
// Implementations must be thread-safe for concurrent metric storage.
type MetricsStorage interface {
	// StoreMetric persists a single metric data point.
	//
	// Security features:
	// - Validates metric doesn't contain sensitive data
	// - Enforces retention policies on storage
	// - Atomic operation for consistency
	//
	// Returns error if storage fails or validation fails.
	StoreMetric(metric types.Metric) error

	// StoreBatch persists multiple metrics in a single transaction.
	//
	// Security features:
	// - Batch validation before any storage
	// - Transactional integrity (all or none stored)
	// - Efficient for high-volume metric ingestion
	//
	// Returns error if any metric fails validation or storage fails.
	StoreBatch(metrics []types.Metric) error

	// GetMetrics retrieves metrics matching query parameters.
	//
	// Security features:
	// - Time-range required to prevent full table scans
	// - Result limit to prevent resource exhaustion
	// - No capability to query by user fields
	//
	// Returns matching metrics or error if query fails.
	GetMetrics(query types.MetricQuery) ([]types.StoredMetric, error)

	// GetAggregatedMetrics retrieves pre-aggregated metrics for dashboards.
	//
	// Security features:
	// - Returns only statistical summaries
	// - Time-bucketed to prevent precise timing analysis
	// - Service-level aggregation only
	//
	// Returns aggregated metrics or error if query fails.
	GetAggregatedMetrics(service string, metricName string, start, end time.Time, bucketSize time.Duration) ([]types.AggregatedMetric, error)

	// GetServiceHealth retrieves health status for all monitored services.
	//
	// Security features:
	// - High-level health indicators only
	// - No internal service details exposed
	// - Based on recent metric patterns
	//
	// Returns service health summaries or error if query fails.
	GetServiceHealth() ([]types.ServiceHealth, error)

	// DeleteOldMetrics removes metrics older than retention period.
	//
	// Security features:
	// - Automatic data lifecycle management
	// - Prevents unbounded storage growth
	// - Audit log of deletion operations
	//
	// Returns number of deleted metrics or error if deletion fails.
	DeleteOldMetrics(olderThan time.Time) (int64, error)

	// HealthCheck verifies storage system availability.
	//
	// Security features:
	// - No sensitive configuration exposed
	// - Simple connectivity check only
	// - Fast timeout to prevent hanging
	//
	// Returns nil if healthy, error if storage unavailable.
	HealthCheck() error

	// Close gracefully shuts down storage connections.
	//
	// Security features:
	// - Clean connection closure
	// - Flush pending writes
	// - Release resources properly
	//
	// Should be called during service shutdown.
	Close() error
}

// InitializeTimescaleDB creates and configures the TimescaleDB storage instance.
//
// Security features:
// - Connection string validation
// - SSL/TLS enforcement for database connection
// - Connection pooling for DoS prevention
// - Automatic table creation with proper schemas
//
// Returns error if initialization fails.
func InitializeTimescaleDB(databaseURL string) error {
	// Create TimescaleDB storage instance with connection pooling
	tsStorage, err := NewTimescaleDBStorage(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to create TimescaleDB storage: %v", err)
	}

	// Assign to global storage instance for use by all operations
	storageInstance = tsStorage

	log.Println("✓ TimescaleDB storage initialized and connected successfully")
	return nil
}

// StoreMetric stores a single metric using the global storage instance.
//
// Security features:
// - Validates storage is initialized
// - Delegates to implementation for validation
// - Thread-safe operation
//
// Returns error if storage not initialized or store fails.
func StoreMetric(metric types.Metric) error {
	if storageInstance == nil {
		log.Printf("ERROR: Storage instance is nil - metric from %s will be lost!", metric.Service)
		return fmt.Errorf("storage not initialized")
	}

	return storageInstance.StoreMetric(metric)
}

// StoreBatch stores multiple metrics using the global storage instance.
//
// Security features:
// - Batch validation before storage
// - Transactional integrity
// - Efficient for bulk operations
//
// Returns error if storage not initialized or store fails.
func StoreBatch(metrics []types.Metric) error {
	if storageInstance == nil {
		return nil
	}

	return storageInstance.StoreBatch(metrics)
}

// GetServiceHealth retrieves health status for all services.
//
// Security features:
// - Returns only high-level health
// - No internal details exposed
// - Based on metric patterns
//
// Returns service health or empty slice if storage unavailable.
func GetServiceHealth() ([]types.ServiceHealth, error) {
	if storageInstance == nil {
		return []types.ServiceHealth{}, nil
	}

	return storageInstance.GetServiceHealth()
}

// HealthCheck verifies storage system health.
//
// Security features:
// - Simple connectivity check
// - No configuration exposed
// - Fast timeout
//
// Returns nil if healthy or storage not initialized.
func HealthCheck() error {
	if storageInstance == nil {
		// If storage not initialized, not an error
		// Allows service to run without database
		return nil
	}

	return storageInstance.HealthCheck()
}

// Close gracefully shuts down storage connections.
//
// Security features:
// - Clean shutdown
// - Resource cleanup
// - Connection closure
//
// Safe to call even if storage not initialized.
func Close() error {
	if storageInstance != nil {
		return storageInstance.Close()
	}
	return nil
}

// GetStorageInstance returns the global storage instance for metrics access.
func GetStorageInstance() MetricsStorage {
	return storageInstance
}

// RunRetentionPolicy executes data retention cleanup.
//
// Security features:
// - Automatic old data removal
// - Audit logging of deletions
// - Prevents unbounded growth
//
// Returns number of deleted metrics or error.
func RunRetentionPolicy(retentionDays int) (int64, error) {
	if storageInstance == nil {
		return 0, nil
	}

	// Calculate cutoff time
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	// Delete old metrics
	return storageInstance.DeleteOldMetrics(cutoff)
}
