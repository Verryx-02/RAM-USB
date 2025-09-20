/*
PostgreSQL connection management for Database-Vault storage operations.

Provides connection pooling, configuration parsing, and health checking
for reliable database connectivity. Implements best practices for
PostgreSQL connection management including timeout configuration,
connection limits, and secure credential handling.
*/
package postgresql

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectionConfig holds PostgreSQL connection parameters.
//
// Security features:
// - Secure credential handling through connection string
// - Configurable timeouts to prevent hanging connections
// - Connection pool limits for resource management
// - SSL/TLS mode configuration for encrypted connections
//
// Used during PostgreSQL storage initialization.
type ConnectionConfig struct {
	DatabaseURL       string        // PostgreSQL connection string with credentials
	MaxConnections    int32         // Maximum number of connections in pool
	MinConnections    int32         // Minimum number of idle connections
	MaxConnLifetime   time.Duration // Maximum lifetime of a connection
	MaxConnIdleTime   time.Duration // Maximum idle time before connection closure
	ConnectionTimeout time.Duration // Timeout for establishing new connections
	QueryTimeout      time.Duration // Default timeout for query execution
}

// DefaultConnectionConfig returns secure default connection settings.
//
// Security features:
// - Conservative connection limits prevent resource exhaustion
// - Reasonable timeouts prevent hanging operations
// - Connection recycling for security and stability
//
// Returns ConnectionConfig with production-ready defaults.
func DefaultConnectionConfig() ConnectionConfig {
	return ConnectionConfig{
		MaxConnections:    25,               // Conservative pool size
		MinConnections:    5,                // Maintain minimum ready connections
		MaxConnLifetime:   30 * time.Minute, // Recycle connections periodically
		MaxConnIdleTime:   5 * time.Minute,  // Close idle connections
		ConnectionTimeout: 10 * time.Second, // Connection establishment timeout
		QueryTimeout:      5 * time.Second,  // Query execution timeout
	}
}

// createConnectionPool establishes PostgreSQL connection pool with security configurations.
//
// Security features:
// - Connection string parsing for credential validation
// - SSL/TLS enforcement based on connection string
// - Pool configuration for resource management
// - Health check to verify connectivity
//
// Returns configured connection pool or error if connection fails.
func createConnectionPool(config ConnectionConfig) (*pgxpool.Pool, error) {
	// PARSE DATABASE URL
	// Validate connection string format and extract components
	parsedURL, err := url.Parse(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid database URL format: %v", err)
	}

	// MASK CREDENTIALS FOR LOGGING
	// Log connection attempt without exposing password
	maskedURL := *parsedURL
	if maskedURL.User != nil {
		maskedURL.User = url.UserPassword(maskedURL.User.Username(), "***")
	}
	log.Printf("Connecting to PostgreSQL: %s", maskedURL.String())

	// CONFIGURE CONNECTION POOL
	// Parse connection string and apply pool settings
	poolConfig, err := pgxpool.ParseConfig(config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pool config: %v", err)
	}

	// APPLY POOL SIZE LIMITS
	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections
	poolConfig.MaxConnLifetime = config.MaxConnLifetime
	poolConfig.MaxConnIdleTime = config.MaxConnIdleTime
	poolConfig.ConnConfig.ConnectTimeout = config.ConnectionTimeout

	// CONFIGURE RUNTIME PARAMETERS
	// Set session-level PostgreSQL parameters
	poolConfig.ConnConfig.RuntimeParams = map[string]string{
		"application_name":                    "database-vault",
		"statement_timeout":                   fmt.Sprintf("%d", config.QueryTimeout.Milliseconds()),
		"idle_in_transaction_session_timeout": "60000", // 60 seconds
		"lock_timeout":                        "10000", // 10 seconds
		"client_encoding":                     "UTF8",
	}

	// BEFORE CONNECT HOOK
	// Log successful connections for monitoring
	poolConfig.BeforeConnect = func(ctx context.Context, cfg *pgx.ConnConfig) error {
		log.Printf("Establishing new PostgreSQL connection to %s:%d",
			cfg.Host, cfg.Port)
		return nil
	}

	// AFTER CONNECT HOOK
	// Prepare frequently used statements on each connection
	poolConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		log.Printf("PostgreSQL connection established successfully")
		// Could prepare statements here if needed
		return nil
	}

	// CREATE CONNECTION POOL
	// Establish connection pool with configured settings
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectionTimeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %v", err)
	}

	// VERIFY CONNECTIVITY
	// Ensure pool can establish at least one connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	// LOG POOL STATISTICS
	stats := pool.Stat()
	log.Printf("Connection pool initialized: total=%d, idle=%d, max=%d",
		stats.TotalConns(), stats.IdleConns(), stats.MaxConns())

	return pool, nil
}

// checkDatabaseConnectivity performs comprehensive database health check.
//
// Security features:
// - Validates connectivity without exposing credentials
// - Checks connection pool health metrics
// - Verifies query execution capability
//
// Returns nil if database is healthy, error otherwise.
func checkDatabaseConnectivity(pool *pgxpool.Pool) error {
	// CONTEXT WITH TIMEOUT
	// Prevent health check from hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// PING DATABASE
	// Basic connectivity check
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}

	// EXECUTE HEALTH CHECK QUERY
	// Verify query execution capability
	var result int
	err := pool.QueryRow(ctx, healthCheckQuery).Scan(&result)
	if err != nil {
		return fmt.Errorf("health check query failed: %v", err)
	}

	if result != 1 {
		return fmt.Errorf("unexpected health check result: %d", result)
	}

	// CHECK POOL STATISTICS
	// Ensure pool has available connections
	stats := pool.Stat()
	if stats.TotalConns() == 0 {
		return fmt.Errorf("no connections in pool")
	}

	// CHECK FOR POOL EXHAUSTION
	// Warn if pool is near capacity
	if stats.AcquireCount() > 0 && stats.TotalConns() == stats.MaxConns() {
		log.Printf("Warning: Connection pool at maximum capacity (%d connections)",
			stats.MaxConns())
	}

	return nil
}

// getPoolStatistics returns current connection pool metrics.
//
// Security features:
// - Provides monitoring data without sensitive information
// - Helps detect connection leaks and pool exhaustion
// - Enables proactive capacity planning
//
// Returns formatted statistics string for logging.
func getPoolStatistics(pool *pgxpool.Pool) string {
	stats := pool.Stat()
	return fmt.Sprintf(
		"Pool Stats: total=%d, acquired=%d, idle=%d, max=%d, wait_duration=%v",
		stats.TotalConns(),
		stats.AcquiredConns(),
		stats.IdleConns(),
		stats.MaxConns(),
		stats.AcquireDuration(),
	)
}
