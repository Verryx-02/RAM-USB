/*
PostgreSQL error handling utilities for Database-Vault storage operations.

Provides error categorization, mapping between PostgreSQL errors and storage
errors, and secure error messages that prevent information disclosure while
maintaining useful debugging information in logs.
*/
package postgresql

import (
	"database-vault/storage"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// mapPostgreSQLError converts PostgreSQL-specific errors to storage layer errors.
//
// Security features:
// - Maps database errors to generic categories preventing information disclosure
// - Provides detailed internal logging while returning sanitized user messages
// - Handles constraint violations for duplicate detection
// - Categorizes connection errors for appropriate retry strategies
//
// Returns appropriate StorageError based on PostgreSQL error type and context.
func mapPostgreSQLError(err error, operation string) error {
	// NO ERROR CASE
	if err == nil {
		return nil
	}

	// RECORD NOT FOUND
	// pgx.ErrNoRows indicates the query returned no results
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.NewStorageError(
			storage.ErrorUserNotFound,
			operation,
			fmt.Sprintf("No user found in database: %v", err),
			"User not found",
		)
	}

	// POSTGRESQL SPECIFIC ERROR HANDLING
	// Check for pgconn.PgError for detailed PostgreSQL error information
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// Handle based on PostgreSQL error code
		// Reference: https://www.postgresql.org/docs/current/errcodes-appendix.html
		switch pgErr.Code {
		// UNIQUE CONSTRAINT VIOLATIONS (23505)
		case "23505":
			// Determine which constraint was violated
			if strings.Contains(pgErr.Detail, "email_hash") {
				return storage.NewStorageError(
					storage.ErrorEmailHashExists,
					operation,
					fmt.Sprintf("Email hash already exists: %v", pgErr.Detail),
					"Email address already registered",
				)
			}
			if strings.Contains(pgErr.Detail, "ssh_public_key") ||
				strings.Contains(pgErr.ConstraintName, "ssh") {
				return storage.NewStorageError(
					storage.ErrorSSHKeyExists,
					operation,
					fmt.Sprintf("SSH key already exists: %v", pgErr.Detail),
					"SSH public key already in use",
				)
			}
			// Generic unique constraint violation
			return storage.NewStorageError(
				storage.ErrorConstraintViolation,
				operation,
				fmt.Sprintf("Unique constraint violation: %v", pgErr.Detail),
				"Duplicate value detected",
			)

		// CHECK CONSTRAINT VIOLATIONS (23514)
		case "23514":
			return storage.NewStorageError(
				storage.ErrorInvalidUserData,
				operation,
				fmt.Sprintf("Check constraint violation: %v", pgErr.Detail),
				"Invalid data format",
			)

		// FOREIGN KEY VIOLATIONS (23503)
		case "23503":
			return storage.NewStorageError(
				storage.ErrorConstraintViolation,
				operation,
				fmt.Sprintf("Foreign key constraint violation: %v", pgErr.Detail),
				"Related data constraint error",
			)

		// CONNECTION ERRORS (08xxx)
		case "08000", "08003", "08006", "08001", "08004":
			return storage.NewStorageError(
				storage.ErrorDatabaseConnection,
				operation,
				fmt.Sprintf("Database connection error: %v", pgErr.Message),
				"Database connection unavailable",
			)

		// INSUFFICIENT PRIVILEGES (42501)
		case "42501":
			return storage.NewStorageError(
				storage.ErrorDatabaseConnection,
				operation,
				fmt.Sprintf("Insufficient privileges: %v", pgErr.Message),
				"Database access denied",
			)

		// DISK FULL (53100)
		case "53100":
			return storage.NewStorageError(
				storage.ErrorDatabaseConnection,
				operation,
				"Database disk full",
				"Storage capacity exceeded",
			)

		// LOCK TIMEOUT (55P03)
		case "55P03":
			return storage.NewStorageError(
				storage.ErrorTransactionFailed,
				operation,
				fmt.Sprintf("Lock timeout: %v", pgErr.Message),
				"Database operation timeout",
			)

		// DEADLOCK DETECTED (40P01)
		case "40P01":
			return storage.NewStorageError(
				storage.ErrorTransactionFailed,
				operation,
				"Deadlock detected",
				"Database conflict, please retry",
			)

		// SERIALIZATION FAILURE (40001)
		case "40001":
			return storage.NewStorageError(
				storage.ErrorTransactionFailed,
				operation,
				"Serialization failure",
				"Database conflict, please retry",
			)
		}
	}

	// CONNECTION POOL ERRORS
	// Check for connection-related errors from pgx pool
	if strings.Contains(err.Error(), "connection") ||
		strings.Contains(err.Error(), "timeout") {
		return storage.NewStorageError(
			storage.ErrorDatabaseConnection,
			operation,
			fmt.Sprintf("Connection pool error: %v", err),
			"Database connection error",
		)
	}

	// TRANSACTION ERRORS
	// Check for transaction-related errors
	if strings.Contains(err.Error(), "transaction") {
		return storage.NewStorageError(
			storage.ErrorTransactionFailed,
			operation,
			fmt.Sprintf("Transaction error: %v", err),
			"Database transaction failed",
		)
	}

	// GENERIC DATABASE ERROR
	// Fallback for unhandled database errors
	return storage.NewStorageError(
		storage.ErrorUnknown,
		operation,
		fmt.Sprintf("Unexpected database error: %v", err),
		"Database operation failed",
	)
}

// isRetryableError determines if an error is safe to retry.
//
// Security features:
// - Identifies transient errors that may succeed on retry
// - Prevents retry on permanent failures (constraints, validation)
// - Helps implement exponential backoff strategies
//
// Returns true if the error is transient and retry might succeed.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// CHECK STORAGE ERROR TYPE
	var storageErr *storage.StorageError
	if errors.As(err, &storageErr) {
		switch storageErr.Type {
		// Retryable errors
		case storage.ErrorDatabaseConnection,
			storage.ErrorTransactionFailed:
			return true
		// Non-retryable errors
		case storage.ErrorUserExists,
			storage.ErrorEmailHashExists,
			storage.ErrorSSHKeyExists,
			storage.ErrorInvalidUserData,
			storage.ErrorConstraintViolation,
			storage.ErrorUserNotFound:
			return false
		}
	}

	// CHECK POSTGRESQL ERROR CODES
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		// Retryable: deadlock, serialization failure, lock timeout
		case "40P01", "40001", "55P03":
			return true
		// Retryable: connection errors
		case "08000", "08003", "08006":
			return true
		}
	}

	// Default: don't retry unknown errors
	return false
}
