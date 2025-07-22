/*
Type definitions for Database-Vault secure storage service.

Provides structured data models for mTLS communication with Security-Switch,
secure user credential storage with Argon2id hashing and non-deterministic
email encryption, and standardized response formatting. Ensures consistent
data handling, validation, and JSON serialization across the final storage
layer of the R.A.M.-U.S.B. distributed authentication system.

TO-DO in LoginRequest: not implemented
*/
package types

import "time"

// RegisterRequest contains validated user registration data from Security-Switch.
//
// Security features:
// - Final validation layer before irreversible credential storage
// - Email validation ensures proper user identification format
// - Password transmission for secure Argon2id hashing with cryptographic salt
// - SSH public key validation for authenticated Storage-Service access
// - Defense-in-depth validation after Security-Switch pre-processing
//
// Received via mTLS from authenticated Security-Switch instances only.
type RegisterRequest struct {
	Email     string `json:"email"`          // User email address for account identification
	Password  string `json:"password"`       // Plain password for secure Argon2id hashing
	SSHPubKey string `json:"ssh_public_key"` // SSH public key for storage service authentication
}

// StoredUser represents complete user record for secure database persistence with enhanced email security.
//
// Security features:
// - SHA-256 email hash serves as primary key preventing user enumeration while enabling fast queries
// - AES-256-GCM encrypted email with random salt prevents deterministic encryption vulnerabilities
// - Unique email salt per user ensures different ciphertext for identical emails across users
// - Argon2id password hash with cryptographically secure salt prevents rainbow table attacks
// - Salt separation ensures unique hash even for identical passwords across users
// - SSH public key storage enables zero-knowledge file access authentication
// - Timestamp tracking for security auditing and account lifecycle management
// - No plaintext email or password storage maintains zero-knowledge principles
//
// Persisted in database with email-level encryption using AES-256-GCM authenticated encryption with random nonce.
type StoredUser struct {
	EmailHash      string    `json:"email_hash"`      // Primary key - SHA-256 hash of email for fast indexing
	EncryptedEmail string    `json:"encrypted_email"` // AES-256-GCM encrypted email with random nonce and salt
	EmailSalt      string    `json:"email_salt"`      // Cryptographically secure random salt for email encryption
	PasswordHash   string    `json:"password_hash"`   // Argon2id hash of password with salt
	PasswordSalt   string    `json:"password_salt"`   // Cryptographically secure random salt for Argon2id
	SSHPubKey      string    `json:"ssh_public_key"`  // SSH public key for Storage-Service authentication
	CreatedAt      time.Time `json:"created_at"`      // Account creation timestamp for auditing
	UpdatedAt      time.Time `json:"updated_at"`      // Last modification timestamp for security monitoring
}

// Response provides standardized API response format for Security-Switch communication.
//
// Security features:
// - Consistent error handling prevents information disclosure variations
// - Success indication for reliable distributed service integration
// - Standardized format across all R.A.M.-U.S.B. mTLS services
// - Audit-friendly message format for security monitoring
//
// Used for Database-Vault responses to Security-Switch via mTLS authentication.
type Response struct {
	Success bool   `json:"success"` // Operation success indicator for service validation
	Message string `json:"message"` // Human-readable status or error description
}

// HealthResponse provides comprehensive Database-Vault health information for monitoring.
//
// Security features:
// - Service availability indication without sensitive configuration disclosure
// - Database connectivity status for distributed system monitoring
// - Storage capacity metrics for operational awareness
// - Consistent format for automated monitoring integration
//
// Extended health information for Database-Vault service dependency tracking.
type HealthResponse struct {
	Success         bool              `json:"success"`                    // Service availability indicator
	Message         string            `json:"message"`                    // Human-readable status description
	Service         string            `json:"service"`                    // Service name identifier
	Status          string            `json:"status"`                     // Detailed service operational status
	DatabaseStatus  string            `json:"database_status"`            // Database connectivity and health
	StorageCapacity string            `json:"storage_capacity,omitempty"` // Available storage capacity information
	Dependencies    map[string]string `json:"dependencies,omitempty"`     // External service dependency status
}

// StorageError represents Database-Vault specific error conditions for detailed error handling.
//
// Security features:
// - Categorized error types prevent information disclosure through error analysis
// - Audit trail creation for security monitoring and incident response
// - Standardized error classification for consistent client handling
// - Internal error details separation from client-facing messages
//
// Used internally for detailed error handling and audit logging.
type StorageError struct {
	Type      string    `json:"type"`       // Error category (validation, storage, duplicate, etc.)
	Message   string    `json:"message"`    // Detailed internal error description
	UserError string    `json:"user_error"` // Sanitized error message for client response
	Code      int       `json:"code"`       // HTTP status code for client response
	Timestamp time.Time `json:"timestamp"`  // Error occurrence time for audit logging
}

// Error implements the error interface for StorageError.
//
// Returns the internal detailed error message for logging and debugging purposes.
func (e *StorageError) Error() string {
	return e.Message
}

// UserExists represents the result of user existence checks for duplicate prevention.
//
// Security features:
// - Prevents timing attacks through consistent response structure
// - Enables duplicate detection without exposing user enumeration vulnerabilities
// - Uses email hash comparison for privacy-preserving uniqueness validation
// - Audit logging support for registration attempt monitoring
//
// Used by storage layer for email hash and SSH key uniqueness validation.
type UserExists struct {
	EmailHashExists bool `json:"email_hash_exists"` // Email hash already registered indicator
	SSHKeyExists    bool `json:"ssh_key_exists"`    // SSH public key already in use indicator
}

// LoginRequest defines user authentication data structure for future implementation.
//
// Security features:
// - Email-based account lookup for user identification
// - Password field for Argon2id verification against stored hash
// - Structured format for consistent authentication processing
//
// Reserved for future login functionality implementation.
// type LoginRequest struct {
// 	Email    string `json:"email"`    // User email for account lookup
//	Password string `json:"password"` // Password for Argon2id verification
// }
