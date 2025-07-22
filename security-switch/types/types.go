/*
Type definitions for Security-Switch service data structures.

Contains struct definitions for API requests, responses, and data models used
for secure communication between Entry-Hub and Database-Vault through the
Security-Switch gateway. Ensures consistent data handling, JSON serialization,
and validation across the distributed mTLS architecture with standardized
error handling and success indication.

TO-DO in LoginRequest: not implemented
*/
package types

// RegisterRequest contains validated user registration data for Database-Vault transmission.
//
// Security features:
// - Email validation ensures proper user identification format
// - Password transmission for secure Argon2id hashing at Database-Vault layer
// - SSH public key validation for authenticated Storage-Service access
// - Defense-in-depth validation at Security-Switch before Database-Vault forwarding
//
// Serialized as JSON for mTLS communication with Database-Vault service.
type RegisterRequest struct {
	Email     string `json:"email"`          // User email address for account identification
	Password  string `json:"password"`       // Plain password for secure hashing at Database-Vault
	SSHPubKey string `json:"ssh_public_key"` // SSH public key for storage service authentication
}

// Response provides standardized API response format for distributed service communication.
//
// Security features:
// - Consistent error handling prevents information disclosure
// - Success indication for reliable client integration
// - Standardized format across all R.A.M.-U.S.B. services
//
// Used for Security-Switch responses to Entry-Hub and Database-Vault responses to Security-Switch.
type Response struct {
	Success bool   `json:"success"` // Operation success indicator for client validation
	Message string `json:"message"` // Human-readable status or error description
}

// HealthResponse provides comprehensive health check information for monitoring systems.
//
// Security features:
// - Service status indication without sensitive configuration disclosure
// - Dependencies status for distributed system monitoring
// - Consistent format for automated monitoring integration
//
// Extended response format for detailed service health verification and dependency tracking.
type HealthResponse struct {
	Success      bool              `json:"success"`                // Service availability indicator
	Message      string            `json:"message"`                // Human-readable status description
	Service      string            `json:"service"`                // Service name identifier
	Status       string            `json:"status"`                 // Detailed service status
	Dependencies map[string]string `json:"dependencies,omitempty"` // Dependent service status map
}

// LoginRequest defines user authentication data structure for future implementation.
//
// Security features:
// - Email-based account lookup for user identification
// - Password field for Argon2id verification at Database-Vault
// - Structured format for consistent authentication processing
//
// Reserved for future login functionality implementation.
// type LoginRequest struct {
// 	Email    string `json:"email"`    // User email for account lookup
//	Password string `json:"password"` // Password for Argon2id verification
// }
