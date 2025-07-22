/*
Type definitions for Entry-Hub API requests and responses.

Provides structured data models for JSON serialization in REST API communication
and mTLS message passing between distributed services. Ensures consistent data
handling and validation across the R.A.M.-U.S.B. architecture layers.

TO-DO in LoginRequest: Implement login functionality
*/

package types

// RegisterRequest contains user registration data for Security-Switch transmission.
//
// Security features:
// - Email validation ensures proper user identification
// - Password transmission for Argon2id hashing at Database-Vault
// - SSH public key for secure access to the Storage-Service
//
// Serialized as JSON for mTLS communication with Security-Switch.
type RegisterRequest struct {
	Email     string `json:"email"`          // User email address for account identification
	Password  string `json:"password"`       // Plain password for secure hashing at Database-Vault
	SSHPubKey string `json:"ssh_public_key"` // SSH public key for storage service authentication
}

// LoginRequest defines user authentication data structure.
//
// TO-DO: Implement login functionality with password verification
/*
type LoginRequest struct {
	Email    string `json:"email"`    // User email for account lookup
	Password string `json:"password"` // Password for Argon2id verification
}
*/

// Response provides standardized API response format for client communication.
//
// Used by:
// - Entry-Hub responses to client applications
// - Security-Switch responses to Entry-Hub
// - Database-Vault responses to Security-Switch
//
// Ensures consistent error handling and success indication across services.
type Response struct {
	Success bool   `json:"success"` // Operation success indicator
	Message string `json:"message"` // Human-readable status or error description
}
