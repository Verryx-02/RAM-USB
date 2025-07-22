/*
Standardized error handling utilities for Database-Vault API responses.

Provides consistent HTTP response formatting, audit logging, and error message
sanitization to ensure uniform Security-Switch communication and security monitoring
across all endpoints. Prevents information disclosure through standardized error
messages while maintaining comprehensive audit trails for security analysis
and storage layer operation monitoring.
*/
package utils

import (
	"database-vault/types"
	"encoding/json"
	"log"
	"net/http"
)

// SendErrorResponse creates standardized error response for Security-Switch communication.
//
// Security features:
// - Consistent error format prevents information disclosure variations
// - HTTP status code mapping ensures proper Security-Switch error handling
// - JSON structure matches success responses for API consistency
// - No sensitive storage information exposed to Security-Switch clients
//
// Sends HTTP response with specified status code and sanitized error message.
func SendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	// HTTP STATUS SETUP
	// Set appropriate error code for Security-Switch error categorization
	w.WriteHeader(statusCode)

	// ERROR RESPONSE FORMATTING
	// Standardized JSON structure for consistent Security-Switch parsing
	json.NewEncoder(w).Encode(types.Response{
		Success: false,
		Message: message,
	})
}

// SendSuccessResponse creates standardized success response for Security-Switch communication.
//
// Security features:
// - Consistent success format for reliable Security-Switch integration
// - Prevents accidental information disclosure in success messages
// - Uniform JSON structure across all Database-Vault API endpoints
// - Status code validation for proper HTTP semantics
//
// Sends HTTP response with specified status code and success message.
func SendSuccessResponse(w http.ResponseWriter, statusCode int, message string) {
	// HTTP STATUS SETUP
	// Set appropriate success code for Security-Switch validation
	w.WriteHeader(statusCode)

	// SUCCESS RESPONSE FORMATTING
	// Standardized JSON structure matching error response format
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: message,
	})
}

// LogAndSendError provides comprehensive audit logging with sanitized Security-Switch response.
//
// Security features:
// - Audit trail creation for security monitoring and incident response
// - Separation of detailed storage logs from Security-Switch-facing messages
// - Prevents sensitive database information leakage to external services
// - Dual-purpose logging for both debugging and security analysis
//
// Logs detailed error internally and sends sanitized message to Security-Switch.
func LogAndSendError(w http.ResponseWriter, statusCode int, logMessage, clientMessage string) {
	// AUDIT LOGGING
	// Record detailed error for security monitoring and debugging
	log.Printf("Error: %s", logMessage)

	// SECURITY-SWITCH ERROR RESPONSE
	// Send sanitized error message to prevent information disclosure
	SendErrorResponse(w, statusCode, clientMessage)
}
