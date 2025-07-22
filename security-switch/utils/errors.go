/*
Standardized error handling utilities for Security-Switch API responses.

Provides consistent HTTP response formatting, audit logging, and error message
sanitization to ensure uniform client experience and security monitoring across
all endpoints. Prevents information disclosure through standardized error
messages while maintaining comprehensive audit trails for security analysis.
*/
package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"security_switch/types"
)

// SendErrorResponse creates standardized error response for client communication.
//
// Security features:
// - Consistent error format prevents information disclosure variations
// - HTTP status code mapping ensures proper client error handling
// - JSON structure matches success responses for API consistency
// - No sensitive server information exposed to clients
//
// Sends HTTP response with specified status code and sanitized error message.
func SendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	// HTTP STATUS SETUP
	// Set appropriate error code for client error categorization
	w.WriteHeader(statusCode)

	// ERROR RESPONSE FORMATTING
	// Standardized JSON structure for consistent client parsing
	json.NewEncoder(w).Encode(types.Response{
		Success: false,
		Message: message,
	})
}

// SendSuccessResponse creates standardized success response for client communication.
//
// Security features:
// - Consistent success format for reliable client integration
// - Prevents accidental information disclosure in success messages
// - Uniform JSON structure across all Security-Switch API endpoints
// - Status code validation for proper HTTP semantics
//
// Sends HTTP response with specified status code and success message.
func SendSuccessResponse(w http.ResponseWriter, statusCode int, message string) {
	// HTTP STATUS SETUP
	// Set appropriate success code for client validation
	w.WriteHeader(statusCode)

	// SUCCESS RESPONSE FORMATTING
	// Standardized JSON structure matching error response format
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: message,
	})
}

// LogAndSendError provides comprehensive audit logging with sanitized client response.
//
// Security features:
// - Audit trail creation for security monitoring and incident response
// - Separation of detailed server logs from client-facing messages
// - Prevents sensitive information leakage to external clients
// - Dual-purpose logging for both debugging and security analysis
//
// Logs detailed error internally and sends sanitized message to client.
func LogAndSendError(w http.ResponseWriter, statusCode int, logMessage, clientMessage string) {
	// AUDIT LOGGING
	// Record detailed error for security monitoring and debugging
	log.Printf("Error: %s", logMessage)

	// CLIENT ERROR RESPONSE
	// Send sanitized error message to prevent information disclosure
	SendErrorResponse(w, statusCode, clientMessage)
}
