/*
Standardized error handling utilities for Entry-Hub API responses.

Provides consistent HTTP response formatting and audit logging to ensure
uniform client experience and security monitoring across all endpoints.
Prevents information disclosure through standardized error messages.
*/
package utils

import (
	"encoding/json"
	"https_server/types"
	"log"
	"net/http"
)

// SendErrorResponse creates standardized error response for client communication.
//
// Security features:
// - Consistent error format prevents information disclosure
// - HTTP status code mapping for proper client error handling
// - JSON structure matches success responses for API consistency
//
// Sends HTTP response with specified status code and error message.
func SendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	// HTTP STATUS SETUP
	// Set appropriate error code for client handling
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
// - Uniform JSON structure across all API endpoints
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

// LogAndSendError provides audit logging with standardized error response.
//
// Security features:
// - Audit trail creation for security monitoring
// - Separation of detailed logs from client-facing messages
// - Prevents sensitive information leakage to clients
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
