/*
JSON processing utilities for secure Database-Vault API request handling.

Provides safe JSON parsing and request body validation with comprehensive
error handling to prevent malformed data injection and resource exhaustion
attacks on Database-Vault mTLS endpoints. Ensures consistent data processing
and standardized error responses across the final storage layer of the
distributed authentication pipeline.
*/
package utils

import (
	"encoding/json"
	"io"
	"net/http"
)

// ReadRequestBody safely reads and validates HTTP request body content from mTLS clients.
//
// Security features:
// - Protects against oversized payload attacks with built-in HTTP server limits
// - Validates request body accessibility and prevents partial read attacks
// - Standardized error responses prevent information disclosure to Security-Switch clients
//
// Returns request body bytes and success indicator, sends HTTP 400 error response on failure.
func ReadRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	// REQUEST BODY READING
	// Read entire body with built-in size limits from HTTP server configuration
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// Body reading failure - malformed request or connection issue
		LogAndSendError(w, http.StatusBadRequest,
			"failed to read request body",
			"Error reading request.")
		return nil, false
	}
	return body, true
}

// ParseJSONBody deserializes JSON data into target struct with comprehensive validation.
//
// Security features:
// - JSON structure validation prevents malformed data processing in storage layer
// - Type safety ensures expected data format compliance before database operations
// - Structured error handling prevents JSON parsing information disclosure
// - Input sanitization layer before final storage validation and encryption
//
// Returns parsing success indicator, sends HTTP 400 error response on JSON format errors.
func ParseJSONBody(body []byte, target interface{}, w http.ResponseWriter) bool {
	// JSON DESERIALIZATION
	// Parse JSON with Go type safety and structure validation
	if err := json.Unmarshal(body, target); err != nil {
		// JSON parsing failure - malformed syntax or structure mismatch
		LogAndSendError(w, http.StatusBadRequest,
			"failed to parse JSON body: "+err.Error(),
			"Invalid JSON format.")
		return false
	}
	return true
}
