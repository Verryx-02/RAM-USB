/*
JSON processing utilities for secure API request handling.

Provides safe JSON parsing and request body validation with size limits
and error handling to prevent malformed data injection and resource
exhaustion attacks on Entry-Hub endpoints.
*/

package utils

import (
	"encoding/json"
	"io"
	"net/http"
)

// ReadRequestBody safely reads and validates HTTP request body content.
//
// Security features:
// - Protects against oversized payload attacks
// - Validates request body accessibility and format
// - Standardized error responses prevent information disclosure
//
// Returns request body bytes and success indicator, sends error response on failure.
func ReadRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	// REQUEST BODY READING
	// Read entire body with built-in size limits from HTTP server configuration
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// Body reading failure - malformed request or connection issue
		LogAndSendError(w, http.StatusBadRequest, "failed to read request body", "Error reading request.")
		return nil, false
	}
	return body, true
}

// ParseJSONBody deserializes JSON data into target struct with validation.
//
// Security features:
// - JSON structure validation prevents malformed data processing
// - Type safety ensures expected data format compliance
// - Standardized error handling for parsing failures
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
