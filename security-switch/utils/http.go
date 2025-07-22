/*
HTTP request validation utilities for Security-Switch endpoint protection.

Provides method enforcement and request validation to prevent CSRF attacks
and unauthorized HTTP method usage. Ensures consistent security policies
across all Security-Switch mTLS API endpoints with standardized error
responses for method violations and security policy enforcement.
*/
package utils

import (
	"net/http"
)

// EnforcePOST restricts endpoint access to POST requests only for security compliance.
//
// Security features:
// - REST API semantic correctness for resource creation and data submission
// - Consistent method enforcement across all Security-Switch endpoints
// - Reject non-POST requests
// - Audit logging for unauthorized method access attempts
//
// Returns true if request method is POST, false with HTTP 405 error response otherwise.
func EnforcePOST(w http.ResponseWriter, r *http.Request) bool {
	// METHOD VALIDATION
	// Reject non-POST requests
	if r.Method != http.MethodPost {
		LogAndSendError(w, http.StatusMethodNotAllowed,
			"invalid method: "+r.Method+"; only POST is allowed",
			"Method not allowed. Use POST.")
		return false
	}
	return true
}
