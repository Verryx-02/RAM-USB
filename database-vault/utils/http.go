/*
HTTP request validation utilities for Database-Vault endpoint protection.

Provides method enforcement and request validation to prevent CSRF attacks
and unauthorized HTTP method usage. Ensures consistent security policies
across all Database-Vault mTLS API endpoints with standardized error
responses for method violations and security policy enforcement in the
final storage layer of the distributed authentication system.
*/
package utils

import (
	"net/http"
)

// EnforcePOST restricts endpoint access to POST requests only for security compliance.
//
// Security features:
// - REST API semantic correctness for resource creation and credential storage
// - Consistent method enforcement across all Database-Vault endpoints
// - Reject non-POST requests to prevent CSRF and method confusion attacks
// - Audit logging for unauthorized method access attempts on storage endpoints
//
// Returns true if request method is POST, false with HTTP 405 error response otherwise.
func EnforcePOST(w http.ResponseWriter, r *http.Request) bool {
	// METHOD VALIDATION
	// Reject non-POST requests to prevent CSRF and method confusion attacks
	if r.Method != http.MethodPost {
		LogAndSendError(w, http.StatusMethodNotAllowed,
			"invalid method: "+r.Method+"; only POST is allowed",
			"Method not allowed. Use POST.")
		return false
	}
	return true
}
