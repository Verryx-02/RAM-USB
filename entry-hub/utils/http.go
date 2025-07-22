/*
HTTP request validation utilities for secure API endpoint protection.

Provides method enforcement and request validation to limitate CSRF(Cross-Site Request Forgery) attacks
and unauthorized HTTP method usage. Ensures consistent security policies
across all Entry-Hub REST API endpoints.
*/
package utils

import (
	"net/http"
)

// EnforcePOST restricts endpoint access to POST requests only.
//
// Design features:
// - REST API semantic correctness (POST for resource creation)
// - Prevents accidental GET-based registration attempts
// - Consistent method enforcement across all endpoints
//
// Returns true if request method is POST, false with error response otherwise.
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
