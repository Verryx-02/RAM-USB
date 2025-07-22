/*
Health check endpoint for Entry-Hub REST API monitoring.

Provides lightweight status verification for load balancers, monitoring
systems, and service discovery. Enables automated detection of service
availability without exposing sensitive system information.
*/

package handlers

import (
	"encoding/json"
	"https_server/types"
	"net/http"
)

// HealthHandler provides service status verification for monitoring systems.
//
// Security features:
// - No sensitive information disclosure in response
// - Minimal resource usage
// - JSON response format ensures consistent monitoring integration
//
// Returns HTTP 200 with success status indicating Entry-Hub availability.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// JSON RESPONSE SETUP
	// Ensure consistent content type for monitoring tools
	w.Header().Set("Content-Type", "application/json")

	// STATUS RESPONSE
	// Simple success indicator for automated health monitoring
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: "HTTPS server working!",
	})
}
