/*
Health check handler for Security-Switch mTLS gateway monitoring.

Provides lightweight status verification for load balancers, monitoring systems,
and service discovery within the zero-trust architecture. Enables automated
detection of Security-Switch availability without exposing sensitive mTLS
configuration or certificate information to monitoring systems.
*/
package handlers

import (
	"encoding/json"
	"net/http"
	"security_switch/types"
)

// HealthHandler provides Security-Switch status verification for monitoring systems.
//
// Security features:
// - mTLS middleware ensures only authenticated Entry-Hub clients can access
// - No sensitive mTLS configuration disclosure in response
// - Minimal resource usage
// - JSON response format ensures consistent monitoring integration
//
// Returns HTTP 200 with success status indicating Security-Switch operational state.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// JSON RESPONSE SETUP
	// Ensure consistent content type for monitoring tools
	w.Header().Set("Content-Type", "application/json")

	// STATUS RESPONSE
	// Simple success indicator for automated health monitoring
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: "Security-Switch operational!",
	})
}
