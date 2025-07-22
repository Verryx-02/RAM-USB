/*
mTLS middleware for Database-Vault request validation and authentication.

Implements certificate-based client authentication to ensure only authorized
Security-Switch instances can communicate with Database-Vault endpoints. Provides
comprehensive certificate validation including TLS connection verification,
client certificate presence, and organizational authorization checks within
the zero-trust inter-service architecture for secure credential storage operations.
*/
package middleware

import (
	"database-vault/utils"
	"fmt"
	"log"
	"net/http"
)

// VerifyMTLS creates middleware function for mTLS client certificate validation.
//
// Security features:
// - TLS connection state verification prevents non-encrypted requests
// - Client certificate presence validation ensures mutual authentication
// - Organizational authorization restricts access to SecuritySwitch services only
// - Comprehensive logging provides audit trail for security monitoring
//
// Returns wrapped handler function with mTLS authentication or error response for unauthorized requests.
func VerifyMTLS(next http.HandlerFunc) http.HandlerFunc {
	// MIDDLEWARE WRAPPER FUNCTION
	// Returns anonymous function that performs mTLS verification before calling next handler
	return func(w http.ResponseWriter, r *http.Request) {
		// JSON RESPONSE SETUP
		// Ensure consistent content type for error responses
		w.Header().Set("Content-Type", "application/json")

		// TLS CONNECTION VERIFICATION
		// Ensure request uses encrypted TLS transport
		if r.TLS == nil {
			// Non-TLS connection attempt - security violation
			log.Printf("Request without TLS from %s", r.RemoteAddr)
			utils.SendErrorResponse(w, http.StatusUnauthorized, "TLS required")
			return
		}

		// CLIENT CERTIFICATE VERIFICATION
		// Verify that client presented certificate for mutual authentication
		if len(r.TLS.PeerCertificates) == 0 {
			// Missing client certificate - authentication failure
			log.Printf("Request without client certificate from %s", r.RemoteAddr)
			utils.SendErrorResponse(w, http.StatusUnauthorized, "Client certificate required")
			return
		}

		// CERTIFICATE EXTRACTION AND LOGGING
		// Extract client certificate for detailed validation
		clientCert := r.TLS.PeerCertificates[0]

		// AUTHENTICATION SUCCESS LOGGING
		// Log successful mTLS authentication with certificate details
		log.Printf("mTLS authenticated request from %s (CN=%s, O=%s)",
			r.RemoteAddr,
			clientCert.Subject.CommonName,
			clientCert.Subject.Organization)

		// ORGANIZATIONAL AUTHORIZATION
		// Verify client belongs to authorized SecuritySwitch organization
		if len(clientCert.Subject.Organization) == 0 || clientCert.Subject.Organization[0] != "SecuritySwitch" {
			// Unauthorized organization - access denied
			log.Printf("Unauthorized client organization: %v", clientCert.Subject.Organization)
			utils.SendErrorResponse(w, http.StatusForbidden, "Unauthorized client")
			return
		}

		// REQUEST AUDIT LOGGING
		// Log authenticated request details for security monitoring
		fmt.Printf("Authenticated request: \n\tfrom:\t%s \n\tmethod:\t%s\n\tpath:\t%s\n",
			r.RemoteAddr, r.Method, r.URL.Path)

		// AUTHORIZED REQUEST FORWARDING
		// Call original handler after successful mTLS verification
		next(w, r)
	}
}
