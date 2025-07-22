/*
User registration handler for Entry-Hub REST API service.

Implements first layer of distributed authentication system with comprehensive
input validation and secure forwarding to Security-Switch via mTLS. Follows
defense-in-depth principles to prevent malformed data from reaching downstream services.

The registration flow follows this sequence:
1. Client -> Entry-Hub (HTTPS with server certificates)
2. Entry-Hub -> Security-Switch (mTLS with mutual certificate verification)
3. Security-Switch -> Database-Vault (mTLS with mutual certificate verification)

TO-DO in RegisterHandler
*/
package handlers

import (
	"fmt"
	"https_server/config"
	"https_server/interfaces"
	"https_server/types"
	"https_server/utils"
	"log"
	"net/http"
	"strings"
)

// RegisterHandler processes user registration requests with multi-layer validation.
//
// Security features:
// - Comprehensive input sanitization (email, password, SSH key)
// - Password strength enforcement and weak password detection
// - mTLS forwarding to Security-Switch with certificate verification
// - Defense-in-depth validation prevents downstream contamination
//
// Returns HTTP 201 on successful registration, 4xx on validation errors, 5xx on service errors.
//
// TO-DO: Implement rate limiting to prevent brute force attacks (e.g., 5 attempts per IP per minute)
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// TO-DO: Add rate limiting check here before processing request
	// REQUEST LOGGING
	// Audit trail for security monitoring and debugging
	fmt.Printf("Request: \n\tfrom:\t%s \n\tmethod:\t%s\n", r.RemoteAddr, r.Method)

	// JSON RESPONSE SETUP
	// Ensure consistent API response format
	w.Header().Set("Content-Type", "application/json")

	// HTTP METHOD ENFORCEMENT
	// Enforce REST API semantics
	if !utils.EnforcePOST(w, r) {
		return
	}

	// REQUEST BODY PARSING
	// Read and validate JSON payload structure
	body, ok := utils.ReadRequestBody(w, r)
	if !ok {
		return
	}

	// JSON DESERIALIZATION
	// Convert raw JSON to structured registration data
	var req types.RegisterRequest
	if !utils.ParseJSONBody(body, &req, w) {
		return
	}

	// REQUIRED FIELDS VALIDATION
	// Ensure essential registration data is present
	if req.Email == "" || req.Password == "" {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Email and password are required.")
		return
	}

	// EMAIL FORMAT VALIDATION
	// Prevent malformed emails and injection attacks
	if !utils.IsValidEmail(req.Email) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// EMAIL SECURITY VALIDATION
	// Detect header injection attempts via multiple @ symbols
	if strings.Count(req.Email, "@") != 1 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// PASSWORD LENGTH VALIDATION
	// Enforce minimum security threshold
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters.")
		return
	}

	// WEAK PASSWORD DETECTION
	// Prevent dictionary and credential stuffing attacks
	if utils.IsWeakPassword(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password is too common, please choose a stronger password.")
		return
	}

	// PASSWORD COMPLEXITY VALIDATION
	// Enforce character diversity for resistance to brute force
	if !utils.HasPasswordComplexity(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters.")
		return
	}

	// SSH KEY FORMAT VALIDATION
	// Verify algorithm, encoding, and internal structure
	if !utils.IsValidSSHKey(req.SSHPubKey) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// SSH KEY PREFIX VALIDATION
	// Detect corrupted or manually modified keys
	if !strings.HasPrefix(req.SSHPubKey, "ssh-") {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// SECURITY-SWITCH CLIENT SETUP
	// Configure mTLS client for secure service communication
	config := config.GetConfig()
	securityClient, err := interfaces.NewEntryHubClient(
		config.SecuritySwitchIP,
		config.ClientCertFile,
		config.ClientKeyFile,
		config.CACertFile,
	)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to initialize Security-Switch client: %v", err)
		log.Printf("Error: %s", errorMsg)

		// MTLS CONFIGURATION ERRORS
		// Distinguish between certificate and network issues
		if strings.Contains(err.Error(), "certificate") {
			// Certificate validation failure - configuration issue
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate configuration error. Please contact administrator.")
		} else if strings.Contains(err.Error(), "file") {
			// Certificate files missing - deployment issue
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate files not found. Please contact administrator.")
		} else {
			// Generic client initialization failure - system issue
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Security-Switch client initialization failed. Please contact administrator.")
		}
		return
	}

	// SECURE REQUEST FORWARDING
	// Audit registration attempt and forward to Security-Switch
	log.Printf("Attempting to forward registration request for user: %s", req.Email)

	switchResponse, err := securityClient.ForwardRegistration(req)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to contact Security-Switch for %s: %v", req.Email, err)
		log.Printf("Error: %s", errorMsg)

		// NETWORK ERROR CATEGORIZATION
		// Provide specific guidance based on failure type
		if strings.Contains(err.Error(), "connection refused") {
			// Service unavailable - temporary outage
			utils.SendErrorResponse(w, http.StatusServiceUnavailable,
				"Security-Switch service is unavailable. Please try again later.")
		} else if strings.Contains(err.Error(), "timeout") {
			// Service overloaded - retry recommended
			utils.SendErrorResponse(w, http.StatusGatewayTimeout,
				"Security-Switch service timeout. Please try again later.")
		} else if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls") {
			// TLS/certificate error - configuration issue
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Security certificate validation failed. Please contact administrator.")
		} else {
			// Generic network error - service issue
			utils.SendErrorResponse(w, http.StatusBadGateway,
				"Unable to reach Security-Switch service. Please try again later.")
		}
		return
	}

	// RESPONSE VALIDATION
	// Verify Security-Switch successfully processed registration
	if !switchResponse.Success {
		log.Printf("Security-Switch rejected registration for %s: %s", req.Email, switchResponse.Message)
		utils.SendErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("Registration failed: %s", switchResponse.Message))
		return
	}

	// SUCCESS RESPONSE
	// Complete Entry-Hub registration flow with audit logging
	log.Printf("User successfully registered via Security-Switch: %s", req.Email)
	utils.SendSuccessResponse(w, http.StatusCreated, "User successfully registered!")
}
