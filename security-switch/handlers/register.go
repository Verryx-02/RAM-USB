/*
Registration request handler for Security-Switch mTLS gateway service.

Implements the second layer of the R.A.M.-U.S.B. distributed authentication system
with defense-in-depth validation. Receives mTLS-authenticated registration requests
from Entry-Hub instances, performs comprehensive security validation, and securely
forwards validated requests to Database-Vault using mutual TLS authentication.
Acts as security checkpoint preventing invalid data from reaching storage layer.

TO-DO in RegisterHandler
*/
package handlers

import (
	"fmt"
	"log"
	"net/http"
	"security_switch/config"
	"security_switch/interfaces"
	"security_switch/types"
	"security_switch/utils"
	"strings"
)

// RegisterHandler processes user registration requests with defense-in-depth validation.
//
// Security features:
// - mTLS authentication ensures only authorized Entry-Hub instances can access
// - Defense-in-depth input validation (re-validates all user data)
// - Secure mTLS forwarding to Database-Vault with certificate verification
// - Comprehensive error categorization prevents information disclosure
//
// Returns HTTP 201 on successful registration, 4xx on validation errors, 5xx on service errors.
//
// TO-DO: Implement rate limiting to prevent abuse from compromised Entry-Hub instances

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// TO-DO: Add rate limiting check here despite mTLS authentication
	// HTTP METHOD ENFORCEMENT
	// Enforce REST API semantics
	if !utils.EnforcePOST(w, r) {
		return // Sends HTTP 405 Method Not Allowed and logs violation
	}

	// REQUEST BODY PARSING
	// Read and validate HTTP request body for JSON processing
	body, ok := utils.ReadRequestBody(w, r)
	if !ok {
		return // Sends HTTP 400 Bad Request if body reading fails
	}

	// JSON DESERIALIZATION
	// Convert raw JSON bytes into structured RegisterRequest object
	var req types.RegisterRequest
	if !utils.ParseJSONBody(body, &req, w) {
		return // Sends HTTP 400 Bad Request if JSON parsing fails
	}

	// REQUIRED FIELDS VALIDATION (DEFENSE-IN-DEPTH)
	// Ensure essential fields are present despite Entry-Hub validation
	if req.Email == "" || req.Password == "" {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Email and password are required.")
		return
	}

	// EMAIL FORMAT VALIDATION (DEFENSE-IN-DEPTH)
	// Validate email format using RFC 5322 compliant regular expression
	if !utils.IsValidEmail(req.Email) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// EMAIL SECURITY VALIDATION (DEFENSE-IN-DEPTH)
	// Prevent email header injection attacks via multiple @ symbols
	if strings.Count(req.Email, "@") != 1 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// PASSWORD LENGTH VALIDATION (DEFENSE-IN-DEPTH)
	// Enforce minimum password length of 8 characters
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters.")
		return
	}

	// WEAK PASSWORD DETECTION (DEFENSE-IN-DEPTH)
	// Check against database of commonly used weak passwords
	if utils.IsWeakPassword(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password is too common, please choose a stronger password.")
		return
	}

	// PASSWORD COMPLEXITY VALIDATION (DEFENSE-IN-DEPTH)
	// Ensure password contains at least 3 out of 4 character categories
	if !utils.HasPasswordComplexity(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters.")
		return
	}

	// SSH PUBLIC KEY FORMAT VALIDATION (DEFENSE-IN-DEPTH)
	// Comprehensive validation including algorithm, encoding, and structure
	if !utils.IsValidSSHKey(req.SSHPubKey) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// SSH KEY PREFIX VALIDATION (DEFENSE-IN-DEPTH)
	// Ensure SSH key starts with recognized algorithm prefix
	if !strings.HasPrefix(req.SSHPubKey, "ssh-") {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// DATABASE-VAULT CLIENT INITIALIZATION
	// Create and configure mTLS client for secure Database-Vault communication
	cfg := config.GetConfig()
	dbClient, err := interfaces.NewDatabaseVaultClient(
		cfg.DatabaseVaultIP,
		cfg.ClientCertFile,
		cfg.ClientKeyFile,
		cfg.CACertFile,
	)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to initialize Database-Vault client: %v", err)
		log.Printf("Error: %s", errorMsg)

		// MTLS CONFIGURATION ERRORS
		// Categorize error type for appropriate client response
		if strings.Contains(err.Error(), "certificate") {
			// Certificate configuration error - deployment issue
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate configuration error. Please contact administrator.")
		} else if strings.Contains(err.Error(), "file") {
			// Certificate files missing - file system issue
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate files not found. Please contact administrator.")
		} else {
			// Generic client initialization failure - system issue
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Database-Vault client initialization failed. Please contact administrator.")
		}
		return
	}

	// SECURE REQUEST FORWARDING TO DATABASE-VAULT
	// Log forwarding attempt for audit purposes
	log.Printf("Forwarding registration request for user: %s", req.Email)

	// Forward validated registration request using mTLS authentication
	dbResponse, err := dbClient.StoreUserCredentials(req)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to store user credentials for %s: %v", req.Email, err)
		log.Printf("Error: %s", errorMsg)

		// NETWORK ERROR CATEGORIZATION
		// Provide specific guidance based on failure type
		if strings.Contains(err.Error(), "connection refused") {
			// Service unavailable - temporary outage
			utils.SendErrorResponse(w, http.StatusServiceUnavailable,
				"Database-Vault service is unavailable. Please try again later.")
		} else if strings.Contains(err.Error(), "timeout") {
			// Service overloaded - retry recommended
			utils.SendErrorResponse(w, http.StatusGatewayTimeout,
				"Database-Vault service timeout. Please try again later.")
		} else {
			// Generic network error - service issue
			utils.SendErrorResponse(w, http.StatusBadGateway,
				"Unable to store user credentials. Please try again later.")
		}
		return
	}

	// DATABASE-VAULT RESPONSE VALIDATION
	// Check if Database-Vault successfully processed registration request
	if !dbResponse.Success {
		log.Printf("Database-Vault rejected registration for %s: %s", req.Email, dbResponse.Message)
		// Pass through specific error message while preventing information disclosure
		utils.SendErrorResponse(w, http.StatusBadRequest, dbResponse.Message)
		return
	}

	// SUCCESS RESPONSE
	// Log successful registration and send confirmation to Entry-Hub
	log.Printf("User successfully registered: %s", req.Email)
	utils.SendSuccessResponse(w, http.StatusCreated, "User successfully registered!")
}
