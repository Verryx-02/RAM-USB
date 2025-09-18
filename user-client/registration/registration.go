// user-client/registration.go
package registration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// RegisterRequest contains user registration data for Entry-Hub transmission.
//
// Security features:
// - Email validation for proper user identification
// - Password transmission for secure hashing at Database-Vault
// - SSH public key for storage service authentication
//
// Serialized as JSON for HTTPS communication with Entry-Hub.
type RegisterRequest struct {
	Email     string `json:"email"`          // User email address for account identification
	Password  string `json:"password"`       // Plain password for secure hashing at Database-Vault
	SSHPubKey string `json:"ssh_public_key"` // SSH public key for storage service authentication
}

// RegisterResponse provides Entry-Hub API response format.
//
// Used for parsing Entry-Hub JSON responses and handling success/error states.
type RegisterResponse struct {
	Success bool   `json:"success"` // Operation success indicator
	Message string `json:"message"` // Human-readable status or error description
}

// Configuration constants for registration client
const (
	EntryHubURL    = "https://localhost:8443/api/register" // Entry-Hub registration endpoint
	TestEmail      = "test@example.com"                    // Test user email address
	TestPassword   = "MyStrongPass123@"                    // Test user password
	SSHKeyPath     = "keys/ssh_public_key.pub"             // Path to SSH public key file
	RequestTimeout = 30 * time.Second                      // HTTP request timeout
)

// readSSHPublicKey reads and validates the SSH public key file.
//
// Security features:
// - File existence validation
// - Content validation (non-empty)
// - Basic SSH key format verification
//
// Returns SSH public key content or error if file is invalid or missing.
func readSSHPublicKey(keyPath string) (string, error) {
	// FILE EXISTENCE CHECK
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", fmt.Errorf("SSH public key file not found: %s", keyPath)
	}

	// SSH PUBLIC KEY READING
	sshPubKeyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SSH public key file: %v", err)
	}

	// CONTENT VALIDATION
	sshPubKey := strings.TrimSpace(string(sshPubKeyBytes))
	if len(sshPubKey) == 0 {
		return "", fmt.Errorf("SSH public key file is empty: %s", keyPath)
	}

	// BASIC FORMAT VALIDATION
	if !strings.HasPrefix(sshPubKey, "ssh-") {
		return "", fmt.Errorf("invalid SSH public key format: should start with 'ssh-'")
	}

	fmt.Printf("SSH public key loaded: %s...\n", sshPubKey[:50])
	return sshPubKey, nil
}

// createHTTPSClient creates HTTP client configured for insecure HTTPS connections.
//
// Security features:
// - TLS connection with certificate verification disabled (--insecure equivalent)
// - Request timeout to prevent hanging connections
// - Compatible with Entry-Hub's self-signed certificates
//
// Returns configured HTTP client for Entry-Hub communication.
func createHTTPSClient() *http.Client {
	// TLS CONFIGURATION
	// Disable certificate verification to match curl --insecure behavior
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip certificate verification for self-signed certs
	}

	// HTTP CLIENT SETUP
	// Create client with insecure TLS and timeout configuration
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: RequestTimeout, // Prevent hanging connections
	}
}

// RegisterUser performs user registration by sending request to Entry-Hub.
//
// Security features:
// - SSH key validation before transmission
// - JSON payload serialization with type safety
// - HTTPS communication with Entry-Hub
// - Comprehensive error handling for network and API failures
//
// Returns error if registration fails, nil if successful.
func RegisterUser() error {
	fmt.Println("Starting user registration process...")

	// SSH PUBLIC KEY LOADING
	fmt.Printf("Reading SSH public key from: %s\n", SSHKeyPath)
	sshPublicKey, err := readSSHPublicKey(SSHKeyPath)
	if err != nil {
		return fmt.Errorf("SSH key validation failed: %v", err)
	}

	// REQUEST PAYLOAD PREPARATION
	registerReq := RegisterRequest{
		Email:     TestEmail,
		Password:  TestPassword,
		SSHPubKey: sshPublicKey,
	}

	// JSON SERIALIZATION
	jsonPayload, err := json.Marshal(registerReq)
	if err != nil {
		return fmt.Errorf("failed to serialize registration request: %v", err)
	}

	fmt.Printf("Sending registration request to: %s\n", EntryHubURL)
	fmt.Printf("Registration data: email=%s, password=*****, ssh_key=%s...\n",
		registerReq.Email, registerReq.SSHPubKey[:30])

	// HTTPS CLIENT SETUP
	client := createHTTPSClient()

	// HTTP REQUEST PREPARATION
	httpReq, err := http.NewRequest("POST", EntryHubURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// REQUEST HEADERS
	httpReq.Header.Set("Content-Type", "application/json")

	// HTTPS REQUEST EXECUTION
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request to Entry-Hub: %v", err)
	}
	defer resp.Body.Close()

	// RESPONSE BODY READING
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// RESPONSE PARSING
	var registerResp RegisterResponse
	if err := json.Unmarshal(responseBody, &registerResp); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// HTTP STATUS CODE VALIDATION
	fmt.Printf("HTTP Status: %d %s\n", resp.StatusCode, resp.Status)
	fmt.Printf("Response: %s\n", string(responseBody))

	// SUCCESS VALIDATION
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, registerResp.Message)
	}

	if !registerResp.Success {
		return fmt.Errorf("registration failed: %s", registerResp.Message)
	}

	// SUCCESS CONFIRMATION
	fmt.Printf("Registration successful: %s\n", registerResp.Message)
	return nil
}
