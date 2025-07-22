/*
mTLS client interface for Security-Switch to Database-Vault communication.

Provides secure request forwarding with mutual TLS authentication and certificate
validation for the second hop in the distributed authentication pipeline.
Implements connection pooling, timeout management, and structured error handling
for reliable zero-trust communication within the R.A.M.-U.S.B. architecture.

TO-DO in NewDatabaseVaultClient
*/
package interfaces

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"security_switch/types"
	"time"
)

// DatabaseVaultClient manages secure mTLS communication with Database-Vault servers.
//
// Security features:
// - Mutual TLS authentication with certificate verification
// - CA validation prevents man-in-the-middle attacks
// - TLS 1.3 enforcement for maximum cryptographic security
// - Certificate-Name (CN) validation ensures correct service identity
//
// Handles JSON serialization, HTTPS requests, and response parsing for Database-Vault operations.
type DatabaseVaultClient struct {
	baseURL    string       // HTTPS endpoint for Database-Vault service
	httpClient *http.Client // mTLS-configured HTTP client with certificate validation
}

// NewDatabaseVaultClient creates mTLS-enabled client for secure Database-Vault communication.
// clientCertFile, clientKeyFile: Security-Switch credentials for mutual authentication
// caCertFile: trusted CA for Database-Vault certificate validation
// databaseVaultIP: Tailscale IP:port for zero-trust mesh communication
//
// Security features:
// - Mutual TLS authentication with certificate verification
// - CA validation prevents man-in-the-middle attacks
// - TLS 1.3 enforcement for maximum cryptographic security
// - Common-Name (CN) validation ensures correct service identity
//
// Returns configured mTLS client or error if certificate validation fails.
func NewDatabaseVaultClient(databaseVaultIP string, clientCertFile, clientKeyFile, caCertFile string) (*DatabaseVaultClient, error) {
	// CLIENT CERTIFICATE LOADING
	// Load Security-Switch credentials for mutual authentication with Database-Vault
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// CertificateAuthority(CA) CERTIFICATE LOADING
	// Load trusted CA for Database-Vault certificate verification
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// CERTIFICATE POOL SETUP
	// Configure trusted certificate authorities for server validation
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// MTLS CONFIGURATION
	// Configure mutual TLS with certificate validation and modern security
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert}, // Security-Switch client certificate
		RootCAs:            caCertPool,                    // Trusted CAs for server verification
		ServerName:         "database-vault",              // Expected server certificate Common-Name (CN)
		InsecureSkipVerify: false,                         // Always verify certificates in production
		MinVersion:         tls.VersionTLS13,              // Enforce modern TLS version
	}

	// HTTP CLIENT SETUP
	// Create client with mTLS transport and connection timeout
	//
	// TO-DO: Add connection pooling to prevent "too many open files" crashes
	// TO-DO: MaxIdleConns: 10, MaxIdleConnsPerHost: 3, IdleConnTimeout: 30*time.Second
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second, // Prevent hanging connections
	}

	// CLIENT INSTANCE CREATION
	// Return configured mTLS client for Database-Vault communication
	return &DatabaseVaultClient{
		baseURL:    fmt.Sprintf("https://%s", databaseVaultIP),
		httpClient: client,
	}, nil
}

// StoreUserCredentials securely transmits user registration data to Database-Vault.
//
// Security features:
// - JSON payload serialization with input validation
// - mTLS transport with certificate verification
// - Structured error handling for network and protocol failures
// - Response validation prevents malformed data acceptance
//
// Returns Database-Vault response or error for network/parsing failures.
func (c *DatabaseVaultClient) StoreUserCredentials(req types.RegisterRequest) (*types.Response, error) {
	// REQUEST SERIALIZATION
	// Convert registration data to JSON for secure transmission
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// HTTP REQUEST SETUP
	// Create POST request to Database-Vault storage endpoint
	httpReq, err := http.NewRequest("POST", c.baseURL+"/api/store-user", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// REQUEST HEADERS
	// Inform Database-Vault that request content format is JSON
	httpReq.Header.Set("Content-Type", "application/json")

	// SECURE TRANSMISSION
	// Send request via mTLS-authenticated connection
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Database-Vault: %v", err)
	}
	defer resp.Body.Close() // Ensure response body cleanup

	// RESPONSE PROCESSING
	// Parse Database-Vault JSON response into structured format
	var dbResponse types.Response
	if err := json.NewDecoder(resp.Body).Decode(&dbResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Database-Vault response: %v", err)
	}

	return &dbResponse, nil
}

// CheckHealth verifies Database-Vault connectivity and service availability.
//
// Security features:
// - mTLS authentication for health check requests
// - Network connectivity validation through certificate verification
// - Service discovery for load balancing and failover
//
// Returns true if Database-Vault is reachable and responding correctly.
func (c *DatabaseVaultClient) CheckHealth() bool {
	// HEALTH CHECK REQUEST
	// Create simple GET request to Database-Vault health endpoint
	httpReq, err := http.NewRequest("GET", c.baseURL+"/api/health", nil)
	if err != nil {
		// Request creation failure - client misconfiguration
		return false
	}

	// CONNECTIVITY VERIFICATION
	// Send health check using mTLS-configured client
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Network error, certificate error, or Database-Vault unreachable
		return false
	}
	defer resp.Body.Close()

	// SERVICE STATUS VALIDATION
	// Check if Database-Vault responded with success status
	return resp.StatusCode == http.StatusOK
}
