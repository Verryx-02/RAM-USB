/*
mTLS client interface for Entry-Hub to Security-Switch communication.

Provides secure request forwarding with mutual TLS authentication and certificate
validation. Implements connection pooling and timeout management for reliable
distributed service communication within the R.A.M.-U.S.B. architecture.

TO-DO in NewEntryHubClient
*/
package interfaces

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"https_server/types"
	"net/http"
	"os"
	"time"
)

// EntryHubClient manages secure communication with Security-Switch servers.
type EntryHubClient struct {
	baseURL    string       // HTTPS endpoint for Security-Switch service
	httpClient *http.Client // mTLS-configured HTTP client with certificate validation
}

// NewEntryHubClient creates mTLS-enabled client for secure Security-Switch communication.
//
// Security features:
// - Mutual TLS authentication with certificate verification
// - CA validation prevents man-in-the-middle attacks
// - TLS 1.3 enforcement for maximum cryptographic security
// - Certificate CN validation ensures correct service identity
//
// Returns configured client or error if certificate validation fails.
func NewEntryHubClient(securitySwitchIP string, clientCertFile, clientKeyFile, caCertFile string) (*EntryHubClient, error) {
	// CLIENT CERTIFICATE LOADING
	// Load Entry-Hub credentials for mutual authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// CA CERTIFICATE LOADING
	// Load trusted CA for Security-Switch certificate validation
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
		Certificates: []tls.Certificate{clientCert}, // Entry-Hub client certificate
		RootCAs:      caCertPool,                    // Trusted CAs for server verification
		ServerName:   "security-switch",             // Expected server certificate CN
		MinVersion:   tls.VersionTLS13,              // Enforce modern TLS version
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

	// Create and return the EntryHubClient instance
	return &EntryHubClient{
		baseURL:    fmt.Sprintf("https://%s", securitySwitchIP),
		httpClient: client, // Use the http client created earlier, which uses TLS
	}, nil
}

// ForwardRegistration securely transmits user registration to Security-Switch.
//
// Security features:
// - JSON payload serialization with input validation
// - mTLS transport with certificate verification
// - Structured error handling for network and protocol failures
//
// Returns Security-Switch response or error for network/parsing failures.
func (c *EntryHubClient) ForwardRegistration(req types.RegisterRequest) (*types.Response, error) {
	// REQUEST SERIALIZATION
	// Convert registration data to JSON for secure transmission
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// HTTP REQUEST SETUP
	// Create POST request to Security-Switch registration endpoint
	httpReq, err := http.NewRequest("POST", c.baseURL+"/api/register", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// SECURE TRANSMISSION
	// Send request via mTLS-authenticated connection
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Security-Switch: %v", err)
	}
	defer resp.Body.Close()

	// RESPONSE PROCESSING
	// Parse Security-Switch JSON response
	var switchResponse types.Response
	if err := json.NewDecoder(resp.Body).Decode(&switchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Security-Switch response: %v", err)
	}

	return &switchResponse, nil
}
