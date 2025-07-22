/*
Main application entry point for Database-Vault secure storage server.

Configures mutual TLS authentication, sets up secure routes, and starts the
Database-Vault that acts as the final storage layer between Security-Switch and
encrypted credential persistence. Implements zero-trust inter-service communication
with certificate-based authentication, AES-256-GCM email encryption, and Argon2id
password hashing within the R.A.M.-U.S.B. distributed authentication architecture.

TO-DO: Restrict listening to specific Tailscale IPs (Security-Switch only)
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"database-vault/config"
	"database-vault/handlers"
	"database-vault/middleware"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// main initializes and starts the Database-Vault mTLS server.
//
// Security features:
// - Mutual TLS authentication for Security-Switch client verification
// - Certificate Authority validation prevents unauthorized certificates
// - TLS 1.3 enforcement for maximum cryptographic security
// - mTLS middleware ensures only authenticated clients reach storage endpoints
// - AES-256-GCM encryption key validation for email field-level encryption
//
// Starts secure storage server on port 8445 with comprehensive error handling.
func main() {
	// CONFIGURATION LOADING
	// Load mTLS parameters, database connection, and encryption key
	cfg := config.GetConfig()

	// CONFIGURATION VALIDATION
	// Ensure all critical configuration components are valid
	if err := cfg.ValidateConfig(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// SERVICE STARTUP LOGGING
	// Log configuration without sensitive encryption key or database credentials
	fmt.Printf("Database-Vault starting on port %s\n", cfg.ServerPort)
	fmt.Printf("Database connection configured: %s\n", maskDatabaseURL(cfg.DatabaseURL))
	fmt.Printf("AES-256-GCM encryption enabled (%d-byte key)\n", len(cfg.EncryptionKey))
	fmt.Println("mTLS authentication enabled")

	// CA CERTIFICATE LOADING
	// Load Certificate Authority for Security-Switch certificate validation
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		// CA certificate loading failure: critical security error
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	// CERTIFICATE POOL CREATION
	// Configure trusted certificate authorities for Security-Switch validation
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		// CA certificate parsing failure: invalid certificate format
		log.Fatal("Failed to parse CA certificate")
	}

	// SERVER CERTIFICATE LOADING
	// Load Database-Vault server credentials for Security-Switch authentication
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		// Server certificate loading failure: deployment configuration error
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	// MTLS CONFIGURATION
	// Configure mutual TLS with comprehensive security parameters
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},  // Server certificate for Security-Switch authentication
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mutual authentication requirement
		ClientCAs:    caCertPool,                     // Trusted CAs for Security-Switch certificate validation
		MinVersion:   tls.VersionTLS13,               // Enforce modern TLS version for security
	}

	// HTTP ROUTER SETUP
	// Configure request routing with mTLS middleware protection
	mux := http.NewServeMux()

	// ROUTE REGISTRATION WITH MTLS MIDDLEWARE
	// Apply certificate verification middleware to all Database-Vault endpoints
	mux.HandleFunc("/api/store-user", middleware.VerifyMTLS(handlers.StoreUserHandler))
	mux.HandleFunc("/api/health", middleware.VerifyMTLS(handlers.HealthHandler))

	// HTTPS SERVER CONFIGURATION
	// Create server with mTLS configuration and network binding
	server := &http.Server{
		Addr:      "0.0.0.0:" + cfg.ServerPort, // TO-DO: Restrict to Tailscale IPs only
		Handler:   mux,                         // Router with mTLS-protected endpoints
		TLSConfig: tlsConfig,                   // Mutual TLS authentication configuration
	}

	// SERVICE INFORMATION DISPLAY
	// Provide endpoint documentation and usage guidance
	fmt.Println("Available endpoints:")
	fmt.Println("\tPOST /api/store-user (Store user credentials from Security-Switch)")
	fmt.Println("\tGET  /api/health (Check Database-Vault and database status)")
	fmt.Println("Database-Vault ready to accept mTLS connections from Security-Switch")
	fmt.Println("To stop the server press Ctrl+C")

	// MTLS SERVER STARTUP
	// Start mutual TLS server with certificate-based authentication
	log.Fatal(server.ListenAndServeTLS("", "")) // Empty strings: certificates loaded in TLSConfig
}

// maskDatabaseURL sanitizes database connection string for logging.
//
// Prevents credential disclosure in log files.
// Example:
// Log without masking:  "postgres://user:password@localhost:5432/db"
// Log with masking: "postgres://***MASKED***@localhost:5432/db"
//
// Returns sanitized database URL suitable for logging purposes.
func maskDatabaseURL(dbURL string) string {
	// SIMPLE MASKING FOR DEVELOPMENT
	// TO-DO: Implement proper URL parsing for production

	// Handle empty or very short URLs
	if len(dbURL) <= 20 {
		return "***MASKED***"
	}

	// BASIC CREDENTIAL DETECTION
	// Look for typical patterns: postgres://user:pass@host:port/db
	if strings.Contains(dbURL, "://") && strings.Contains(dbURL, "@") {
		parts := strings.Split(dbURL, "://")
		if len(parts) == 2 {
			scheme := parts[0]
			remainder := parts[1]

			// Find the @ symbol that separates credentials from host
			atIndex := strings.Index(remainder, "@")
			if atIndex > 0 {
				// Extract everything after @ (host:port/database?params)
				hostAndDB := remainder[atIndex+1:]
				// Return scheme + masked credentials + host info
				return scheme + "://***:***@" + hostAndDB
			}
		}
	}

	// FALLBACK MASKING
	// If URL format is unexpected, use simple masking
	return dbURL[:10] + "***MASKED***" + dbURL[len(dbURL)-10:]
}
