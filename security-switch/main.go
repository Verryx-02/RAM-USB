/*
Main application entry point for Security-Switch mTLS gateway server.

Configures mutual TLS authentication, sets up secure routes, and starts the
Security-Switch that acts as security checkpoint between Entry-Hub and Database-Vault.
Implements zero-trust inter-service communication with certificate-based authentication
and comprehensive validation middleware within the R.A.M.-U.S.B. distributed architecture.

TO-DO: Restrict listening to specific Tailscale IPs (Entry-Hub, Database-Vault, Storage-Service, OPA)
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"security_switch/config"
	"security_switch/handlers"
	"security_switch/middleware"
)

// main initializes and starts the Security-Switch mTLS server.
//
// Security features:
// - Mutual TLS authentication for Entry-Hub client verification
// - Certificate Authority validation prevents unauthorized certificates
// - TLS 1.3 enforcement for maximum cryptographic security
// - mTLS middleware ensures only authenticated clients reach endpoints
//
// Starts secure gateway server on port 8444 with comprehensive error handling.
func main() {
	// CONFIGURATION LOADING
	// Load mTLS parameters and service endpoints for distributed communication
	cfg := config.GetConfig()

	// SERVICE STARTUP LOGGING
	// Log configuration without sensitive certificate data
	fmt.Printf("Security-Switch starting on port %s\n", cfg.ServerPort)
	fmt.Printf("Database-Vault endpoint: %s\n", cfg.DatabaseVaultIP)
	fmt.Println("mTLS authentication enabled")

	// CA CERTIFICATE LOADING
	// Load Certificate Authority for client certificate validation
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		// CA certificate loading failure - critical security error
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	// CERTIFICATE POOL CREATION
	// Configure trusted certificate authorities for client validation
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		// CA certificate parsing failure - invalid certificate format
		log.Fatal("Failed to parse CA certificate")
	}

	// SERVER CERTIFICATE LOADING
	// Load Security-Switch server credentials for client authentication
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		// Server certificate loading failure - deployment configuration error
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	// MTLS CONFIGURATION
	// Configure mutual TLS with comprehensive security parameters
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},  // Server certificate for client authentication
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mutual authentication requirement
		ClientCAs:    caCertPool,                     // Trusted CAs for client certificate validation
		MinVersion:   tls.VersionTLS13,               // Enforce modern TLS version for security
	}

	// HTTP ROUTER SETUP
	// Configure request routing with mTLS middleware protection
	mux := http.NewServeMux()

	// ROUTE REGISTRATION WITH MTLS MIDDLEWARE
	// Apply certificate verification middleware to all Security-Switch endpoints
	mux.HandleFunc("/api/register", middleware.VerifyMTLS(handlers.RegisterHandler))
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
	fmt.Println("\tPOST /api/register (Forward user registration to Database-Vault)")
	fmt.Println("\tGET  /api/health (Check Security-Switch status)")
	fmt.Println("Security-Switch ready to accept mTLS connections")
	fmt.Println("To stop the server press Ctrl+C")

	// MTLS SERVER STARTUP
	// Start mutual TLS server with certificate-based authentication
	log.Fatal(server.ListenAndServeTLS("", "")) // Empty strings - certificates loaded in TLSConfig
}
