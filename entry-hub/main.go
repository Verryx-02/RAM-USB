/*
Entry-Hub HTTPS server for R.A.M.-U.S.B. distributed backup system.

Implements secure REST API gateway with TLS encryption for clients and mTLS
client capabilities for distributed service communication. Serves as the
public-facing entry point in the zero-trust inter-service architecture
where all service-to-service communication uses mutual TLS authentication.

TO-DO in main: IPER-DANGEROUS SECURITY ISSUE:
*/
package main

import (
	"fmt"
	"https_server/config"
	"https_server/handlers"
	"log"
	"net/http"
)

// main initializes and starts the Entry-Hub HTTPS server with TLS encryption.
//
// Security features:
// - TLS 1.2+ encryption for client communications
// - Certificate-based server authentication for external clients
// - mTLS client configuration for zero-trust service communication
// - Secure route configuration with comprehensive input validation
//
// Part of distributed mTLS architecture: Entry-Hub - Security-Switch - Database-Vault - Storage-Service
// Starts HTTPS server on port 8443 with error handling.
func main() {
	// DISTRIBUTED SERVICE CONFIGURATION
	// Load mTLS parameters for secure inter-service communication
	cfg := config.GetConfig()

	// ZERO-TRUST ARCHITECTURE LOGGING
	// Confirm mTLS client setup for distributed service mesh
	fmt.Printf("Security-Switch IP: %s\n", cfg.SecuritySwitchIP)
	fmt.Println("mTLS certificates configured for distributed service communication")

	// ROUTE CONFIGURATION
	// Setup REST API endpoints with secure handlers
	http.HandleFunc("/api/register", handlers.RegisterHandler)
	http.HandleFunc("/api/health", handlers.HealthHandler)

	// SERVICE INFORMATION DISPLAY
	// Provide endpoint documentation and usage examples
	fmt.Println("Available endpoints:")
	fmt.Println("\tPOST /api/register (User registration)")
	fmt.Println("\tGET  /api/health (Check server status)")
	fmt.Println("Use the command below to register a new user:")
	fmt.Println("\tcurl https://IP TAILSCALE DEL CONTAINER:8443/api/register --insecure --header \"Content-Type: application/json\" --request \"POST\" --data '{\"email\":\"your.email@example.com\",\"password\":\"password123\",\"ssh_public_key\":\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... your-ssh-key\"}'")
	fmt.Println("To stop the server press Ctrl+C")

	// HTTPS SERVER STARTUP
	// Start TLS-encrypted server on all interfaces with certificate authentication
	// Listen on 0.0.0.0:8443
	// Uses default HTTP multiplexer with registered route handlers
	//
	// TO-DO: Implement triple-layer security (Defense-in-Depth)
	// TO-DO STEP 1: Change bind from "0.0.0.0:8443" to "127.0.0.1:8443" (localhost only)
	// TO-DO STEP 2: Setup Tailscale serve: `tailscale serve https / http://localhost:8443`
	// TO-DO STEP 3: Add firewall rules to block non-Tailscale traffic as backup
	log.Fatal(http.ListenAndServeTLS("0.0.0.0:8443", "../certificates/entry-hub/server.crt", "../certificates/entry-hub/server.key", nil))
}
