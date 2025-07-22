/*
Configuration management for Security-Switch mTLS gateway service.

Provides centralized configuration for dual-role mTLS operations: server configuration
for accepting authenticated Entry-Hub connections and client configuration for secure
Database-Vault communication. Uses hardcoded Tailscale IPs and certificate paths for
development with zero-trust inter-service communication.

// TO-DO in GetConfig()
*/
package config

// Config holds Security-Switch configuration for bidirectional mTLS communication.
//
// Security features:
// - Separate server/client certificate pairs for role-based authentication
// - Tailscale IP addressing prevents external network exposure
// - CA certificate validation ensures trusted certificate chain
//
// Supports dual mTLS roles: server (accepting Entry-Hub) and client (connecting to Database-Vault).
type Config struct {
	// SERVER CONFIGURATION - for accepting mTLS connections from Entry-Hub
	ServerPort     string // Port for mTLS server listening (8444)
	ServerCertFile string // Server certificate for Entry-Hub authentication
	ServerKeyFile  string // Server private key for TLS handshake
	CACertFile     string // CA certificate for client certificate validation

	// CLIENT CONFIGURATION - for outgoing mTLS connections to Database-Vault
	DatabaseVaultIP string // Tailscale IP:port for secure mesh communication
	ClientCertFile  string // Client certificate for Database-Vault authentication
	ClientKeyFile   string // Client private key for mutual TLS handshake
}

// GetConfig returns Security-Switch configuration with mTLS parameters for zero-trust architecture.
//
// Security features:
// - Hardcoded Tailscale IPs prevent accidental external exposure
// - Separate certificate pairs for server/client roles enhance security isolation
// - CA validation ensures certificate chain integrity across distributed services
//
// Returns pointer to Config struct with all mTLS connection parameters.
//
// TO-DO: In production, load configuration from environment variables
// TO-DO: Load DATABASE_VAULT_IP from environment variable instead of hardcoded value

func GetConfig() *Config {
	return &Config{
		// MTLS SERVER SETTINGS
		// Configuration for accepting authenticated Entry-Hub connections
		ServerPort:     "8444", // Listen on Tailscale network only
		ServerCertFile: "../certificates/security-switch/server.crt",
		ServerKeyFile:  "../certificates/security-switch/server.key",
		CACertFile:     "../certificates/certification-authority/ca.crt",

		// MTLS CLIENT SETTINGS
		// Configuration for secure Database-Vault communication
		// TO-DO: Replace hardcoded IP with os.Getenv("DATABASE_VAULT_IP")
		DatabaseVaultIP: "100.93.246.69:8445", // TO-DO: Replace with actual Database-Vault Tailscale IP
		ClientCertFile:  "../certificates/security-switch/client.crt",
		ClientKeyFile:   "../certificates/security-switch/client.key",
	}
}
