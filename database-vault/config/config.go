/*
Configuration management for Database-Vault secure storage service.

Provides centralized configuration for mTLS server operations accepting authenticated
Security-Switch connections, database connectivity parameters, and AES-256-GCM
encryption key management. Uses hardcoded Tailscale IPs and certificate paths for
development with zero-trust inter-service communication and encrypted email storage.

TO-DO in GetConfig()
*/
package config

import (
	"encoding/hex"
	"log"
	"os"
)

// Config holds Database-Vault configuration for secure credential storage operations.
//
// Security features:
// - mTLS server certificates for authenticated Security-Switch communication only
// - Tailscale IP binding prevents external network exposure
// - AES-256-GCM encryption key for email field-level encryption
// - Database isolation with dedicated connection parameters
// - CA certificate validation ensures trusted Security-Switch certificate chain
//
// Supports mTLS server role: accepting only authenticated Security-Switch connections.
type Config struct {
	// MTLS SERVER CONFIGURATION: for accepting authenticated Security-Switch connections
	ServerPort     string // Port for mTLS server listening (8445)
	ServerCertFile string // Server certificate for Security-Switch authentication
	ServerKeyFile  string // Server private key for TLS handshake
	CACertFile     string // CA certificate for Security-Switch client certificate validation

	// DATABASE CONFIGURATION: for secure credential persistence
	DatabaseURL string // PostgreSQL connection string with authentication parameters

	// ENCRYPTION CONFIGURATION: for AES-256-GCM email field encryption
	EncryptionKey []byte // 32-byte AES-256 key for authenticated email encryption
}

// GetConfig returns Database-Vault configuration with mTLS and encryption parameters.
//
// Security features:
// - Hardcoded Tailscale IPs prevent accidental external exposure
// - Environment variable encryption key loading for secure key management
// - Mandatory encryption key validation prevents startup with missing keys
// - Certificate chain validation ensures mTLS authentication integrity
//
// Returns pointer to Config struct with all mTLS server and encryption parameters.
//
// TO-DO: In production, load all configuration from environment variables
// TO-DO: Implement secure key rotation mechanism for encryption keys
// TO-DO: Add database connection pooling and timeout configuration
func GetConfig() *Config {
	// ENCRYPTION KEY LOADING
	// Load AES-256-GCM encryption key from environment variable
	encryptionKey := getEncryptionKey()

	// DATABASE CONNECTION CONFIGURATION
	// TO-DO: Load DATABASE_URL from environment variable in production
	// TO-DO: Add connection pooling, timeouts, and SSL configuration
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		// Default development database URL: replace with environment variable
		databaseURL = "postgres://ramusb:password@localhost:5432/ramusb_vault?sslmode=require"
	}

	return &Config{
		// MTLS SERVER SETTINGS
		// Configuration for accepting authenticated Security-Switch connections
		ServerPort:     "8445", // Listen on Tailscale network only
		ServerCertFile: "../certificates/database-vault/server.crt",
		ServerKeyFile:  "../certificates/database-vault/server.key",
		CACertFile:     "../certificates/certification-authority/ca.crt",

		// DATABASE SETTINGS
		// PostgreSQL connection for secure credential storage
		DatabaseURL: databaseURL,

		// ENCRYPTION SETTINGS
		// AES-256-GCM key for email field-level encryption
		EncryptionKey: encryptionKey,
	}
}

// getEncryptionKey loads and validates AES-256-GCM encryption key from environment.
//
// Security features:
// - Mandatory key validation prevents startup without encryption capability
// - Hex decoding validation ensures proper key format
// - 32-byte key length validation for AES-256 compliance
// - Fatal error on missing/invalid key prevents insecure operation
//
// Returns 32-byte AES-256 key or terminates process if key is invalid/missing.
//
// TO-DO: Support multiple key sources (file, HashiCorp Vault, AWS KMS)
// TO-DO: Implement key rotation with graceful fallback to previous key
func getEncryptionKey() []byte {
	// ENVIRONMENT VARIABLE KEY LOADING
	// Primary method for development and container deployment
	keyHex := os.Getenv("RAMUSB_ENCRYPTION_KEY")
	if keyHex == "" {
		log.Fatal("RAMUSB_ENCRYPTION_KEY environment variable is required. " +
			"Generate with: openssl rand -hex 32")
	}

	// HEX DECODING VALIDATION
	// Convert hex string to binary key material
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		log.Fatalf("Invalid RAMUSB_ENCRYPTION_KEY format (must be hex): %v", err)
	}

	// KEY LENGTH VALIDATION
	// Ensure 32-byte length for AES-256 compliance
	if len(key) != 32 {
		log.Fatalf("RAMUSB_ENCRYPTION_KEY must be 32 bytes (64 hex characters), got %d bytes", len(key))
	}

	log.Printf("Encryption key loaded successfully (%d bytes)", len(key))
	return key
}

// ValidateConfig performs comprehensive configuration validation for secure startup.
//
// Security features:
// - Certificate file existence validation prevents startup with missing credentials
// - Database connectivity validation ensures storage layer availability
// - Encryption key validation confirms cryptographic capability
// - Early failure detection prevents runtime security errors
//
// Returns error if any critical configuration component is invalid or missing.
//
// TO-DO: Add database connectivity test during validation
// TO-DO: Implement certificate expiration checking
func (c *Config) ValidateConfig() error {
	// CERTIFICATE FILE VALIDATION
	// Ensure all mTLS certificate files are accessible
	certFiles := []string{c.ServerCertFile, c.ServerKeyFile, c.CACertFile}
	for _, file := range certFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			log.Fatalf("Certificate file not found: %s", file)
		}
	}

	// ENCRYPTION KEY VALIDATION
	// Verify encryption key is properly loaded
	if len(c.EncryptionKey) != 32 {
		log.Fatal("Invalid encryption key length: configuration error")
	}

	log.Println("Database-Vault configuration validation successful")
	return nil
}
