/*
Configuration management for Entry-Hub HTTPS service.

Provides centralized configuration including Security-Switch connection
parameters and mTLS certificate paths. Uses hardcoded values for development.

TO-DO in GetConfig()
TO-DO: Add GetPepper() function for password pepper from environment variables
*/
package config

// Config holds Entry-Hub application configuration parameters.
type Config struct {
	SecuritySwitchIP string // Tailscale IP address for secure mesh communication
	ClientCertFile   string // mTLS client certificate path for Security-Switch authentication
	ClientKeyFile    string // mTLS private key path for secure communication
	CACertFile       string // Certificate Authority for validating Security-Switch certificates
}

// GetConfig returns Entry-Hub configuration with security connection parameters.
//
// Security features:
// - Hardcoded Tailscale IPs prevent external network exposure
// - mTLS certificate paths ensure mutual authentication
// - CA validation prevents man-in-the-middle attacks
//
// Returns pointer to Config struct with all required connection parameters.
//
// TO-DO: In production, load this from environment variables or config file.
// TO-DO: Replace with actual Security-Switch IP and port. This is the macbook Tailscale IP
// TO-DO: Load pepper from PASSWORD_PEPPER environment variable with fatal error if missing
// TO-DO: Load SECURITY_SWITCH_IP from environment variable instead of hardcoded value
func GetConfig() *Config {
	return &Config{
		// SECURITY-SWITCH CONNECTION
		// Use Tailscale private network to prevent external access
		// TO-DO: Replace hardcoded IP with os.Getenv("SECURITY_SWITCH_IP")
		SecuritySwitchIP: "100.93.246.69:8444",

		// MTLS CERTIFICATE CONFIGURATION
		// Client credentials for mutual TLS authentication with Security-Switch
		ClientCertFile: "../certificates/entry-hub/client.crt",
		ClientKeyFile:  "../certificates/entry-hub/client.key",
		CACertFile:     "../certificates/certification-authority/ca.crt",
	}
}
