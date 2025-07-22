package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Structure for the data to be sent in the POST request
type Data struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	SSHPubKey string `json:"ssh_public_key"`
}

// readSSHPublicKey reads and validates the SSH public key file
func readSSHPublicKey(sshPubKeyPath string) (string, error) {
	// Read the SSH public key file
	sshPubKeyBytes, err := os.ReadFile(sshPubKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SSH public key file: %v", err)
	}

	// Convert to string and trim whitespace
	sshPubKey := strings.TrimSpace(string(sshPubKeyBytes))

	// Basic validation - check if it looks like an SSH public key
	if !strings.HasPrefix(sshPubKey, "ssh-") {
		return "", fmt.Errorf("invalid SSH public key format: should start with 'ssh-'")
	}

	return sshPubKey, nil
}

// createMTLSClient creates an HTTP client configured for mutual TLS
func createMTLSClient(certPath, keyPath, caPath string) (*http.Client, error) {
	// Load client certificate and key for mTLS
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS client certificate and key: %v", err)
	}

	// Load CA certificate for server verification
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// Create CA certificate pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	// Configure TLS with mutual authentication
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "localhost", // Must match the server certificate CN/SAN
	}

	// Create HTTP client with mTLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	return client, nil
}

func main() {
	// Load environment variables from .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file. Make sure .env file exists and is accessible.")
	}

	// Load required environment variables
	serverInterfaceIp := os.Getenv("SERVER_INTERFACE_IP")
	tlsCertPath := os.Getenv("TLS_CERT_PATH")
	tlsKeyPath := os.Getenv("TLS_KEY_PATH")
	caCertPath := os.Getenv("CA_CERT_PATH")
	sshPubKeyPath := os.Getenv("SSH_PUBLIC_KEY_PATH")

	// Validate environment variables
	if serverInterfaceIp == "" {
		log.Fatal("SERVER_INTERFACE_IP environment variable not set.")
	}
	if tlsCertPath == "" {
		log.Fatal("TLS_CERT_PATH environment variable not set.")
	}
	if tlsKeyPath == "" {
		log.Fatal("TLS_KEY_PATH environment variable not set.")
	}
	if caCertPath == "" {
		log.Fatal("CA_CERT_PATH environment variable not set.")
	}
	if sshPubKeyPath == "" {
		log.Fatal("SSH_PUBLIC_KEY_PATH environment variable not set.")
	}

	// Read SSH public key
	sshPublicKey, err := readSSHPublicKey(sshPubKeyPath)
	if err != nil {
		log.Fatalf("Error reading SSH public key: %v", err)
	}

	fmt.Printf("Loaded SSH public key: %s\n", sshPublicKey[:50]+"...") // Show only first 50 chars for security

	// Create mTLS client
	client, err := createMTLSClient(tlsCertPath, tlsKeyPath, caCertPath)
	if err != nil {
		log.Fatalf("Error creating mTLS client: %v", err)
	}

	fmt.Println("mTLS client configured successfully")

	email := "pippo.balordo@gmail.com"
	password := "password123"

	// Register user with SSH public key using mTLS client
	registerUser(email, password, sshPublicKey, serverInterfaceIp, client)
}

func registerUser(email string, password string, sshPublicKey string, interfaceIp string, client *http.Client) {
	url := fmt.Sprintf("https://%s:8443/api/register", interfaceIp)

	// Prepare the Data struct
	data := Data{
		Email:     email,
		Password:  password,
		SSHPubKey: sshPublicKey,
	}

	requestBody, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	fmt.Println("Sending registration request...")
	// Don't print the full JSON body for security reasons in production
	// fmt.Println("Generated JSON Body:", string(requestBody))

	// Create HTTP POST request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Error creating POST request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Perform the request using the mTLS client
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making POST request to %s: %v", url, err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(resp.Body)
		log.Fatalf("Received unexpected HTTP status for POST: %d %s. Response: %s",
			resp.StatusCode, resp.Status, string(responseBody))
	}

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	fmt.Println("Response Body (POST):")
	fmt.Println(string(responseBody))

	fmt.Printf("Successfully attempted registration for user '%s'. Check server response for details.\n", email)
}
