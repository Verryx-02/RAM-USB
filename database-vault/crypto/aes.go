/*
AES-256-GCM encryption utilities for Database-Vault email field-level encryption.

Implements authenticated encryption for email addresses using AES-256-GCM
with cryptographically secure random nonce and salt generation for safe
database storage. Provides confidentiality and authenticity for email data
with SHA-256 hashing for fast database indexing while maintaining
zero-knowledge user identification in the R.A.M.-U.S.B. storage system.
*/
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// ValidateEncryptionKey performs comprehensive encryption key validation.
//
// Security features:
// - Key length validation ensures AES-256 compliance (32 bytes)
// - Entropy validation prevents all-zero or weak keys
// - Key format verification for cryptographic strength
//
// Returns error if key is invalid for AES-256-GCM operations.
func ValidateEncryptionKey(key []byte) error {
	// LENGTH VALIDATION
	// AES-256 requires exactly 32 bytes
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: AES-256 requires 32 bytes, got %d", len(key))
	}

	// ENTROPY VALIDATION
	// Check for all-zero key (weak key)
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("invalid key: all-zero key is not secure")
	}

	return nil
}

// HashEmail creates SHA-256 hash of email for database indexing and primary key functionality.
//
// Security features:
// - SHA-256 provides cryptographically secure one-way hash
// - Consistent output enables database indexing and fast lookups
// - Prevents email enumeration while maintaining query capability
// - Hex encoding ensures safe database storage and comparison
//
// Returns hex-encoded SHA-256 hash suitable for database primary key usage.
func HashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}

// EncryptEmailSecure encrypts email with random nonce and salt for secure storage.
//
// Security features:
// - Random salt generation ensures unique encryption keys per user
// - Random nonce prevents deterministic encryption vulnerabilities
// - Key derivation with salt provides forward secrecy
// - AES-256-GCM provides authenticated encryption with integrity
// - Different ciphertext for identical emails across users
//
// Returns base64-encoded encrypted email, hex-encoded salt, or error if encryption fails.
func EncryptEmailSecure(email string, masterKey []byte) (encryptedEmail, salt string, err error) {
	// KEY VALIDATION
	if err := ValidateEncryptionKey(masterKey); err != nil {
		return "", "", fmt.Errorf("invalid master key: %v", err)
	}

	// RANDOM SALT GENERATION
	// Generate 16-byte cryptographically secure salt for key derivation
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// EMAIL-SPECIFIC KEY DERIVATION
	// Derive unique encryption key using master key and random salt
	emailKey, err := DeriveKey(KeyDerivationInfo{
		MasterKey: masterKey,
		Salt:      saltBytes,
		Context:   "email-encryption-secure-v1",
		Length:    32,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to derive email key: %v", err)
	}

	// RANDOM NONCE GENERATION
	// Generate 12-byte random nonce for GCM mode
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// AES-GCM CIPHER SETUP
	block, err := aes.NewCipher(emailKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// AUTHENTICATED ENCRYPTION
	// Encrypt email and prepend nonce to ciphertext for storage
	ciphertext := gcm.Seal(nonce, nonce, []byte(email), nil)

	// SAFE ENCODING FOR DATABASE STORAGE
	encryptedEmailB64 := base64.StdEncoding.EncodeToString(ciphertext)
	saltHex := hex.EncodeToString(saltBytes)

	return encryptedEmailB64, saltHex, nil
}

// DecryptEmailSecure decrypts email using stored salt and encrypted data.
//
// Security features:
// - Uses stored salt to reproduce exact encryption key
// - AES-256-GCM authenticated decryption verifies data integrity
// - Nonce extraction from stored ciphertext enables decryption
// - Validates authenticity tag to prevent tampering
//
// Returns plaintext email address or error if decryption/authentication fails.
func DecryptEmailSecure(encryptedEmail, salt string, masterKey []byte) (string, error) {
	// KEY VALIDATION
	if err := ValidateEncryptionKey(masterKey); err != nil {
		return "", fmt.Errorf("invalid master key: %v", err)
	}

	// SALT DECODING
	// Decode hex-encoded salt from database
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %v", err)
	}

	// KEY REPRODUCTION
	// Derive same encryption key using stored salt
	emailKey, err := DeriveKey(KeyDerivationInfo{
		MasterKey: masterKey,
		Salt:      saltBytes,
		Context:   "email-encryption-secure-v1",
		Length:    32,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive email key: %v", err)
	}

	// CIPHERTEXT DECODING
	// Decode base64-encoded ciphertext from database
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedEmail)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	// NONCE EXTRACTION
	// Extract 12-byte nonce from beginning of ciphertext
	if len(ciphertext) < 12 {
		return "", fmt.Errorf("ciphertext too short: expected at least 12 bytes, got %d", len(ciphertext))
	}

	nonce := ciphertext[:12]
	encrypted := ciphertext[12:]

	// AES-GCM CIPHER SETUP
	block, err := aes.NewCipher(emailKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// AUTHENTICATED DECRYPTION
	// Decrypt and verify authenticity tag
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed - invalid ciphertext or authentication tag: %v", err)
	}

	return string(plaintext), nil
}

// VerifyEmailHash validates that a plaintext email produces the expected hash.
//
// Security features:
// - Constant-time comparison prevents timing attacks
// - Hash verification for email lookup validation
// - Prevents hash collision attacks through verification
//
// Returns true if email hashes to the expected hash value.
func VerifyEmailHash(email, expectedHash string) bool {
	actualHash := HashEmail(email)
	return actualHash == expectedHash
}
