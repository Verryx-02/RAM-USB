/*
Key management utilities for Database-Vault secure cryptographic operations.

Provides centralized key derivation, loading, validation, and lifecycle management
for AES-256-GCM encryption keys used in email field-level encryption. Implements
secure key handling practices including HKDF derivation, multiple source loading,
entropy validation, and memory cleanup to support zero-knowledge storage
principles in the R.A.M.-U.S.B. distributed authentication system.

TO-DO: Implement key rotation mechanism with graceful fallback
*/
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// KeyDerivationInfo contains parameters for HKDF key derivation operations.
//
// Security features:
// - HKDF-SHA256 for cryptographically secure key derivation
// - Context separation prevents key reuse across different operations
// - Salt inclusion for additional entropy and domain separation
// - Configurable output length for different cryptographic algorithms
//
// Used for deriving operation-specific keys from master encryption key.
type KeyDerivationInfo struct {
	MasterKey []byte // Source key material for derivation
	Salt      []byte // Optional salt for additional entropy
	Context   string // Operation context for key separation
	Length    int    // Desired output key length in bytes
}

// DeriveKey generates operation-specific key from master key using HKDF-SHA256.
//
// Security features:
// - HKDF-SHA256 provides cryptographically secure key derivation
// - Context-based separation prevents key reuse across operations
// - Configurable salt for additional entropy and security
// - Deterministic output enables consistent key regeneration
//
// Returns derived key of specified length or error if derivation fails.
func DeriveKey(info KeyDerivationInfo) ([]byte, error) {
	// INPUT VALIDATION
	// Ensure master key and output length are valid
	if len(info.MasterKey) == 0 {
		return nil, fmt.Errorf("master key cannot be empty")
	}
	if info.Length <= 0 || info.Length > 255 {
		return nil, fmt.Errorf("invalid key length: must be between 1 and 255 bytes")
	}

	// HKDF INITIALIZATION
	// Create HKDF instance with SHA256 hash function
	hkdfReader := hkdf.New(sha256.New, info.MasterKey, info.Salt, []byte(info.Context))

	// KEY DERIVATION
	// Generate derived key of specified length
	derivedKey := make([]byte, info.Length)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %v", err)
	}

	return derivedKey, nil
}

// LoadEncryptionKeyFromSources attempts to load encryption key from multiple sources.
//
// Security features:
// - Prioritized source loading (environment -> file -> generated)
// - Comprehensive validation for each loaded key
// - Secure error handling without key material disclosure
// - Fallback generation for development environments only
//
// Returns 32-byte AES-256 key or error if no valid key source available.
//
// TO-DO: Add HashiCorp Vault and AWS KMS integration
// TO-DO: Implement key rotation with multiple key support
func LoadEncryptionKeyFromSources() ([]byte, error) {
	// PRIMARY SOURCE: Environment Variable
	// Preferred method for containerized deployments
	if key, err := loadKeyFromEnvironment(); err == nil {
		return key, nil
	}

	// SECONDARY SOURCE: File System
	// Production deployment with protected key files
	if key, err := loadKeyFromFile("/etc/ramusb/keys/database.key"); err == nil {
		return key, nil
	}

	// TERTIARY SOURCE: Development Fallback
	// Only for development environments - not production safe
	if isDevelopmentEnvironment() {
		return generateDevelopmentKey()
	}

	return nil, fmt.Errorf("no valid encryption key source found - set RAMUSB_ENCRYPTION_KEY or provide key file")
}

// loadKeyFromEnvironment loads and validates encryption key from environment variable.
//
// Security features:
// - Hex decoding validation ensures proper key format
// - Length validation for AES-256 compliance
// - Entropy validation prevents weak or predictable keys
//
// Returns validated 32-byte key or error if environment key is invalid.
func loadKeyFromEnvironment() ([]byte, error) {
	// ENVIRONMENT VARIABLE RETRIEVAL
	keyHex := os.Getenv("RAMUSB_ENCRYPTION_KEY")
	if keyHex == "" {
		return nil, fmt.Errorf("RAMUSB_ENCRYPTION_KEY environment variable not set")
	}

	// HEX DECODING
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex format in RAMUSB_ENCRYPTION_KEY: %v", err)
	}

	// KEY VALIDATION
	if err := ValidateKeyStrength(key); err != nil {
		return nil, fmt.Errorf("environment key validation failed: %v", err)
	}

	return key, nil
}

// loadKeyFromFile loads and validates encryption key from protected file system location.
//
// Security features:
// - File permission validation (should be 600 or 400)
// - Binary key loading for maximum entropy
// - Length and strength validation
// - Secure error handling without file content disclosure
//
// Returns validated key or error if file key is invalid or inaccessible.
func loadKeyFromFile(keyPath string) ([]byte, error) {
	// FILE EXISTENCE CHECK
	fileInfo, err := os.Stat(keyPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s", keyPath)
	}
	if err != nil {
		return nil, fmt.Errorf("key file access error: %v", err)
	}

	// FILE PERMISSION VALIDATION
	// Ensure restrictive permissions for security
	mode := fileInfo.Mode()
	if mode&0077 != 0 {
		return nil, fmt.Errorf("key file has insecure permissions: %v (should be 600 or 400)", mode)
	}

	// KEY FILE READING
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	// BINARY VS HEX DETECTION
	var key []byte
	if len(keyData) == 64 {
		// Assume hex-encoded key
		key, err = hex.DecodeString(string(keyData))
		if err != nil {
			return nil, fmt.Errorf("key file contains invalid hex data: %v", err)
		}
	} else if len(keyData) == 32 {
		// Assume binary key
		key = keyData
	} else {
		return nil, fmt.Errorf("key file has invalid length: expected 32 or 64 bytes, got %d", len(keyData))
	}

	// KEY VALIDATION
	if err := ValidateKeyStrength(key); err != nil {
		return nil, fmt.Errorf("file key validation failed: %v", err)
	}

	return key, nil
}

// ValidateKeyStrength performs comprehensive cryptographic key strength validation.
//
// Security features:
// - Length validation for AES-256 compliance (32 bytes)
// - Entropy analysis prevents weak or predictable keys
// - Pattern detection identifies common weak key patterns
// - Cryptographic randomness assessment
//
// Returns error if key fails any strength validation criteria.
func ValidateKeyStrength(key []byte) error {
	// LENGTH VALIDATION
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: AES-256 requires 32 bytes, got %d", len(key))
	}

	// ALL-ZERO KEY DETECTION
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("key contains all zeros - not cryptographically secure")
	}

	// ALL-ONES KEY DETECTION
	allOnes := true
	for _, b := range key {
		if b != 0xFF {
			allOnes = false
			break
		}
	}
	if allOnes {
		return fmt.Errorf("key contains all ones - not cryptographically secure")
	}

	// REPEATING PATTERN DETECTION
	if hasRepeatingPattern(key) {
		return fmt.Errorf("key contains repeating patterns - insufficient entropy")
	}

	// BASIC ENTROPY CHECK
	if !hasMinimumEntropy(key) {
		return fmt.Errorf("key has insufficient entropy - not cryptographically secure")
	}

	return nil
}

// hasRepeatingPattern detects simple repeating patterns in key material.
//
// Security features:
// - Detects obvious repeating byte sequences
// - Identifies keys generated by weak random number generators
// - Prevents usage of patterned or structured key material
//
// Returns true if key contains detectable repeating patterns.
func hasRepeatingPattern(key []byte) bool {
	// CHECK FOR 4-BYTE REPEATING PATTERNS
	for patternLen := 1; patternLen <= 4; patternLen++ {
		if len(key)%patternLen == 0 {
			pattern := key[:patternLen]
			isRepeating := true
			for i := patternLen; i < len(key); i += patternLen {
				for j := 0; j < patternLen; j++ {
					if key[i+j] != pattern[j] {
						isRepeating = false
						break
					}
				}
				if !isRepeating {
					break
				}
			}
			if isRepeating {
				return true
			}
		}
	}
	return false
}

// hasMinimumEntropy performs basic entropy assessment on key material.
//
// Security features:
// - Byte frequency analysis for randomness assessment
// - Distribution uniformity checking
// - Identifies obviously weak or structured keys
//
// Returns true if key appears to have sufficient entropy for cryptographic use.
func hasMinimumEntropy(key []byte) bool {
	// BYTE FREQUENCY ANALYSIS
	frequency := make(map[byte]int)
	for _, b := range key {
		frequency[b]++
	}

	// MINIMUM UNIQUE BYTES CHECK
	// Require at least 16 different byte values in 32-byte key
	if len(frequency) < 16 {
		return false
	}

	// MAXIMUM FREQUENCY CHECK
	// No single byte value should appear more than 8 times in 32-byte key
	for _, count := range frequency {
		if count > 8 {
			return false
		}
	}

	return true
}

// isDevelopmentEnvironment detects if running in development mode.
//
// Security features:
// - Environment-based detection for appropriate key generation
// - Prevents production deployment with generated keys
// - Safe fallback only in explicitly marked development environments
//
// Returns true if development environment indicators are present.
func isDevelopmentEnvironment() bool {
	// DEVELOPMENT ENVIRONMENT DETECTION
	devEnv := os.Getenv("RAMUSB_ENV")
	return devEnv == "development" || devEnv == "dev" || devEnv == "local"
}

// generateDevelopmentKey creates a random key for development environments only.
//
// Security features:
// - Cryptographically secure random generation
// - Clear warning about development-only usage
// - Proper entropy for testing and development
//
// Returns 32-byte random key for development use only.
//
// WARNING: This function should NEVER be used in production environments.
func generateDevelopmentKey() ([]byte, error) {
	fmt.Println("WARNING: Generating random encryption key for development use only!")
	fmt.Println("WARNING: This key will NOT persist across restarts!")
	fmt.Println("WARNING: Set RAMUSB_ENCRYPTION_KEY for production deployment!")

	// RANDOM KEY GENERATION
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate development key: %v", err)
	}

	fmt.Printf("Generated development key: %x\n", key)
	return key, nil
}

// SecureKeyCleanup overwrites key material in memory for secure cleanup.
//
// Security features:
// - Memory overwriting prevents key recovery from memory dumps
// - Multiple overwrite passes for enhanced security
// - Secure cleanup of sensitive cryptographic material
//
// Should be called when key material is no longer needed.
func SecureKeyCleanup(key []byte) {
	// MEMORY OVERWRITING
	// Multiple passes with different patterns for secure cleanup
	for i := range key {
		key[i] = 0x00
	}
	for i := range key {
		key[i] = 0xFF
	}
	for i := range key {
		key[i] = 0x00
	}
}
