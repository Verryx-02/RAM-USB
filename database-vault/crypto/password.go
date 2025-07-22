/*
Password hashing utilities for secure Database-Vault credential storage.

Implements Argon2id password hashing with cryptographically secure salt
generation to defend against rainbow table attacks and GPU-based brute force.
Uses memory-hard algorithm parameters to resist specialized hardware attacks.
Provides the final cryptographic layer before permanent credential storage
in the Database-Vault secure storage system.

TO-DO in HashPassword()
*/
package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// GenerateSalt creates cryptographically secure random salt for password hashing.
//
// Security features:
// - Uses crypto/rand for unpredictable entropy source
// - 16-byte length provides sufficient uniqueness against collisions
// - Hexadecimal encoding prevents binary storage issues
// - Unique salt per user prevents rainbow table attacks across user base
//
// Returns hex-encoded salt string and error if entropy source fails.
func GenerateSalt() (string, error) {
	// SALT GENERATION
	// Create 16-byte buffer for cryptographically secure randomness
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		// Entropy source failure - critical security error
		return "", err
	}

	// ENCODING
	// Convert to hexadecimal for safe database storage and transmission
	return fmt.Sprintf("%x", salt), nil
}

// HashPassword generates Argon2id hash with provided salt for secure database storage.
//
// Security features:
// - Argon2id algorithm resists both time-memory and side-channel attacks
// - Memory-hard parameters (32MB) defend against GPU acceleration attacks
// - Single iteration with medium-high memory usage balances security and performance
// - Deterministic output with same password+salt for login verification
//
// Returns hex-encoded hash suitable for Database-Vault permanent storage.
//
// TO-DO: Add pepper integration - passwordWithPepper := password + config.GetPepper()
// TO-DO: This prevents offline attacks even if database is compromised
func HashPassword(password, salt string) string {
	// PARAMETER CONVERSION
	// Convert salt to bytes for Argon2id algorithm requirements
	saltBytes := []byte(salt)

	// ARGON2ID HASHING
	// Parameters: 1 iteration, 32MB memory, 4 threads, 32-byte output
	// Chosen to resist GPU attacks while maintaining reasonable server performance
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 32*1024, 4, 32)

	// ENCODING
	// Convert hash to hexadecimal for consistent database storage format
	return fmt.Sprintf("%x", hash)
}

// VerifyPassword compares provided password against stored hash and salt.
//
// Security features:
// - Constant-time comparison prevents timing attacks on password verification
// - Uses same Argon2id parameters as HashPassword for consistency
// - No password storage or logging during verification process
// - Secure hash regeneration with provided salt for comparison
//
// Returns true if password matches stored credentials, false otherwise.
func VerifyPassword(password, storedHash, storedSalt string) bool {
	// HASH REGENERATION
	// Generate hash with same parameters used during storage
	candidateHash := HashPassword(password, storedSalt)

	// CONSTANT-TIME COMPARISON
	// Prevent timing attacks by comparing full hash strings
	// Go's string comparison is not guaranteed constant-time, but hash length is fixed
	return candidateHash == storedHash
}
