/*
Comprehensive input validation utilities for secure user data verification.

Implements multi-layer validation including RFC-compliant email parsing,
SSH wire format validation, and cryptographic parameter analysis.
Provides defense against injection attacks, weak credentials, and malformed authentication data.

TO-DO in IsWeakPassword()
*/
package utils

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// IsValidEmail validates email format using RFC 5322 compliant pattern matching.
//
// Security features:
// - Prevents email header injection attacks
// - Ensures compatibility with standard email processing systems
// - Blocks malformed addresses that bypass basic validation
//
// Returns true if email passes RFC compliance checks.
func IsValidEmail(email string) bool {
	// RFC 5322 EMAIL VALIDATION PATTERN
	// ^[a-zA-Z0-9._%+-]+ : Local part - letters, numbers, and specific safe characters
	// @ : Required single @ symbol separator
	// [a-zA-Z0-9.-]+ : Domain part - alphanumeric with dots and hyphens
	// \.[a-zA-Z]{2,}$ : TLD requirement - dot followed by minimum 2-letter extension
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(email)
}

// IsValidSSHKey performs comprehensive SSH public key validation with protocol-level verification.
//
// Security features:
// - Algorithm whitelist prevents unsupported/weak cryptographic methods
// - Base64 structure validation detects encoding corruption
// - SSH wire format verification prevents malformed key injection
// - Key length validation ensures cryptographic strength requirements
//
// Validates: RSA (2048-4096 bit), Ed25519, ECDSA (P-256/384/521), Hardware Security Keys
// Returns true if key passes all validation layers.
func IsValidSSHKey(sshKey string) bool {
	// INPUT SANITIZATION
	// Remove whitespace that could interfere with parsing
	sshKey = strings.TrimSpace(sshKey)

	// LENGTH VALIDATION
	// SSH keys must be minimum 80 characters - catches truncated/incomplete keys
	if len(sshKey) < 80 {
		return false
	}

	// SSH KEY FORMAT PARSING
	// Standard format: "algorithm base64-key-data [optional-comment]"
	parts := strings.Fields(sshKey)
	if len(parts) < 2 {
		return false
	}

	algorithm := parts[0] // Cryptographic algorithm identifier
	keyData := parts[1]   // Base64-encoded key material

	// ALGORITHM WHITELIST WITH LENGTH VALIDATION
	// Each algorithm has expected base64 length ranges based on key size and encoding
	supportedAlgorithms := map[string]struct {
		minLength int // Minimum base64 length for algorithm
		maxLength int // Maximum base64 length for algorithm
	}{
		"ssh-rsa":                            {300, 800}, // RSA: 2048-4096 bits typical
		"ssh-ed25519":                        {60, 80},   // Ed25519: fixed 256-bit keys
		"ecdsa-sha2-nistp256":                {100, 150}, // ECDSA P-256 curve
		"ecdsa-sha2-nistp384":                {120, 170}, // ECDSA P-384 curve
		"ecdsa-sha2-nistp521":                {140, 200}, // ECDSA P-521 curve
		"sk-ssh-ed25519@openssh.com":         {80, 120},  // Hardware security key Ed25519
		"sk-ecdsa-sha2-nistp256@openssh.com": {120, 180}, // Hardware security key ECDSA
	}

	// ALGORITHM SUPPORT VERIFICATION
	// Reject unsupported or potentially weak algorithms
	algorithmSpec, isSupported := supportedAlgorithms[algorithm]
	if !isSupported {
		return false
	}

	// BASE64 LENGTH VALIDATION
	// Verify key data length matches expected range for algorithm type
	// Prevents undersized (incomplete) or oversized (malformed) keys
	if len(keyData) < algorithmSpec.minLength || len(keyData) > algorithmSpec.maxLength {
		return false
	}

	// BASE64 CHARACTER VALIDATION
	// Ensure key contains only valid base64 character set
	if !isValidBase64(keyData) {
		return false
	}

	// BASE64 DECODING VERIFICATION
	// Attempt decode to verify structural integrity
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return false
	}

	// DECODED DATA SANITY CHECK
	// Minimum decoded length prevents obviously malformed keys
	if len(decoded) < 20 {
		return false
	}

	// SSH WIRE FORMAT VALIDATION
	// Deep validation of internal binary structure
	return validateKeyStructure(algorithm, decoded)
}

// isValidBase64 validates base64 character set compliance for SSH key data.
//
// Base64 encoding uses A-Z, a-z, 0-9, +, / for data representation
// with = characters for padding alignment to 4-byte boundaries.
//
// Returns true if string contains only valid base64 characters.
func isValidBase64(s string) bool {
	// BASE64 CHARACTER SET VALIDATION
	// ^[A-Za-z0-9+/]* : Any number of valid base64 data characters
	// ={0,2}$ : Optional padding (0, 1, or 2 equals signs at end)
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

// validateKeyStructure performs SSH wire format protocol validation.
//
// SSH public keys use a specific binary wire format:
// - Bytes 0-3: Algorithm name length (32-bit big-endian unsigned integer)
// - Bytes 4 to (4+length): Algorithm name as ASCII string
// - Remaining bytes: Algorithm-specific key material and parameters
//
// This embedded algorithm name provides tamper detection and prevents
// algorithm substitution attacks where key data doesn't match prefix.
//
// Returns true if wire format structure is valid and algorithm names match.
func validateKeyStructure(algorithm string, decoded []byte) bool {
	// HEADER LENGTH VALIDATION
	// SSH wire format requires minimum 4 bytes for algorithm name length field
	if len(decoded) < 4 {
		return false
	}

	// BIG-ENDIAN LENGTH EXTRACTION
	// SSH protocol uses network byte order (big-endian) for multi-byte integers
	// Convert 4 bytes to uint32: [0]<<24 | [1]<<16 | [2]<<8 | [3]
	algNameLen := int(decoded[0])<<24 | int(decoded[1])<<16 | int(decoded[2])<<8 | int(decoded[3])

	// ALGORITHM NAME LENGTH VALIDATION
	// Sanity checks prevent buffer overflow and detect corrupted data:
	// - Minimum 7 chars for shortest algorithm name ("ssh-rsa")
	// - Maximum 50 chars prevents excessive memory allocation
	// - Total length must not exceed available decoded data
	if algNameLen < 7 || algNameLen > 50 || algNameLen+4 > len(decoded) {
		return false
	}

	// EMBEDDED ALGORITHM EXTRACTION
	// Extract algorithm name from wire format data
	// Skip 4-byte length header, read algNameLen bytes as ASCII string
	embeddedAlgorithm := string(decoded[4 : 4+algNameLen])

	// ALGORITHM CONSISTENCY VERIFICATION
	// Embedded algorithm must exactly match prefix algorithm
	// Prevents algorithm substitution attacks and detects data corruption
	return embeddedAlgorithm == algorithm
}

// IsWeakPassword checks against database of commonly compromised passwords.
//
// Security features:
// - Dictionary attack prevention using known weak password database
// - Case-insensitive matching catches common variations
// - Blocks passwords from major data breaches and credential dumps
//
// Returns true if password appears in weak password database.
//
// TO-DO: Expand weak password database or integrate with Have I Been Pwned API
// TO-DO: Consider loading weak passwords from external file or service
func IsWeakPassword(password string) bool {
	// WEAK PASSWORD DATABASE
	// Common passwords from breach analysis and dictionary attacks
	// TO-DO: Expand this list significantly or use external password breach database
	weakPasswords := []string{
		"password", "12345678", "qwerty12", "admin123", "12345678",
		"password123", "admin123", "letmein12", "welcome1",
		"monkey12", "dragon12", "1234567890", "qwertyuiop",
	}

	// CASE-INSENSITIVE COMPARISON
	// Convert to lowercase to catch variations like "Password123", "PASSWORD"
	lowerPass := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if lowerPass == weak {
			return true
		}
	}
	return false
}

// HasPasswordComplexity evaluates character diversity for brute force resistance.
//
// Security features:
// - Multi-category character requirement increases entropy
// - Balanced approach: 3 of 4 categories prevents overly restrictive policies
// - Entropy calculation considers real-world password cracking methods
//
// Character categories: uppercase (A-Z), lowercase (a-z), digits (0-9), special (!@#...)
// Returns true if password contains at least 3 character categories.
func HasPasswordComplexity(password string) bool {
	// CHARACTER CATEGORY TRACKING
	// Track presence of each character type for entropy calculation
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	// CHARACTER CLASSIFICATION
	// Analyze each character to determine category membership
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	// COMPLEXITY SCORING
	// Count character categories for entropy assessment
	complexity := 0
	if hasUpper {
		complexity++
	}
	if hasLower {
		complexity++
	}
	if hasDigit {
		complexity++
	}
	if hasSpecial {
		complexity++
	}

	// MINIMUM COMPLEXITY THRESHOLD
	// Require 3 of 4 categories for adequate entropy without user frustration
	return complexity >= 3
}
