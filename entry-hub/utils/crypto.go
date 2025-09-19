package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashEmail creates SHA-256 hash of email for consistent logging
func HashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}
