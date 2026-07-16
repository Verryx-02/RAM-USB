// Package hashing computes the SHA-256 hash Database-Vault uses to index
// and look up user records by email (DV-F-03, DV-F-13), without ever
// requiring the plaintext email to flow through anything but this function
// and its caller. It holds no database connection: persisting the
// resulting hash as an indexed primary key is DV-F-08's job, not this
// package's.
package hashing

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
)

// HashEmail returns the lowercase hex-encoded SHA-256 digest of email, for
// use as Database-Vault's lookup key and primary key (DV-F-03).
//
// email is normalized to lowercase before hashing, so the returned digest
// is a case-insensitive lookup key: "User@Example.com" and
// "user@example.com" hash identically. This is what makes DV-F-13's login
// lookup (recomputing the same hash at login time) match what DV-F-03
// stored at registration, regardless of the letter casing either caller
// happens to submit. HashEmail is the single point that guarantees this
// consistency; callers must not normalize the email themselves before
// calling it.
//
// The parameter is typed as logging.Redacted, not string: this is the
// function that receives the plaintext email at the point closest to
// where it enters this code path, so accidental logging of the argument
// (for example via a future slog.Any("email", email) added near a call
// site) prints "REDACTED" instead of the plaintext, by construction
// (DV-F-03, RD-01).
func HashEmail(email logging.Redacted) string {
	normalized := strings.ToLower(string(email))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
