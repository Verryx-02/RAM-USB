// Package password holds Database-Vault's password-hashing configuration
// and logic (DV-F-06, DV-F-07). It is separate from the internal/hashing
// package, which implements DV-F-03's email lookup-key hashing — a
// different secret, a different algorithm (Argon2id here vs. SHA-256
// there), and a different purpose.
package password

import (
	"errors"
	"fmt"
	"os"
)

// pepperEnvVar is the configurable source DV-F-06 requires. Per SRS §2.6
// ("Assumptions and dependencies"), the pepper is assumed to reside in an
// environment variable for now; no other source (file, KMS, secrets
// manager) is in scope until the SRS says otherwise.
const pepperEnvVar = "RAM_USB_PASSWORD_PEPPER"

// ErrPepperMissing means pepperEnvVar is unset or empty.
var ErrPepperMissing = errors.New("password: pepper environment variable is not set")

// LoadPepper reads and validates the password-hashing pepper from its
// configured source (DV-F-06).
//
// Unlike DV-F-05's master key, the SRS places no length or encoding
// constraint on the pepper. The pepper is a secret value that DV-F-07
// will append to the password's bytes before Argon2id hashing — a role
// closer to an additional passphrase segment than to a fixed-size binary
// AES key — so its raw bytes are used as-is, with no base64 decoding.
//
// Per RD-04 (fail-secure: on any uncertainty, deny), a missing or empty
// pepper returns an error instead of silently falling back to an empty
// or default value.
func LoadPepper() ([]byte, error) {
	value, ok := os.LookupEnv(pepperEnvVar)
	if !ok || value == "" {
		return nil, fmt.Errorf("%w: %s", ErrPepperMissing, pepperEnvVar)
	}

	return []byte(value), nil
}
