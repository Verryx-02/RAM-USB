package encryption

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// masterKeyEnvVar is the configurable source DV-F-05 requires. Per SRS
// §2.6 ("Assumptions and dependencies"), the master key is assumed to
// reside in an environment variable for now; no other source (file, KMS,
// secrets manager) is in scope until the SRS says otherwise.
const masterKeyEnvVar = "RAM_USB_MASTER_KEY"

// masterKeySize is the length DV-F-05 requires of the decoded master key:
// 32 bytes, so it selects AES-256 in aes.NewCipher via newGCM.
const masterKeySize = 32

// ErrMasterKeyMissing means masterKeyEnvVar is unset or empty.
var ErrMasterKeyMissing = errors.New("encryption: master key environment variable is not set")

// ErrMasterKeyInvalidEncoding means masterKeyEnvVar's value is not valid
// standard base64.
var ErrMasterKeyInvalidEncoding = errors.New("encryption: master key is not valid base64")

// ErrMasterKeyInvalidLength means the decoded master key is not exactly
// masterKeySize bytes.
var ErrMasterKeyInvalidLength = errors.New("encryption: master key has invalid length")

// LoadMasterKey reads and validates the encryption master key from its
// configured source (DV-F-05).
//
// The env var's value is expected to be standard base64 (RFC 4648):
// binary secrets, such as a raw 32-byte AES-256 key, are not safe or
// practical to store directly in an environment variable, so base64 is
// the conventional encoding for this case.
//
// Per RD-04 (fail-secure: on any uncertainty, deny), any problem with the
// source — missing, malformed, or wrong decoded length — returns an error
// instead of silently padding, truncating, or falling back to a default
// key.
func LoadMasterKey() ([]byte, error) {
	encoded, ok := os.LookupEnv(masterKeyEnvVar)
	if !ok || encoded == "" {
		return nil, fmt.Errorf("%w: %s", ErrMasterKeyMissing, masterKeyEnvVar)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMasterKeyInvalidEncoding, err)
	}

	if len(decoded) != masterKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrMasterKeyInvalidLength, len(decoded), masterKeySize)
	}

	return decoded, nil
}
