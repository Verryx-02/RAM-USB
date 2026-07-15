// Package encryption implements Database-Vault's per-record email
// encryption (DV-F-04): a per-record key derived from the master key via
// HKDF-SHA256 and a random 16-byte salt, then AES-256-GCM sealing of the
// email with that derived key and a random 12-byte nonce. It holds no
// database connection: persisting the resulting salt, nonce, and
// ciphertext is DV-F-08's job, not this package's, and sourcing/validating
// the master key is DV-F-05's job.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
)

const (
	// saltSize and nonceSize are fixed by DV-F-04.
	saltSize  = 16
	nonceSize = 12

	// derivedKeySize is 32 bytes so the derived key selects AES-256 in
	// aes.NewCipher (16/24/32-byte keys select AES-128/192/256).
	derivedKeySize = 32

	// hkdfInfo domain-separates this derived key from any other key a
	// future caller might ever derive from the same master key via
	// HKDF, per RFC 5869's "info" parameter guidance.
	hkdfInfo = "RAM-USB/database-vault/email-encryption"
)

// EncryptedEmail holds everything DV-F-08 needs to persist and
// DecryptEmail needs to reverse an EncryptEmail call: the random
// per-record salt, the random GCM nonce, and the resulting ciphertext.
// cipher.AEAD.Seal appends the GCM authentication tag to the ciphertext it
// returns, so Ciphertext already includes it.
type EncryptedEmail struct {
	Salt       []byte
	Nonce      []byte
	Ciphertext []byte
}

// EncryptEmail encrypts email under a key derived from masterKey (DV-F-04).
//
// masterKey is treated as an already-validated 32-byte key: sourcing and
// length-validating it is DV-F-05's job, not this function's.
//
// A fresh 16-byte salt and a fresh 12-byte nonce are generated on every
// call via crypto/rand, so two calls with the same email and masterKey
// produce different Salt, Nonce, and Ciphertext every time.
//
// The parameter is typed as logging.Redacted, not string, for the same
// reason as hashing.HashEmail's parameter: this is the function that
// receives the plaintext email closest to where it enters this code path,
// so accidental logging of the argument prints "REDACTED" instead of the
// plaintext, by construction (DV-F-03 precedent, RD-01).
func EncryptEmail(masterKey []byte, email logging.Redacted) (EncryptedEmail, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return EncryptedEmail{}, fmt.Errorf("encryption: generate salt: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedEmail{}, fmt.Errorf("encryption: generate nonce: %w", err)
	}

	gcm, err := newGCM(masterKey, salt)
	if err != nil {
		return EncryptedEmail{}, err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(email), nil)

	return EncryptedEmail{Salt: salt, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// DecryptEmail reverses EncryptEmail, returning the plaintext email.
//
// The SRS's DV-F-04 only requires encryption; DecryptEmail exists as this
// package's necessary verification counterpart, since AES-256-GCM
// ciphertext is randomized by the salt and nonce and admits no fixed
// known-answer test — decrypting the result and comparing against the
// original plaintext is the only way to confirm EncryptEmail is correct.
// No SRS requirement yet describes a production flow that reads the
// email back; see this task's report for that gap.
func DecryptEmail(masterKey []byte, enc EncryptedEmail) (string, error) {
	gcm, err := newGCM(masterKey, enc.Salt)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("encryption: decrypt email: %w", err)
	}

	return string(plaintext), nil
}

// newGCM derives a per-record AES-256 key from masterKey and salt via
// HKDF-SHA256 (DV-F-04), and wraps it in an AES-256-GCM cipher.AEAD. The
// derived key is zeroed as soon as the AES cipher block has consumed it
// (RD-02: derived keys stay in memory only for the duration of the
// operation that needs them).
func newGCM(masterKey, salt []byte) (cipher.AEAD, error) {
	derivedKey := make([]byte, derivedKeySize)
	kdf := hkdf.New(sha256.New, masterKey, salt, []byte(hkdfInfo))
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		return nil, fmt.Errorf("encryption: derive key: %w", err)
	}

	block, err := aes.NewCipher(derivedKey)
	for i := range derivedKey {
		derivedKey[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("encryption: new AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("encryption: new GCM: %w", err)
	}

	return gcm, nil
}
