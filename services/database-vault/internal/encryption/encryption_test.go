package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
)

// testMasterKey is a fixed 32-byte stand-in for the already-validated
// master key DV-F-05 is responsible for sourcing; DV-F-04 treats it as an
// opaque input.
var testMasterKey = []byte("01234567890123456789012345678901"[:32])

// openIndependently re-derives the same per-record key EncryptEmail derives
// internally (HKDF-SHA256 over masterKey/salt/hkdfInfo, DV-F-04) and opens
// enc's ciphertext with a cipher.AEAD built directly from that key — never
// through an application-level Decrypt* function. This is the only way to
// confirm EncryptEmail's output is genuinely decryptable AES-256-GCM
// ciphertext under the key/nonce/salt it claims to have used, since GCM
// ciphertext is randomized and admits no fixed known-answer test.
func openIndependently(t *testing.T, masterKey []byte, enc EncryptedEmail) ([]byte, error) {
	t.Helper()

	derivedKey := make([]byte, derivedKeySize)
	kdf := hkdf.New(sha256.New, masterKey, enc.Salt, []byte(hkdfInfo))
	if _, err := io.ReadFull(kdf, derivedKey); err != nil {
		t.Fatalf("independently deriving key: %v", err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		t.Fatalf("independently building AES cipher: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("independently building GCM: %v", err)
	}

	return aesgcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
}

// Requirement: DV-F-04
func TestEncryptEmail_RoundTripsUnderIndependentlyDerivedKey(t *testing.T) {
	tests := []struct {
		name  string
		email logging.Redacted
	}{
		{name: "typical email", email: logging.Redacted("user@example.com")},
		{name: "empty email", email: logging.Redacted("")},
		{name: "mixed case email", email: logging.Redacted("User.Name+tag@Example.CO.UK")},
		{name: "long email", email: logging.Redacted("a.very.long.local.part.that.stretches.the.buffer@sub.example.com")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := EncryptEmail(testMasterKey, tt.email)
			if err != nil {
				t.Fatalf("EncryptEmail(%q) returned error: %v", tt.email, err)
			}

			got, err := openIndependently(t, testMasterKey, enc)
			if err != nil {
				t.Fatalf("independent GCM Open returned error: %v", err)
			}

			if string(got) != string(tt.email) {
				t.Errorf("round trip = %q, want %q", got, string(tt.email))
			}
		})
	}
}

// Requirement: DV-F-04
func TestEncryptEmail_SaltAndNonceShape(t *testing.T) {
	enc, err := EncryptEmail(testMasterKey, logging.Redacted("shape@example.com"))
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	const wantSaltLen = 16
	const wantNonceLen = 12

	if len(enc.Salt) != wantSaltLen {
		t.Errorf("len(Salt) = %d, want %d", len(enc.Salt), wantSaltLen)
	}
	if len(enc.Nonce) != wantNonceLen {
		t.Errorf("len(Nonce) = %d, want %d", len(enc.Nonce), wantNonceLen)
	}
	if len(enc.Ciphertext) == 0 {
		t.Errorf("Ciphertext is empty, want at least the GCM authentication tag")
	}
}

// Requirement: DV-F-04
func TestEncryptEmail_RandomizedAcrossCalls(t *testing.T) {
	const email = logging.Redacted("repeat@example.com")

	first, err := EncryptEmail(testMasterKey, email)
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	second, err := EncryptEmail(testMasterKey, email)
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	if bytes.Equal(first.Salt, second.Salt) {
		t.Errorf("Salt reused across calls: %x", first.Salt)
	}
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Errorf("Nonce reused across calls: %x", first.Nonce)
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Errorf("Ciphertext identical across calls despite random salt/nonce: %x", first.Ciphertext)
	}
}

// Requirement: DV-F-04
func TestEncryptEmail_CiphertextNeverContainsPlaintext(t *testing.T) {
	const email = logging.Redacted("plaintext-should-not-leak@example.com")

	enc, err := EncryptEmail(testMasterKey, email)
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	if bytes.Contains(enc.Ciphertext, []byte(email)) {
		t.Errorf("Ciphertext contains the plaintext email as a substring: %x", enc.Ciphertext)
	}
	if strings.Contains(string(enc.Ciphertext), string(email)) {
		t.Errorf("Ciphertext string-contains the plaintext email: %x", enc.Ciphertext)
	}
}

// Requirement: DV-F-04
func TestEncryptEmail_TamperedCiphertextFailsIndependentOpen(t *testing.T) {
	enc, err := EncryptEmail(testMasterKey, logging.Redacted("tamper@example.com"))
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	tampered := enc
	tampered.Ciphertext = append([]byte(nil), enc.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xFF

	if _, err := openIndependently(t, testMasterKey, tampered); err == nil {
		t.Error("independent GCM Open succeeded on tampered ciphertext, want authentication failure")
	}
}

// Requirement: DV-F-04
func TestEncryptEmail_TamperedNonceFailsIndependentOpen(t *testing.T) {
	enc, err := EncryptEmail(testMasterKey, logging.Redacted("tamper-nonce@example.com"))
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	tampered := enc
	tampered.Nonce = append([]byte(nil), enc.Nonce...)
	tampered.Nonce[0] ^= 0xFF

	if _, err := openIndependently(t, testMasterKey, tampered); err == nil {
		t.Error("independent GCM Open succeeded on tampered nonce, want authentication failure")
	}
}

// Requirement: DV-F-04
func TestEncryptEmail_TamperedSaltFailsIndependentOpen(t *testing.T) {
	enc, err := EncryptEmail(testMasterKey, logging.Redacted("tamper-salt@example.com"))
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	tampered := enc
	tampered.Salt = append([]byte(nil), enc.Salt...)
	tampered.Salt[0] ^= 0xFF

	// A corrupted salt re-derives a different key (HKDF-SHA256 mixes the
	// salt into the derived key material), so opening against it should
	// fail the same way a wrong master key would.
	if _, err := openIndependently(t, testMasterKey, tampered); err == nil {
		t.Error("independent GCM Open succeeded with a tampered salt, want authentication failure")
	}
}

// Requirement: DV-F-04
func TestEncryptEmail_WrongMasterKeyFailsIndependentOpen(t *testing.T) {
	enc, err := EncryptEmail(testMasterKey, logging.Redacted("wrongkey@example.com"))
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	wrongKey := []byte("98765432109876543210987654321098"[:32])

	if _, err := openIndependently(t, wrongKey, enc); err == nil {
		t.Error("independent GCM Open succeeded with wrong master key, want failure")
	}
}
