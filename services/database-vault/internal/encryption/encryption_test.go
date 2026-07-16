package encryption

import (
	"bytes"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
)

// testMasterKey is a fixed 32-byte stand-in for the already-validated
// master key DV-F-05 is responsible for sourcing; DV-F-04 treats it as an
// opaque input.
var testMasterKey = []byte("01234567890123456789012345678901"[:32])

// Requirement: DV-F-04
func TestEncryptDecryptEmail_RoundTrip(t *testing.T) {
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

			got, err := DecryptEmail(testMasterKey, enc)
			if err != nil {
				t.Fatalf("DecryptEmail returned error: %v", err)
			}

			if got != string(tt.email) {
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
func TestDecryptEmail_TamperedCiphertextFails(t *testing.T) {
	enc, err := EncryptEmail(testMasterKey, logging.Redacted("tamper@example.com"))
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	tampered := enc
	tampered.Ciphertext = append([]byte(nil), enc.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xFF

	if _, err := DecryptEmail(testMasterKey, tampered); err == nil {
		t.Error("DecryptEmail succeeded on tampered ciphertext, want authentication failure")
	}
}

// Requirement: DV-F-04
func TestDecryptEmail_WrongMasterKeyFails(t *testing.T) {
	enc, err := EncryptEmail(testMasterKey, logging.Redacted("wrongkey@example.com"))
	if err != nil {
		t.Fatalf("EncryptEmail returned error: %v", err)
	}

	wrongKey := []byte("98765432109876543210987654321098"[:32])

	if _, err := DecryptEmail(wrongKey, enc); err == nil {
		t.Error("DecryptEmail succeeded with wrong master key, want failure")
	}
}
