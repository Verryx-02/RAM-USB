package storage

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
)

// Requirement: DV-F-08
func TestMarshalEncryptedEmail_ByteLayout(t *testing.T) {
	tests := []struct {
		name string
		enc  encryption.EncryptedEmail
	}{
		{
			name: "typical DV-F-04 shape (16-byte salt, 12-byte nonce)",
			enc: encryption.EncryptedEmail{
				Salt:       []byte("0123456789abcdef"),
				Nonce:      []byte("012345678901"),
				Ciphertext: []byte("some ciphertext bytes with a GCM tag appended"),
			},
		},
		{
			name: "empty ciphertext",
			enc: encryption.EncryptedEmail{
				Salt:       []byte("saltsaltsaltsalt"),
				Nonce:      []byte("noncenonce12"),
				Ciphertext: []byte{},
			},
		},
		{
			name: "single-byte salt and nonce",
			enc: encryption.EncryptedEmail{
				Salt:       []byte{0xFF},
				Nonce:      []byte{0x00},
				Ciphertext: []byte{0x01, 0x02, 0x03},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marshaled, err := marshalEncryptedEmail(tt.enc)
			if err != nil {
				t.Fatalf("marshalEncryptedEmail() error = %v, want nil", err)
			}

			// Verify the on-disk layout directly, byte by byte, rather
			// than through unmarshalEncryptedEmail: a 1-byte salt length,
			// a 1-byte nonce length, then salt, nonce, and ciphertext back
			// to back (see marshalEncryptedEmail's doc comment).
			wantLen := 2 + len(tt.enc.Salt) + len(tt.enc.Nonce) + len(tt.enc.Ciphertext)
			if len(marshaled) != wantLen {
				t.Fatalf("len(marshaled) = %d, want %d", len(marshaled), wantLen)
			}

			if got := int(marshaled[0]); got != len(tt.enc.Salt) {
				t.Errorf("salt length header = %d, want %d", got, len(tt.enc.Salt))
			}
			if got := int(marshaled[1]); got != len(tt.enc.Nonce) {
				t.Errorf("nonce length header = %d, want %d", got, len(tt.enc.Nonce))
			}

			body := marshaled[2:]
			gotSalt := body[:len(tt.enc.Salt)]
			gotNonce := body[len(tt.enc.Salt) : len(tt.enc.Salt)+len(tt.enc.Nonce)]
			gotCiphertext := body[len(tt.enc.Salt)+len(tt.enc.Nonce):]

			if !bytes.Equal(gotSalt, tt.enc.Salt) {
				t.Errorf("salt bytes = %q, want %q", gotSalt, tt.enc.Salt)
			}
			if !bytes.Equal(gotNonce, tt.enc.Nonce) {
				t.Errorf("nonce bytes = %q, want %q", gotNonce, tt.enc.Nonce)
			}
			if !bytes.Equal(gotCiphertext, tt.enc.Ciphertext) {
				t.Errorf("ciphertext bytes = %q, want %q", gotCiphertext, tt.enc.Ciphertext)
			}
		})
	}
}

// Requirement: DV-F-08
func TestMarshalEncryptedEmail_LengthTooLargeForHeader(t *testing.T) {
	oversizedSalt := make([]byte, 256)

	_, err := marshalEncryptedEmail(encryption.EncryptedEmail{
		Salt:       oversizedSalt,
		Nonce:      []byte("012345678901"),
		Ciphertext: []byte("ciphertext"),
	})
	if !errors.Is(err, ErrMalformedEncryptedEmail) {
		t.Fatalf("marshalEncryptedEmail() error = %v, want wrapping ErrMalformedEncryptedEmail for a 256-byte salt", err)
	}
}
