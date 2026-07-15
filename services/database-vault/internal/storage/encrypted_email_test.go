package storage

import (
	"errors"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
)

// Requirement: DV-F-08
func TestMarshalUnmarshalEncryptedEmail_RoundTrip(t *testing.T) {
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

			got, err := unmarshalEncryptedEmail(marshaled)
			if err != nil {
				t.Fatalf("unmarshalEncryptedEmail() error = %v, want nil", err)
			}

			if string(got.Salt) != string(tt.enc.Salt) {
				t.Errorf("Salt = %q, want %q", got.Salt, tt.enc.Salt)
			}
			if string(got.Nonce) != string(tt.enc.Nonce) {
				t.Errorf("Nonce = %q, want %q", got.Nonce, tt.enc.Nonce)
			}
			if string(got.Ciphertext) != string(tt.enc.Ciphertext) {
				t.Errorf("Ciphertext = %q, want %q", got.Ciphertext, tt.enc.Ciphertext)
			}
		})
	}
}

// Requirement: DV-F-08
func TestUnmarshalEncryptedEmail_Malformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "only one length byte", data: []byte{16}},
		{name: "declared lengths exceed available data", data: []byte{16, 12, 1, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unmarshalEncryptedEmail(tt.data)
			if !errors.Is(err, ErrMalformedEncryptedEmail) {
				t.Fatalf("unmarshalEncryptedEmail() error = %v, want wrapping ErrMalformedEncryptedEmail", err)
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
