package storage

import (
	"errors"
	"fmt"
	"math"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
)

// ErrMalformedEncryptedEmail means a stored email_encrypted BYTEA value does
// not match the format marshalEncryptedEmail produces, so
// unmarshalEncryptedEmail cannot safely split it back into salt, nonce, and
// ciphertext.
var ErrMalformedEncryptedEmail = errors.New("storage: stored encrypted email is malformed")

// marshalEncryptedEmail packs an encryption.EncryptedEmail's three separate
// fields (Salt, Nonce, Ciphertext — see that type's doc comment) into the
// single BYTEA the email_encrypted column holds
// (docs/design/diagrams/06-data-er-database-vault.puml).
//
// Format: a 1-byte salt length, a 1-byte nonce length, then salt, nonce,
// and ciphertext back to back. Lengths are read from enc itself rather than
// assumed fixed at 16/12 bytes, so this format does not depend on
// encryption package internals; both lengths fit comfortably in one byte
// (EncryptEmail always produces a 16-byte salt and a 12-byte nonce).
func marshalEncryptedEmail(enc encryption.EncryptedEmail) ([]byte, error) {
	if len(enc.Salt) > math.MaxUint8 {
		return nil, fmt.Errorf("%w: salt length %d exceeds the 1-byte length header", ErrMalformedEncryptedEmail, len(enc.Salt))
	}
	if len(enc.Nonce) > math.MaxUint8 {
		return nil, fmt.Errorf("%w: nonce length %d exceeds the 1-byte length header", ErrMalformedEncryptedEmail, len(enc.Nonce))
	}

	buf := make([]byte, 0, 2+len(enc.Salt)+len(enc.Nonce)+len(enc.Ciphertext))
	buf = append(buf, byte(len(enc.Salt)), byte(len(enc.Nonce))) //nolint:gosec // bounded by the explicit MaxUint8 checks above
	buf = append(buf, enc.Salt...)
	buf = append(buf, enc.Nonce...)
	buf = append(buf, enc.Ciphertext...)

	return buf, nil
}

// unmarshalEncryptedEmail reverses marshalEncryptedEmail. No production
// DV-F-* requirement yet reads the email_encrypted column back (see
// encryption.DecryptEmail's doc comment for the same gap); this exists so
// SaveUser's on-disk format has a tested round trip, and so a future
// requirement that does need to read it back has this ready.
func unmarshalEncryptedEmail(data []byte) (encryption.EncryptedEmail, error) {
	if len(data) < 2 {
		return encryption.EncryptedEmail{}, fmt.Errorf("%w: too short for a length header", ErrMalformedEncryptedEmail)
	}

	saltLen := int(data[0])
	nonceLen := int(data[1])
	data = data[2:]

	if len(data) < saltLen+nonceLen {
		return encryption.EncryptedEmail{}, fmt.Errorf("%w: declared salt/nonce length exceeds available data", ErrMalformedEncryptedEmail)
	}

	salt := data[:saltLen]
	nonce := data[saltLen : saltLen+nonceLen]
	ciphertext := data[saltLen+nonceLen:]

	return encryption.EncryptedEmail{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}
