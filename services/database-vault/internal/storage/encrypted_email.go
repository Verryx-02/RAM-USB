package storage

import (
	"errors"
	"fmt"
	"math"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
)

// ErrMalformedEncryptedEmail means a value passed to marshalEncryptedEmail
// does not fit the format it produces (docs/design/diagrams/06-data-er-database-vault.puml).
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
