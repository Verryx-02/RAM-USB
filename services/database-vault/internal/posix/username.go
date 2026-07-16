// Package posix implements DV-F-09: generating the POSIX username
// Database-Vault assigns a newly-registered user, and asking Storage-Service
// to create that POSIX account over mTLS, waiting for its response.
//
// Scope note: this package covers DV-F-09 only. Rolling back the saved user
// record when POSIX-user creation fails (DV-F-10) and reporting success back
// to Security-Switch (DV-F-11) are separate requirements, implemented
// elsewhere; callers of this package are expected to inspect the error this
// package returns and act on it themselves.
package posix

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// usernamePrefix is fixed by DV-F-09/ST-F-06: every generated POSIX username
// starts with "user" (lowercase), followed by the random suffix.
const usernamePrefix = "user"

// suffixLength is the number of random base-36 characters DV-F-09/ST-F-06
// specify ("user<xxxxxx>", six characters).
const suffixLength = 6

// base36Alphabet is lowercase-only, per the requirement's explicit note
// that "user<xxxxxx>" is "all lowercase".
const base36Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// GenerateUsername returns a new POSIX username of the form
// "user<xxxxxx>", where <xxxxxx> is six random characters drawn uniformly
// from the lowercase base-36 alphabet [0-9a-z]. It uses crypto/rand, not
// math/rand: although the username is not itself a secret, a predictable
// generator would let an attacker guess in-flight or upcoming usernames,
// which this project's zero-trust posture (RNF-SEC-02/03) treats as
// avoidable risk for negligible cost.
func GenerateUsername() (string, error) {
	alphabetSize := big.NewInt(int64(len(base36Alphabet)))

	suffix := make([]byte, suffixLength)
	for i := range suffix {
		n, err := rand.Int(rand.Reader, alphabetSize)
		if err != nil {
			return "", fmt.Errorf("posix: generate random username suffix: %w", err)
		}
		suffix[i] = base36Alphabet[n.Int64()]
	}

	return usernamePrefix + string(suffix), nil
}
