package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"
)

// saltSize is this session's judgment call, not an SRS-specified value:
// DV-F-07/DV-F-14 require "the salt" without ever giving a length (unlike
// DV-F-04, whose "random 16-byte salt" wording is explicit). 16 bytes (128
// bits) is used here because it is the minimum RFC 9106 (§3.1) requires for
// any Argon2 salt and the size the reference implementation itself
// recommends for password hashing, not a business rule with a meaningful
// trade-off space the way Argon2id's cost parameters below are — so it is
// implemented directly rather than deferred as part of the blocking gap.
const saltSize = 16

// Argon2id cost parameters, confirmed by the user against the live OWASP
// Password Storage Cheat Sheet (2026-07-15), not from training-data
// recollection or the RFC 9106 defaults. This is a deliberate choice more
// expensive than any single OWASP "equal defense" row (OWASP pairs 46 MiB
// with t=1, not t=2) — implemented exactly as given, not second-guessed or
// substituted with a different pairing.
const (
	// argonTime is the number of Argon2id passes over memory.
	argonTime = 2
	// argonMemoryKiB is the working-memory size in KiB (46 MiB).
	argonMemoryKiB = 47104
	// argonThreads is the degree of parallelism.
	argonThreads = 1
	// argonKeyLen is the output hash length in bytes.
	argonKeyLen = 32
)

// phcAlgorithmID identifies the algorithm segment of the stored hash's PHC
// string encoding (see HashPassword's doc comment).
const phcAlgorithmID = "argon2id"

// ErrPasswordHashInvalidSalt means HashPassword was called with a salt that
// is not exactly saltSize bytes. HashPassword only ever consumes salts it
// (via GenerateSalt) or an equivalent trusted source produced; per
// RNF-SEC-03 (every layer independently re-validates input) it does not
// trust a caller-supplied salt's length silently.
var ErrPasswordHashInvalidSalt = errors.New("password: salt has invalid length")

// ErrPasswordHashMalformed means an encoded hash string does not match the
// PHC-style format HashPassword produces, so VerifyPassword cannot safely
// parse cost parameters, salt, or digest out of it.
var ErrPasswordHashMalformed = errors.New("password: encoded hash is malformed")

// ErrPasswordHashUnsupportedAlgorithm means an encoded hash string names an
// algorithm other than argon2id. Per RD-03 (Argon2id is a non-negotiable
// technology constraint) and RD-04 (fail-secure), VerifyPassword refuses to
// recompute or compare against any other algorithm rather than guess how to
// handle it.
var ErrPasswordHashUnsupportedAlgorithm = errors.New("password: encoded hash uses an unsupported algorithm")

// ErrPasswordHashInvalidParameters means an encoded hash string's cost
// parameters or digest length fall outside argon2.IDKey's valid ranges
// (e.g. a negative or out-of-range value). Per RD-04 (fail-secure),
// decodeHash rejects these explicitly rather than silently truncating them
// during the int-to-uint32/uint8 conversion.
var ErrPasswordHashInvalidParameters = errors.New("password: encoded hash has invalid cost parameters")

// GenerateSalt returns a fresh random per-record salt for Argon2id password
// hashing (DV-F-07). A new salt must be generated for every registration
// (DV-F-07) and stored alongside the resulting hash so DV-F-13/DV-F-14 can
// retrieve it again at login.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("password: generate salt: %w", err)
	}

	return salt, nil
}

// composePassword combines the password and the pepper into the single
// byte slice Argon2id hashes as its "password" input (DV-F-07/DV-F-14).
//
// Design decision (this session): the pepper is appended after the
// password (password || pepper), and the salt is passed separately as
// Argon2id's own salt parameter — it is not folded into this byte slice.
// Reasoning:
//   - The salt's whole purpose is to be unique per record and stored
//     alongside the hash (DV-F-13/DV-F-14 retrieve it for recomputation);
//     mixing it into the "password" bytes instead of using Argon2id's
//     dedicated salt parameter would just reimplement what that parameter
//     already does, with no security benefit.
//   - The pepper is a single secret shared by every record (DV-F-06), not
//     unique per record, so it cannot serve as the salt. Concatenating it
//     with the password before hashing is the standard way to fold a
//     pepper into a KDF that has no dedicated pepper parameter.
//   - Append (not prepend) was chosen arbitrarily between two otherwise
//     equivalent options — there is no cryptographic difference between
//     password||pepper and pepper||password for this purpose. This order
//     is fixed once chosen: changing it later invalidates every existing
//     hash, since recomputation must reproduce the exact same input bytes.
func composePassword(password, pepper []byte) []byte {
	combined := make([]byte, 0, len(password)+len(pepper))
	combined = append(combined, password...)
	combined = append(combined, pepper...)

	return combined
}

// HashPassword computes the Argon2id hash of password, salted with salt and
// peppered with pepper (DV-F-07), and returns it encoded in the
// conventional PHC string format:
//
//	$argon2id$v=19$m=47104,t=2,p=1$<base64 salt>$<base64 hash>
//
// Design decision (this session): the returned string self-describes the
// exact Argon2id version and cost parameters used to produce it, rather
// than returning raw hash bytes alone. This guarantees DV-F-14's
// login-time recomputation always uses the identical parameters the
// record was created with, even if this file's argonTime/argonMemoryKiB/
// argonThreads/argonKeyLen constants are ever changed later — the alternative
// (recomputing with "whatever the current constants say") would silently
// break every hash created under different parameters. The SRS has no
// stated requirement for parameter rotation/versioning (unlike DV-F-19's
// master-key rotation, which is only a "should"), so no rotation policy is
// implemented here — only the self-describing format itself, which is a
// small, low-risk addition that keeps that door open without building
// anything unrequested.
//
// See composePassword's doc comment for how password, salt, and pepper are
// combined into the underlying argon2.IDKey call.
func HashPassword(password, salt, pepper []byte) (string, error) {
	if len(salt) != saltSize {
		return "", fmt.Errorf("%w: got %d bytes, want %d", ErrPasswordHashInvalidSalt, len(salt), saltSize)
	}

	hash := argon2.IDKey(composePassword(password, pepper), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)

	return encodeHash(salt, hash), nil
}

// VerifyPassword recomputes the Argon2id hash of password (peppered with
// pepper) using the cost parameters and salt embedded in encoded, and
// reports whether it matches encoded's stored digest (DV-F-14's
// recomputation step). Comparison uses crypto/subtle.ConstantTimeCompare to
// avoid leaking timing information about how much of the hash matched.
//
// A non-nil error means encoded could not be parsed or names an
// unsupported algorithm — per RD-04 (fail-secure), callers must treat that
// identically to a failed match, not as a distinct "maybe valid" outcome.
func VerifyPassword(password, pepper []byte, encoded string) (bool, error) {
	salt, wantHash, time, memoryKiB, threads, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}

	if len(wantHash) > math.MaxUint32 {
		return false, fmt.Errorf("%w: digest length %d exceeds uint32 range", ErrPasswordHashInvalidParameters, len(wantHash))
	}

	gotHash := argon2.IDKey(composePassword(password, pepper), salt, time, memoryKiB, threads, uint32(len(wantHash))) //nolint:gosec // bounded by the explicit MaxUint32 check above

	return subtle.ConstantTimeCompare(gotHash, wantHash) == 1, nil
}

// encodeHash formats salt and hash into the PHC string this package uses
// for storage (see HashPassword's doc comment). Both segments use
// unpadded standard base64 (RawStdEncoding), the conventional choice for
// PHC-style strings since padding characters ('=') would collide with the
// '$' delimiter scheme if a different separator were ever needed.
func encodeHash(salt, hash []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		phcAlgorithmID, argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// decodeHash parses a PHC string produced by encodeHash back into its
// salt, digest, and Argon2id cost parameters. It only needs to round-trip
// this package's own output, not accept arbitrary PHC strings from other
// Argon2 implementations.
func decodeHash(encoded string) (salt, hash []byte, time, memoryKiB uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	// strings.Split("$argon2id$v=19$m=...,t=...,p=...$salt$hash", "$")
	// yields ["", "argon2id", "v=19", "m=...,t=...,p=...", "salt", "hash"].
	if len(parts) != 6 || parts[0] != "" {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: %q", ErrPasswordHashMalformed, encoded)
	}

	if parts[1] != phcAlgorithmID {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: %q", ErrPasswordHashUnsupportedAlgorithm, parts[1])
	}

	var version int
	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid version segment %q", ErrPasswordHashMalformed, parts[2])
	}

	var m, t, p int
	if _, scanErr := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); scanErr != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid parameters segment %q", ErrPasswordHashMalformed, parts[3])
	}
	if m < 0 || m > math.MaxUint32 || t < 0 || t > math.MaxUint32 {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: m=%d, t=%d out of range", ErrPasswordHashInvalidParameters, m, t)
	}
	if p < 0 || p > math.MaxUint8 {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: p=%d out of range", ErrPasswordHashInvalidParameters, p)
	}

	decodedSalt, saltErr := base64.RawStdEncoding.DecodeString(parts[4])
	if saltErr != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid salt encoding: %w", ErrPasswordHashMalformed, saltErr)
	}

	decodedHash, hashErr := base64.RawStdEncoding.DecodeString(parts[5])
	if hashErr != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("%w: invalid hash encoding: %w", ErrPasswordHashMalformed, hashErr)
	}

	return decodedSalt, decodedHash, uint32(t), uint32(m), uint8(p), nil //nolint:gosec // bounded by the explicit range checks above
}
