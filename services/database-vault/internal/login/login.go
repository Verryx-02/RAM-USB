// Package login orchestrates Database-Vault's login control flow (DV-F-13,
// DV-F-14, DV-F-15), per
// docs/design/diagrams/04-usecases-sequence-uc02-login.puml:
//
//   - DV-F-13: look up the stored password_hash by the SHA-256 hash of the
//     received email (DV-F-03). The salt is not retrieved separately — it
//     is embedded in the stored PHC string and decoded by
//     password.VerifyPassword itself (DV-F-07's storage format).
//   - DV-F-14: recompute Argon2id on the received password using the
//     retrieved salt and the pepper, and compare with the stored hash.
//   - DV-F-15: respond with the same outcome, and log the same message,
//     whether the email does not exist or the password does not match —
//     these two cases are byte-identical in Login's return value, by
//     design. A third case, a verification error from
//     password.VerifyPassword itself (e.g. a malformed stored password
//     hash — data corruption or a bug, not a user mistake), maps to the
//     same HTTP-facing Outcome (still 401) but a distinct Err a logging
//     layer can distinguish from an ordinary authentication failure. That
//     distinct Err carries no content from the underlying error — DV-F-15
//     only forbids distinguishing "nonexistent email" from "wrong
//     password"; it does not require hiding an internal verification
//     error, so long as nothing in the log identifies which record/user
//     triggered it.
//
// This package does not implement any HTTP boundary: Result's Outcome
// field is what a future handler maps to 401/200, without inspecting Err's
// content — same deferred-wiring pattern as the registration package's
// Result/Outcome for DV-F-09 through DV-F-12.
package login

import (
	"context"
	"errors"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/hashing"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/password"
)

// Outcome distinguishes the two ways Login can conclude, so a future HTTP
// handler can map each to a status code without inspecting error strings.
type Outcome int

const (
	// OutcomeUnauthorized covers every failure case DV-F-15 requires to be
	// indistinguishable: a nonexistent email, a wrong password for an
	// email that does exist, and any error encountered along the way
	// (fail-secure, RD-04 — an uncertain result is treated as a failure,
	// never as success). Maps to HTTP 401.
	OutcomeUnauthorized Outcome = iota

	// OutcomeSuccess means the stored password hash was found and the
	// received password matched it (DV-F-14). Maps to HTTP 200.
	OutcomeSuccess
)

// String supports logging Outcome values without a type assertion.
func (o Outcome) String() string {
	switch o {
	case OutcomeUnauthorized:
		return "unauthorized"
	case OutcomeSuccess:
		return "success"
	default:
		return "unknown"
	}
}

// ErrAuthenticationFailed is the single sentinel Result.Err ever wraps on
// OutcomeUnauthorized (DV-F-15). It is returned as-is — never combined with
// a lookup error's or a verification error's own message — so that a log
// line built from Result.Err reads identically regardless of which
// underlying cause produced it. Login intentionally discards those
// underlying causes' content rather than merely omitting it from an HTTP
// response, per DV-F-15's explicit "nor in the log" wording.
var ErrAuthenticationFailed = errors.New("login: authentication failed")

// ErrPasswordVerificationFailed means password.VerifyPassword itself
// returned an error (e.g. the stored password_hash is malformed) rather
// than reporting a clean match/mismatch. Unlike ErrAuthenticationFailed,
// this is not a normal user-side auth failure — it signals internal data
// corruption or a bug, which is useful for an operator to distinguish in
// logs. It still maps to the same HTTP-facing OutcomeUnauthorized (still
// 401, per DV-F-15's response-uniformity requirement) and, critically,
// carries a fixed, generic message only: it must never wrap or embed
// password.VerifyPassword's own error content, since that content can
// include record-specific data (e.g. the malformed stored hash string
// itself) that would let a log reader correlate a failure back to a
// specific stored row/user — exactly what DV-F-15 forbids for the
// email/password distinction, and a stricter leak besides.
var ErrPasswordVerificationFailed = errors.New("login: password verification failed due to an internal error")

// Result is Login's return value. Err is nil only when Outcome is
// OutcomeSuccess. On OutcomeUnauthorized, Err is exactly
// ErrAuthenticationFailed for the two cases DV-F-15 requires to be
// indistinguishable (nonexistent email, wrong password), or exactly
// ErrPasswordVerificationFailed for an internal verification error — a
// case DV-F-15 does not require hiding, so long as the value itself
// carries no per-record content (see ErrPasswordVerificationFailed's doc
// comment).
type Result struct {
	Outcome Outcome
	Err     error
}

// Storage is the subset of persistence Login needs: retrieving the stored
// password_hash for an email hash (DV-F-13). Depending on this narrow
// interface, rather than on storage.Querier directly, lets tests
// substitute a hand-written fake (CONTRIBUTING.md §7.5) without a real
// database — same pattern as the registration package's Storage interface
// over storage.Beginner.
type Storage interface {
	GetPasswordHash(ctx context.Context, emailHash string) (string, error)
}

// Input holds the credentials a login request supplies. Email is typed as
// logging.Redacted, matching hashing.HashEmail's parameter, so an
// accidental log of Input prints "REDACTED" instead of the plaintext
// address (DV-F-03, RD-01).
type Input struct {
	Email    logging.Redacted
	Password []byte
}

// Login runs the login control flow described in this package's doc
// comment. store looks up the stored password hash by email hash; pepper
// is the shared secret DV-F-06 sources, needed by password.VerifyPassword
// to recompute the same hash DV-F-07 produced at registration.
//
// Per DV-F-15, a nonexistent email (store.GetPasswordHash's error) and a
// wrong password (password.VerifyPassword returning matched == false, err
// == nil) return the exact same Result{Outcome: OutcomeUnauthorized, Err:
// ErrAuthenticationFailed} — these two cases must never be distinguishable,
// in the response or in the log. A third case, password.VerifyPassword
// itself returning an error (e.g. a malformed stored hash), maps to the
// same Outcome but Err: ErrPasswordVerificationFailed instead — still 401,
// but distinguishable in a log for operational purposes, and carrying none
// of VerifyPassword's own error content (see ErrPasswordVerificationFailed's
// doc comment). Only a positive match returns OutcomeSuccess.
func Login(ctx context.Context, store Storage, pepper []byte, input Input) Result {
	emailHash := hashing.HashEmail(input.Email)

	storedHash, err := store.GetPasswordHash(ctx, emailHash)
	if err != nil {
		// DV-F-15: a nonexistent email must be indistinguishable, in both
		// the returned Result and any log built from it, from the
		// wrong-password case below. err's content (e.g. wrapping
		// storage.ErrUserNotFound) is deliberately not carried into Err.
		return Result{Outcome: OutcomeUnauthorized, Err: ErrAuthenticationFailed}
	}

	matched, err := password.VerifyPassword(input.Password, pepper, storedHash)
	if err != nil {
		// A verification error (not a clean mismatch) signals something
		// other than ordinary wrong credentials — e.g. data corruption or a
		// bug in the stored record. RD-04 (fail-secure) still applies: the
		// HTTP-facing Outcome stays Unauthorized. err's own content is
		// deliberately discarded here — only the fixed, generic sentinel is
		// returned — so nothing per-record ever reaches Result.
		return Result{Outcome: OutcomeUnauthorized, Err: ErrPasswordVerificationFailed}
	}
	if !matched {
		// DV-F-15: a wrong password must be indistinguishable, in both the
		// returned Result and any log built from it, from the
		// nonexistent-email case above.
		return Result{Outcome: OutcomeUnauthorized, Err: ErrAuthenticationFailed}
	}

	return Result{Outcome: OutcomeSuccess}
}
