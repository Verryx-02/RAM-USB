// Package registration orchestrates the three branches of Database-Vault's
// registration control flow that happen after DV-F-02 (input validation),
// DV-F-03 (email hashing), DV-F-04 (email encryption), and DV-F-07 (password
// hashing) have already produced their outputs, per
// docs/design/diagrams/03-usecases-sequence-uc01-registration.puml:
//
//   - DV-F-12: a duplicate email or SSH key is rejected without leaking
//     which field collided or any other detail beyond "duplicate".
//   - DV-F-09/DV-F-11: on no duplicate, a POSIX username is generated, the
//     user record is saved, Storage-Service is asked to create the POSIX
//     user, and success is reported back to the caller.
//   - DV-F-10: if POSIX-user creation fails after the record was saved, the
//     record is deleted as a compensating rollback and failure is reported
//     back to the caller.
//
// This package does not compute any hash or ciphertext itself — Register's
// RegistrationInput takes already-computed fields exactly like
// storage.UserRecord does. It also does not implement any HTTP boundary:
// Result's Outcome field is what a future handler maps to 201/409/5xx,
// without inspecting error strings (that handler is out of scope here, the
// same gap already flagged and accepted for DV-F-08/DV-F-09).
package registration

import (
	"context"
	"errors"
	"fmt"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/posix"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// Outcome distinguishes the three ways Register can conclude, so a future
// HTTP handler can map each to a status code without inspecting error
// strings.
type Outcome int

const (
	// OutcomeRegistered means the user record was saved and the POSIX user
	// was created successfully (DV-F-11). Maps to HTTP 201.
	OutcomeRegistered Outcome = iota

	// OutcomeDuplicate means the email or SSH key already exists (DV-F-12).
	// Maps to HTTP 409, and the caller must not surface Result.Err's
	// details to the client, only that registration failed.
	OutcomeDuplicate

	// OutcomeFailed means registration did not succeed for any reason other
	// than a duplicate: POSIX-user creation failed (DV-F-10), the initial
	// save failed for a non-duplicate reason, or username generation
	// failed. Maps to a 5xx.
	OutcomeFailed
)

// String supports logging Outcome values without a type assertion.
func (o Outcome) String() string {
	switch o {
	case OutcomeRegistered:
		return "registered"
	case OutcomeDuplicate:
		return "duplicate"
	case OutcomeFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Result is Register's return value. Err is an internal detail for logging
// only — per DV-F-12, a caller mapping OutcomeDuplicate to HTTP 409 must not
// echo Err's content back to the client.
type Result struct {
	Outcome Outcome

	// PosixUsername is set only when Outcome is OutcomeRegistered.
	PosixUsername string

	// Err is nil only when Outcome is OutcomeRegistered.
	Err error
}

// ErrOrphanedRecord means POSIX-user creation failed AND the compensating
// rollback (storage.DeleteUser) also failed: the user record was not
// deleted, but no POSIX account exists for it either. Nothing currently
// monitors for rows in this state — a future operational task should watch
// for errors.Is(result.Err, ErrOrphanedRecord) rather than assume the
// database is always consistent with the POSIX user list.
var ErrOrphanedRecord = errors.New("registration: compensating rollback failed after POSIX user creation failure; user record may be orphaned in the database")

// RegistrationInput holds every field Register needs that some earlier step
// has already computed: the email hash (DV-F-03), the encrypted email
// (DV-F-04), the password hash (DV-F-07), and the (already
// structurally-validated, DV-F-02) SSH public key. Register does not
// recompute any of these — it only generates the POSIX username and decides
// what to do with SaveUser/CreatePOSIXUser's outcomes.
type RegistrationInput struct {
	EmailHash      string
	EmailEncrypted encryption.EncryptedEmail
	PasswordHash   string
	SSHPublicKey   string
}

// Register runs the registration control flow described in this package's
// doc comment. store persists and (on rollback) deletes the user record;
// posixSvc asks Storage-Service to create the POSIX user.
func Register(ctx context.Context, store Storage, posixSvc POSIXProvisioner, input RegistrationInput) Result {
	username, err := posix.GenerateUsername()
	if err != nil {
		return Result{
			Outcome: OutcomeFailed,
			Err:     fmt.Errorf("registration: generate posix username: %w", err),
		}
	}

	record := storage.UserRecord{
		EmailHash:      input.EmailHash,
		EmailEncrypted: input.EmailEncrypted,
		PasswordHash:   input.PasswordHash,
		SSHPublicKey:   input.SSHPublicKey,
		PosixUsername:  username,
	}

	if err := store.SaveUser(ctx, record); err != nil {
		if errors.Is(err, storage.ErrDuplicateUser) {
			// DV-F-12: reject without giving details beyond "duplicate".
			// Err is kept for internal logging only, not for the client.
			return Result{Outcome: OutcomeDuplicate, Err: err}
		}
		return Result{
			Outcome: OutcomeFailed,
			Err:     fmt.Errorf("registration: save user record: %w", err),
		}
	}

	if err := posixSvc.CreatePOSIXUser(ctx, username); err != nil {
		// DV-F-10: compensating rollback. The record was saved above; it
		// must not survive a failed POSIX-user creation.
		if delErr := store.DeleteUser(ctx, input.EmailHash); delErr != nil {
			return Result{
				Outcome: OutcomeFailed,
				Err:     fmt.Errorf("%w: posix creation error: %v; delete error: %v", ErrOrphanedRecord, err, delErr),
			}
		}
		return Result{
			Outcome: OutcomeFailed,
			Err:     fmt.Errorf("registration: posix user creation failed, user record rolled back: %w", err),
		}
	}

	// DV-F-11: both steps succeeded.
	return Result{Outcome: OutcomeRegistered, PosixUsername: username}
}
