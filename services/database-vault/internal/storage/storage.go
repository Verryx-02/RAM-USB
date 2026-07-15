// Package storage persists a Database-Vault user record in a single atomic
// transaction (DV-F-08). It performs no hashing or encryption itself: the
// email hash (DV-F-03), the encrypted email (DV-F-04), and the password hash
// (DV-F-07) are all computed by their own packages before reaching SaveUser.
// The password salt is not stored as a separate column: it is embedded in
// the self-describing password_hash PHC string (DV-F-07's storage format)
// and recovered from it at login time (DV-F-13), never persisted twice.
//
// Scope note: this package only covers DV-F-08 (save the user record
// atomically). Asking Storage-Service to create the POSIX user (DV-F-09),
// rolling back on POSIX-creation failure (DV-F-10), the success response
// (DV-F-11), and the HTTP 409 duplicate-registration response (DV-F-12) are
// separate requirements, implemented elsewhere. SaveUser does distinguish a
// unique-constraint violation (ErrDuplicateUser) from any other insert
// failure, since DV-F-12 will need to catch that case specifically.
package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
)

// insertUserSQL matches the schema in
// docs/design/diagrams/06-data-er-database-vault.puml exactly: column names,
// types, and the email_hash primary key / ssh_public_key unique constraint
// this file's unique-violation handling depends on.
const insertUserSQL = `
INSERT INTO users (
	email_hash, email_encrypted, password_hash,
	ssh_public_key, posix_username, registered_at
) VALUES ($1, $2, $3, $4, $5, $6)`

// pgUniqueViolationCode is the PostgreSQL SQLSTATE for unique_violation
// (23505), documented at
// https://www.postgresql.org/docs/current/errcodes-appendix.html. Used to
// recognize a duplicate email_hash or ssh_public_key without depending on a
// separate error-code constants module for a single value.
const pgUniqueViolationCode = "23505"

// ErrDuplicateUser means the insert violated the users table's email_hash
// primary key or ssh_public_key unique constraint (DV-F-12's future 409
// handling matches on this via errors.Is; SaveUser itself does not produce
// an HTTP response).
var ErrDuplicateUser = errors.New("storage: user with this email or SSH key already exists")

// Tx is the minimal subset of pgx.Tx that SaveUser needs. Depending on this
// narrow interface, instead of the full pgx.Tx interface (which also
// includes CopyFrom, SendBatch, LargeObjects, Prepare, Query, QueryRow,
// Begin, Conn — none of which SaveUser calls), lets unit tests substitute a
// small hand-written fake per CONTRIBUTING.md §7.5.
type Tx interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Beginner starts a Tx. It exists so SaveUser depends on an interface, not
// directly on *pgxpool.Pool, keeping the same test-substitution benefit as
// Tx above.
type Beginner interface {
	Begin(ctx context.Context) (Tx, error)
}

// PoolBeginner adapts a *pgxpool.Pool to Beginner. *pgxpool.Pool.Begin
// returns the full pgx.Tx interface, which satisfies this package's
// narrower Tx interface by construction (pgx.Tx declares every method Tx
// requires, plus others SaveUser never calls).
type PoolBeginner struct {
	Pool *pgxpool.Pool
}

// Begin implements Beginner.
func (b PoolBeginner) Begin(ctx context.Context) (Tx, error) {
	return b.Pool.Begin(ctx)
}

// UserRecord holds every already-computed field DV-F-08 persists. Callers
// build this from hashing.HashEmail, encryption.EncryptEmail, and
// password.HashPassword — SaveUser does not call any of those itself. There
// is no separate salt field: password.HashPassword's PHC-format output
// already embeds the salt used to compute it (DV-F-07).
type UserRecord struct {
	EmailHash      string
	EmailEncrypted encryption.EncryptedEmail
	PasswordHash   string
	SSHPublicKey   string
	PosixUsername  string
}

// SaveUser persists record inside a single atomic transaction (DV-F-08):
// the insert either fully commits or, on any failure, is rolled back. db is
// typically a PoolBeginner wrapping the service's *pgxpool.Pool in
// production, or a hand-written fake in tests.
//
// registered_at is set here, to the moment of the call
// (time.Now().UTC()) — the SRS names no other source for this column,
// and UTC avoids ambiguity from a server's local timezone.
//
// A returned error wrapping ErrDuplicateUser (checked via errors.Is) means
// the insert violated the email_hash or ssh_public_key unique constraint;
// any other error means the transaction failed for a different reason. In
// both cases the transaction has already been rolled back before SaveUser
// returns, per RD-04 (fail-secure): no partial row is ever left behind.
func SaveUser(ctx context.Context, db Beginner, record UserRecord) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin transaction: %w", err)
	}

	encryptedEmail, err := marshalEncryptedEmail(record.EmailEncrypted)
	if err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("storage: marshal encrypted email: %w (rollback also failed: %v)", err, rbErr)
		}
		return fmt.Errorf("storage: marshal encrypted email: %w", err)
	}

	_, execErr := tx.Exec(ctx, insertUserSQL,
		record.EmailHash,
		encryptedEmail,
		record.PasswordHash,
		record.SSHPublicKey,
		record.PosixUsername,
		time.Now().UTC(),
	)
	if execErr != nil {
		classified := classifyInsertError(execErr)
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("%w (rollback also failed: %v)", classified, rbErr)
		}
		return classified
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit transaction: %w", err)
	}

	return nil
}

// classifyInsertError wraps a raw insert error, distinguishing a
// unique-constraint violation (ErrDuplicateUser) from any other failure, so
// a future DV-F-12 handler can tell them apart via errors.Is without this
// package needing to know anything about HTTP status codes.
func classifyInsertError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolationCode {
		return fmt.Errorf("%w: %s", ErrDuplicateUser, pgErr.ConstraintName)
	}

	return fmt.Errorf("storage: insert user: %w", err)
}
