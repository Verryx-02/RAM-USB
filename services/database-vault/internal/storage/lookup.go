// This file adds the read-side counterpart to storage.go's SaveUser/
// DeleteUser: retrieving a user's stored password_hash by email_hash, the
// database step DV-F-13 needs before the login package (DV-F-13/DV-F-14/
// DV-F-15) can recompute Argon2id and compare it against the received
// password. It does not decode the PHC string or touch the salt embedded
// in it — password.VerifyPassword does that (see the package doc comment
// on storage.go for why there is no separate password_salt column).
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// selectPasswordHashSQL matches the schema in
// docs/design/diagrams/06-data-er-database-vault.puml, same as
// insertUserSQL in storage.go.
const selectPasswordHashSQL = `SELECT password_hash FROM users WHERE email_hash = $1`

// ErrUserNotFound means no row matches the given email_hash. Per DV-F-15,
// callers (specifically the login package) must treat this identically to
// a wrong-password failure: both produce the same HTTP 401 and the same
// log line, with nothing here or upstream distinguishing the two cases.
var ErrUserNotFound = errors.New("storage: no user found for this email hash")

// Querier is the minimal subset of *pgxpool.Pool that GetPasswordHash
// needs: a single QueryRow call. Depending on this narrow interface,
// instead of *pgxpool.Pool directly, lets unit tests substitute a small
// hand-written fake per CONTRIBUTING.md §7.5 — same pattern as this
// package's existing Tx/Beginner interfaces over SaveUser/DeleteUser.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PoolQuerier adapts a *pgxpool.Pool to Querier. *pgxpool.Pool.QueryRow
// already returns pgx.Row, so no wrapping logic is needed beyond binding
// the receiver, mirroring PoolBeginner over *pgxpool.Pool.Begin.
type PoolQuerier struct {
	Pool *pgxpool.Pool
}

// QueryRow implements Querier.
func (q PoolQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return q.Pool.QueryRow(ctx, sql, args...)
}

// GetPasswordHash retrieves the stored password_hash PHC string (DV-F-07)
// for the user identified by emailHash (DV-F-03), so a caller can recompute
// Argon2id against it (DV-F-13/DV-F-14). It performs no transaction: a
// single read needs no Begin/Commit/Rollback the way SaveUser/DeleteUser's
// writes do.
//
// A returned error wrapping ErrUserNotFound (checked via errors.Is) means no
// row matched emailHash; any other error means the query itself failed. Per
// DV-F-15, the login package must not treat ErrUserNotFound any differently
// from a matched-but-wrong-password result — this function only reports
// what happened at the database layer, it does not decide the HTTP/log
// behavior.
func GetPasswordHash(ctx context.Context, db Querier, emailHash string) (string, error) {
	var passwordHash string

	if err := db.QueryRow(ctx, selectPasswordHashSQL, emailHash).Scan(&passwordHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("%w", ErrUserNotFound)
		}
		return "", fmt.Errorf("storage: query password hash: %w", err)
	}

	return passwordHash, nil
}
