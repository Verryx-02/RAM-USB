package grants

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// meshUsersSchema is applied once, idempotently, alongside the grants
// table's own schema (see store.go's package doc comment for why this
// table lives in the same Store/connection despite being conceptually
// unrelated to a grant). email is the primary key: NM-F-08 creates exactly
// one Headscale user, and therefore exactly one pre-auth key, per
// registered email - a repeat NM-F-08 call for the same email (should one
// ever happen) replaces the prior row rather than accumulating a second
// one, the same idempotency CreateMeshUser's own doc comment already
// establishes for the underlying Headscale calls.
const meshUsersSchema = `
CREATE TABLE IF NOT EXISTS mesh_users (
	email            TEXT PRIMARY KEY,
	pre_auth_key_id  INTEGER NOT NULL
);
`

// RecordPreAuthKeyID persists (or, for an already-recorded email, replaces)
// the Headscale pre-auth-key ID CreateMeshUser (NM-F-08) generated for
// email. This is the mapping GrantStorageAccess (NM-F-09) needs at every
// future login - see this package's own doc comment and internal/headscale/
// client.go's "Bug fix" section for why. Satisfies httpapi.MeshUserStore.
func (s *Store) RecordPreAuthKeyID(ctx context.Context, email string, preAuthKeyID uint64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO mesh_users (email, pre_auth_key_id) VALUES (?, ?)
		 ON CONFLICT(email) DO UPDATE SET pre_auth_key_id = excluded.pre_auth_key_id`,
		email, preAuthKeyID,
	)
	if err != nil {
		// RD-01/DV-F-03's "credentials stay out of logs" discipline
		// applied here even though an email is not itself a password:
		// this error is logged by internal/httpapi.Handler, so the
		// wrapped message deliberately does not embed email.
		return fmt.Errorf("grants: record pre-auth key id: %w", err)
	}
	return nil
}

// PreAuthKeyIDForEmail looks up the Headscale pre-auth-key ID recorded for
// email by an earlier RecordPreAuthKeyID call. found is false, with a nil
// error, when no row exists for email (e.g. this email was never
// registered through NM-F-08, or CreateMeshUser succeeded at Headscale but
// this table's write failed - see internal/httpapi.Handler.CreateMeshUser's
// own doc comment for why that is treated as a hard failure, not silently
// swallowed) - RD-04, fail-secure: the caller must treat "not found" as a
// denial, never guess or fall back to any other lookup. Satisfies
// httpapi.MeshUserStore.
func (s *Store) PreAuthKeyIDForEmail(ctx context.Context, email string) (uint64, bool, error) {
	var preAuthKeyID uint64
	err := s.db.QueryRowContext(ctx,
		`SELECT pre_auth_key_id FROM mesh_users WHERE email = ?`,
		email,
	).Scan(&preAuthKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("grants: query pre-auth key id: %w", err)
	}
	return preAuthKeyID, true, nil
}
