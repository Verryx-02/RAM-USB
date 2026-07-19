// Package grants implements NM-F-11 (persisting NM-F-09's storage-access
// grant expiries, so a Network-Manager restart does not lose them) and
// NM-F-10 (the periodic sweep that finds expired grants and revokes them).
//
// Storage choice: embedded SQLite (modernc.org/sqlite - a CGo-free port,
// matching Network-Manager's existing CGO_ENABLED=0 distroless build,
// see deployments/docker/network-manager/Dockerfile), not a new Postgres
// container. Decision made and confirmed before this package was written,
// not re-litigated here: a small table of node/tag/expiry rows (one row
// per user with an active grant, updated/deleted on every grant/revoke)
// does not justify a whole new stateful container the way Database-Vault's
// user table does, and it mirrors Headscale's own upstream-recommended
// choice of SQLite over Postgres for a comparably small coordination
// dataset (see this package's sibling internal/headscale's own doc
// comment history).
//
// File location: the SQLite file's path is entirely caller-supplied (see
// Open) - this package makes no assumption about where on disk it lives.
// cmd/network-manager/main.go is expected to point it at a path backed by
// a durable volume outside the container's writable layer, so the file
// (and therefore every persisted grant) survives a container restart -
// that is the whole point of NM-F-11. Wiring an actual bind-mounted
// volume into deployments/docker-compose.dev.yml is explicitly out of
// this task's scope (see this session's own report); restart survival was
// instead verified empirically against a real SQLite file and a real
// process restart, not merely asserted structurally - see this package's
// own test file and the session's report for exactly how.
package grants

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// schema is applied once, idempotently, every time Open runs (CREATE
// TABLE IF NOT EXISTS - no golang-migrate/versioned-migration machinery
// for one small table, unlike Database-Vault's own schema package, which
// tracks many tables across an evolving schema). expires_at is stored as
// a Unix timestamp (INTEGER, UTC seconds) - SQLite has no native
// timestamp type, and an integer sorts/compares correctly for
// ExpiredGrants' "less than now" query without any timezone ambiguity.
//
// email is the primary key: NM-F-09's grant is one-per-user (Handler.Grant
// is idempotent - granting an already-granted user just extends their
// existing node's tag set, see internal/headscale.unionTag), so a repeat
// grant for the same email should replace the prior row's expiry, not
// accumulate a second one.
const schema = `
CREATE TABLE IF NOT EXISTS grants (
	email      TEXT PRIMARY KEY,
	node_id    INTEGER NOT NULL,
	tag        TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
`

// Store is a SQLite-backed persistence layer for NM-F-09's grants
// (NM-F-11). Its methods satisfy httpapi.GrantRecorder and this package's
// own SweepStore interface directly through Go's structural typing - no
// adapter type is needed at either call site, the same shape already
// established for headscale.Service and paho's mqtt.Client elsewhere in
// this codebase.
type Store struct {
	db *sql.DB
}

// Open opens (creating if absent) the SQLite database at path and applies
// schema. path is any value database/sql's "sqlite" driver
// (modernc.org/sqlite) accepts as a filesystem path - see this package's
// doc comment for why the durability guarantee NM-F-11 needs comes from
// where the caller points path, not from anything this function does.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("grants: open %s: %w", path, err)
	}

	// SQLite only truly supports one writer at a time; capping the pool
	// at a single connection avoids "database is locked" errors under
	// concurrent access from this process's own HTTP handler goroutines
	// and sweep loop, at the cost of serializing writes - an acceptable
	// trade for this table's tiny write volume (one row write per
	// login-time grant, one row per expiry per sweep tick).
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("grants: apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// RecordGrant persists (or, for an already-granted email, replaces) one
// grant's node, tag, and expiry (NM-F-11). Satisfies
// httpapi.GrantRecorder.
func (s *Store) RecordGrant(ctx context.Context, email string, nodeID uint64, tag string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO grants (email, node_id, tag, expires_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET node_id = excluded.node_id, tag = excluded.tag, expires_at = excluded.expires_at`,
		email, nodeID, tag, expiresAt.UTC().Unix(),
	)
	if err != nil {
		// RD-01/DV-F-03's "credentials stay out of logs" discipline
		// applied here even though an email is not itself a password:
		// this error is logged by internal/httpapi.Handler, so the
		// wrapped message deliberately does not embed email.
		return fmt.Errorf("grants: record grant: %w", err)
	}
	return nil
}

// Grant is one persisted row: which node holds which ACL tag, until when.
type Grant struct {
	Email     string
	NodeID    uint64
	Tag       string
	ExpiresAt time.Time
}

// ExpiredGrants returns every grant whose expiry is at or before now
// (NM-F-10's sweep query). Satisfies this package's own SweepStore
// interface.
func (s *Store) ExpiredGrants(ctx context.Context, now time.Time) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT email, node_id, tag, expires_at FROM grants WHERE expires_at <= ?`,
		now.UTC().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("grants: query expired grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []Grant
	for rows.Next() {
		var (
			g            Grant
			expiresAtUTC int64
		)
		if err := rows.Scan(&g.Email, &g.NodeID, &g.Tag, &expiresAtUTC); err != nil {
			return nil, fmt.Errorf("grants: scan expired grant: %w", err)
		}
		g.ExpiresAt = time.Unix(expiresAtUTC, 0).UTC()
		result = append(result, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grants: iterate expired grants: %w", err)
	}

	return result, nil
}

// DeleteGrant removes email's persisted grant row, once NM-F-10's sweep
// has revoked the corresponding ACL tag. A zero-row delete (already
// absent) is not itself an error - same convention as Database-Vault's
// storage.DeleteUser (DV-F-10).
func (s *Store) DeleteGrant(ctx context.Context, email string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE email = ?`, email); err != nil {
		return fmt.Errorf("grants: delete grant: %w", err)
	}
	return nil
}
