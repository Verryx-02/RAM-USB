// Package grants implements NM-F-11 (persisting NM-F-09's storage-access
// grant expiries, so a Network-Manager restart does not lose them) and
// NM-F-10 (the periodic sweep that finds expired grants and revokes them).
//
// This package also owns a second, unrelated table (meshusers.go):
// mesh_users, a permanent email -> Headscale-pre-auth-key-ID mapping,
// added to fix a real bug reproduced live against a running Headscale
// instance (see internal/headscale/client.go's package doc comment,
// "Bug fix" section, for the full root cause). GrantStorageAccess (NM-F-09)
// needs this ID at every login to find a user's mesh node, since
// Headscale's own per-user node ownership cannot be used for that lookup.
// This table shares the Store's SQLite connection/schema-application
// machinery (opened once, by the same Open call) purely because it is
// already the right, already-wired infrastructure for a small durable
// table - it is NOT a grant, and its rows have a fundamentally different
// lifecycle from the grants table above: a grants row is deliberately
// time-limited and deleted by NM-F-10's sweep once expired, while a
// mesh_users row is written once at NM-F-08 (registration) time and never
// expires or gets swept - it must survive for the lifetime of the user's
// account, since every future login depends on it. Do not add expiry/sweep
// logic to mesh_users; do not fold NM-F-11's grant rows and this mapping
// into one table.
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
// volume into deployments/compose/network-manager.yml is explicitly out of
// this task's scope (see this session's own report); restart survival was
// instead verified empirically against a real SQLite file and a real
// process restart, not merely asserted structurally - see this package's
// own test file and the session's report for exactly how.
package grants

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// emailKey is the only form of a user's email this package ever writes to
// disk: the hex-encoded SHA-256 of the lowercased address, the same
// normalize-then-hash rule Database-Vault applies for its own index
// (DV-F-03) and internal/headscale.meshUsername applies before handing an
// identifier to Headscale. Network-Manager only ever needs a lookup key,
// never the plaintext, so nothing is lost by never storing it.
func emailKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	return hex.EncodeToString(sum[:])
}

// schema is applied once, idempotently, every time Open runs (CREATE
// TABLE IF NOT EXISTS - no golang-migrate/versioned-migration machinery
// for one small table, unlike Database-Vault's own schema package, which
// tracks many tables across an evolving schema). expires_at is stored as
// a Unix timestamp (INTEGER, UTC seconds) - SQLite has no native
// timestamp type, and an integer sorts/compares correctly for
// ExpiredGrants' "less than now" query without any timezone ambiguity.
//
// email_hash (emailKey: SHA-256 of the lowercased address) is the primary
// key: NM-F-09's grant is one-per-user (Handler.Grant is idempotent -
// granting an already-granted user just extends their existing node's tag
// set, see internal/headscale.unionTag), so a repeat grant for the same
// email should replace the prior row's expiry, not accumulate a second
// one. The address itself is never stored: a lookup key is all this
// package needs (see emailKey).
const schema = `
CREATE TABLE IF NOT EXISTS grants (
	email_hash TEXT PRIMARY KEY,
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
// both schema (the grants table, NM-F-11) and meshUsersSchema (the
// mesh_users table - see this package's own doc comment for why it lives
// here). path is any value database/sql's "sqlite" driver
// (modernc.org/sqlite) accepts as a filesystem path - see this package's
// doc comment for why the durability guarantee NM-F-11 needs comes from
// where the caller points path, not from anything this function does.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("grants: open %s: %w", path, err)
	}

	// SQLite only truly supports one writer at a time; capping the pool
	// at a single connection avoids "database is locked" errors under
	// concurrent access from this process's own HTTP handler goroutines
	// and sweep loop, at the cost of serializing writes - an acceptable
	// trade for this table's tiny write volume (one row write per
	// login-time grant, one row per expiry per sweep tick, one row per
	// registration for mesh_users).
	db.SetMaxOpenConns(1)

	// Migration, such as it is: a database file written before emails were
	// hashed still has a plaintext "email" column, which every statement
	// below would fail against. There is no versioned-migration machinery
	// for these two tiny tables (see schema's own comment), and the rows
	// are cheap to regenerate - a grants row is re-created at the user's
	// next login, a mesh_users row at re-registration - so the legacy
	// form is dropped rather than converted, which also means no
	// plaintext address survives in the file.
	if err := dropLegacyPlaintextTable(ctx, db, `PRAGMA table_info(grants)`, `DROP TABLE grants`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := dropLegacyPlaintextTable(ctx, db, `PRAGMA table_info(mesh_users)`, `DROP TABLE mesh_users`); err != nil {
		_ = db.Close()
		return nil, err
	}

	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("grants: apply schema: %w", err)
	}
	if _, err := db.ExecContext(ctx, meshUsersSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("grants: apply mesh_users schema: %w", err)
	}

	return &Store{db: db}, nil
}

// dropLegacyPlaintextTable runs dropStmt if the table described by
// infoStmt (a "PRAGMA table_info(...)" query) still has a plaintext
// "email" column. Both statements are caller-supplied literals, never
// built from external input. A table that does not exist yet reports no
// columns, so this is a no-op on a fresh file.
func dropLegacyPlaintextTable(ctx context.Context, db *sql.DB, infoStmt, dropStmt string) error {
	rows, err := db.QueryContext(ctx, infoStmt)
	if err != nil {
		return fmt.Errorf("grants: inspect legacy schema: %w", err)
	}
	defer func() { _ = rows.Close() }()

	legacy := false
	for rows.Next() {
		var (
			cid        int
			name       string
			declType   string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &declType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("grants: inspect legacy schema: %w", err)
		}
		if name == "email" {
			legacy = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("grants: inspect legacy schema: %w", err)
	}
	if !legacy {
		return nil
	}

	if _, err := db.ExecContext(ctx, dropStmt); err != nil {
		return fmt.Errorf("grants: drop legacy plaintext table: %w", err)
	}
	return nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// RecordGrant persists (or, for an already-granted email, replaces) one
// grant's node, tag, and expiry (NM-F-11). Satisfies
// httpapi.GrantRecorder.
func (s *Store) RecordGrant(ctx context.Context, email string, nodeID uint64, tag string, expiresAt time.Time) error {
	return s.recordGrant(ctx, emailKey(email), nodeID, tag, expiresAt)
}

// RestoreGrant re-inserts a row SweepOnce deleted before a revoke that
// then failed, so the next sweep tick retries it instead of forgetting an
// ACL tag that is still applied (RD-04, fail-secure). Takes an already-
// hashed key, since that is all a swept Grant carries.
func (s *Store) RestoreGrant(ctx context.Context, g Grant) error {
	return s.recordGrant(ctx, g.EmailHash, g.NodeID, g.Tag, g.ExpiresAt)
}

func (s *Store) recordGrant(ctx context.Context, emailHash string, nodeID uint64, tag string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO grants (email_hash, node_id, tag, expires_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(email_hash) DO UPDATE SET node_id = excluded.node_id, tag = excluded.tag, expires_at = excluded.expires_at`,
		emailHash, nodeID, tag, expiresAt.UTC().Unix(),
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
// EmailHash is emailKey's hash, never the address itself - nothing in this
// package or its callers needs the plaintext.
type Grant struct {
	EmailHash string
	NodeID    uint64
	Tag       string
	ExpiresAt time.Time
}

// ExpiredGrants returns every grant whose expiry is at or before now
// (NM-F-10's sweep query). Satisfies this package's own SweepStore
// interface.
func (s *Store) ExpiredGrants(ctx context.Context, now time.Time) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT email_hash, node_id, tag, expires_at FROM grants WHERE expires_at <= ?`,
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
		if err := rows.Scan(&g.EmailHash, &g.NodeID, &g.Tag, &expiresAtUTC); err != nil {
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

// DeleteGrant removes one persisted grant row, identified by its hashed
// email key AND the exact expiry the caller read - NM-F-10's sweep claims
// a row this way before revoking it, so a login that renewed the grant in
// between (new expires_at) is not deleted out from under the user by a
// sweep still holding the old value. Returns whether a row was actually
// removed: false means somebody else already renewed or deleted it, and
// the caller must not revoke.
func (s *Store) DeleteGrant(ctx context.Context, emailHash string, expiresAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM grants WHERE email_hash = ? AND expires_at = ?`,
		emailHash, expiresAt.UTC().Unix(),
	)
	if err != nil {
		return false, fmt.Errorf("grants: delete grant: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("grants: delete grant: rows affected: %w", err)
	}
	return affected > 0, nil
}
