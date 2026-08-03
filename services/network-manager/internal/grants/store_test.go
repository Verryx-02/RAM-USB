package grants

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Requirement: NM-F-11
//
// Real SQLite file, not a mock - persistence is exactly the category of
// code that looks right against a fake and fails for real (this
// session's own explicit verification instruction). No network, no other
// service, no Docker: SQLite is embedded, so a real file under t.TempDir()
// is a genuine component test, not an integration test that needs a
// stub.
func TestStore_RecordAndQueryGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")

	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if err := store.RecordGrant(ctx, "user@example.com", 42, "tag:storage-access", now.Add(12*time.Hour)); err != nil {
		t.Fatalf("RecordGrant() error = %v", err)
	}

	// Not yet expired at 'now'.
	expired, err := store.ExpiredGrants(ctx, now)
	if err != nil {
		t.Fatalf("ExpiredGrants() error = %v", err)
	}
	if len(expired) != 0 {
		t.Fatalf("ExpiredGrants() = %v, want none (grant is not yet expired)", expired)
	}

	// Expired 13 hours later.
	expired, err = store.ExpiredGrants(ctx, now.Add(13*time.Hour))
	if err != nil {
		t.Fatalf("ExpiredGrants() error = %v", err)
	}
	if len(expired) != 1 {
		t.Fatalf("ExpiredGrants() = %v, want exactly 1", expired)
	}
	got := expired[0]
	// KI-40: the address itself is never stored, only emailKey's hash.
	if got.EmailHash != emailKey("user@example.com") || got.NodeID != 42 || got.Tag != "tag:storage-access" {
		t.Fatalf("ExpiredGrants()[0] = %+v, want hash of user@example.com, nodeID=42, tag=tag:storage-access", got)
	}
	wantExpiry := now.Add(12 * time.Hour)
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, wantExpiry)
	}

	// A grant expiring at EXACTLY the query time must be included
	// ("expires_at <= ?", not "<") - the boundary itself, not just
	// well-before/well-after cases.
	if err := store.RecordGrant(ctx, "boundary@example.com", 99, "tag:storage-access", now.Add(12*time.Hour)); err != nil {
		t.Fatalf("RecordGrant() error = %v", err)
	}
	expired, err = store.ExpiredGrants(ctx, now.Add(12*time.Hour))
	if err != nil {
		t.Fatalf("ExpiredGrants() error = %v", err)
	}
	found := false
	for _, g := range expired {
		if g.EmailHash == emailKey("boundary@example.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ExpiredGrants() = %v, want boundary@example.com included (expires_at exactly equal to query time)", expired)
	}
}

// Requirement: NM-F-11
func TestStore_RecordGrant_ReplacesExistingRowForSameEmail(t *testing.T) {
	// Handler.Grant is idempotent per-email (a repeat login-time grant
	// for an already-granted user must extend the existing expiry, not
	// create a second row) - see store.go's schema doc comment.
	path := filepath.Join(t.TempDir(), "grants.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if err := store.RecordGrant(ctx, "user@example.com", 42, "tag:storage-access", now.Add(time.Hour)); err != nil {
		t.Fatalf("RecordGrant() (1st) error = %v", err)
	}
	if err := store.RecordGrant(ctx, "user@example.com", 42, "tag:storage-access", now.Add(24*time.Hour)); err != nil {
		t.Fatalf("RecordGrant() (2nd) error = %v", err)
	}

	expired, err := store.ExpiredGrants(ctx, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ExpiredGrants() error = %v", err)
	}
	if len(expired) != 0 {
		t.Fatalf("ExpiredGrants() = %v, want none - the 2nd RecordGrant should have replaced the 1st's shorter expiry", expired)
	}
}

// Requirement: NM-F-11
func TestStore_DeleteGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if err := store.RecordGrant(ctx, "user@example.com", 42, "tag:storage-access", now.Add(-time.Hour)); err != nil {
		t.Fatalf("RecordGrant() error = %v", err)
	}
	deleted, err := store.DeleteGrant(ctx, emailKey("user@example.com"), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DeleteGrant() error = %v", err)
	}
	if !deleted {
		t.Fatal("DeleteGrant() = false, want true (the row existed with exactly that expiry)")
	}

	expired, err := store.ExpiredGrants(ctx, now)
	if err != nil {
		t.Fatalf("ExpiredGrants() error = %v", err)
	}
	if len(expired) != 0 {
		t.Fatalf("ExpiredGrants() = %v, want none after delete", expired)
	}

	// Deleting an already-absent row is not an error (mirrors
	// storage.DeleteUser's DV-F-10 convention), just a false claim.
	deleted, err = store.DeleteGrant(ctx, emailKey("user@example.com"), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DeleteGrant() on an already-deleted row: error = %v, want nil", err)
	}
	if deleted {
		t.Fatal("DeleteGrant() on an already-deleted row = true, want false")
	}
}

// Requirement: NM-F-11
//
// This is the empirical "survives a Network-Manager restart" proof this
// session's task explicitly required, not just a structural assertion:
// it opens the SQLite file, writes a grant, closes the *Store exactly the
// way a process shutdown would (no special teardown), then opens a brand
// new *Store against the same path - simulating a real process restart
// pointed at the same durable file - and confirms the grant is still
// there. The file itself is what survives; Docker/compose-level bind-
// mount wiring (making that file's path durable across a *container*
// restart specifically) is a deployment concern this session's task
// explicitly places out of scope - see store.go's package doc comment.
func TestStore_GrantSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	func() {
		store, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("Open() (1st process) error = %v", err)
		}
		defer func() { _ = store.Close() }()

		if err := store.RecordGrant(ctx, "user@example.com", 42, "tag:storage-access", now.Add(12*time.Hour)); err != nil {
			t.Fatalf("RecordGrant() error = %v", err)
		}
	}()
	// store is now fully closed - the same state a killed/restarted
	// process would leave behind.

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() (2nd process, after 'restart') error = %v", err)
	}
	defer func() { _ = reopened.Close() }()

	expired, err := reopened.ExpiredGrants(ctx, now.Add(13*time.Hour))
	if err != nil {
		t.Fatalf("ExpiredGrants() after reopen: error = %v", err)
	}
	if len(expired) != 1 || expired[0].EmailHash != emailKey("user@example.com") || expired[0].NodeID != 42 {
		t.Fatalf("ExpiredGrants() after reopen = %v, want the grant recorded before the simulated restart", expired)
	}
}

// Requirement: NM-F-10, NM-F-11
//
// The conditional delete is what closes the sweep-vs-login race: a sweep
// still holding the expiry it read at the start of the tick must not
// remove a row a concurrent login has since renewed.
func TestStore_DeleteGrant_IsConditionalOnTheExpiryRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	oldExpiry := now.Add(-time.Hour)

	if err := store.RecordGrant(ctx, "user@example.com", 42, "tag:storage-access", oldExpiry); err != nil {
		t.Fatalf("RecordGrant() error = %v", err)
	}
	// The concurrent login: same email, fresh 12h expiry.
	if err := store.RecordGrant(ctx, "user@example.com", 42, "tag:storage-access", now.Add(12*time.Hour)); err != nil {
		t.Fatalf("RecordGrant() (renewal) error = %v", err)
	}

	deleted, err := store.DeleteGrant(ctx, emailKey("user@example.com"), oldExpiry)
	if err != nil {
		t.Fatalf("DeleteGrant() error = %v", err)
	}
	if deleted {
		t.Fatal("DeleteGrant() = true, want false - the row was renewed, so a stale claim must not remove it")
	}

	stillThere, err := store.ExpiredGrants(ctx, now.Add(13*time.Hour))
	if err != nil {
		t.Fatalf("ExpiredGrants() error = %v", err)
	}
	if len(stillThere) != 1 {
		t.Fatalf("ExpiredGrants() = %v, want the renewed grant to have survived", stillThere)
	}
}

// Requirement: NM-F-11, RD-01
//
// KI-40: neither table may leave a user's address in plaintext on disk -
// asserted against the real file's bytes, the only place that guarantee
// can actually be checked.
func TestStore_NoPlaintextEmailOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")
	ctx := context.Background()
	const email = "plaintext-canary@example.com"

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := store.RecordGrant(ctx, email, 42, "tag:storage-access", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RecordGrant() error = %v", err)
	}
	if err := store.RecordPreAuthKeyID(ctx, email, 7); err != nil {
		t.Fatalf("RecordPreAuthKeyID() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is this test's own t.TempDir()-derived SQLite file, never externally-supplied input.
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	if bytes.Contains(data, []byte(email)) {
		t.Fatal("the SQLite file contains the plaintext email address")
	}
	if !bytes.Contains(data, []byte(emailKey(email))) {
		t.Fatal("the SQLite file does not contain the hashed key, so this test is not actually checking the written rows")
	}
}

// Requirement: NM-F-10
func TestStore_RestoreGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	g := Grant{EmailHash: emailKey("user@example.com"), NodeID: 42, Tag: "tag:storage-access", ExpiresAt: now.Add(-time.Hour)}

	if err := store.RestoreGrant(ctx, g); err != nil {
		t.Fatalf("RestoreGrant() error = %v", err)
	}

	expired, err := store.ExpiredGrants(ctx, now)
	if err != nil {
		t.Fatalf("ExpiredGrants() error = %v", err)
	}
	if len(expired) != 1 || expired[0] != g {
		t.Fatalf("ExpiredGrants() = %+v, want the restored grant %+v", expired, g)
	}
}
