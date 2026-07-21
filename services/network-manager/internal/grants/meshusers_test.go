package grants

import (
	"context"
	"path/filepath"
	"testing"
)

// Requirement: NM-F-08, NM-F-09
//
// Real SQLite file, not a mock - same convention as store_test.go and this
// package's own doc comment ("persistence is exactly the category of code
// that looks right against a fake and fails for real").
func TestStore_RecordAndQueryPreAuthKeyID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")

	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	if err := store.RecordPreAuthKeyID(ctx, "user@example.com", 42); err != nil {
		t.Fatalf("RecordPreAuthKeyID() error = %v", err)
	}

	gotID, found, err := store.PreAuthKeyIDForEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("PreAuthKeyIDForEmail() error = %v", err)
	}
	if !found {
		t.Fatal("PreAuthKeyIDForEmail() found = false, want true")
	}
	if gotID != 42 {
		t.Fatalf("PreAuthKeyIDForEmail() id = %d, want 42", gotID)
	}
}

// Requirement: NM-F-09
func TestStore_PreAuthKeyIDForEmail_NotFoundIsNotAnError(t *testing.T) {
	// RD-04, fail-secure: an unregistered email is "not found", not an
	// error - the caller (internal/httpapi.Handler.Grant) is responsible
	// for treating "not found" as a denial.
	path := filepath.Join(t.TempDir(), "grants.db")

	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	gotID, found, err := store.PreAuthKeyIDForEmail(ctx, "never-registered@example.com")
	if err != nil {
		t.Fatalf("PreAuthKeyIDForEmail() error = %v, want nil", err)
	}
	if found {
		t.Fatal("PreAuthKeyIDForEmail() found = true, want false")
	}
	if gotID != 0 {
		t.Fatalf("PreAuthKeyIDForEmail() id = %d, want 0", gotID)
	}
}

// Requirement: NM-F-08
func TestStore_RecordPreAuthKeyID_ReplacesExistingRowForSameEmail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")

	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	if err := store.RecordPreAuthKeyID(ctx, "user@example.com", 1); err != nil {
		t.Fatalf("RecordPreAuthKeyID() (1st) error = %v", err)
	}
	if err := store.RecordPreAuthKeyID(ctx, "user@example.com", 2); err != nil {
		t.Fatalf("RecordPreAuthKeyID() (2nd) error = %v", err)
	}

	gotID, found, err := store.PreAuthKeyIDForEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("PreAuthKeyIDForEmail() error = %v", err)
	}
	if !found {
		t.Fatal("PreAuthKeyIDForEmail() found = false, want true")
	}
	if gotID != 2 {
		t.Fatalf("PreAuthKeyIDForEmail() id = %d, want 2 (the 2nd record should replace the 1st)", gotID)
	}
}

// Requirement: NM-F-08
//
// The mesh_users mapping is permanent, unlike the grants table's rows
// (NM-F-10/NM-F-11): this is the empirical proof it survives a simulated
// Network-Manager restart, mirroring store_test.go's
// TestStore_GrantSurvivesReopen for the grants table.
func TestStore_PreAuthKeyIDSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")
	ctx := context.Background()

	func() {
		store, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("Open() (1st process) error = %v", err)
		}
		defer func() { _ = store.Close() }()

		if err := store.RecordPreAuthKeyID(ctx, "user@example.com", 42); err != nil {
			t.Fatalf("RecordPreAuthKeyID() error = %v", err)
		}
	}()
	// store is now fully closed - the same state a killed/restarted
	// process would leave behind.

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() (2nd process, after 'restart') error = %v", err)
	}
	defer func() { _ = reopened.Close() }()

	gotID, found, err := reopened.PreAuthKeyIDForEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("PreAuthKeyIDForEmail() after reopen: error = %v", err)
	}
	if !found || gotID != 42 {
		t.Fatalf("PreAuthKeyIDForEmail() after reopen = (id=%d, found=%v), want (id=42, found=true)", gotID, found)
	}
}
