package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
)

// fakeTx is a hand-written fake implementing this package's own Tx
// interface (CONTRIBUTING.md §7.5), not the full pgx.Tx interface: SaveUser
// only ever calls Exec, Commit, and Rollback, so the fake only needs to
// implement those.
type fakeTx struct {
	execErr   error
	commitErr error
	rollErr   error

	execCalled     bool
	execSQL        string
	execArgs       []any
	commitCalled   bool
	rollbackCalled bool
}

func (f *fakeTx) Exec(_ context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	f.execCalled = true
	f.execSQL = sql
	f.execArgs = arguments
	return pgconn.CommandTag{}, f.execErr
}

func (f *fakeTx) Commit(_ context.Context) error {
	f.commitCalled = true
	return f.commitErr
}

func (f *fakeTx) Rollback(_ context.Context) error {
	f.rollbackCalled = true
	return f.rollErr
}

// fakeBeginner is a hand-written fake implementing this package's Beginner
// interface, returning a preconfigured fakeTx (or a begin error).
type fakeBeginner struct {
	tx       *fakeTx
	beginErr error
}

func (f *fakeBeginner) Begin(_ context.Context) (Tx, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return f.tx, nil
}

// testRecord is a fixed fixture of already-computed, non-secret test bytes
// (not real credentials) used across this file's test cases.
func testRecord() UserRecord {
	return UserRecord{ //nolint:gosec // fixture data, not a real password hash
		EmailHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		EmailEncrypted: encryption.EncryptedEmail{
			Salt:       []byte("0123456789abcdef"),
			Nonce:      []byte("012345678901"),
			Ciphertext: []byte("ciphertext-bytes"),
		},
		PasswordHash:  "$argon2id$v=19$m=47104,t=2,p=1$c2FsdA$aGFzaA",
		SSHPublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host",
		PosixUsername: "user1a2b3c",
	}
}

// Requirement: DV-F-08
func TestSaveUser_CommitsOnSuccess(t *testing.T) {
	tx := &fakeTx{}
	db := &fakeBeginner{tx: tx}

	before := time.Now()
	err := SaveUser(context.Background(), db, testRecord())
	after := time.Now()

	if err != nil {
		t.Fatalf("SaveUser() error = %v, want nil", err)
	}
	if !tx.execCalled {
		t.Fatal("Exec was not called")
	}
	if !tx.commitCalled {
		t.Fatal("Commit was not called")
	}
	if tx.rollbackCalled {
		t.Fatal("Rollback was called on the success path")
	}
	if tx.execSQL != insertUserSQL {
		t.Fatalf("Exec SQL = %q, want %q", tx.execSQL, insertUserSQL)
	}

	record := testRecord()
	wantEncryptedEmail, err := marshalEncryptedEmail(record.EmailEncrypted)
	if err != nil {
		t.Fatalf("marshalEncryptedEmail() error = %v, want nil", err)
	}
	wantArgs := []any{
		record.EmailHash,
		wantEncryptedEmail,
		record.PasswordHash,
		record.SSHPublicKey,
		record.PosixUsername,
	}
	if len(tx.execArgs) != len(wantArgs)+1 {
		t.Fatalf("Exec args len = %d, want %d", len(tx.execArgs), len(wantArgs)+1)
	}
	for i, want := range wantArgs {
		got := tx.execArgs[i]
		gotBytes, gotIsBytes := got.([]byte)
		wantBytes, wantIsBytes := want.([]byte)
		if gotIsBytes && wantIsBytes {
			if string(gotBytes) != string(wantBytes) {
				t.Errorf("Exec args[%d] = %v, want %v", i, got, want)
			}
			continue
		}
		if got != want {
			t.Errorf("Exec args[%d] = %v, want %v", i, got, want)
		}
	}

	registeredAt, ok := tx.execArgs[len(tx.execArgs)-1].(time.Time)
	if !ok {
		t.Fatalf("Exec args[last] = %T, want time.Time", tx.execArgs[len(tx.execArgs)-1])
	}
	if registeredAt.Before(before) || registeredAt.After(after) {
		t.Fatalf("registered_at = %v, want between %v and %v", registeredAt, before, after)
	}
	if registeredAt.Location() != time.UTC {
		t.Fatalf("registered_at location = %v, want UTC", registeredAt.Location())
	}
}

// Requirement: DV-F-08
func TestSaveUser_BeginError(t *testing.T) {
	wantErr := errors.New("connection refused")
	db := &fakeBeginner{beginErr: wantErr}

	err := SaveUser(context.Background(), db, testRecord())

	if err == nil {
		t.Fatal("SaveUser() error = nil, want non-nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("SaveUser() error = %v, want wrapping %v", err, wantErr)
	}
}

// Requirement: DV-F-08
func TestSaveUser_RollsBackOnInsertError(t *testing.T) {
	insertErr := errors.New("connection reset")
	tx := &fakeTx{execErr: insertErr}
	db := &fakeBeginner{tx: tx}

	err := SaveUser(context.Background(), db, testRecord())

	if err == nil {
		t.Fatal("SaveUser() error = nil, want non-nil")
	}
	if !tx.rollbackCalled {
		t.Fatal("Rollback was not called after an Exec error")
	}
	if tx.commitCalled {
		t.Fatal("Commit was called after an Exec error")
	}
	if !errors.Is(err, insertErr) {
		t.Fatalf("SaveUser() error = %v, want wrapping %v", err, insertErr)
	}
	if errors.Is(err, ErrDuplicateUser) {
		t.Fatal("SaveUser() error wraps ErrDuplicateUser for a non-unique-violation failure")
	}
}

// Requirement: DV-F-08
func TestSaveUser_DuplicateUser(t *testing.T) {
	pgErr := &pgconn.PgError{Code: pgUniqueViolationCode, ConstraintName: "users_ssh_public_key_key"}
	tx := &fakeTx{execErr: pgErr}
	db := &fakeBeginner{tx: tx}

	err := SaveUser(context.Background(), db, testRecord())

	if !errors.Is(err, ErrDuplicateUser) {
		t.Fatalf("SaveUser() error = %v, want wrapping ErrDuplicateUser", err)
	}
	if !tx.rollbackCalled {
		t.Fatal("Rollback was not called after a unique-violation error")
	}
	if tx.commitCalled {
		t.Fatal("Commit was called after a unique-violation error")
	}
}

// Requirement: DV-F-08
func TestSaveUser_OtherPgErrorIsNotDuplicate(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23502"} // not_null_violation, not unique_violation
	tx := &fakeTx{execErr: pgErr}
	db := &fakeBeginner{tx: tx}

	err := SaveUser(context.Background(), db, testRecord())

	if errors.Is(err, ErrDuplicateUser) {
		t.Fatalf("SaveUser() error = %v, want NOT wrapping ErrDuplicateUser for code %q", err, pgErr.Code)
	}
	if !tx.rollbackCalled {
		t.Fatal("Rollback was not called after an Exec error")
	}
}

// Requirement: DV-F-08
func TestSaveUser_RollbackErrorIsSurfaced(t *testing.T) {
	insertErr := errors.New("insert failed")
	rollbackErr := errors.New("rollback failed")
	tx := &fakeTx{execErr: insertErr, rollErr: rollbackErr}
	db := &fakeBeginner{tx: tx}

	err := SaveUser(context.Background(), db, testRecord())

	if err == nil {
		t.Fatal("SaveUser() error = nil, want non-nil")
	}
	if !errors.Is(err, insertErr) {
		t.Fatalf("SaveUser() error = %v, want wrapping the original insert error %v", err, insertErr)
	}
}

// Requirement: DV-F-08
func TestSaveUser_CommitError(t *testing.T) {
	commitErr := errors.New("commit failed")
	tx := &fakeTx{commitErr: commitErr}
	db := &fakeBeginner{tx: tx}

	err := SaveUser(context.Background(), db, testRecord())

	if !errors.Is(err, commitErr) {
		t.Fatalf("SaveUser() error = %v, want wrapping %v", err, commitErr)
	}
	if tx.rollbackCalled {
		t.Fatal("Rollback was called after a Commit error; Commit failing does not mean the insert failed")
	}
}

// Requirement: DV-F-10
func TestDeleteUser_CommitsOnSuccess(t *testing.T) {
	tx := &fakeTx{}
	db := &fakeBeginner{tx: tx}

	err := DeleteUser(context.Background(), db, testRecord().EmailHash)

	if err != nil {
		t.Fatalf("DeleteUser() error = %v, want nil", err)
	}
	if !tx.execCalled {
		t.Fatal("Exec was not called")
	}
	if tx.execSQL != deleteUserSQL {
		t.Fatalf("Exec SQL = %q, want %q", tx.execSQL, deleteUserSQL)
	}
	if len(tx.execArgs) != 1 || tx.execArgs[0] != testRecord().EmailHash {
		t.Fatalf("Exec args = %v, want [%q]", tx.execArgs, testRecord().EmailHash)
	}
	if !tx.commitCalled {
		t.Fatal("Commit was not called")
	}
	if tx.rollbackCalled {
		t.Fatal("Rollback was called on the success path")
	}
}

// Requirement: DV-F-10
func TestDeleteUser_BeginError(t *testing.T) {
	wantErr := errors.New("connection refused")
	db := &fakeBeginner{beginErr: wantErr}

	err := DeleteUser(context.Background(), db, testRecord().EmailHash)

	if !errors.Is(err, wantErr) {
		t.Fatalf("DeleteUser() error = %v, want wrapping %v", err, wantErr)
	}
}

// Requirement: DV-F-10
func TestDeleteUser_RollsBackOnExecError(t *testing.T) {
	execErr := errors.New("connection reset")
	tx := &fakeTx{execErr: execErr}
	db := &fakeBeginner{tx: tx}

	err := DeleteUser(context.Background(), db, testRecord().EmailHash)

	if !errors.Is(err, execErr) {
		t.Fatalf("DeleteUser() error = %v, want wrapping %v", err, execErr)
	}
	if !tx.rollbackCalled {
		t.Fatal("Rollback was not called after an Exec error")
	}
	if tx.commitCalled {
		t.Fatal("Commit was called after an Exec error")
	}
}

// Requirement: DV-F-10
func TestDeleteUser_RollbackErrorIsSurfaced(t *testing.T) {
	execErr := errors.New("delete failed")
	rollbackErr := errors.New("rollback failed")
	tx := &fakeTx{execErr: execErr, rollErr: rollbackErr}
	db := &fakeBeginner{tx: tx}

	err := DeleteUser(context.Background(), db, testRecord().EmailHash)

	if err == nil {
		t.Fatal("DeleteUser() error = nil, want non-nil")
	}
	if !errors.Is(err, execErr) {
		t.Fatalf("DeleteUser() error = %v, want wrapping the original exec error %v", err, execErr)
	}
}

// Requirement: DV-F-10
func TestDeleteUser_CommitError(t *testing.T) {
	commitErr := errors.New("commit failed")
	tx := &fakeTx{commitErr: commitErr}
	db := &fakeBeginner{tx: tx}

	err := DeleteUser(context.Background(), db, testRecord().EmailHash)

	if !errors.Is(err, commitErr) {
		t.Fatalf("DeleteUser() error = %v, want wrapping %v", err, commitErr)
	}
	if tx.rollbackCalled {
		t.Fatal("Rollback was called after a Commit error")
	}
}
