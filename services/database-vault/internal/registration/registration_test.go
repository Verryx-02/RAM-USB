package registration

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// usernamePattern matches DV-F-09's "user<xxxxxx>" format: a lowercase
// six-character base-36 suffix.
var usernamePattern = regexp.MustCompile(`^user[0-9a-z]{6}$`)

// fakeStorage is a hand-written fake implementing this package's Storage
// interface (CONTRIBUTING.md §7.5), recording every call so tests can
// assert on call order and arguments without a real database.
type fakeStorage struct {
	saveErr   error
	deleteErr error

	savedRecord  storage.UserRecord
	saveCalled   bool
	deletedHash  string
	deleteCalled bool
}

func (f *fakeStorage) SaveUser(_ context.Context, record storage.UserRecord) error {
	f.saveCalled = true
	f.savedRecord = record
	return f.saveErr
}

func (f *fakeStorage) DeleteUser(_ context.Context, emailHash string) error {
	f.deleteCalled = true
	f.deletedHash = emailHash
	return f.deleteErr
}

// fakePOSIX is a hand-written fake implementing this package's
// POSIXProvisioner interface.
type fakePOSIX struct {
	createErr error

	createCalled   bool
	createUsername string
}

func (f *fakePOSIX) CreatePOSIXUser(_ context.Context, username string) error {
	f.createCalled = true
	f.createUsername = username
	return f.createErr
}

// testInput is a fixed fixture of already-computed, non-secret test values
// (not real credentials).
func testInput() RegistrationInput {
	return RegistrationInput{ //nolint:gosec // fixture data, not a real password hash
		EmailHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		EmailEncrypted: encryption.EncryptedEmail{
			Salt:       []byte("0123456789abcdef"),
			Nonce:      []byte("012345678901"),
			Ciphertext: []byte("ciphertext-bytes"),
		},
		PasswordHash: "$argon2id$v=19$m=47104,t=2,p=1$c2FsdA$aGFzaA",
		SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host",
	}
}

// Requirement: DV-F-11
func TestRegister_SuccessPath(t *testing.T) {
	store := &fakeStorage{}
	posixSvc := &fakePOSIX{}
	input := testInput()

	result := Register(context.Background(), store, posixSvc, input)

	if result.Outcome != OutcomeRegistered {
		t.Fatalf("Outcome = %v, want OutcomeRegistered", result.Outcome)
	}
	if result.Err != nil {
		t.Fatalf("Err = %v, want nil", result.Err)
	}
	if !usernamePattern.MatchString(result.PosixUsername) {
		t.Fatalf("PosixUsername = %q, want match of %s", result.PosixUsername, usernamePattern)
	}
	if !store.saveCalled {
		t.Fatal("SaveUser was not called")
	}
	if store.savedRecord.PosixUsername != result.PosixUsername {
		t.Fatalf("saved record PosixUsername = %q, want %q", store.savedRecord.PosixUsername, result.PosixUsername)
	}
	if store.savedRecord.EmailHash != input.EmailHash {
		t.Fatalf("saved record EmailHash = %q, want %q", store.savedRecord.EmailHash, input.EmailHash)
	}
	if !posixSvc.createCalled {
		t.Fatal("CreatePOSIXUser was not called")
	}
	if posixSvc.createUsername != result.PosixUsername {
		t.Fatalf("CreatePOSIXUser username = %q, want %q", posixSvc.createUsername, result.PosixUsername)
	}
	if store.deleteCalled {
		t.Fatal("DeleteUser was called on the success path")
	}
}

// Requirement: DV-F-12
func TestRegister_DuplicateUser(t *testing.T) {
	store := &fakeStorage{saveErr: errWrapping(storage.ErrDuplicateUser)}
	posixSvc := &fakePOSIX{}

	result := Register(context.Background(), store, posixSvc, testInput())

	if result.Outcome != OutcomeDuplicate {
		t.Fatalf("Outcome = %v, want OutcomeDuplicate", result.Outcome)
	}
	if !errors.Is(result.Err, storage.ErrDuplicateUser) {
		t.Fatalf("Err = %v, want wrapping storage.ErrDuplicateUser", result.Err)
	}
	if posixSvc.createCalled {
		t.Fatal("CreatePOSIXUser was called for a duplicate registration")
	}
	if store.deleteCalled {
		t.Fatal("DeleteUser was called for a duplicate registration")
	}
}

// Requirement: DV-F-12
func TestRegister_SaveUserGenericFailure(t *testing.T) {
	genericErr := errors.New("connection reset")
	store := &fakeStorage{saveErr: genericErr}
	posixSvc := &fakePOSIX{}

	result := Register(context.Background(), store, posixSvc, testInput())

	if result.Outcome != OutcomeFailed {
		t.Fatalf("Outcome = %v, want OutcomeFailed", result.Outcome)
	}
	if errors.Is(result.Err, storage.ErrDuplicateUser) {
		t.Fatal("Err wraps storage.ErrDuplicateUser for a non-duplicate save failure")
	}
	if !errors.Is(result.Err, genericErr) {
		t.Fatalf("Err = %v, want wrapping %v", result.Err, genericErr)
	}
	if posixSvc.createCalled {
		t.Fatal("CreatePOSIXUser was called after SaveUser failed")
	}
}

// Requirement: DV-F-10
func TestRegister_POSIXCreationFailure_RollsBack(t *testing.T) {
	posixErr := errors.New("storage-service unreachable")
	store := &fakeStorage{}
	posixSvc := &fakePOSIX{createErr: posixErr}
	input := testInput()

	result := Register(context.Background(), store, posixSvc, input)

	if result.Outcome != OutcomeFailed {
		t.Fatalf("Outcome = %v, want OutcomeFailed", result.Outcome)
	}
	if !errors.Is(result.Err, posixErr) {
		t.Fatalf("Err = %v, want wrapping %v", result.Err, posixErr)
	}
	if errors.Is(result.Err, ErrOrphanedRecord) {
		t.Fatal("Err wraps ErrOrphanedRecord when the rollback itself succeeded")
	}
	if !store.deleteCalled {
		t.Fatal("DeleteUser was not called after POSIX user creation failed")
	}
	if store.deletedHash != input.EmailHash {
		t.Fatalf("DeleteUser emailHash = %q, want %q", store.deletedHash, input.EmailHash)
	}
}

// Requirement: DV-F-10
func TestRegister_POSIXCreationFailure_RollbackAlsoFails(t *testing.T) {
	posixErr := errors.New("storage-service unreachable")
	deleteErr := errors.New("database unreachable")
	store := &fakeStorage{deleteErr: deleteErr}
	posixSvc := &fakePOSIX{createErr: posixErr}

	result := Register(context.Background(), store, posixSvc, testInput())

	if result.Outcome != OutcomeFailed {
		t.Fatalf("Outcome = %v, want OutcomeFailed", result.Outcome)
	}
	if !errors.Is(result.Err, ErrOrphanedRecord) {
		t.Fatalf("Err = %v, want wrapping ErrOrphanedRecord", result.Err)
	}
	if !store.deleteCalled {
		t.Fatal("DeleteUser was not called")
	}
}

// errWrapping builds an error that errors.Is reports as matching target,
// simulating the way storage.SaveUser wraps storage.ErrDuplicateUser with
// additional context (e.g. the violated constraint name) rather than
// returning the sentinel bare.
func errWrapping(target error) error {
	return &wrappedError{target: target}
}

type wrappedError struct {
	target error
}

func (e *wrappedError) Error() string {
	return "wrapped: " + e.target.Error()
}

func (e *wrappedError) Unwrap() error {
	return e.target
}
