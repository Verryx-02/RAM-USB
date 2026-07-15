package login

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/hashing"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/password"
)

// testPepper is a fixed, non-secret test fixture (not a real pepper).
var testPepper = []byte("test-pepper-not-a-real-secret")

// fakeStorage is a hand-written fake implementing this package's Storage
// interface (CONTRIBUTING.md §7.5): it returns a fixed stored hash keyed by
// email hash, or a fixed "not found" error, without a real database.
type fakeStorage struct {
	hashes map[string]string
}

func (f *fakeStorage) GetPasswordHash(_ context.Context, emailHash string) (string, error) {
	hash, ok := f.hashes[emailHash]
	if !ok {
		return "", errNotFound
	}
	return hash, nil
}

// errNotFound simulates storage.ErrUserNotFound without importing the
// storage package here — login.Storage only needs an error to exist, its
// identity/wrapping is storage's concern, not login's (DV-F-15: login must
// not branch on what kind of error the lookup returned).
var errNotFound = errors.New("fake storage: no such user")

const testEmail = "user@example.com"
const testPassword = "correct horse battery staple 42!"
const testWrongPassword = "definitely-the-wrong-password"

// newStoredHash builds a real PHC-format hash for testEmail/testPassword
// using the same password.HashPassword this project's registration flow
// calls, so VerifyPassword's real parsing/recompute logic is exercised
// end to end, not just a hand-crafted string.
func newStoredHash(t *testing.T) string {
	t.Helper()
	salt, err := password.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	hash, err := password.HashPassword([]byte(testPassword), salt, testPepper)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return hash
}

// Requirement: DV-F-13
// Requirement: DV-F-14
func TestLogin_Success(t *testing.T) {
	emailHash := hashing.HashEmail(logging.Redacted(testEmail))
	store := &fakeStorage{hashes: map[string]string{emailHash: newStoredHash(t)}}

	result := Login(context.Background(), store, testPepper, Input{
		Email:    logging.Redacted(testEmail),
		Password: []byte(testPassword),
	})

	if result.Outcome != OutcomeSuccess {
		t.Fatalf("Outcome = %v, want OutcomeSuccess", result.Outcome)
	}
	if result.Err != nil {
		t.Fatalf("Err = %v, want nil", result.Err)
	}
}

// Requirement: DV-F-15
func TestLogin_NonexistentEmailAndWrongPassword_AreIndistinguishable(t *testing.T) {
	emailHash := hashing.HashEmail(logging.Redacted(testEmail))
	storeWithUser := &fakeStorage{hashes: map[string]string{emailHash: newStoredHash(t)}}
	storeWithoutUser := &fakeStorage{hashes: map[string]string{}}

	nonexistentEmailResult := Login(context.Background(), storeWithoutUser, testPepper, Input{
		Email:    logging.Redacted(testEmail),
		Password: []byte(testPassword),
	})

	wrongPasswordResult := Login(context.Background(), storeWithUser, testPepper, Input{
		Email:    logging.Redacted(testEmail),
		Password: []byte(testWrongPassword),
	})

	if nonexistentEmailResult.Outcome != OutcomeUnauthorized {
		t.Fatalf("nonexistent-email Outcome = %v, want OutcomeUnauthorized", nonexistentEmailResult.Outcome)
	}
	if wrongPasswordResult.Outcome != OutcomeUnauthorized {
		t.Fatalf("wrong-password Outcome = %v, want OutcomeUnauthorized", wrongPasswordResult.Outcome)
	}

	// The literal DV-F-15 assertion: not merely "both fail," but "both fail
	// in the exact same observable way" — same Outcome value and the exact
	// same Err value (not just the same text), so nothing downstream
	// (response mapping or a log line) can tell them apart.
	if nonexistentEmailResult.Outcome != wrongPasswordResult.Outcome {
		t.Fatalf("Outcome differs: nonexistent email = %v, wrong password = %v",
			nonexistentEmailResult.Outcome, wrongPasswordResult.Outcome)
	}
	if !errors.Is(nonexistentEmailResult.Err, ErrAuthenticationFailed) {
		t.Fatalf("nonexistent-email Err = %v, want ErrAuthenticationFailed", nonexistentEmailResult.Err)
	}
	if !errors.Is(wrongPasswordResult.Err, ErrAuthenticationFailed) {
		t.Fatalf("wrong-password Err = %v, want ErrAuthenticationFailed", wrongPasswordResult.Err)
	}
	if nonexistentEmailResult.Err.Error() != wrongPasswordResult.Err.Error() {
		t.Fatalf("log message differs: nonexistent email = %q, wrong password = %q",
			nonexistentEmailResult.Err.Error(), wrongPasswordResult.Err.Error())
	}
}

// Requirement: DV-F-15
func TestLogin_NonexistentEmail(t *testing.T) {
	store := &fakeStorage{hashes: map[string]string{}}

	result := Login(context.Background(), store, testPepper, Input{
		Email:    logging.Redacted(testEmail),
		Password: []byte(testPassword),
	})

	if result.Outcome != OutcomeUnauthorized {
		t.Fatalf("Outcome = %v, want OutcomeUnauthorized", result.Outcome)
	}
	if !errors.Is(result.Err, ErrAuthenticationFailed) {
		t.Fatalf("Err = %v, want ErrAuthenticationFailed", result.Err)
	}
}

// Requirement: DV-F-15
func TestLogin_WrongPassword(t *testing.T) {
	emailHash := hashing.HashEmail(logging.Redacted(testEmail))
	store := &fakeStorage{hashes: map[string]string{emailHash: newStoredHash(t)}}

	result := Login(context.Background(), store, testPepper, Input{
		Email:    logging.Redacted(testEmail),
		Password: []byte(testWrongPassword),
	})

	if result.Outcome != OutcomeUnauthorized {
		t.Fatalf("Outcome = %v, want OutcomeUnauthorized", result.Outcome)
	}
	if !errors.Is(result.Err, ErrAuthenticationFailed) {
		t.Fatalf("Err = %v, want ErrAuthenticationFailed", result.Err)
	}
}

// Requirement: DV-F-14
func TestLogin_MalformedStoredHash_TreatedAsUnauthorized(t *testing.T) {
	const malformedHash = "not-a-valid-phc-string"
	emailHash := hashing.HashEmail(logging.Redacted(testEmail))
	store := &fakeStorage{hashes: map[string]string{emailHash: malformedHash}}

	result := Login(context.Background(), store, testPepper, Input{
		Email:    logging.Redacted(testEmail),
		Password: []byte(testPassword),
	})

	// Response-uniformity half of DV-F-15: a verification error still maps
	// to the same HTTP-facing Outcome (401) as an ordinary auth failure.
	if result.Outcome != OutcomeUnauthorized {
		t.Fatalf("Outcome = %v, want OutcomeUnauthorized", result.Outcome)
	}

	// User-clarified scope boundary: DV-F-15 only forbids distinguishing
	// "nonexistent email" from "wrong password." A verification error (the
	// stored hash itself is malformed — data corruption or a bug, not a
	// user mistake) is a different case, and is allowed to be
	// distinguishable in Err for internal logging purposes.
	if errors.Is(result.Err, ErrAuthenticationFailed) {
		t.Fatalf("Err = %v, want a distinct sentinel from ErrAuthenticationFailed", result.Err)
	}
	if !errors.Is(result.Err, ErrPasswordVerificationFailed) {
		t.Fatalf("Err = %v, want ErrPasswordVerificationFailed", result.Err)
	}

	// Critical no-leakage constraint: the returned Err's message must never
	// contain content from the underlying password.VerifyPassword error
	// (e.g. password.ErrPasswordHashMalformed's %q-embedded stored hash
	// string), since that content is specific to one database record and
	// could let a log reader correlate a failure back to a specific
	// stored row/user.
	if got := result.Err.Error(); strings.Contains(got, malformedHash) {
		t.Fatalf("Err.Error() = %q leaks the fixture's malformed stored hash content", got)
	}
}
