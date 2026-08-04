package login

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/hashing"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/password"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// testPepper is a fixed, non-secret test fixture (not a real pepper).
var testPepper = []byte("test-pepper-not-a-real-secret")

// fakeStorage is a hand-written fake implementing this package's Storage
// interface (CONTRIBUTING.md section 7.5): it returns a fixed stored hash
// keyed by email hash, or a fixed "not found" error, without a real
// database.
type fakeStorage struct {
	hashes map[string]string

	// lookupErr, when non-nil, is returned instead of consulting hashes:
	// the fake stands in for a database that is unreachable or whose query
	// failed, as opposed to one that reported "no such user".
	lookupErr error
}

func (f *fakeStorage) GetPasswordHash(_ context.Context, emailHash string) (string, error) {
	if f.lookupErr != nil {
		return "", f.lookupErr
	}
	hash, ok := f.hashes[emailHash]
	if !ok {
		// The real storage.GetPasswordHash wraps this exact sentinel, and
		// Login now distinguishes it from any other lookup error, so the
		// fake must reproduce its identity rather than an arbitrary error.
		return "", fmt.Errorf("fake storage: %w", storage.ErrUserNotFound)
	}
	return hash, nil
}

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

// Requirement: DV-F-15
func TestLogin_LookupFailure_IsDistinctFromBadCredentials(t *testing.T) {
	store := &fakeStorage{lookupErr: errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")}

	result := Login(context.Background(), store, testPepper, Input{
		Email:    logging.Redacted(testEmail),
		Password: []byte(testPassword),
	})

	// RD-04, fail-secure: the client-facing outcome is still 401.
	if result.Outcome != OutcomeUnauthorized {
		t.Fatalf("Outcome = %v, want OutcomeUnauthorized", result.Outcome)
	}

	// DV-F-15 requires "nonexistent email" and "wrong password" to be
	// indistinguishable. A database outage is neither: presenting it as a
	// bad credential makes an infrastructure failure look like an attack in
	// the operator's logs, so it carries its own sentinel.
	if !errors.Is(result.Err, ErrLookupFailed) {
		t.Fatalf("Err = %v, want ErrLookupFailed", result.Err)
	}
	if errors.Is(result.Err, ErrAuthenticationFailed) {
		t.Fatalf("Err = %v, want a distinct sentinel from ErrAuthenticationFailed", result.Err)
	}

	// The sentinel must stay generic: no address, no query, nothing that
	// ties the failure to a specific record or host.
	if got := result.Err.Error(); strings.Contains(got, "10.0.0.5") {
		t.Fatalf("Err.Error() = %q leaks the underlying error's content", got)
	}
}

// medianLoginDuration runs Login runs times and returns the median elapsed
// time. The median, not the mean, because a single scheduler hiccup or GC
// pause on a loaded machine skews a mean badly while leaving the median
// intact — the point is to compare orders of magnitude, not to benchmark.
func medianLoginDuration(store Storage, input Input, runs int) time.Duration {
	samples := make([]time.Duration, 0, runs)
	for range runs {
		start := time.Now()
		_ = Login(context.Background(), store, testPepper, input)
		samples = append(samples, time.Since(start))
	}
	slices.Sort(samples)

	return samples[len(samples)/2]
}

// Requirement: DV-F-15
func TestLogin_NonexistentEmailTakesComparableTimeToWrongPassword(t *testing.T) {
	emailHash := hashing.HashEmail(logging.Redacted(testEmail))
	storeWithUser := &fakeStorage{hashes: map[string]string{emailHash: newStoredHash(t)}}
	storeWithoutUser := &fakeStorage{hashes: map[string]string{}}

	existing := Input{Email: logging.Redacted(testEmail), Password: []byte(testWrongPassword)}
	missing := Input{Email: logging.Redacted("nobody@example.com"), Password: []byte(testWrongPassword)}

	// Warm-up: the first call on the missing-email path also pays for
	// building the process-wide dummy hash (password.VerifyDummy's
	// sync.OnceValue), which must not land in the measured samples.
	_ = Login(context.Background(), storeWithoutUser, testPepper, missing)
	_ = Login(context.Background(), storeWithUser, testPepper, existing)

	const runs = 5
	wrongPassword := medianLoginDuration(storeWithUser, existing, runs)
	nonexistent := medianLoginDuration(storeWithoutUser, missing, runs)

	// DV-F-15's response and log line were already identical; the elapsed
	// time was not, because Argon2id only ran when a row existed. That gap
	// is over an order of magnitude and trivially measurable from anywhere
	// on the mesh, i.e. a user-enumeration oracle.
	//
	// The threshold is deliberately loose: this asserts "same order of
	// magnitude," which is what closes the oracle, and stays quiet under
	// the noise of a loaded machine or the race detector. A tight timing
	// assertion would flake, and a flaky timing test is worse than none.
	const maxRatio = 3.0
	ratio := float64(wrongPassword) / float64(nonexistent)
	if ratio > maxRatio || ratio < 1/maxRatio {
		t.Fatalf("median login time differs by %.1fx (wrong password %v, nonexistent email %v), want within %.0fx",
			ratio, wrongPassword, nonexistent, maxRatio)
	}
}
