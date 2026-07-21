package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/password"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/registration"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// Fixed, non-secret test fixtures (not real credentials/keys).
const (
	testEmail        = "user@example.com"
	testPassword     = "Str0ng!Pass"
	testSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJl6r+SEQfM50WkfR/4iZpu9NDXCBs4RwIKidjhOCbdw user@client"
)

var testMasterKey = bytes.Repeat([]byte{0x01}, 32)
var testPepper = []byte("test-pepper-not-a-real-secret")

// fakeRegistrationStorage is a hand-written fake implementing
// registration.Storage (CONTRIBUTING.md §7.5), same shape as
// registration_test.go's fakeStorage.
type fakeRegistrationStorage struct {
	saveErr   error
	deleteErr error
}

func (f *fakeRegistrationStorage) SaveUser(_ context.Context, _ storage.UserRecord) error {
	return f.saveErr
}

func (f *fakeRegistrationStorage) DeleteUser(_ context.Context, _ string) error {
	return f.deleteErr
}

// fakePOSIX is a hand-written fake implementing registration.POSIXProvisioner.
type fakePOSIX struct {
	createErr error
}

func (f *fakePOSIX) CreatePOSIXUser(_ context.Context, _ string) error {
	return f.createErr
}

// fakeLoginStorage is a hand-written fake implementing login.Storage, same
// shape as login_test.go's fakeStorage.
type fakeLoginStorage struct {
	hash string
	err  error
}

func (f *fakeLoginStorage) GetPasswordHash(_ context.Context, _ string) (string, error) {
	return f.hash, f.err
}

// newTestHandler builds a Handler wired to hand-written fakes and a
// buffer-backed logger, so tests can both drive HTTP requests through it
// and inspect exactly what was logged (DV-F-20's "without identifying the
// user" requirement needs the latter, not just the response body).
func newTestHandler(store registration.Storage, posixProvisioner registration.POSIXProvisioner, loginStore *fakeLoginStorage) (*Handler, *bytes.Buffer) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := &Handler{
		Store:            store,
		POSIXProvisioner: posixProvisioner,
		LoginStore:       loginStore,
		MasterKey:        testMasterKey,
		Pepper:           testPepper,
		Metrics:          &Counters{},
		Logger:           logger,
	}
	return h, &logBuf
}

func registerRequestBody(email, password, sshKey string) string {
	body, _ := json.Marshal(map[string]string{
		"email":          email,
		"password":       password,
		"ssh_public_key": sshKey,
	})
	return string(body)
}

func loginRequestBody(email, password string) string {
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	return string(body)
}

// Requirement: DV-F-09
// Requirement: DV-F-11
func TestHandler_Register_Success(t *testing.T) {
	h, _ := newTestHandler(&fakeRegistrationStorage{}, &fakePOSIX{}, &fakeLoginStorage{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.PosixUsername == "" {
		t.Fatal("expected a non-empty posix_username in the response")
	}

	if got := h.Metrics.Snapshot(); got.RequestCount != 1 || got.ErrorCount != 0 {
		t.Fatalf("counters after success = %+v, want RequestCount=1, ErrorCount=0", got)
	}
}

// Requirement: DV-F-12
func TestHandler_Register_DuplicateDoesNotLeakDetail(t *testing.T) {
	h, _ := newTestHandler(&fakeRegistrationStorage{saveErr: storage.ErrDuplicateUser}, &fakePOSIX{}, &fakeLoginStorage{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	if strings.Contains(rec.Body.String(), storage.ErrDuplicateUser.Error()) {
		t.Fatalf("response body must not leak the internal error detail: %s", rec.Body.String())
	}

	if got := h.Metrics.Snapshot(); got.ErrorCount != 1 {
		t.Fatalf("ErrorCount = %d, want 1", got.ErrorCount)
	}
}

// Requirement: DV-F-10
func TestHandler_Register_POSIXFailureIsInternalError(t *testing.T) {
	h, _ := newTestHandler(&fakeRegistrationStorage{}, &fakePOSIX{createErr: context.DeadlineExceeded}, &fakeLoginStorage{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// Requirement: DV-F-20
func TestHandler_Register_ValidationFailure(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty email", registerRequestBody("", testPassword, testSSHPublicKey)},
		{"malformed email", registerRequestBody("not-an-email", testPassword, testSSHPublicKey)},
		{"weak password", registerRequestBody(testEmail, "weak", testSSHPublicKey)},
		{"malformed ssh key", registerRequestBody(testEmail, testPassword, "not-an-ssh-key")},
		{"malformed json", `{"email":`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeRegistrationStorage{}
			posixProvisioner := &fakePOSIX{}
			h, logBuf := newTestHandler(store, posixProvisioner, &fakeLoginStorage{})

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RegisterPath, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}

			var resp appErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Error == "" {
				t.Fatal("expected a non-empty generic error message")
			}
			// The generic body must never mention which field/rule failed.
			forbidden := []string{"email", "password", "ssh"}
			lowerMsg := strings.ToLower(resp.Error)
			for _, f := range forbidden {
				if strings.Contains(lowerMsg, f) {
					t.Fatalf("response body must not specify which problem was encountered, got: %q", resp.Error)
				}
			}

			// The log must not contain the email, password, or SSH key.
			logged := logBuf.String()
			for _, secret := range []string{testEmail, testPassword, testSSHPublicKey, "not-an-email", "weak", "not-an-ssh-key"} {
				if secret == "" {
					continue
				}
				if strings.Contains(logged, secret) {
					t.Fatalf("log must not identify the user, but contains %q:\n%s", secret, logged)
				}
			}
		})
	}
}

// Requirement: DV-F-20
func TestHandler_Register_ValidationFailureDoesNotForwardRequest(t *testing.T) {
	store := &fakeRegistrationStorage{saveErr: nil}
	posixProvisioner := &fakePOSIX{}
	h, _ := newTestHandler(store, posixProvisioner, &fakeLoginStorage{})

	// A tracking wrapper would be ideal, but the existing fakes have no
	// "was I called" flag for Save/Create in this file (only pass/fail
	// behavior) - so this asserts indirectly: a saveErr/createErr that
	// would otherwise flip the response to 409/500 must never fire,
	// because Register must return 400 before Store/POSIXProvisioner are
	// ever invoked.
	store.saveErr = storage.ErrDuplicateUser
	posixProvisioner.createErr = context.DeadlineExceeded

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody("", testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (validation failure must short-circuit before Store/POSIXProvisioner are called)", rec.Code, http.StatusBadRequest)
	}
}

// Requirement: DV-F-13
// Requirement: DV-F-14
func TestHandler_Login_Success(t *testing.T) {
	hash := realStoredHash(t)
	loginStore := &fakeLoginStorage{hash: hash}
	h, _ := newTestHandler(&fakeRegistrationStorage{}, &fakePOSIX{}, loginStore)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// Requirement: DV-F-15
func TestHandler_Login_UnauthorizedDoesNotLeakDetail(t *testing.T) {
	loginStore := &fakeLoginStorage{err: context.DeadlineExceeded}
	h, _ := newTestHandler(&fakeRegistrationStorage{}, &fakePOSIX{}, loginStore)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp appErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Contains(strings.ToLower(resp.Error), "email") || strings.Contains(strings.ToLower(resp.Error), "password") {
		t.Fatalf("response body must not distinguish the failure cause, got: %q", resp.Error)
	}
}

// Requirement: DV-F-20
func TestHandler_Login_ValidationFailure(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty email", loginRequestBody("", testPassword)},
		{"malformed email", loginRequestBody("not-an-email", testPassword)},
		{"empty password", loginRequestBody(testEmail, "")},
		{"malformed json", `{"email":`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loginStore := &fakeLoginStorage{}
			h, logBuf := newTestHandler(&fakeRegistrationStorage{}, &fakePOSIX{}, loginStore)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, LoginPath, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.Login(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}

			var resp appErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			lowerMsg := strings.ToLower(resp.Error)
			for _, f := range []string{"email", "password"} {
				if strings.Contains(lowerMsg, f) {
					t.Fatalf("response body must not specify which problem was encountered, got: %q", resp.Error)
				}
			}

			logged := logBuf.String()
			for _, secret := range []string{testEmail, testPassword, "not-an-email"} {
				if secret == "" {
					continue
				}
				if strings.Contains(logged, secret) {
					t.Fatalf("log must not identify the user, but contains %q:\n%s", secret, logged)
				}
			}
		})
	}
}

// realStoredHash builds a real PHC-format hash for testPassword using this
// project's real password.GenerateSalt/HashPassword, mirroring
// login_test.go's newStoredHash helper. fakeLoginStorage.GetPasswordHash
// ignores its emailHash argument and always returns this fixed hash, so no
// separate email-hash-keyed lookup is needed here.
func realStoredHash(t *testing.T) string {
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
