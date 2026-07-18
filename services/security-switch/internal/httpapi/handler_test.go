package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/dbvault"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/networkmanager"
)

// Fixed, non-secret test fixtures (not real credentials/keys).
const (
	testEmail        = "user@example.com"
	testPassword     = "Str0ng!Pass"
	testSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJl6r+SEQfM50WkfR/4iZpu9NDXCBs4RwIKidjhOCbdw user@client"
)

// fakeDBVault is a hand-written fake implementing DatabaseVaultClient
// (CONTRIBUTING.md §7.5).
type fakeDBVault struct {
	registerResult dbvault.Result
	loginResult    dbvault.Result
	registerCalled bool
	loginCalled    bool
}

func (f *fakeDBVault) Register(_ context.Context, _ validation.RegisterRequest) dbvault.Result {
	f.registerCalled = true
	return f.registerResult
}

func (f *fakeDBVault) Login(_ context.Context, _ validation.LoginRequest) dbvault.Result {
	f.loginCalled = true
	return f.loginResult
}

// fakeNetworkManager is a hand-written fake implementing NetworkManagerClient.
type fakeNetworkManager struct {
	err          error
	grantCalled  bool
	grantedUsers []string

	meshUserErr      error
	meshUserPreAuth  string
	meshUserCalled   bool
	meshUserRequests []string
}

func (f *fakeNetworkManager) GrantAccess(_ context.Context, email string) error {
	f.grantCalled = true
	f.grantedUsers = append(f.grantedUsers, email)
	return f.err
}

func (f *fakeNetworkManager) CreateMeshUser(_ context.Context, email string) (string, error) {
	f.meshUserCalled = true
	f.meshUserRequests = append(f.meshUserRequests, email)
	return f.meshUserPreAuth, f.meshUserErr
}

// newTestHandler builds a Handler wired to hand-written fakes and a
// buffer-backed logger, mirroring
// services/database-vault/internal/httpapi/handler_test.go's
// newTestHandler exactly (SS-F-03's "no user-identifying value in the
// log" needs the buffer, not just status-code assertions).
func newTestHandler(dbVault DatabaseVaultClient, networkManager NetworkManagerClient) (*Handler, *bytes.Buffer) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := &Handler{
		DBVault:        dbVault,
		NetworkManager: networkManager,
		Metrics:        &Counters{},
		Logger:         logger,
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

// Requirement: SS-F-04
// Requirement: SS-F-09
func TestHandler_Register_Success(t *testing.T) {
	dbVault := &fakeDBVault{registerResult: dbvault.Result{Outcome: dbvault.OutcomeRegistered, PosixUsername: "user7k2m9x"}}
	networkManager := &fakeNetworkManager{meshUserPreAuth: "authkey-abc123"}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if !dbVault.registerCalled {
		t.Fatal("expected DBVault.Register to be called on successful validation")
	}
	if !networkManager.meshUserCalled {
		t.Fatal("SS-F-09: a successful registration must request Network-Manager to create a mesh user")
	}
	if len(networkManager.meshUserRequests) != 1 || networkManager.meshUserRequests[0] != testEmail {
		t.Fatalf("meshUserRequests = %v, want [%q]", networkManager.meshUserRequests, testEmail)
	}

	var resp registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.PosixUsername != "user7k2m9x" {
		t.Fatalf("PosixUsername = %q, want %q", resp.PosixUsername, "user7k2m9x")
	}
	if resp.PreAuthKey != "authkey-abc123" {
		t.Fatalf("PreAuthKey = %q, want %q", resp.PreAuthKey, "authkey-abc123")
	}

	if got := h.Metrics.Snapshot(); got.RequestCount != 1 || got.ErrorCount != 0 {
		t.Fatalf("counters after success = %+v, want RequestCount=1, ErrorCount=0", got)
	}
}

// Requirement: SS-F-09
func TestHandler_Register_MeshUserCreationDeniedMapsToForbidden(t *testing.T) {
	dbVault := &fakeDBVault{registerResult: dbvault.Result{Outcome: dbvault.OutcomeRegistered, PosixUsername: "user7k2m9x"}}
	networkManager := &fakeNetworkManager{meshUserErr: fmt.Errorf("%w: simulated denial", networkmanager.ErrMeshUserCreationDenied)}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (a mesh-user creation denial must not still report 201 Created)", rec.Code, http.StatusForbidden)
	}
}

// Requirement: SS-F-09
func TestHandler_Register_MeshUserCreationUnreachableMapsToBadGateway(t *testing.T) {
	dbVault := &fakeDBVault{registerResult: dbvault.Result{Outcome: dbvault.OutcomeRegistered, PosixUsername: "user7k2m9x"}}
	networkManager := &fakeNetworkManager{meshUserErr: fmt.Errorf("%w: simulated 503", networkmanager.ErrNetworkManagerUnreachable)}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (Network-Manager's own failure must not be reported as a 403 denial)", rec.Code, http.StatusBadGateway)
	}
}

// Requirement: SS-F-09
func TestHandler_Register_MeshUserCreationTimeoutMapsToGatewayTimeout(t *testing.T) {
	dbVault := &fakeDBVault{registerResult: dbvault.Result{Outcome: dbvault.OutcomeRegistered, PosixUsername: "user7k2m9x"}}
	networkManager := &fakeNetworkManager{meshUserErr: fmt.Errorf("%w: simulated timeout", networkmanager.ErrNetworkManagerTimeout)}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
}

// Requirement: SS-F-04
func TestHandler_Register_DuplicateRelayed(t *testing.T) {
	dbVault := &fakeDBVault{registerResult: dbvault.Result{Outcome: dbvault.OutcomeDuplicate}}
	h, _ := newTestHandler(dbVault, &fakeNetworkManager{})

	req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

// Requirement: SS-F-06
func TestHandler_Register_DatabaseVaultUnreachableMapsToBadGateway(t *testing.T) {
	dbVault := &fakeDBVault{registerResult: dbvault.Result{Outcome: dbvault.OutcomeUnknown, Err: dbvault.ErrDatabaseVaultUnreachable}}
	h, _ := newTestHandler(dbVault, &fakeNetworkManager{})

	req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

// Requirement: SS-F-06
func TestHandler_Register_DatabaseVaultTimeoutMapsToGatewayTimeout(t *testing.T) {
	dbVault := &fakeDBVault{registerResult: dbvault.Result{Outcome: dbvault.OutcomeUnknown, Err: dbvault.ErrDatabaseVaultTimeout}}
	h, _ := newTestHandler(dbVault, &fakeNetworkManager{})

	req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
}

// Requirement: SS-F-03
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
			dbVault := &fakeDBVault{}
			h, logBuf := newTestHandler(dbVault, &fakeNetworkManager{})

			req := httptest.NewRequest(http.MethodPost, RegisterPath, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if dbVault.registerCalled {
				t.Fatal("SS-F-03: a validation failure must not forward the request to Database-Vault")
			}

			var resp appErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Error == "" {
				t.Fatal("expected a non-empty generic error message")
			}
			lowerMsg := strings.ToLower(resp.Error)
			for _, f := range []string{"email", "password", "ssh"} {
				if strings.Contains(lowerMsg, f) {
					t.Fatalf("response body must not specify which problem was encountered, got: %q", resp.Error)
				}
			}

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

// Requirement: SS-F-04
func TestHandler_Login_SuccessGrantsNetworkAccess(t *testing.T) {
	dbVault := &fakeDBVault{loginResult: dbvault.Result{Outcome: dbvault.OutcomeAuthenticated}}
	networkManager := &fakeNetworkManager{}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !networkManager.grantCalled {
		t.Fatal("SS-F-05: a successful login must request a Network-Manager grant")
	}
	if len(networkManager.grantedUsers) != 1 || networkManager.grantedUsers[0] != testEmail {
		t.Fatalf("grantedUsers = %v, want [%q]", networkManager.grantedUsers, testEmail)
	}
}

// Requirement: SS-F-05
// Requirement: SS-F-06
func TestHandler_Login_GrantDeniedMapsToForbidden(t *testing.T) {
	dbVault := &fakeDBVault{loginResult: dbvault.Result{Outcome: dbvault.OutcomeAuthenticated}}
	networkManager := &fakeNetworkManager{err: fmt.Errorf("%w: simulated denial", networkmanager.ErrGrantDenied)}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (a grant denial must not still report 200 OK - fail-secure, RD-04)", rec.Code, http.StatusForbidden)
	}
}

// Requirement: SS-F-06
func TestHandler_Login_GrantUnreachableMapsToBadGateway(t *testing.T) {
	dbVault := &fakeDBVault{loginResult: dbvault.Result{Outcome: dbvault.OutcomeAuthenticated}}
	networkManager := &fakeNetworkManager{err: fmt.Errorf("%w: simulated 503", networkmanager.ErrNetworkManagerUnreachable)}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (Network-Manager's own failure must not be reported as a 403 grant denial)", rec.Code, http.StatusBadGateway)
	}
}

// Requirement: SS-F-04
func TestHandler_Login_UnauthorizedDoesNotGrantAccess(t *testing.T) {
	dbVault := &fakeDBVault{loginResult: dbvault.Result{Outcome: dbvault.OutcomeUnauthorized}}
	networkManager := &fakeNetworkManager{}
	h, _ := newTestHandler(dbVault, networkManager)

	req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if networkManager.grantCalled {
		t.Fatal("a failed authentication must never request a Network-Manager grant")
	}
}

// Requirement: SS-F-03
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
			dbVault := &fakeDBVault{}
			h, logBuf := newTestHandler(dbVault, &fakeNetworkManager{})

			req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.Login(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if dbVault.loginCalled {
				t.Fatal("SS-F-03: a validation failure must not forward the request to Database-Vault")
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
