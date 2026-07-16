package dbvault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
)

const (
	testEmail        = "user@example.com"
	testPassword     = "Str0ng!Pass"
	testSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJl6r+SEQfM50WkfR/4iZpu9NDXCBs4RwIKidjhOCbdw user@client"
)

// newStub starts an httptest.Server presenting a Database-Vault-organization
// mTLS certificate, handling the request with handler, and returns a base
// URL usable by Register/Login plus an mTLS-configured *http.Client trusting
// only this stub. Mirrors
// services/database-vault/internal/posix/client_test.go's stub pattern
// (httptest, per explicit prior-session user instruction, not a
// hand-written interface fake) - see that package's client_test.go and
// code-agent.md for why https://localhost:<port> must be used instead of
// srv.URL's 127.0.0.1 form.
func newStub(t *testing.T, handler http.HandlerFunc) (string, *http.Client, func()) {
	t.Helper()

	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	serverCert, err := ca.IssueLeaf("DatabaseVault", "database-vault-stub")
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v", err)
	}
	clientCert, err := ca.IssueLeaf("SecuritySwitch", "security-switch-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(client) error = %v", err)
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	srv.StartTLS()

	_, port, ok := strings.Cut(srv.Listener.Addr().String(), ":")
	if !ok {
		t.Fatalf("could not extract port from %s", srv.Listener.Addr().String())
	}
	baseURL := "https://localhost:" + port

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtls.ClientConfig(clientCert, ca.Pool(), OrganizationDatabaseVault),
		},
		Timeout: 5 * time.Second,
	}

	return baseURL, client, srv.Close
}

// Requirement: SS-F-04
func TestRegister_Success(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != RegisterPath {
			t.Errorf("path = %s, want %s", r.URL.Path, RegisterPath)
		}
		var got validation.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode forwarded request: %v", err)
		}
		if got.Email != testEmail {
			t.Fatalf("forwarded email = %q, want %q", got.Email, testEmail)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(registerResponse{PosixUsername: "user7k2m9x"})
	})
	defer stop()

	result := Register(context.Background(), client, baseURL, validation.RegisterRequest{
		Email:        testEmail,
		Password:     testPassword,
		SSHPublicKey: testSSHPublicKey,
	})

	if result.Outcome != OutcomeRegistered {
		t.Fatalf("Outcome = %v, want OutcomeRegistered; err = %v", result.Outcome, result.Err)
	}
	if result.PosixUsername != "user7k2m9x" {
		t.Fatalf("PosixUsername = %q, want %q", result.PosixUsername, "user7k2m9x")
	}
}

// Requirement: SS-F-04
func TestRegister_Duplicate(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(appErrorResponse{Error: "the request could not be completed"})
	})
	defer stop()

	result := Register(context.Background(), client, baseURL, validation.RegisterRequest{Email: testEmail, Password: testPassword, SSHPublicKey: testSSHPublicKey})

	if result.Outcome != OutcomeDuplicate {
		t.Fatalf("Outcome = %v, want OutcomeDuplicate; err = %v", result.Outcome, result.Err)
	}
}

// Requirement: SS-F-06
func TestRegister_UnexpectedStatus(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(appErrorResponse{Error: "the request could not be completed"})
	})
	defer stop()

	result := Register(context.Background(), client, baseURL, validation.RegisterRequest{Email: testEmail, Password: testPassword, SSHPublicKey: testSSHPublicKey})

	if result.Outcome != OutcomeUnknown {
		t.Fatalf("Outcome = %v, want OutcomeUnknown", result.Outcome)
	}
	if result.Err == nil {
		t.Fatal("expected a non-nil error for an unexpected status")
	}
}

// Requirement: SS-F-06
func TestRegister_Unreachable(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	stop() // close immediately: the server is unreachable for the real call below

	result := Register(context.Background(), client, baseURL, validation.RegisterRequest{Email: testEmail, Password: testPassword, SSHPublicKey: testSSHPublicKey})

	if result.Outcome != OutcomeUnknown {
		t.Fatalf("Outcome = %v, want OutcomeUnknown", result.Outcome)
	}
	if result.Err == nil {
		t.Fatal("expected a non-nil error when the peer is unreachable")
	}
}

// Requirement: SS-F-04
func TestLogin_Success(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != LoginPath {
			t.Errorf("path = %s, want %s", r.URL.Path, LoginPath)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(loginResponse{Status: "ok"})
	})
	defer stop()

	result := Login(context.Background(), client, baseURL, validation.LoginRequest{Email: testEmail, Password: testPassword})

	if result.Outcome != OutcomeAuthenticated {
		t.Fatalf("Outcome = %v, want OutcomeAuthenticated; err = %v", result.Outcome, result.Err)
	}
}

// Requirement: SS-F-04
// Requirement: DV-F-15
func TestLogin_Unauthorized(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(appErrorResponse{Error: "authentication failed"})
	})
	defer stop()

	result := Login(context.Background(), client, baseURL, validation.LoginRequest{Email: testEmail, Password: testPassword})

	if result.Outcome != OutcomeUnauthorized {
		t.Fatalf("Outcome = %v, want OutcomeUnauthorized; err = %v", result.Outcome, result.Err)
	}
}
