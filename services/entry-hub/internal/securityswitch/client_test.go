package securityswitch

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

// newStub starts an httptest.Server presenting a SecuritySwitch-
// organization mTLS certificate, handling the request with handler, and
// returns a base URL usable by Register/Login plus an mTLS-configured
// *http.Client trusting only this stub. Mirrors
// services/security-switch/internal/dbvault/client_test.go's stub
// pattern exactly (httptest, per prior-session convention, using
// https://localhost:<port> rather than srv.URL's 127.0.0.1 form - see
// that file and code-agent.md for why).
func newStub(t *testing.T, handler http.HandlerFunc) (string, *http.Client, func()) {
	t.Helper()

	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	serverCert, err := ca.IssueLeaf("SecuritySwitch", "security-switch-stub")
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v", err)
	}
	clientCert, err := ca.IssueLeaf("EntryHub", "entry-hub-under-test")
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
			TLSClientConfig: mtls.ClientConfig(clientCert, ca.Pool(), OrganizationSecuritySwitch),
		},
		Timeout: 5 * time.Second,
	}

	return baseURL, client, srv.Close
}

// Requirement: EH-F-07
// Requirement: EH-F-08
func TestRegister_RelaysResponseUnchanged(t *testing.T) {
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"posix_username":"user7k2m9x"}`))
	})
	defer stop()

	result := Register(context.Background(), client, baseURL, validation.RegisterRequest{
		Email:        testEmail,
		Password:     testPassword,
		SSHPublicKey: testSSHPublicKey,
	})

	if result.Err != nil {
		t.Fatalf("Err = %v, want nil", result.Err)
	}
	if result.StatusCode != http.StatusCreated {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusCreated)
	}
	if string(result.Body) != `{"posix_username":"user7k2m9x"}` {
		t.Fatalf("Body = %q, want the stub's response body unchanged", result.Body)
	}
	if result.ContentType != "application/json" {
		t.Fatalf("ContentType = %q, want %q", result.ContentType, "application/json")
	}
}

// Requirement: EH-F-08
func TestRegister_RelaysDuplicateStatusUnchanged(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"the request could not be completed"}`))
	})
	defer stop()

	result := Register(context.Background(), client, baseURL, validation.RegisterRequest{Email: testEmail, Password: testPassword, SSHPublicKey: testSSHPublicKey})

	if result.Err != nil {
		t.Fatalf("Err = %v, want nil (a 409 is Security-Switch's own final answer, not a call failure)", result.Err)
	}
	if result.StatusCode != http.StatusConflict {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusConflict)
	}
}

// Requirement: EH-F-09
func TestRegister_Unreachable(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	stop() // close immediately: the server is unreachable for the real call below

	result := Register(context.Background(), client, baseURL, validation.RegisterRequest{Email: testEmail, Password: testPassword, SSHPublicKey: testSSHPublicKey})

	if result.Err == nil {
		t.Fatal("expected a non-nil error when the peer is unreachable")
	}
	if result.StatusCode != 0 {
		t.Fatalf("StatusCode = %d, want 0 on a call failure", result.StatusCode)
	}
}

// Requirement: EH-F-07
// Requirement: EH-F-08
func TestLogin_RelaysResponseUnchanged(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != LoginPath {
			t.Errorf("path = %s, want %s", r.URL.Path, LoginPath)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	defer stop()

	result := Login(context.Background(), client, baseURL, validation.LoginRequest{Email: testEmail, Password: testPassword})

	if result.Err != nil {
		t.Fatalf("Err = %v, want nil", result.Err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if string(result.Body) != `{"status":"ok"}` {
		t.Fatalf("Body = %q, want the stub's response body unchanged", result.Body)
	}
}

// Requirement: EH-F-08
func TestLogin_RelaysUnauthorizedStatusUnchanged(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"authentication failed"}`))
	})
	defer stop()

	result := Login(context.Background(), client, baseURL, validation.LoginRequest{Email: testEmail, Password: testPassword})

	if result.Err != nil {
		t.Fatalf("Err = %v, want nil (a 401 is Security-Switch's own final answer, not a call failure)", result.Err)
	}
	if result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusUnauthorized)
	}
}
