package posix_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/posix"
)

// stubStorageService starts an httptest.Server standing in for
// Storage-Service (ST-F-06/ST-F-10 have no real implementation yet), wired
// with the exact same mtls.ServerConfig/mtls.ClientConfig production logic
// Database-Vault and Storage-Service will really use, so this test exercises
// real mTLS handshakes and organization checks, not a bypass of them. It
// returns a base URL using "localhost" rather than httptest's default
// 127.0.0.1: mtls.TestCA.IssueLeaf only puts "localhost" in the leaf
// certificate's DNSNames (no IP SAN), and http.Client's hostname
// verification checks whatever host appears in the request URL.
func stubStorageService(t *testing.T, ca *mtls.TestCA, serverOrg string, handler http.HandlerFunc) (baseURL string, srv *httptest.Server) {
	t.Helper()

	serverCert, err := ca.IssueLeaf(serverOrg, "storage-service-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v", err)
	}

	srv = httptest.NewUnstartedServer(handler)
	srv.TLS = mtls.ServerConfig(serverCert, ca.Pool(), "Database-Vault")
	srv.StartTLS()
	t.Cleanup(srv.Close)

	_, port, ok := strings.Cut(srv.Listener.Addr().String(), ":")
	if !ok {
		t.Fatalf("listener address %q has no port", srv.Listener.Addr().String())
	}

	return "https://localhost:" + port, srv
}

// newClient builds the http.Client Database-Vault uses to call
// Storage-Service: an outbound mTLS client trusting only ca and presenting
// a "Database-Vault" client certificate, requiring the peer's certificate
// come from "StorageService" (DV-F-09).
func newClient(t *testing.T, ca *mtls.TestCA) *http.Client {
	t.Helper()

	clientCert, err := ca.IssueLeaf("Database-Vault", "database-vault-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(client) error = %v", err)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtls.ClientConfig(clientCert, ca.Pool(), "StorageService"),
		},
		Timeout: 2 * time.Second,
	}
}

// Requirement: DV-F-09
func TestCreatePOSIXUser_Success(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	baseURL, _ := stubStorageService(t, ca, "StorageService", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != posix.CreateUserPath {
			t.Errorf("request path = %q, want %q", r.URL.Path, posix.CreateUserPath)
		}
		if r.Method != http.MethodPost {
			t.Errorf("request method = %q, want POST", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})

	client := newClient(t, ca)

	err = posix.CreatePOSIXUser(context.Background(), client, baseURL, "user1a2b3c")
	if err != nil {
		t.Fatalf("CreatePOSIXUser() error = %v, want nil", err)
	}
}

// Requirement: DV-F-09
func TestCreatePOSIXUser_FailureResponse(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	baseURL, _ := stubStorageService(t, ca, "StorageService", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   "useradd exited with status 1",
		})
	})

	client := newClient(t, ca)

	err = posix.CreatePOSIXUser(context.Background(), client, baseURL, "user1a2b3c")
	if err == nil {
		t.Fatal("CreatePOSIXUser() error = nil, want a failure error")
	}
	if !errors.Is(err, posix.ErrPOSIXUserCreationFailed) {
		t.Fatalf("CreatePOSIXUser() error = %v, want it to wrap ErrPOSIXUserCreationFailed", err)
	}
}

// Requirement: DV-F-09
func TestCreatePOSIXUser_MalformedResponseBody(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	baseURL, _ := stubStorageService(t, ca, "StorageService", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("not json"))
	})

	client := newClient(t, ca)

	err = posix.CreatePOSIXUser(context.Background(), client, baseURL, "user1a2b3c")
	if err == nil {
		t.Fatal("CreatePOSIXUser() error = nil, want a failure error")
	}
	if !errors.Is(err, posix.ErrPOSIXUserCreationFailed) {
		t.Fatalf("CreatePOSIXUser() error = %v, want it to wrap ErrPOSIXUserCreationFailed", err)
	}
}

// Requirement: DV-F-09
func TestCreatePOSIXUser_ServerWrongOrganization(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	// The stub presents a certificate from an organization other than
	// "StorageService" - the outbound mTLS client (DV-F-09's zero-trust
	// requirement, RNF-SEC-02/03) must refuse to treat this as
	// Storage-Service at all, regardless of what the handler would answer.
	baseURL, _ := stubStorageService(t, ca, "SomeOtherService", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})

	client := newClient(t, ca)

	err = posix.CreatePOSIXUser(context.Background(), client, baseURL, "user1a2b3c")
	if err == nil {
		t.Fatal("CreatePOSIXUser() error = nil, want a failure error for a non-StorageService peer")
	}
	if !errors.Is(err, posix.ErrStorageServiceUnreachable) {
		t.Fatalf("CreatePOSIXUser() error = %v, want it to wrap ErrStorageServiceUnreachable", err)
	}
}

// Requirement: DV-F-09
func TestCreatePOSIXUser_ConnectionFailure(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	baseURL, srv := stubStorageService(t, ca, "StorageService", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	})
	srv.Close() // stop listening before the client ever calls out

	client := newClient(t, ca)

	err = posix.CreatePOSIXUser(context.Background(), client, baseURL, "user1a2b3c")
	if err == nil {
		t.Fatal("CreatePOSIXUser() error = nil, want a connection failure error")
	}
	if !errors.Is(err, posix.ErrStorageServiceUnreachable) {
		t.Fatalf("CreatePOSIXUser() error = %v, want it to wrap ErrStorageServiceUnreachable", err)
	}
}
