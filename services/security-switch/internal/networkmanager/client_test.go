package networkmanager

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// newStub mirrors dbvault/client_test.go's newStub, issuing a
// Network-Manager-organization server certificate instead.
func newStub(t *testing.T, handler http.HandlerFunc) (string, *http.Client, func()) {
	t.Helper()

	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	serverCert, err := ca.IssueLeaf("NetworkManager", "network-manager-stub")
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
			TLSClientConfig: mtls.ClientConfig(clientCert, ca.Pool(), OrganizationNetworkManager),
		},
		Timeout: 5 * time.Second,
	}

	return baseURL, client, srv.Close
}

// Requirement: SS-F-05
func TestGrantAccess_Success(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != GrantPath {
			t.Errorf("path = %s, want %s", r.URL.Path, GrantPath)
		}
		var got grantRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode grant request: %v", err)
		}
		if got.Email != "user@example.com" {
			t.Fatalf("Email = %q, want %q", got.Email, "user@example.com")
		}
		if got.DurationSeconds != int64(GrantDuration.Seconds()) {
			t.Fatalf("DurationSeconds = %d, want %d", got.DurationSeconds, int64(GrantDuration.Seconds()))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(grantResponse{Success: true})
	})
	defer stop()

	err := GrantAccess(context.Background(), client, baseURL, "user@example.com")
	if err != nil {
		t.Fatalf("GrantAccess() error = %v, want nil", err)
	}
}

// Requirement: SS-F-05
// Requirement: SS-F-06
func TestGrantAccess_Denied(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(grantResponse{Success: false, Error: "denied"})
	})
	defer stop()

	err := GrantAccess(context.Background(), client, baseURL, "user@example.com")
	if !errors.Is(err, ErrGrantDenied) {
		t.Fatalf("GrantAccess() error = %v, want ErrGrantDenied", err)
	}
}

// Requirement: SS-F-06
func TestGrantAccess_ServerErrorMapsToUnreachable(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"internal server error", http.StatusInternalServerError},
		{"bad gateway", http.StatusBadGateway},
		{"service unavailable", http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(grantResponse{Success: false, Error: "upstream failure"})
			})
			defer stop()

			err := GrantAccess(context.Background(), client, baseURL, "user@example.com")
			if !errors.Is(err, ErrNetworkManagerUnreachable) {
				t.Fatalf("GrantAccess() error = %v, want ErrNetworkManagerUnreachable", err)
			}
			if errors.Is(err, ErrGrantDenied) {
				t.Fatalf("GrantAccess() error = %v must not also be ErrGrantDenied - a 5xx is Network-Manager's own failure, not a considered denial", err)
			}
		})
	}
}

// Requirement: SS-F-06
func TestGrantAccess_ServerErrorWithMalformedBodyMapsToUnreachable(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("<html>Service Unavailable</html>"))
	})
	defer stop()

	err := GrantAccess(context.Background(), client, baseURL, "user@example.com")
	if !errors.Is(err, ErrNetworkManagerUnreachable) {
		t.Fatalf("GrantAccess() error = %v, want ErrNetworkManagerUnreachable even with a non-JSON body", err)
	}
}

// Requirement: SS-F-06
func TestGrantAccess_Unreachable(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	stop()

	err := GrantAccess(context.Background(), client, baseURL, "user@example.com")
	if err == nil {
		t.Fatal("expected a non-nil error when the peer is unreachable")
	}
}

// Requirement: SS-F-09
func TestCreateMeshUser_Success(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != MeshUserPath {
			t.Errorf("path = %s, want %s", r.URL.Path, MeshUserPath)
		}
		var got meshUserRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode mesh user request: %v", err)
		}
		if got.Email != "user@example.com" {
			t.Fatalf("Email = %q, want %q", got.Email, "user@example.com")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(meshUserResponse{Success: true, PreAuthKey: "authkey-abc123"})
	})
	defer stop()

	preAuthKey, err := CreateMeshUser(context.Background(), client, baseURL, "user@example.com")
	if err != nil {
		t.Fatalf("CreateMeshUser() error = %v, want nil", err)
	}
	if preAuthKey != "authkey-abc123" {
		t.Fatalf("preAuthKey = %q, want %q", preAuthKey, "authkey-abc123")
	}
}

// Requirement: SS-F-09
func TestCreateMeshUser_Denied(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(meshUserResponse{Success: false, Error: "denied"})
	})
	defer stop()

	preAuthKey, err := CreateMeshUser(context.Background(), client, baseURL, "user@example.com")
	if !errors.Is(err, ErrMeshUserCreationDenied) {
		t.Fatalf("CreateMeshUser() error = %v, want ErrMeshUserCreationDenied", err)
	}
	if preAuthKey != "" {
		t.Fatalf("preAuthKey = %q, want empty on denial", preAuthKey)
	}
}

// Requirement: SS-F-09
func TestCreateMeshUser_ServerErrorMapsToUnreachable(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"internal server error", http.StatusInternalServerError},
		{"bad gateway", http.StatusBadGateway},
		{"service unavailable", http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(meshUserResponse{Success: false, Error: "upstream failure"})
			})
			defer stop()

			_, err := CreateMeshUser(context.Background(), client, baseURL, "user@example.com")
			if !errors.Is(err, ErrNetworkManagerUnreachable) {
				t.Fatalf("CreateMeshUser() error = %v, want ErrNetworkManagerUnreachable", err)
			}
			if errors.Is(err, ErrMeshUserCreationDenied) {
				t.Fatalf("CreateMeshUser() error = %v must not also be ErrMeshUserCreationDenied - a 5xx is Network-Manager's own failure, not a considered denial", err)
			}
		})
	}
}

// Requirement: SS-F-09
func TestCreateMeshUser_ServerErrorWithMalformedBodyMapsToUnreachable(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("<html>Service Unavailable</html>"))
	})
	defer stop()

	_, err := CreateMeshUser(context.Background(), client, baseURL, "user@example.com")
	if !errors.Is(err, ErrNetworkManagerUnreachable) {
		t.Fatalf("CreateMeshUser() error = %v, want ErrNetworkManagerUnreachable even with a non-JSON body", err)
	}
}

// Requirement: SS-F-09
func TestCreateMeshUser_Unreachable(t *testing.T) {
	baseURL, client, stop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	stop()

	_, err := CreateMeshUser(context.Background(), client, baseURL, "user@example.com")
	if err == nil {
		t.Fatal("expected a non-nil error when the peer is unreachable")
	}
}
