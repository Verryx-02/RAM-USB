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
