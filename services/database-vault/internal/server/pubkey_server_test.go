package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/server"
)

// Requirement: ST-F-11
func TestPublicKeyTLSConfig_AcceptsOnlyStorageServiceOrganization(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	serverCert, err := ca.IssueLeaf("DatabaseVault", "database-vault-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v", err)
	}

	storageServiceCert, err := ca.IssueLeaf("StorageService", "storage-service-client")
	if err != nil {
		t.Fatalf("IssueLeaf(StorageService) error = %v", err)
	}

	securitySwitchCert, err := ca.IssueLeaf("SecuritySwitch", "security-switch-client")
	if err != nil {
		t.Fatalf("IssueLeaf(SecuritySwitch) error = %v", err)
	}

	otherOrgCert, err := ca.IssueLeaf("SomeOtherService", "impostor-client")
	if err != nil {
		t.Fatalf("IssueLeaf(SomeOtherService) error = %v", err)
	}

	tests := []struct {
		name       string
		clientCert *tls.Certificate
		wantError  bool
	}{
		{
			name:       "client certificate organization StorageService is accepted",
			clientCert: &storageServiceCert,
			wantError:  false,
		},
		{
			// SS-F-01/DV-F-01's own caller must NOT reach this listener:
			// Security-Switch has no business calling Database-Vault's
			// public-key lookup endpoint, only Storage-Service does.
			name:       "client certificate organization SecuritySwitch is rejected",
			clientCert: &securitySwitchCert,
			wantError:  true,
		},
		{
			name:       "client certificate with a different organization is rejected",
			clientCert: &otherOrgCert,
			wantError:  true,
		},
		{
			name:       "connection without any client certificate is rejected",
			clientCert: nil,
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, results, stop := startPublicKeyTestServer(t, serverCert, ca.Pool())
			defer stop()

			// Same TLS 1.3 0.5-RTT caveat as TestTLSConfig_AcceptsOnlySecuritySwitchOrganization
			// in server_test.go: the client-side dial's own error is not
			// authoritative, only the server's own handshake result is.
			_ = dialWithClientCert(addr, ca.Pool(), tt.clientCert)

			select {
			case err := <-results:
				if tt.wantError && err == nil {
					t.Fatalf("server handshake error = nil, want an error")
				}
				if !tt.wantError && err != nil {
					t.Fatalf("server handshake error = %v, want nil", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for server handshake result")
			}
		})
	}
}

// startPublicKeyTestServer mirrors startTestServer in server_test.go,
// but against server.NewPublicKeyTLSConfig instead of server.NewTLSConfig —
// the two listeners must be exercised separately since they enforce
// different organizations.
func startPublicKeyTestServer(t *testing.T, serverCert tls.Certificate, clientCAs *x509.CertPool) (string, <-chan error, func()) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", server.NewPublicKeyTLSConfig(serverCert, clientCAs))
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}

	results := make(chan error, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				tlsConn, ok := c.(*tls.Conn)
				if !ok {
					results <- errors.New("accepted connection is not a *tls.Conn")
					return
				}
				results <- tlsConn.HandshakeContext(context.Background())
			}(conn)
		}
	}()

	return listener.Addr().String(), results, func() { _ = listener.Close() }
}
