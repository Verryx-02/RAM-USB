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
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/server"
)

// Requirement: SS-F-01
func TestTLSConfig_AcceptsOnlyEntryHubOrganization(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	serverCert, err := ca.IssueLeaf("SecuritySwitch", "security-switch-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v", err)
	}

	entryHubCert, err := ca.IssueLeaf("EntryHub", "entry-hub-client")
	if err != nil {
		t.Fatalf("IssueLeaf(EntryHub) error = %v", err)
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
			name:       "client certificate organization EntryHub is accepted",
			clientCert: &entryHubCert,
			wantError:  false,
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
			addr, results, stop := startTestServer(t, serverCert, ca.Pool())
			defer stop()

			// See services/database-vault/internal/server/server_test.go's
			// identical comment: the client-side dial error is not
			// authoritative under TLS 1.3's 0.5-RTT client-perceived
			// completion, so only the server's own handshake result,
			// reported on results, is asserted on.
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

// startTestServer starts an mTLS listener using server.NewTLSConfig and
// accepts connections in the background, same shape as
// database-vault/internal/server/server_test.go's helper.
func startTestServer(t *testing.T, serverCert tls.Certificate, clientCAs *x509.CertPool) (string, <-chan error, func()) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", server.NewTLSConfig(serverCert, clientCAs))
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

// dialWithClientCert attempts an mTLS handshake against addr, presenting
// clientCert if non-nil.
func dialWithClientCert(addr string, rootCAs *x509.CertPool, clientCert *tls.Certificate) error {
	config := &tls.Config{
		RootCAs:    rootCAs,
		ServerName: "localhost",
	}
	if clientCert != nil {
		config.Certificates = []tls.Certificate{*clientCert}
	}

	dialer := &tls.Dialer{Config: config}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	return nil
}
