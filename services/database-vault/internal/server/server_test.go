package server_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/server"
)

// Requirement: DV-F-01
func TestTLSConfig_AcceptsOnlySecuritySwitchOrganization(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	serverCert, err := ca.IssueLeaf("Database-Vault", "database-vault-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v", err)
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
			name:       "client certificate organization SecuritySwitch is accepted",
			clientCert: &securitySwitchCert,
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

			// The client's own view of the handshake is not authoritative:
			// in TLS 1.3 the client sends its last handshake flight
			// (Finished) without waiting for the server to finish
			// validating the client certificate, so tls.Dial can report
			// success even when the server is about to reject the peer
			// (the "0.5-RTT" client-perceived completion). What DV-F-01
			// specifies is which connections Database-Vault itself
			// accepts, so the server's own handshake result, reported on
			// results, is the assertion that matters here. The dial is
			// still issued to drive that server-side handshake; any error
			// it returns is not asserted on.
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
// accepts connections in the background. Each accepted connection's own
// handshake result (the server's authoritative view of whether it accepted
// that peer) is sent to the returned channel. It also returns the listener
// address and a stop function to close it.
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
				results <- tlsConn.Handshake()
			}(conn)
		}
	}()

	return listener.Addr().String(), results, func() { _ = listener.Close() }
}

// dialWithClientCert attempts an mTLS handshake against addr, presenting
// clientCert if non-nil, and trusting rootCAs to verify the server's
// certificate. It returns the client-side dial/handshake error, if any; see
// the caller for why that error is not the assertion of record.
func dialWithClientCert(addr string, rootCAs *x509.CertPool, clientCert *tls.Certificate) error {
	config := &tls.Config{
		RootCAs:    rootCAs,
		ServerName: "localhost",
	}
	if clientCert != nil {
		config.Certificates = []tls.Certificate{*clientCert}
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	return nil
}
