package server_test

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/server"
)

// Requirement: EH-F-01
func TestTLSConfig_AcceptsConnectionsWithNoClientCertificate(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	serverCert, err := ca.IssueLeaf("EntryHub", "entry-hub-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v", err)
	}

	addr, results, stop := startTestServer(t, serverCert)
	defer stop()

	// Unlike every mTLS-accepting service in this codebase, Entry-Hub's
	// public listener (EH-F-01) must accept a plain TLS client presenting
	// no certificate at all - a real end user's browser/CLI client never
	// has one.
	if err := dial(addr); err != nil {
		t.Fatalf("dial() error = %v, want a successful plain-TLS handshake", err)
	}

	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("server handshake error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server handshake result")
	}
}

// startTestServer starts a plain-TLS listener using server.NewTLSConfig and
// accepts one connection in the background, same shape as
// security-switch/internal/server/server_test.go's helper, minus the client
// certificate acceptance/rejection rows this listener does not apply.
func startTestServer(t *testing.T, serverCert tls.Certificate) (string, <-chan error, func()) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", server.NewTLSConfig(serverCert))
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}

	results := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			results <- errors.New("accepted connection is not a *tls.Conn")
			return
		}
		results <- tlsConn.Handshake()
	}()

	return listener.Addr().String(), results, func() { _ = listener.Close() }
}

// dial attempts a plain TLS handshake against addr, presenting no client
// certificate - the server's own root of trust is irrelevant here since
// EH-F-01's listener never asks for one, so the dialer only needs to trust
// whatever certificate the server presents.
func dial(addr string) error {
	config := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, //nolint:gosec // test dialer trusting an in-memory test leaf whose CA is not otherwise wired into this dial; EH-F-01's own client-facing trust is the public Let's Encrypt CA, out of scope for this unit test
	}

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	return nil
}
