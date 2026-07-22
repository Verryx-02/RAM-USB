package mtls

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// startPlainTLSServer starts a bare TLS listener (no client-cert
// requirement of its own) presenting serverCert, standing in for a real
// peer this test dials with WithOrganization's output - mirroring
// pkg/metrics/tlsconfig_test.go's own startTestBroker helper (same shape:
// drive each accepted connection's handshake in the background, since a
// client's dial only completes once the server side has serviced it).
func startPlainTLSServer(t *testing.T, serverCert tls.Certificate) (addr string, stop func()) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tls.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.HandshakeContext(context.Background())
			}(conn.(*tls.Conn)) //nolint:forcetypeassert // tls.Listen always returns *tls.Conn from Accept
		}
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}

// Requirement: PKI-F-02
//
// WithOrganization accepts a peer certificate carrying allowedOrganization
// and rejects one that does not - proving the layered VerifyConnection
// callback is genuinely enforced at the handshake level (not merely
// present but unwired), the same guarantee ClientConfig's own
// VerifyConnection provides when built from scratch.
func TestWithOrganization_AcceptsAllowedRejectsOther(t *testing.T) {
	ca, err := NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	clientCert, err := ca.IssueLeaf("SomeService", "with-organization-test-client")
	if err != nil {
		t.Fatalf("IssueLeaf(client) error = %v, want nil", err)
	}

	allowedServerCert, err := ca.IssueLeaf("MQTTBroker", "with-organization-test-server-allowed")
	if err != nil {
		t.Fatalf("IssueLeaf(allowed server) error = %v, want nil", err)
	}
	impostorServerCert, err := ca.IssueLeaf("SomeOtherOrg", "with-organization-test-server-impostor")
	if err != nil {
		t.Fatalf("IssueLeaf(impostor server) error = %v, want nil", err)
	}

	// base stands in for a pki-bootstrapped *tls.Config: it presents a
	// client certificate and trusts ca's pool. WithOrganization must not
	// touch either of these.
	base := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.Pool(),
		ServerName:   "localhost",
	}

	tests := []struct {
		name       string
		serverCert tls.Certificate
		wantError  bool
	}{
		{name: "server certificate organization MQTTBroker is accepted", serverCert: allowedServerCert, wantError: false},
		{name: "server certificate with a different organization is rejected", serverCert: impostorServerCert, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, stop := startPlainTLSServer(t, tt.serverCert)
			defer stop()

			cfg := WithOrganization(base, "MQTTBroker")

			dialer := &tls.Dialer{Config: cfg}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if tt.wantError {
				if err == nil {
					_ = conn.Close()
					t.Fatal("dialer.DialContext() error = nil, want an error for the wrong-organization server")
				}
				return
			}
			if err != nil {
				t.Fatalf("dialer.DialContext() error = %v, want nil", err)
			}
			_ = conn.Close()
		})
	}
}

// Requirement: PKI-F-02
//
// WithOrganization never mutates base - the same *tls.Config a caller may
// be reusing for several other roles at once (mirroring
// pki.ClientTLSConfig's identical guarantee, tested in
// pkg/pki/servername_test.go's TestClientTLSConfig_DoesNotMutateBase).
func TestWithOrganization_DoesNotMutateBase(t *testing.T) {
	base := &tls.Config{ServerName: "example"}

	cfg := WithOrganization(base, "MQTTBroker")

	if base.VerifyConnection != nil {
		t.Fatal("base.VerifyConnection was set by WithOrganization, want base left untouched")
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("cfg.VerifyConnection is nil, want WithOrganization's callback")
	}
	if cfg == base {
		t.Fatal("WithOrganization returned base itself, want an independent clone")
	}
	if cfg.ServerName != base.ServerName {
		t.Fatalf("cfg.ServerName = %q, want unchanged %q", cfg.ServerName, base.ServerName)
	}
}
