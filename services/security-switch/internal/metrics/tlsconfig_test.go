package metrics_test

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/metrics"
)

// Requirement: SS-F-07
func TestTLSConfig_AcceptsOnlyMQTTBrokerOrganization(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	clientCert, err := ca.IssueLeaf("SecuritySwitch", "security-switch-client")
	if err != nil {
		t.Fatalf("IssueLeaf(client) error = %v", err)
	}

	brokerCert, err := ca.IssueLeaf(metrics.OrganizationMQTTBroker, "mqtt-broker-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(broker) error = %v", err)
	}

	impostorCert, err := ca.IssueLeaf("SomeOtherService", "impostor-broker")
	if err != nil {
		t.Fatalf("IssueLeaf(impostor) error = %v", err)
	}

	tests := []struct {
		name       string
		serverCert tls.Certificate
		wantError  bool
	}{
		{
			name:       "broker certificate organization MQTTBroker is accepted",
			serverCert: brokerCert,
			wantError:  false,
		},
		{
			name:       "broker certificate with a different organization is rejected",
			serverCert: impostorCert,
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, stop := startTestBroker(t, tt.serverCert)
			defer stop()

			config := metrics.TLSConfig(clientCert, ca.Pool())
			config.ServerName = "localhost"

			dialer := &tls.Dialer{Config: config}
			conn, err := dialer.DialContext(context.Background(), "tcp", addr)
			if tt.wantError {
				if err == nil {
					_ = conn.Close()
					t.Fatal("dialer.DialContext() error = nil, want an error for the wrong-organization broker")
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

// startTestBroker starts a bare (no client-cert-required) TLS listener
// standing in for the MQTT broker, presenting serverCert. It drives each
// accepted connection's handshake in the background, exactly like
// server_test.go's startTestServer helper, since a client's tls.Dial
// only completes once the server side has serviced the handshake.
func startTestBroker(t *testing.T, serverCert tls.Certificate) (addr string, stop func()) {
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
			}(conn.(*tls.Conn))
		}
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}
