package metrics_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	packets "github.com/eclipse/paho.mqtt.golang/packets"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

const testClientConnectTimeout = 5 * time.Second

// Requirement: EH-F-10
// Requirement: SS-F-07
// Requirement: DV-F-16
// Requirement: ST-F-12
// Requirement: NM-F-17
// Requirement: CA-F-03
//
// Regression coverage: NewClient's pre-existing default behavior (a nil
// dial) is the exact same plain TCP-then-TLS connection every existing
// call site (services/*/cmd/*/main.go, services/metrics-collector/cmd/
// metrics-collector/main.go) still gets today.
func TestNewClient_DefaultDial_ConnectsWithoutAnyOption(t *testing.T) {
	tlsConfig, brokerCert := newMQTTClientTLSConfig(t, metrics.OrganizationMQTTBroker)
	addr, stop := startFakeMQTTBroker(t, brokerCert)
	defer stop()

	client, err := metrics.NewClient("tls://"+addr, tlsConfig, "default-dial-client", testClientConnectTimeout, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v, want nil", err)
	}
	defer client.Disconnect(250)

	if !client.IsConnected() {
		t.Fatal("client.IsConnected() = false, want true")
	}
}

// Requirement: NET-F-02
// Requirement: RD-04
//
// A dialer supplied to NewClient (standing in for pkg/mesh.Server.Dial)
// must actually be invoked, and the connection must still complete -
// proving the mesh-dial path is real, not merely accepted and ignored.
func TestNewClient_WithDial_InvokesCustomDialerAndConnects(t *testing.T) {
	tlsConfig, brokerCert := newMQTTClientTLSConfig(t, metrics.OrganizationMQTTBroker)
	addr, stop := startFakeMQTTBroker(t, brokerCert)
	defer stop()

	var dialCount atomic.Int32
	fakeDial := func(ctx context.Context, network, dialAddr string) (net.Conn, error) {
		dialCount.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, dialAddr)
	}

	client, err := metrics.NewClient("tls://"+addr, tlsConfig, "mesh-dial-client", testClientConnectTimeout, fakeDial)
	if err != nil {
		t.Fatalf("NewClient() error = %v, want nil", err)
	}
	defer client.Disconnect(250)

	if !client.IsConnected() {
		t.Fatal("client.IsConnected() = false, want true")
	}
	if dialCount.Load() == 0 {
		t.Fatal("custom dial function was never invoked, want at least one call")
	}
}

// Requirement: RD-04
//
// A custom dialer's own error must reach NewClient's caller, not be
// silently swallowed or retried into a misleading generic timeout.
func TestNewClient_WithDial_DialerErrorSurfaces(t *testing.T) {
	tlsConfig, brokerCert := newMQTTClientTLSConfig(t, metrics.OrganizationMQTTBroker)
	addr, stop := startFakeMQTTBroker(t, brokerCert)
	defer stop()

	wantErr := errors.New("mesh: forced dial failure for test")
	failingDial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, wantErr
	}

	_, err := metrics.NewClient("tls://"+addr, tlsConfig, "failing-dial-client", testClientConnectTimeout, failingDial)
	if err == nil {
		t.Fatal("NewClient() error = nil, want an error when the custom dialer always fails")
	}
}

// Requirement: PKI-F-02
//
// The mesh-dial path must enforce exactly the same
// organization check the default dial path already enforces
// (TestTLSConfig_AcceptsOnlyMQTTBrokerOrganization in tlsconfig_test.go) -
// the dial mechanism changing must never silently degrade the TLS
// handshake's authentication guarantee.
func TestNewClient_WithDial_EnforcesMQTTBrokerOrganization(t *testing.T) {
	tests := []struct {
		name           string
		brokerOrg      string
		wantConnectErr bool
	}{
		{
			name:           "broker certificate organization MQTTBroker is accepted",
			brokerOrg:      metrics.OrganizationMQTTBroker,
			wantConnectErr: false,
		},
		{
			name:           "broker certificate with a different organization is rejected",
			brokerOrg:      "SomeOtherService",
			wantConnectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, brokerCert := newMQTTClientTLSConfig(t, tt.brokerOrg)
			addr, stop := startFakeMQTTBroker(t, brokerCert)
			defer stop()

			dial := func(ctx context.Context, network, dialAddr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, dialAddr)
			}

			client, err := metrics.NewClient("tls://"+addr, tlsConfig, "org-check-client", testClientConnectTimeout, dial)
			if tt.wantConnectErr {
				if err == nil {
					client.Disconnect(250)
					t.Fatal("NewClient() error = nil, want an error for the wrong-organization broker")
				}
				return
			}

			if err != nil {
				t.Fatalf("NewClient() error = %v, want nil", err)
			}
			defer client.Disconnect(250)
			if !client.IsConnected() {
				t.Fatal("client.IsConnected() = false, want true")
			}
		})
	}
}

// newMQTTClientTLSConfig builds a client tlsConfig (per metrics.TLSConfig)
// trusting a freshly minted test CA, and issues a broker leaf certificate
// under brokerOrg for the caller to present via startFakeMQTTBroker - the
// same shape tlsconfig_test.go's TestTLSConfig_AcceptsOnlyMQTTBrokerOrganization
// already uses, factored out for reuse across this file's cases.
func newMQTTClientTLSConfig(t *testing.T, brokerOrg string) (tlsConfig *tls.Config, brokerCert tls.Certificate) {
	t.Helper()

	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}

	clientCert, err := ca.IssueLeaf("SomeService", "some-service-client")
	if err != nil {
		t.Fatalf("IssueLeaf(client) error = %v", err)
	}

	brokerCert, err = ca.IssueLeaf(brokerOrg, "mqtt-broker-under-test")
	if err != nil {
		t.Fatalf("IssueLeaf(broker) error = %v", err)
	}

	base := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.Pool(),
		ServerName:   "localhost",
	}

	return metrics.TLSConfig(base), brokerCert
}

// startFakeMQTTBroker starts a TLS listener presenting serverCert that
// speaks just enough real MQTT 3.1.1 server-side protocol
// (github.com/eclipse/paho.mqtt.golang/packets, already a transitive
// dependency of this module) for a real paho client's Connect() to
// succeed: read one CONNECT packet, reply with one accepting CONNACK, then
// keep the connection open until the client closes it. Unlike
// tlsconfig_test.go's startTestBroker (a bare TLS listener with no
// application-layer protocol, sufficient for a raw tls.Dialer test),
// metrics.NewClient drives a full paho mqtt.Client.Connect() call, which
// blocks waiting for a real CONNACK - a bare TLS accept-and-idle listener
// would make every "should succeed" case in this file indistinguishable
// from a hung/failed one (both just time out).
func startFakeMQTTBroker(t *testing.T, serverCert tls.Certificate) (addr string, stop func()) {
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
			go serveFakeMQTTConn(conn)
		}
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}

// serveFakeMQTTConn drives one accepted connection: the CONNECT/CONNACK
// handshake, then blocks reading (discarding anything received) until the
// client disconnects, keeping the connection - and therefore the paho
// client's IsConnected() - alive for the test to assert against.
func serveFakeMQTTConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if _, err := packets.ReadPacket(conn); err != nil {
		return
	}

	ack, ok := packets.NewControlPacket(packets.Connack).(*packets.ConnackPacket)
	if !ok {
		return
	}
	ack.ReturnCode = packets.Accepted
	if err := ack.Write(conn); err != nil {
		return
	}

	buf := make([]byte, 256)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}
