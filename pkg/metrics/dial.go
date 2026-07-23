package metrics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// DialFunc dials a network connection to addr, exactly the shape
// pkg/mesh.Server.Dial and net.Dialer.DialContext both already implement
// (also matching the inline dial parameter type every mesh-aware HTTP
// client builder in this codebase already uses, e.g.
// services/security-switch/cmd/security-switch/main.go's
// buildDatabaseVaultClient). WithDial accepts one so NewClient's MQTT
// connection can be routed through the private mesh instead of the
// default plain TCP dial - see WithDial.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// meshOpenConnectionFn adapts dial into a paho mqtt.OpenConnectionFunc for
// NewClient/WithDial.
//
// Confirmed by reading the pinned github.com/eclipse/paho.mqtt.golang@v1.5.1
// source directly: once options.CustomOpenConnectionFn is set,
// client.go's attemptConnection calls ONLY that function to obtain the
// connection - it never separately calls netconn.go's openConnection (the
// default path) afterward, for a "tls://" broker URL or any other scheme.
// So this function is entirely responsible for both dialing AND completing
// the TLS handshake itself, exactly mirroring what openConnection's own
// "ssl"/"tls" branch does for the default path (tls.DialWithDialer, whose
// single Timeout bounds the TCP connect AND the TLS handshake together) -
// so a mesh-routed connection gets the identical mTLS guarantee
// (PKI-F-02's organization check, already layered onto tlsConfig by
// TLSConfig/mtls.WithOrganization before this function ever runs) as the
// default path, never a silently downgraded/unverified one.
//
// OpenConnectionFunc's signature (uri *url.URL, options ClientOptions)
// carries no context.Context for this function to thread through, so
// timeout bounds both dial and handshake via context.WithTimeout(
// context.Background(), timeout) - timeout is connectTimeout, the same
// value NewClient's default path already uses for SetConnectTimeout,
// keeping the two paths' connection-establishment budget identical.
func meshOpenConnectionFn(dial DialFunc, tlsConfig *tls.Config, timeout time.Duration) mqtt.OpenConnectionFunc {
	return func(uri *url.URL, _ mqtt.ClientOptions) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		conn, err := dial(ctx, "tcp", uri.Host)
		if err != nil {
			return nil, fmt.Errorf("metrics: mesh dial %s: %w", uri.Host, err)
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("metrics: mesh TLS handshake with %s: %w", uri.Host, err)
		}

		return tlsConn, nil
	}
}
