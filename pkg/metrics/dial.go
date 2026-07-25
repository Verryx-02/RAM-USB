package metrics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/mesh"
)

// meshOpenConnectionFn adapts dial into a paho mqtt.OpenConnectionFunc for
// NewClient's dial parameter.
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
func meshOpenConnectionFn(dial mesh.DialFunc, tlsConfig *tls.Config, timeout time.Duration) mqtt.OpenConnectionFunc {
	return func(uri *url.URL, _ mqtt.ClientOptions) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout) //nolint:contextcheck // paho's OpenConnectionFunc signature carries no context.Context to thread through (see doc comment above)
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
