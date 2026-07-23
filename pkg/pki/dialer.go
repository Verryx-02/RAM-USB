package pki

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	stepca "github.com/smallstep/certificates/ca"
)

// DialFunc dials a single network connection for this package's outbound
// HTTP traffic. Its signature matches (*pkg/mesh.Server).Dial and
// (*net.Dialer).DialContext exactly, so either can be passed directly as
// the dial argument to NewClientWithDialer/NewServerWithDialer/
// RouteThroughDialer - in particular a mesh-joined service's own
// meshNode.Dial, to route this package's traffic through its mesh
// identity instead of plain DNS/TCP (NET-F-01, NM-F-04).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ErrUnexpectedTransportType is returned when the *http.Client this
// package is asked to route isn't backed by a *http.Transport - the same
// guard, and the same reasoning, as TLSConfig/ForceServerName's identical
// type assertion elsewhere in this package (client_tls_config.go,
// servername.go). This is not a documented contract of
// github.com/smallstep/certificates@v0.30.2: a future version of
// ca.BootstrapClient could stop returning a concrete *http.Transport
// without warning. Rather than silently leaving outbound traffic
// unrouted, RouteThroughDialer fails closed (RD-04) when this happens.
var ErrUnexpectedTransportType = errors.New("pki: client.Transport is not a *http.Transport; dialer routing cannot be installed")

// ErrServerDialerUnsupported is returned by NewServerWithDialer when a
// non-nil dial is supplied. Investigated directly against the pinned
// github.com/smallstep/certificates@v0.30.2 source
// (ca.Client.GetServerTLSConfig, called internally by ca.BootstrapServer,
// in ca/tls.go): the *http.Transport its background certificate-renewal
// goroutine dials through (built by ca's own unexported getDefaultTransport
// + Client.buildDialTLSContext) is constructed entirely inside that call
// and is never returned to the caller - GetServerTLSConfig hands back only
// the resulting *tls.Config, and BootstrapServer only ever exposes that
// *tls.Config (as base.TLSConfig), discarding the transport. Unlike
// BootstrapClient (whose returned *http.Client.Transport IS that same
// renewal transport - see RouteThroughDialer), there is no reference to it
// anywhere reachable from BootstrapServer's return value.
//
// This means a bootstrapped server's own outbound renewal calls back to
// the Certificate-Authority cannot be routed through a custom dialer using
// only this library version's public API. Rather than accepting the
// option and silently leaving that traffic unrouted, NewServerWithDialer
// fails loud (RD-04) so a caller relying on mesh-only reachability finds
// out immediately, not the first time a renewal silently fails after the
// Certificate-Authority stops being reachable over plain DNS/TCP.
var ErrServerDialerUnsupported = errors.New("pki: a bootstrapped server's own certificate-renewal traffic cannot be routed through a custom dialer with the pinned smallstep/certificates version")

// NewClientWithDialer is NewClient, except every outbound connection the
// returned *http.Client makes AFTER this function returns - every request
// the caller sends through it, and its automatic certificate-renewal
// requests back to the Certificate-Authority alike - is dialed via dial
// instead of the process's default network stack. A nil dial makes this
// call behave identically to NewClient (and NewClient is defined in terms
// of this function, with a nil dial).
//
// Not covered: the single initial certificate-signing exchange (the
// root-of-trust pinning fetch, then the Version/Sign requests)
// stepca.BootstrapClient performs internally before this function ever
// returns a handle to the caller. The vendored library gives no hook to
// reach that transport from outside the ca package - it is built and used
// entirely inside ca.createBootstrap/ca.Bootstrap, called before
// BootstrapClient constructs the *http.Client this function receives. That
// one-time exchange therefore still goes out over the process's default
// network path even when dial is non-nil; only traffic through the
// returned *http.Client afterward is routed.
//
// See RouteThroughDialer's doc comment for the mechanism and the specific
// undocumented library behavior it relies on.
func NewClientWithDialer(ctx context.Context, token string, dial DialFunc) (*http.Client, error) {
	client, err := stepca.BootstrapClient(ctx, token)
	if err != nil {
		return nil, err
	}
	if dial == nil {
		return client, nil
	}
	if err := RouteThroughDialer(client, dial); err != nil {
		return nil, err
	}
	return client, nil
}

// NewServerWithDialer is NewServer, except a non-nil dial is rejected with
// ErrServerDialerUnsupported: see that error's doc comment for why no
// interception point exists, in the pinned library version, for a
// bootstrapped server's own certificate-renewal traffic. A nil dial makes
// this call behave identically to NewServer (and NewServer is defined in
// terms of this function, with a nil dial).
func NewServerWithDialer(ctx context.Context, token string, base *http.Server, dial DialFunc) (*http.Server, error) {
	if dial != nil {
		return nil, ErrServerDialerUnsupported
	}
	return stepca.BootstrapServer(ctx, token, base)
}

// RouteThroughDialer reconfigures client - as returned by NewClient/
// NewClientWithDialer(ctx, token, nil) - so every connection it dials from
// this point forward, including the ones its own background certificate-
// renewal goroutine makes, goes through dial instead of the process's
// default network stack.
//
// This needs more than installing dial as client.Transport.(*http.Transport)
// .DialContext: confirmed by reading
// github.com/smallstep/certificates@v0.30.2/ca/tls.go's
// Client.getClientTLSConfig (BootstrapClient's caller), the returned
// *http.Transport always has DialTLSContext set
// (Client.buildDialTLSContext), and net/http's own documented behavior is
// that when DialTLSContext is set, the Dial/DialContext hooks are not used
// for HTTPS requests at all - installing only DialContext would therefore
// be a silent no-op for every real request this package's callers make
// (they are all HTTPS). RouteThroughDialer instead replaces DialTLSContext
// outright, with a dialer built from dial plus
// client.Transport.TLSClientConfig - the same *tls.Config object
// (confirmed via the same source read: getDefaultTransport sets
// TLSClientConfig to the exact tlsConfig the SDK already wired
// GetClientCertificate into) ForceServerName already relies on being
// equivalent, for the same renewal-preservation reason documented there
// (servername.go). Certificate renewal, driven by the SDK's own
// TLSRenewer via that shared GetClientCertificate closure, keeps working
// unchanged.
//
// This mechanism is not a documented contract of the vendored library and
// could break on a future version - see ErrUnexpectedTransportType.
func RouteThroughDialer(client *http.Client, dial DialFunc) error {
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("%w: got %T", ErrUnexpectedTransportType, client.Transport)
	}

	transport.DialContext = dial

	// Only replace DialTLSContext if the SDK set one in the first place
	// (it always does today, for every HTTPS request client's callers
	// make - see the doc comment above). This keeps RouteThroughDialer
	// correct even if a future SDK version's Transport() stops setting
	// one, in which case installing DialContext above is already
	// sufficient (net/http falls back to DialContext + TLSClientConfig).
	if transport.DialTLSContext != nil {
		tlsConfig := transport.TLSClientConfig
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		}
	}

	return nil
}
