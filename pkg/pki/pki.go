// Package pki is a thin wrapper around github.com/smallstep/certificates/ca's
// bootstrap primitives (CA-F-04, PKI-F-01). Each RAM-USB service holds a
// single-use bootstrap token, distributed out-of-band (SRS section 2.6, the
// note on "Distribution of initial certificates" — same channel used for
// RAM_USB_MASTER_KEY (DV-F-05) and RAM_USB_PASSWORD_PEPPER (DV-F-06)), and
// exchanges it exactly once, at startup, for an initial mTLS certificate
// issued by the Certificate-Authority (the official smallstep/step-ca server,
// run as a separate container — see
// deployments/compose/certificate-authority.yml and
// docs/design/diagrams/08-security-pki-hierarchy.puml). Subsequent renewal
// happens automatically, driven by the vendor SDK's own built-in mechanism
// (renewing at 2/3 of the certificate's lifetime by default) — no polling
// loop, and the bootstrap token itself is never reused for a renewal
// (CA-F-04).
//
// The bootstrap token carries the CA's URL (its "aud" claim) and the CA's
// root certificate fingerprint (its "sha" claim) — see
// github.com/smallstep/certificates/ca.Bootstrap's implementation.
// Callers of this package therefore need only the token itself, not a
// separately configured CA URL.
//
// Deliberately out of scope for this package:
//   - Issuing bootstrap tokens: that is the CA operator's job (`step ca
//     token`/`step ca provisioner`), not something a RAM-USB service does
//     for itself.
//   - Enforcing PKI-F-02's certificate-organization check on the
//     server/client this package returns: that check lives in pkg/mtls
//     (mtls.ServerConfig/ClientConfig's VerifyConnection callback).
//     Wiring pkg/mtls's organization check into the *tls.Config this
//     package produces is a follow-up integration task for whichever
//     service adopts pkg/pki, not built here.
//
// A caller building an outbound client from this package's *tls.Config/
// *http.Client (ClientTLSConfig/ForceServerName in servername.go) must
// also force that outbound TLS handshake's ServerName to the expected
// peer organization, not leave it to default to the dialed network
// address: RAM-USB's identity model (this session's confirmed
// architecture decision) relies solely on PKI-F-02's organization check,
// not on crypto/tls's own independent, handshake-level hostname
// verification, which would otherwise reject a correctly-issued
// certificate whenever the dialed network name (which differs between
// dev/compose and production topology) doesn't literally match the
// certificate's SAN (itself always equal to the requested organization,
// per third-party/certificate-authority/config/organization.x509.tpl).
// See servername.go's doc comments for the full reasoning and the
// verified-safe mechanics of doing this without ever touching
// InsecureSkipVerify or skipping chain validation.
package pki

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"

	stepca "github.com/smallstep/certificates/ca"
)

// forceTLS13 is a stepca.TLSOption applied unconditionally by every
// bootstrap call in this package. NET-F-02 requires TLS 1.3 with no
// exceptions, but ca.BootstrapServer/BootstrapClient's own default
// *tls.Config (getDefaultTLSConfig, ca/tls.go) sets MinVersion to TLS 1.2
// when the CA's TLSOptions are unset — and RAM-USB's Certificate-Authority
// config doesn't set them either. TLSOptionCtx.Config is the same
// *tls.Config pointer the SDK goes on to use for the listener/transport
// (confirmed by reading ca/tls.go's GetServerTLSConfig/getClientTLSConfig),
// so mutating it here survives certificate renewal.
func forceTLS13(ctx *stepca.TLSOptionCtx) error {
	ctx.Config.MinVersion = tls.VersionTLS13
	return nil
}

// BootstrapTokenEnvVar names the environment variable holding this
// service's single-use CA bootstrap token (CA-F-04), distributed
// out-of-band per SRS section 2.6. This name is this package's own judgment
// call (the SRS specifies only "out-of-band," no variable name) — chosen
// to follow the same RAM_USB_* convention as RAM_USB_MASTER_KEY and
// RAM_USB_PASSWORD_PEPPER.
const BootstrapTokenEnvVar = "RAM_USB_CA_BOOTSTRAP_TOKEN" //nolint:gosec // an env var *name*, not a credential value

// ErrBootstrapTokenMissing is returned when BootstrapTokenEnvVar is unset
// or set to an empty string. Both are treated identically (RD-04,
// fail-secure) — same pattern as
// encryption.LoadMasterKey/password.LoadPepper's missing-secret handling.
var ErrBootstrapTokenMissing = errors.New("pki: bootstrap token missing")

// LoadBootstrapToken reads this service's bootstrap token from
// BootstrapTokenEnvVar. It performs no further validation of the token's
// shape — a malformed or expired token is surfaced later, as an error
// from NewServer/NewClient, by the Certificate-Authority itself refusing
// to sign.
func LoadBootstrapToken() (string, error) {
	token, ok := os.LookupEnv(BootstrapTokenEnvVar)
	if !ok || token == "" {
		return "", ErrBootstrapTokenMissing
	}
	return token, nil
}

// NewServer exchanges token for an initial certificate from the
// Certificate-Authority and returns base configured for mTLS
// (ca.BootstrapServer): by default the server requires and verifies the
// client's certificate. The certificate renews automatically for the
// lifetime of ctx — callers should pass a context that lives at least as
// long as the server itself, not a short-lived per-request context.
//
// Every outbound call this package makes on base's behalf (the initial
// bootstrap exchange, and the server's own background renewal calls back
// to the Certificate-Authority) goes out over the process's default
// network stack. Unlike NewClient/NewClientWithDialer, no dialer-injecting
// variant exists here: github.com/smallstep/certificates@v0.30.2's
// ca.Client.GetServerTLSConfig (called internally by ca.BootstrapServer,
// in ca/tls.go) builds the *http.Transport its background
// certificate-renewal goroutine dials through entirely inside that call
// and never returns it to the caller - GetServerTLSConfig hands back only
// the resulting *tls.Config, and BootstrapServer only ever exposes that
// *tls.Config (as base.TLSConfig), discarding the transport. Unlike
// BootstrapClient (whose returned *http.Client.Transport IS that same
// renewal transport - see RouteThroughDialer), there is no reference to
// it anywhere reachable from BootstrapServer's return value, so a
// bootstrapped server's own outbound renewal traffic cannot be routed
// through a custom dialer using only this library version's public API.
func NewServer(ctx context.Context, token string, base *http.Server) (*http.Server, error) {
	return stepca.BootstrapServer(ctx, token, base, forceTLS13)
}

// NewClient exchanges token for an initial certificate from the
// Certificate-Authority and returns an *http.Client configured to present
// it on every outbound mTLS connection (ca.BootstrapClient). The
// certificate renews automatically, same as NewServer, for the lifetime
// of ctx.
//
// This is NewClientWithDialer with a nil dial — see that function's doc
// comment for how to route this package's outbound traffic (including
// certificate renewal) through a mesh identity instead.
func NewClient(ctx context.Context, token string) (*http.Client, error) {
	return NewClientWithDialer(ctx, token, nil)
}
