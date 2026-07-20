// Package pki is a thin wrapper around github.com/smallstep/certificates/ca's
// bootstrap primitives (CA-F-04, PKI-F-01). Each RAM-USB service holds a
// single-use bootstrap token, distributed out-of-band (SRS §2.6, the note
// on "Distribution of initial certificates" — same channel used for
// RAM_USB_MASTER_KEY (DV-F-05) and RAM_USB_PASSWORD_PEPPER (DV-F-06)), and
// exchanges it exactly once, at startup, for an initial mTLS certificate
// issued by the Certificate-Authority (the official smallstep/step-ca
// server, run as a separate container — see
// deployments/docker-compose.dev.yml and
// docs/design/diagrams/08-security-pki-hierarchy.puml). Subsequent
// renewal happens automatically, driven by the vendor SDK's own built-in
// mechanism (renewing at 2/3 of the certificate's lifetime by default) —
// no polling loop, and the bootstrap token itself is never reused for a
// renewal (CA-F-04).
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
	"errors"
	"net/http"
	"os"

	stepca "github.com/smallstep/certificates/ca"
)

// BootstrapTokenEnvVar names the environment variable holding this
// service's single-use CA bootstrap token (CA-F-04), distributed
// out-of-band per SRS §2.6. This name is this package's own judgment
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
func NewServer(ctx context.Context, token string, base *http.Server) (*http.Server, error) {
	return stepca.BootstrapServer(ctx, token, base)
}

// NewClient exchanges token for an initial certificate from the
// Certificate-Authority and returns an *http.Client configured to present
// it on every outbound mTLS connection (ca.BootstrapClient). The
// certificate renews automatically, same as NewServer, for the lifetime
// of ctx.
func NewClient(ctx context.Context, token string) (*http.Client, error) {
	return stepca.BootstrapClient(ctx, token)
}
