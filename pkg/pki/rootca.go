package pki

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"

	stepca "github.com/smallstep/certificates/ca"
	"go.step.sm/crypto/jose"
)

// ErrRootCAResponseEmpty is returned when the Certificate-Authority's own
// /root/:sha endpoint responds without a certificate - treated the same
// (fail-secure, RD-04) as any other malformed response from that endpoint.
var ErrRootCAResponseEmpty = errors.New("pki: root-ca response contained no certificate")

// bootstrapTokenClaims mirrors the unexported tokenClaims type
// github.com/smallstep/certificates@v0.30.2/ca/bootstrap.go's own
// Bootstrap function parses a token into - duplicated here (rather than
// imported, since it is unexported) purely to read the same two claims
// ("sha", "aud") that function already trusts as this token's source of
// the Certificate-Authority's URL and pinned root fingerprint.
type bootstrapTokenClaims struct {
	SHA string `json:"sha"`
	jose.Claims
}

// RootCA fetches the Certificate-Authority's own root certificate,
// PEM-encoded, pinned against the root fingerprint embedded in token's own
// "sha" claim - the same pinning ca.Bootstrap itself relies on for every
// other exchange in this package.
//
// Unlike NewClient/NewServer, RootCA does NOT consume token's single use:
// it never calls the CA's Sign endpoint (CA-F-04's one-time exchange,
// performed only by NewClient/NewServer/NewClientWithDialer), only the
// CA's own public, root-fingerprint-pinned
// /root/:sha endpoint (github.com/smallstep/certificates@v0.30.2/ca/
// client.go's Client.RootWithContext), which requires no bootstrap-token
// credential at all - only already knowing the pinned fingerprint, exactly
// as this project's own root-of-trust model already assumes. Safe to call
// any number of times, including with a token another caller (in the same
// process or a different one) already spent via NewClient/NewServer.
//
// This exists for a caller that needs the CA's root certificate as
// standalone PEM bytes on disk - e.g. a short-lived subprocess invoked by
// sshd (ST-F-11's AuthorizedKeysCommand) that cannot hold an in-memory
// *tls.Config the way every other RAM-USB service does, and instead reads
// its trust material fresh from a file on every invocation. A caller that
// only needs an in-memory trust root (i.e. every long-lived RAM-USB
// service) never needs this function - NewClient/NewServer's returned
// *tls.Config already carries the equivalent RootCAs pool.
func RootCA(ctx context.Context, token string) ([]byte, error) {
	tok, err := jose.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("pki: parse bootstrap token: %w", err)
	}

	var claims bootstrapTokenClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("pki: parse bootstrap token claims: %w", err)
	}
	if claims.SHA == "" || len(claims.Audience) == 0 {
		return nil, errors.New("pki: bootstrap token missing sha/aud claim")
	}

	// WithRootSHA256 is required here, not optional: ca.NewClient's default
	// transport (no option supplied at all) refuses to build at all
	// ("a transport, a root cert, or a root sha256 must be used") - it
	// never silently falls back to plain, unpinned HTTPS. Passing the same
	// fingerprint the CA's own /root/:sha endpoint is about to verify the
	// response against additionally pins this client's OWN initial
	// connection to that endpoint, closing the same MITM window
	// ca.Bootstrap itself closes for the Sign exchange.
	client, err := stepca.NewClient(claims.Audience[0], stepca.WithRootSHA256(claims.SHA))
	if err != nil {
		return nil, fmt.Errorf("pki: build root-ca client: %w", err)
	}

	root, err := client.RootWithContext(ctx, claims.SHA)
	if err != nil {
		return nil, fmt.Errorf("pki: fetch root certificate: %w", err)
	}
	if root.RootPEM.Certificate == nil {
		return nil, ErrRootCAResponseEmpty
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.RootPEM.Certificate.Raw,
	}), nil
}
