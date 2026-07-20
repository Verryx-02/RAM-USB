package pki

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// dialTimeout mirrors github.com/smallstep/certificates@v0.30.2/ca/
// tls.go's own createDefaultDialer default (30 * time.Second) - used only
// by ForceServerName, to keep its replacement dial behavior equivalent to
// the vendored SDK's default instead of falling back to net.Dialer's zero
// value (no timeout at all).
const dialTimeout = 30 * time.Second

// ClientTLSConfig returns a clone of base (see (*tls.Config).Clone; base
// is frequently a *tls.Config a shared inbound listener also uses - e.g.
// Database-Vault's buildServerTLSConfig result, reused for its own
// register/login listener, its public-key listener, AND an outbound
// Storage-Service client - so mutating base in place would corrupt every
// other use of it) with ServerName forced to organization, instead of
// left empty (which makes crypto/tls default it to the dialed network
// address).
//
// Why forcing ServerName is safe and correct, not a weakening of
// verification: crypto/tls's own hostname check (independent of, and
// running strictly before, PKI-F-02's mtls.RequireOrganization/
// mtls.WrapRoundTripper check - see this package's doc comment for why
// that check runs at the HTTP level instead of inside VerifyConnection)
// compares the peer certificate's SAN against Config.ServerName. RAM-USB's
// Certificate-Authority template
// (third-party/certificate-authority/config/organization.x509.tpl) always
// mirrors Subject.CommonName into both Subject.Organization and the
// certificate's SAN, so a certificate correctly issued for organization X
// always carries X as a SAN. Forcing ServerName to the *expected peer
// organization* - rather than leaving it to default to whatever network
// name happens to be dialed, which differs between dev/compose service
// names and production DNS names - makes that comparison succeed for any
// correctly-issued certificate, without skipping it: chain validation
// against base's RootCAs, and the SAN comparison itself, both still run.
// InsecureSkipVerify is never set by this function or anywhere in this
// package. RAM-USB's actual identity check - does this certificate belong
// to the organization this caller expects - is PKI-F-02's job
// (mtls.RequireOrganization/mtls.WrapRoundTripper), which still runs,
// unchanged, after the handshake this enables completes.
func ClientTLSConfig(base *tls.Config, organization string) *tls.Config {
	cfg := base.Clone()
	cfg.ServerName = organization
	return cfg
}

// ForceServerName reconfigures client - as returned by NewClient - so its
// outbound TLS handshake's hostname check targets organization instead of
// the dialed network address, the same intent as ClientTLSConfig but for
// an *http.Client rather than a plain *tls.Config.
//
// This needs more than "clone client.Transport.(*http.Transport)
// .TLSClientConfig and set ServerName" (ClientTLSConfig's own pattern),
// confirmed by reading github.com/smallstep/certificates@v0.30.2/ca/
// tls.go's Client.getClientTLSConfig and ca/mutable_tls_config.go:
// BootstrapClient's returned *http.Transport has DialTLSContext set
// (Client.buildDialTLSContext), and Go's own http.Transport ignores
// TLSClientConfig entirely whenever DialTLSContext is set - the actual
// dial there uses an independent, unexported *tls.Config clone
// (mutableTLSConfig.Init clones the SDK's own tlsConfig before
// Client.Transport ever returns, and that clone is not reachable from
// outside package ca). Mutating only TLSClientConfig would therefore be a
// silent no-op for the real dial.
//
// ForceServerName instead replaces DialTLSContext outright, with a
// crypto/tls.Dialer (the modern context-aware stdlib replacement for the
// vendored SDK's own tls.DialWithDialer+manual-deadline-plumbing dialer)
// built from client.Transport.TLSClientConfig, cloned via
// ClientTLSConfig. That field IS reachable, and is confirmed equivalent
// in content to the SDK's own internal clone for every property this
// matters for: both are populated, at getClientTLSConfig call time, from
// the same *tls.Config object before it is cloned into the SDK's private
// mutableTLSConfig (RootCAs and the immutable CA root are added to that
// shared object directly, before the clone), and both carry the same
// GetClientCertificate function value, so certificate renewal (driven by
// the SDK's own *TLSRenewer, whose state lives outside any single
// *tls.Config - see this package's other callers' Clone() safety notes)
// keeps working on the replacement dialer exactly as before.
func ForceServerName(client *http.Client, organization string) error {
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("pki: client.Transport is %T, want *http.Transport", client.Transport)
	}

	cfg := ClientTLSConfig(transport.TLSClientConfig, organization)
	transport.TLSClientConfig = cfg

	// Only replace DialTLSContext if NewClient's underlying SDK call set
	// one in the first place (it always does today, but this keeps
	// ForceServerName correct even if a future SDK version's Transport()
	// stops setting it, in which case leaving TLSClientConfig set above is
	// already sufficient).
	if transport.DialTLSContext != nil {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: dialTimeout},
			Config:    cfg,
		}
		transport.DialTLSContext = dialer.DialContext
	}

	return nil
}
