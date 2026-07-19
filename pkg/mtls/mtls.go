// Package mtls provides the mutual-TLS configuration shared by every
// RAM-USB service that must accept connections only from a specific caller,
// or make outbound connections only to a specific callee (PKI-F-02: verify
// the peer certificate's organization field, not merely its validity).
// Each component-level requirement that repeats the accept-side pattern -
// DV-F-01 (Database-Vault accepts only "SecuritySwitch"), SS-F-01
// (Security-Switch accepts only "EntryHub"), ST-F-01 (Storage-Service
// accepts only "Database-Vault") - configures ServerConfig with its own
// allowed organization instead of re-implementing the check. The symmetric
// outbound-call pattern - DV-F-09 (Database-Vault calls Storage-Service,
// verifying organization="StorageService") - configures ClientConfig the
// same way.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// ServerConfig returns a *tls.Config for a server that requires a valid
// client certificate (mTLS) and rejects any peer whose certificate Subject
// does not carry allowedOrganization. Network-level restrictions (e.g. the
// requirement that the caller also be on the private mesh network) are
// enforced outside this package, at the network layer.
func ServerConfig(serverCert tls.Certificate, clientCAs *x509.CertPool, allowedOrganization string) *tls.Config {
	return &tls.Config{
		Certificates:     []tls.Certificate{serverCert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		MinVersion:       tls.VersionTLS13,
		VerifyConnection: verifyOrganization(allowedOrganization),
	}
}

// ClientConfig returns a *tls.Config for a client making an outbound mTLS
// call: it presents clientCert to the server and, symmetrically to
// ServerConfig, rejects any server whose certificate Subject does not carry
// allowedOrganization (e.g. Database-Vault calling Storage-Service for
// DV-F-09, verifying the peer's certificate comes from
// organization="StorageService"). rootCAs is the pool trusted to have
// issued the server's certificate.
func ClientConfig(clientCert tls.Certificate, rootCAs *x509.CertPool, allowedOrganization string) *tls.Config {
	return &tls.Config{
		Certificates:     []tls.Certificate{clientCert},
		RootCAs:          rootCAs,
		MinVersion:       tls.VersionTLS13,
		VerifyConnection: verifyOrganization(allowedOrganization),
	}
}

// verifyOrganization returns a tls.Config.VerifyConnection callback that
// accepts a connection only if the verified peer leaf certificate's
// Subject.Organization contains exactly allowedOrganization. It runs after
// crypto/tls's own chain validation, so a certificate reaching this callback
// is already known to be valid (correctly signed, unexpired); this callback
// adds the organization check PKI-F-02 requires on top of that validity.
// VerifyConnection, unlike VerifyPeerCertificate, also runs on resumed
// sessions, so a session ticket cannot bypass the organization check
// (zero-trust, RNF-SEC-02/03; fail-secure on any gap, RD-04).
func verifyOrganization(allowedOrganization string) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		leaf, err := verifiedLeaf(cs)
		if err != nil {
			return err
		}
		return checkOrganization(leaf, allowedOrganization)
	}
}

// verifiedLeaf returns the peer leaf certificate from cs.VerifiedChains -
// the certificate crypto/tls has already cryptographically verified against
// the configured trust pool (Config.ClientCAs on a server, Config.RootCAs
// on a client) - or an error if no verified chain is present. cs.PeerCertificates
// is deliberately not used here: it is populated with whatever the peer
// sent, not necessarily with what has been verified (see the doc comment on
// crypto/tls.ConnectionState.VerifiedChains: on the server side it is only
// set when Config.ClientAuth is VerifyClientCertIfGiven or
// RequireAndVerifyClientCert). Shared by verifyOrganization
// (tls.Config.VerifyConnection, the handshake-level check) and by
// RequireOrganization/WrapRoundTripper (organization_http.go, the
// HTTP-request-level check used by services built on pkg/pki, whose
// *tls.Config is not composable with VerifyConnection - see pkg/pki's
// package doc comment).
func verifiedLeaf(cs tls.ConnectionState) (*x509.Certificate, error) {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("mtls: no verified peer certificate chain")
	}
	return cs.VerifiedChains[0][0], nil
}

// checkOrganization reports whether leaf's Subject.Organization contains
// allowedOrganization, returning nil if so and a descriptive error
// otherwise (PKI-F-02).
func checkOrganization(leaf *x509.Certificate, allowedOrganization string) error {
	for _, org := range leaf.Subject.Organization {
		if org == allowedOrganization {
			return nil
		}
	}
	return fmt.Errorf("mtls: peer certificate organization %v does not match required organization %q", leaf.Subject.Organization, allowedOrganization)
}
