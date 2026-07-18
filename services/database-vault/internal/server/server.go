// Package server holds Database-Vault's connection-acceptance logic:
// the mTLS configuration required for a client to reach it at all
// (DV-F-01), before any request-level handling is considered.
package server

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// AllowedClientOrganization is the organization DV-F-01 requires of every
// mTLS client connecting to Database-Vault's register/login listener.
// Security-Switch is the only component authorized to call this listener.
//
// This is no longer the only mTLS listener Database-Vault runs: ST-F-11
// added a second, separate listener (pubkey_server.go's
// AllowedPublicKeyClientOrganization/NewPublicKeyTLSConfig) for
// Storage-Service's public-key lookups. See that file's doc comment for why
// this is two listeners, each with its own single-organization check via
// pkg/mtls.ServerConfig, rather than one listener accepting either
// organization — pkg/mtls.ServerConfig takes exactly one allowedOrganization
// string, by design (NM-F-02 already names three distinct direct callers of
// Database-Vault with three distinct purposes; conflating them behind one
// check would let Security-Switch reach the public-key endpoint and
// Storage-Service reach register/login, neither of which is authorized).
const AllowedClientOrganization = "SecuritySwitch"

// NewTLSConfig returns the mTLS server configuration Database-Vault uses to
// satisfy DV-F-01 for its register/login listener: a connection completes
// its handshake only if the peer presents a valid certificate issued by a
// CA in clientCAs whose Subject.Organization is AllowedClientOrganization.
// The requirement's third condition, that the caller also be reachable only
// from the private mesh network, is enforced by Network-Manager's ACL rules
// (NM-F-02), not here.
func NewTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return mtls.ServerConfig(serverCert, clientCAs, AllowedClientOrganization)
}
