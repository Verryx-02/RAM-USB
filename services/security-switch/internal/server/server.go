// Package server holds Security-Switch's connection-acceptance logic: the
// mTLS configuration required for a client to reach it at all (SS-F-01),
// before any request-level handling is considered. Mirrors
// services/database-vault/internal/server exactly, with the allowed
// organization changed to the caller Security-Switch itself accepts from.
package server

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// AllowedClientOrganization is the organization SS-F-01 requires of every
// mTLS client connecting to Security-Switch. Entry-Hub is the only
// component authorized to call Security-Switch directly.
const AllowedClientOrganization = "EntryHub"

// NewTLSConfig returns the mTLS server configuration Security-Switch uses to
// satisfy SS-F-01: a connection completes its handshake only if the peer
// presents a valid certificate issued by a CA in clientCAs whose
// Subject.Organization is AllowedClientOrganization. The requirement's third
// condition, that the caller also be reachable only from the private mesh
// network, is enforced by Network-Manager's ACL rules (NM-F-01), not here.
func NewTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return mtls.ServerConfig(serverCert, clientCAs, AllowedClientOrganization)
}
