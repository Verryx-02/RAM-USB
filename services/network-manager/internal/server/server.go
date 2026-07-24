// Package server holds Network-Manager's connection-acceptance logic: the
// mTLS configuration required for a client to reach it at all (NM-F-03),
// before any request-level handling is considered. Mirrors
// services/security-switch/internal/server and
// services/database-vault/internal/server exactly, with the allowed
// organization changed to the caller Network-Manager itself accepts from.
package server

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// AllowedClientOrganization is the organization NM-F-03 requires of every
// mTLS client connecting to Network-Manager's own request-driven HTTP API
// (NM-F-08's mesh-user creation, NM-F-09's grant). NM-F-03 names two
// authorized callers, Security-Switch and Certificate-Authority - only
// Security-Switch calls this HTTP API; Certificate-Authority's contact is
// the separate bootstrap-token certificate-issuance flow (CA-F-04), not an
// mTLS client of this server.
const AllowedClientOrganization = "SecuritySwitch"

// NewTLSConfig returns the mTLS server configuration Network-Manager uses
// to satisfy NM-F-03: a connection completes its handshake only if the
// peer presents a valid certificate issued by a CA in clientCAs whose
// Subject.Organization is AllowedClientOrganization. This listener's own
// network-level reachability (bound only to this node's Tailscale mesh
// interface, per NET-F-01) is enforced by Network-Manager's own
// deployment/network configuration, not here - distinct from Headscale's
// own coordination endpoint (NM-F-14), which is deliberately
// public-facing and unrelated to this mTLS listener.
func NewTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return mtls.ServerConfig(serverCert, clientCAs, AllowedClientOrganization)
}
