// Package server holds Storage-Service's connection-acceptance logic: the
// mTLS configuration required for a client to reach it at all (ST-F-01),
// before any request-level handling is considered.
package server

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// AllowedClientOrganization is the organization ST-F-01 requires of every
// mTLS client connecting to Storage-Service. Database-Vault is the only
// component authorized to call Storage-Service's internal mTLS endpoints
// directly (SFTP access, ST-F-03, is a separate, non-mTLS access path with
// its own authentication and is not affected by this configuration).
//
// The SRS's ST-F-01 row previously quoted organization="Database-Vault"
// (hyphenated), inconsistent with every other component's own
// organization-check requirement (DV-F-01: "SecuritySwitch", SS-F-01:
// "EntryHub") and Database-Vault's own outbound call to Storage-Service
// (DV-F-09, see services/database-vault/internal/posix/client.go), which
// already used the hyphen-free PascalCase form for every organization
// literal. The SRS has since been corrected to organization="DatabaseVault"
// (no hyphen), matching this constant and the codebase's established
// convention — this is no longer an open discrepancy.
const AllowedClientOrganization = "DatabaseVault"

// NewTLSConfig returns the mTLS server configuration Storage-Service uses
// to satisfy ST-F-01: a connection completes its handshake only if the
// peer presents a valid certificate issued by a CA in clientCAs whose
// Subject.Organization is AllowedClientOrganization. The requirement's
// third condition, that the caller also be reachable only from the private
// mesh network, is enforced by Network-Manager's ACL rules (NM-F-02), not
// here.
func NewTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return mtls.ServerConfig(serverCert, clientCAs, AllowedClientOrganization)
}
