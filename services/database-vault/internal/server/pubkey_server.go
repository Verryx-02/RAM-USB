// This file adds Database-Vault's second mTLS listener, for ST-F-11's
// public-key lookup endpoint. It is a separate listener/*tls.Config from
// server.go's register/login one, not a shared config accepting either
// organization, because pkg/mtls.ServerConfig's allowedOrganization
// parameter is a single string, by design: each service-to-service call in
// this codebase authenticates against exactly one required organization
// (DV-F-01, SS-F-01, ST-F-01, DV-F-09's outbound call to Storage-Service, ...
// all follow the same one-config-one-organization shape). Two options were
// considered for "Database-Vault must now accept two different calling
// organizations, for two different endpoints":
//
//  1. Two separate net.Listener/*tls.Config values, each bound to its own
//     TCP address, each running its own http.Server with only the relevant
//     handler(s) registered. Chosen here.
//  2. One *tls.Config whose VerifyConnection callback accepts either
//     "SecuritySwitch" or "StorageService", relying on the HTTP handler
//     layer (net/http.ServeMux's registered path) to keep each organization
//     confined to its own endpoint.
//
// (2) was rejected: TLS's VerifyConnection runs during the handshake,
// before any HTTP request line (and therefore before the request path) is
// known — the certificate check would have no way to also require "and
// only for this specific path," so a Storage-Service certificate accepted
// by a shared listener would then be one HTTP request away from reaching
// the register/login endpoints too, relying entirely on the handler to
// refuse it rather than on defense-in-depth at the transport layer. (1)
// keeps the organization check itself doing double duty as the endpoint
// boundary: a certificate that fails this listener's check never completes
// a TLS handshake against it at all, regardless of what the HTTP layer
// would have done next (RD-04, fail-secure; RNF-SEC-02/03, zero-trust — each
// layer re-validates independently, not merely deferring to the layer
// above it).
package server

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// AllowedPublicKeyClientOrganization is the organization ST-F-11 requires of
// every mTLS client connecting to Database-Vault's public-key lookup
// listener. Storage-Service is the only component authorized to call it —
// per NM-F-02, Storage-Service also reaches Database-Vault directly
// (unlike Entry-Hub, which only ever reaches Security-Switch), because
// AuthorizedKeysCommand runs synchronously during an SSH connection attempt
// and needs a direct, low-latency path, not one routed through
// Security-Switch.
const AllowedPublicKeyClientOrganization = "StorageService"

// NewPublicKeyTLSConfig returns the mTLS server configuration
// Database-Vault uses for ST-F-11's public-key lookup listener: a
// connection completes its handshake only if the peer presents a valid
// certificate issued by a CA in clientCAs whose Subject.Organization is
// AllowedPublicKeyClientOrganization. As with NewTLSConfig, the requirement
// that the caller also be reachable only from the private mesh network is
// enforced by Network-Manager's ACL rules (NM-F-02), not here.
func NewPublicKeyTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return mtls.ServerConfig(serverCert, clientCAs, AllowedPublicKeyClientOrganization)
}
