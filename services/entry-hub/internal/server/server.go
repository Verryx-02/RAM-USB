// Package server holds Entry-Hub's connection-acceptance logic: the TLS
// configuration for its public-facing listener (EH-F-01, EH-F-02, EH-F-03).
//
// Unlike every other service in this codebase (Database-Vault, Security-
// Switch, Storage-Service), Entry-Hub's inbound listener is NOT mTLS.
// EH-F-01/02/03 require plain HTTPS, certified by the public Let's
// Encrypt CA, precisely so that an end user's client never needs to trust
// or reach this system's internal, private Certificate-Authority (per the
// SRS's own note on EH-F-01: "the public CA is used so that Users can
// never reach the internal CA that certifies mTLS connections between the
// system's internal components"). NewTLSConfig therefore does not set
// ClientAuth/ClientCAs/VerifyConnection the way pkg/mtls.ServerConfig
// does - there is no client certificate to verify, by requirement, not by
// omission.
//
// For local development, the same env-var-driven certificate/key file
// loading convention every other service's cmd/<service>/main.go already
// uses (tls.LoadX509KeyPair from operator-controlled paths) applies here
// too - no dev-cert-bootstrapping helper exists anywhere in this codebase
// or under deployments/ to reuse (checked before writing this package: no
// ACME/autocert code, no Let's Encrypt staging config here). A locally
// self-signed certificate at those same env-var paths is this service's
// own operator's responsibility for local runs, exactly like Database-
// Vault/Security-Switch's own server certificates are for their mTLS
// listeners.
package server

import (
	"crypto/tls"
)

// NewTLSConfig returns the TLS configuration Entry-Hub's public listener
// uses to satisfy EH-F-01/EH-F-02/EH-F-03: present serverCert to every
// connecting client, with no client certificate requirement.
func NewTLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}
}
