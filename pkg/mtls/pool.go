package mtls

import (
	"crypto/x509"
	"fmt"
	"os"
)

// TrustPool reads the PEM-encoded CA certificate(s) at path and returns an
// *x509.CertPool trusting them, failing closed (RD-04) rather than letting
// an unreadable file or a file with no valid certificate surface only much
// later as a cryptic TLS handshake error. It is the one shared
// implementation of the "load an operator-configured CA bundle from disk"
// step every service that builds its own tls.Config.RootCAs/ClientCAs
// outside pkg/pki's step-ca bootstrap flow (PKI-F-01) needs - e.g.
// Network-Manager's Headscale admin-API client and Storage-Service's
// Database-Vault client.
func TrustPool(path string) (*x509.CertPool, error) {
	// codeql[go/path-injection] re-verified against every TrustPool caller (storage-service's cfg.clientCAPath,
	// network-manager's envHeadscaleAPICAFile): all trace to operator-supplied deployment config, never request input.
	pemBytes, err := os.ReadFile(path) //nolint:gosec // path is an operator-controlled deployment path, not request input
	if err != nil {
		return nil, fmt.Errorf("mtls: read CA file %s: %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("mtls: %s contains no valid PEM certificate", path)
	}

	return pool, nil
}
