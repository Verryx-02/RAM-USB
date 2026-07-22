package pki

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// TLSConfig extracts the *tls.Config backing client (as returned by
// NewClient): client.Transport.(*http.Transport).TLSClientConfig. This is
// the same field ForceServerName reads and mutates - see that function's
// own doc comment for why TLSClientConfig, not any private SDK-internal
// clone, is the correct and sufficient extraction point for any use that
// only needs this identity's certificate/trust material (Certificates/
// GetClientCertificate/RootCAs), not http.Transport's own DialTLSContext
// override.
//
// A caller that also needs ForceServerName's HTTP-hostname-forcing
// behavior for an outbound HTTP call should call ForceServerName instead;
// this accessor exists for a caller with no HTTP role of its own to force
// - e.g. Metrics-Collector's MQTT-only subscribe identity - which only
// needs the *tls.Config itself, then applies ClientTLSConfig/
// mtls.WithOrganization to it directly, the same as any service reusing a
// pki.NewServer-bootstrapped *tls.Config for an outbound role.
func TLSConfig(client *http.Client) (*tls.Config, error) {
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("pki: client.Transport is %T, want *http.Transport", client.Transport)
	}
	return transport.TLSClientConfig, nil
}
