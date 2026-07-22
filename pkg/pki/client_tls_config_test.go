package pki

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// Requirement: PKI-F-01
//
// TLSConfig extracts exactly the *tls.Config set on a *http.Transport's
// TLSClientConfig field - the same field ForceServerName reads (see
// servername.go's own doc comment for why this field, not any private
// SDK-internal clone, is correct and sufficient).
func TestTLSConfig_ExtractsTransportTLSClientConfig(t *testing.T) {
	want := &tls.Config{ServerName: "MQTTBroker"}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: want}}

	got, err := TLSConfig(client)
	if err != nil {
		t.Fatalf("TLSConfig() error = %v, want nil", err)
	}
	if got != want {
		t.Fatalf("TLSConfig() = %p, want the same *tls.Config set on the transport (%p)", got, want)
	}
}

// Requirement: PKI-F-01
//
// TLSConfig fails closed (RD-04) for a client whose Transport isn't a
// *http.Transport, mirroring ForceServerName's own identical guard
// (TestForceServerName_RejectsUnsupportedTransport).
func TestTLSConfig_RejectsUnsupportedTransport(t *testing.T) {
	client := &http.Client{Transport: noopRoundTripper{}}

	if _, err := TLSConfig(client); err == nil {
		t.Fatal("TLSConfig() error = nil, want an error for a non-*http.Transport Transport")
	}
}
