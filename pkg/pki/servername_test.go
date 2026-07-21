package pki

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// newSANOnlyServer starts an httptest.Server whose certificate's only SAN
// is organization (no "localhost"), standing in for a real RAM-USB peer
// certificate - issued for an organization name, never for the network
// address a caller happens to dial it by (see pkg/pki's package doc
// comment). This is what makes these tests a genuine proof of this
// session's architecture decision, not merely of Clone()'s mechanics.
func newSANOnlyServer(t *testing.T, ca *mtls.TestCA, organization string) *httptest.Server {
	t.Helper()

	serverCert, err := ca.IssueLeaf(organization, "pki-servername-test-server", organization)
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v, want nil", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// Requirement: PKI-F-02
//
// ClientTLSConfig's clone never mutates base - the same *tls.Config object
// callers such as Database-Vault's buildStorageServiceClient reuse across
// an inbound listener and an outbound client (see this file's doc
// comment).
func TestClientTLSConfig_DoesNotMutateBase(t *testing.T) {
	base := &tls.Config{ServerName: ""}

	cfg := ClientTLSConfig(base, "DatabaseVault")

	if base.ServerName != "" {
		t.Fatalf("base.ServerName = %q after ClientTLSConfig, want unchanged empty string", base.ServerName)
	}
	if cfg.ServerName != "DatabaseVault" {
		t.Fatalf("cfg.ServerName = %q, want %q", cfg.ServerName, "DatabaseVault")
	}
	if cfg == base {
		t.Fatal("ClientTLSConfig returned base itself, want an independent clone")
	}
}

// Requirement: PKI-F-02
//
// This is the behavior change this session's architecture decision rests
// on: a certificate whose only SAN is its organization - never the network
// address a caller happens to dial it by - is ACCEPTED once ServerName is
// forced to that organization, even though the dialed address ("localhost")
// is absent from the certificate entirely. Before this fix, the same dial
// (ServerName left to default to "localhost") would fail with crypto/tls's
// own hostname error before ever reaching PKI-F-02's organization check.
func TestClientTLSConfig_AcceptsCorrectOrganizationDespiteHostnameMismatch(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	srv := newSANOnlyServer(t, ca, "DatabaseVault")

	base := &tls.Config{RootCAs: ca.Pool()}
	cfg := ClientTLSConfig(base, "DatabaseVault")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	resp, err := client.Get(baseURL) //nolint:noctx // test, no request-scoped deadline needed
	if err != nil {
		t.Fatalf("client.Get() error = %v, want nil - a certificate whose SAN is the organization name, not the dialed host, must be accepted once ServerName is forced to that organization", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// Requirement: PKI-F-02
// Requirement: RNF-SEC-01
//
// Forcing ServerName never weakens chain validation: a certificate issued
// by a CA the client does NOT trust is still REJECTED, even when its SAN
// exactly matches the forced ServerName. Proves this fix never touches
// InsecureSkipVerify or otherwise skips the RootCAs check.
func TestClientTLSConfig_RejectsCertificateFromUntrustedCA(t *testing.T) {
	trustedCA, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}
	untrustedCA, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	// The server presents a certificate signed by untrustedCA, not
	// trustedCA - same organization, same SAN, different signer.
	srv := newSANOnlyServer(t, untrustedCA, "DatabaseVault")

	base := &tls.Config{RootCAs: trustedCA.Pool()}
	cfg := ClientTLSConfig(base, "DatabaseVault")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	resp, err := client.Get(baseURL) //nolint:noctx // test, no request-scoped deadline needed
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatal("client.Get() error = nil, want a chain-validation error for a certificate from an untrusted CA")
	}
}

// noopRoundTripper is a minimal http.RoundTripper that is deliberately
// NOT a *http.Transport, used only to prove ForceServerName's fail-closed
// type check.
type noopRoundTripper struct{}

func (noopRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

// Requirement: PKI-F-02
//
// ForceServerName fails closed (RD-04) for a client whose Transport isn't
// a *http.Transport (http.DefaultTransport, and pki.NewClient's own
// returned Transport, both are *http.Transport under the hood - this uses
// a deliberately different http.RoundTripper implementation) - it has no
// TLSClientConfig/DialTLSContext to reconfigure, so silently doing nothing
// would leave the caller believing ServerName was forced when it wasn't.
func TestForceServerName_RejectsUnsupportedTransport(t *testing.T) {
	client := &http.Client{Transport: noopRoundTripper{}}

	if err := ForceServerName(client, "DatabaseVault"); err == nil {
		t.Fatal("ForceServerName() error = nil, want an error for a non-*http.Transport Transport")
	}
}

// Requirement: PKI-F-02
//
// ForceServerName's DialTLSContext replacement, not merely its
// TLSClientConfig field assignment, is what actually takes effect: a
// Transport whose original DialTLSContext dials with an empty ServerName
// (letting crypto/tls default it to the dialed host, "localhost" here -
// mirroring github.com/smallstep/certificates@v0.30.2/ca/tls.go's own
// buildDialTLSContext, confirmed by reading that source - see
// servername.go's doc comment) would fail against newSANOnlyServer's
// certificate (SAN="SecuritySwitch" only). After ForceServerName runs,
// the SAME transport's DialTLSContext dials successfully, proving the
// replacement - not the otherwise-inert TLSClientConfig field alone - is
// what makes this fix work for pki.NewClient's returned *http.Client.
func TestForceServerName_ReplacesDialTLSContext(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	srv := newSANOnlyServer(t, ca, "SecuritySwitch")

	// dialerConfig is captured by the original DialTLSContext closure,
	// separately from transport.TLSClientConfig - mirroring the vendored
	// SDK's own mutableTLSConfig, which is likewise unreachable from
	// outside its owning package and independent of TLSClientConfig.
	dialerConfig := &tls.Config{RootCAs: ca.Pool()}
	dialer := &tls.Dialer{Config: dialerConfig}

	transport := &http.Transport{
		// Deliberately never given ServerName - matching the vendored
		// SDK's own tlsConfig, which also leaves it empty (see
		// servername.go's doc comment).
		TLSClientConfig: dialerConfig,
		DialTLSContext:  dialer.DialContext,
	}
	client := &http.Client{Transport: transport}
	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	if _, err := client.Get(baseURL); err == nil { //nolint:noctx,bodyclose // test asserts failure before a response exists
		t.Fatal("client.Get() error = nil before ForceServerName, want a hostname-verification error (SAN does not cover \"localhost\")")
	}

	if err := ForceServerName(client, "SecuritySwitch"); err != nil {
		t.Fatalf("ForceServerName() error = %v, want nil", err)
	}

	resp, err := client.Get(baseURL) //nolint:noctx // test, no request-scoped deadline needed
	if err != nil {
		t.Fatalf("client.Get() error = %v, want nil after ForceServerName", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
