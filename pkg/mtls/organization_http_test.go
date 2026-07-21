package mtls

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newOrgTestServer starts an httptest.Server requiring (but not, at the TLS
// handshake level, organization-checking) a client certificate - the same
// shape pki.NewServer's underlying ca.BootstrapServer produces (see
// pkg/pki's package doc comment: RequireAndVerifyClientCert, no
// VerifyConnection hook available to install pkg/mtls's usual check) - so
// RequireOrganization is genuinely the only thing enforcing PKI-F-02 in
// this test, not ServerConfig's own VerifyConnection callback.
func newOrgTestServer(t *testing.T, ca *TestCA, allowedOrganization string, next http.Handler) *httptest.Server {
	t.Helper()

	serverCert, err := ca.IssueLeaf("DatabaseVault", "org-http-test-server")
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v, want nil", err)
	}

	srv := httptest.NewUnstartedServer(RequireOrganization(allowedOrganization, next))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func dialWithOrganization(t *testing.T, ca *TestCA, srv *httptest.Server, organization string) (*http.Response, error) {
	t.Helper()

	clientCert, err := ca.IssueLeaf(organization, "org-http-test-client")
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v, want nil", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      ca.Pool(),
			},
		},
	}

	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	return client.Get(baseURL) //nolint:noctx // test helper, no request-scoped deadline needed
}

// Requirement: PKI-F-02
func TestRequireOrganization_AcceptsAllowedOrganization(t *testing.T) {
	ca, err := NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	srv := newOrgTestServer(t, ca, "SecuritySwitch", next)

	resp, err := dialWithOrganization(t, ca, srv, "SecuritySwitch")
	if err != nil {
		t.Fatalf("client.Get() error = %v, want nil", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !called {
		t.Fatal("next handler was not called, want called")
	}
}

// Requirement: PKI-F-02
func TestRequireOrganization_RejectsOtherOrganization(t *testing.T) {
	ca, err := NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	srv := newOrgTestServer(t, ca, "SecuritySwitch", next)

	resp, err := dialWithOrganization(t, ca, srv, "StorageService")
	if err != nil {
		t.Fatalf("client.Get() error = %v, want nil", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if called {
		t.Fatal("next handler was called, want not called")
	}
}

// Requirement: PKI-F-02
//
// RD-04, fail-secure: a request with no TLS connection state at all (e.g.
// r.TLS is nil, as it would be for a request net/http never completed a TLS
// handshake for) must be denied, not treated as a pass.
func TestRequireOrganization_RejectsMissingTLS(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireOrganization("SecuritySwitch", next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.TLS = nil
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("next handler was called, want not called")
	}
}

// newOrgClientServer starts a plain httptest.Server whose TLS config issues
// a server certificate of serverOrganization and, mirroring
// newOrgTestServer, performs no organization check of its own - so
// WrapRoundTripper is genuinely the only thing enforcing PKI-F-02 in these
// tests.
func newOrgClientServer(t *testing.T, ca *TestCA, serverOrganization string) *httptest.Server {
	t.Helper()

	serverCert, err := ca.IssueLeaf(serverOrganization, "org-http-test-server")
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

func newOrgClient(ca *TestCA, allowedOrganization string) *http.Client {
	return &http.Client{
		Transport: WrapRoundTripper(&http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
		}, allowedOrganization),
	}
}

// Requirement: PKI-F-02
func TestWrapRoundTripper_AcceptsAllowedOrganization(t *testing.T) {
	ca, err := NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	srv := newOrgClientServer(t, ca, "StorageService")
	client := newOrgClient(ca, "StorageService")

	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := client.Get(baseURL) //nolint:noctx // test helper, no request-scoped deadline needed
	if err != nil {
		t.Fatalf("client.Get() error = %v, want nil", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// Requirement: PKI-F-02
func TestWrapRoundTripper_RejectsOtherOrganization(t *testing.T) {
	ca, err := NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v, want nil", err)
	}

	srv := newOrgClientServer(t, ca, "SecuritySwitch")
	client := newOrgClient(ca, "StorageService")

	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := client.Get(baseURL) //nolint:noctx // test helper, no request-scoped deadline needed
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatalf("client.Get() error = nil, want an organization-mismatch error (status = %d)", resp.StatusCode)
	}
}

// Requirement: PKI-F-02
//
// RD-04, fail-secure: a response with no TLS connection state at all (a
// plain, unencrypted HTTP response) must be rejected, not returned to the
// caller.
func TestWrapRoundTripper_RejectsMissingTLS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(plain.Close)

	client := &http.Client{
		Transport: WrapRoundTripper(http.DefaultTransport, "SecuritySwitch"),
	}

	resp, err := client.Get(plain.URL) //nolint:noctx // test helper, no request-scoped deadline needed
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		t.Fatalf("client.Get() error = nil, want an error for a plain HTTP response with no TLS state")
	}
}
