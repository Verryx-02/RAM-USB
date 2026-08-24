package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/server"
)

// This file verifies buildServerTLSConfig - the function run wires
// together with mtls.RequireOrganization to satisfy PKI-F-01/PKI-F-02/
// CA-F-04 end to end - against a REAL running Certificate-Authority
// container (deployments/compose/certificate-authority.yml's certificate-authority
// service), mirroring database-vault/cmd/database-vault/
// main_integration_test.go's own real-CA pattern exactly (same
// env-var-gated skip, same docker-exec-based token minting). Storage-
// Service only needs this one inbound-server-role test: unlike
// Database-Vault, it makes no outbound mTLS call of its own (ST-F-10 is
// satisfied by this same listener's HTTP response, see main.go's package
// doc comment), so there is no buildStorageServiceClient-equivalent
// function to test here.
//
// Requires the certificate-authority-init compose service
// (deployments/compose/certificate-authority.yml) to have completed, which `docker compose up`
// now guarantees automatically. Without it, every certificate this CA
// issues has an empty Subject.Organization and the case below would fail
// closed (RD-04).

const (
	caURLEnvVar        = "PKI_TEST_CA_URL"
	caContainerEnvVar  = "PKI_TEST_CA_CONTAINER"
	defaultCAContainer = "certificate-authority"

	containerRootCert     = "/home/step/certs/root_ca.crt"
	containerPasswordFile = "/run/secrets/ca-password.dev-only" //nolint:gosec // a file path, not a credential value
)

func skipUnlessCAConfigured(t *testing.T) (caURL, container string) {
	t.Helper()

	caURL = os.Getenv(caURLEnvVar)
	if caURL == "" {
		t.Skipf("%s not set; skipping the real-Certificate-Authority PKI-F-02 test. "+
			"Run `docker compose -f deployments/compose/certificate-authority.yml up` "+
			"(certificate-authority-init applies the organization template "+
			"automatically) and set this variable (e.g. https://localhost:9000) "+
			"to run it.", caURLEnvVar)
	}

	container = os.Getenv(caContainerEnvVar)
	if container == "" {
		container = defaultCAContainer
	}

	return caURL, container
}

// generateToken shells into the running certificate-authority container
// and mints a real, single-use bootstrap token via `step ca token`, using
// the same admin JWK provisioner and dev-only password file
// deployments/compose/certificate-authority.yml bootstrapped the container with -
// same technique as pkg/pki/stepca_test.go's generateTestToken and
// database-vault/cmd/database-vault/main_integration_test.go's own
// generateToken. subject becomes both the certificate's CommonName and
// (via third-party/certificate-authority/config/organization.x509.tpl)
// Subject.Organization.
func generateToken(ctx context.Context, t *testing.T, caURL, container, subject string) string {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not available: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	//nolint:gosec // container/caURL/subject come from this test's own env-gated
	// config and call sites, not untrusted request input.
	cmd := exec.CommandContext(ctx, "docker", "exec", container,
		"step", "ca", "token", subject,
		// Every server certificate this test mints is dialed as
		// https://localhost:<port> (matching mtls.TestCA.IssueLeaf's own
		// established "use localhost, not 127.0.0.1" convention elsewhere
		// in this codebase), so "localhost" must be an authorized SAN or
		// the client's own hostname verification (independent of, and
		// prior to, the PKI-F-02 organization check this test exists to
		// prove) rejects the connection before RequireOrganization ever
		// runs.
		"--san", "localhost",
		"--san", subject,
		"--ca-url", caURL,
		"--root", containerRootCert,
		"--provisioner", "admin",
		"--password-file", containerPasswordFile,
	)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("docker exec %s step ca token %s: %v\nstderr: %s", container, subject, err, exitErr.Stderr)
		}
		t.Fatalf("docker exec %s step ca token %s: %v", container, subject, err)
	}

	return strings.TrimSpace(string(out))
}

// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// buildServerTLSConfig's *tls.Config, wrapped by mtls.RequireOrganization
// exactly as run() wires it, accepts a real CA-issued client certificate
// whose organization matches (server.AllowedClientOrganization,
// "DatabaseVault") and rejects one whose organization doesn't - end to
// end against the real CA, no fakes on either side.
func TestBuildServerTLSConfig_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// buildServerTLSConfig reads pki.LoadBootstrapToken() internally (the
	// env var, not a parameter), same as production.
	serverToken := generateToken(ctx, t, caURL, container, "StorageService-itest-server")
	t.Setenv(pki.BootstrapTokenEnvVar, serverToken)
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewUnstartedServer(mtls.RequireOrganization(server.AllowedClientOrganization, next))
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	defer srv.Close()

	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	t.Run("allowed organization is accepted", func(t *testing.T) {
		called = false
		clientToken := generateToken(ctx, t, caURL, container, server.AllowedClientOrganization)
		client, err := pki.NewClient(ctx, clientToken)
		if err != nil {
			t.Fatalf("pki.NewClient() error = %v, want nil", err)
		}

		resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
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
	})

	t.Run("other organization is rejected", func(t *testing.T) {
		called = false
		clientToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-wrong-org")
		client, err := pki.NewClient(ctx, clientToken)
		if err != nil {
			t.Fatalf("pki.NewClient() error = %v, want nil", err)
		}

		resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
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
	})
}

// Requirement: NET-F-02
//
// buildServerTLSConfig's *tls.Config must enforce TLS 1.3 with no
// exceptions (pkg/pki's forceTLS13, applied unconditionally inside
// pki.NewServer): a real CA-issued client certificate, presented over a
// handshake explicitly capped at TLS 1.2, is rejected by the real
// listener - an actual dial attempt that fails, not merely a *tls.Config
// field assertion.
func TestBuildServerTLSConfig_RealCA_RejectsTLS12(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverToken := generateToken(ctx, t, caURL, container, "StorageService-itest-tls12-server")
	t.Setenv(pki.BootstrapTokenEnvVar, serverToken)
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	defer srv.Close()

	clientToken := generateToken(ctx, t, caURL, container, server.AllowedClientOrganization)
	client, err := pki.NewClient(ctx, clientToken)
	if err != nil {
		t.Fatalf("pki.NewClient() error = %v, want nil", err)
	}
	if err := pki.ForceServerName(client, "StorageService-itest-tls12-server"); err != nil {
		t.Fatalf("pki.ForceServerName() error = %v, want nil", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport type = %T, want *http.Transport", client.Transport)
	}
	transport.TLSClientConfig.MinVersion = 0
	transport.TLSClientConfig.MaxVersion = tls.VersionTLS12

	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err == nil {
		t.Fatal("client.Get() over a TLS-1.2-capped handshake error = nil, want a version-negotiation failure")
	}
}

// Requirement: RNF-SEC-04
//
// buildServerTLSConfig's *tls.Config enforces mTLS with no exceptions: a
// real TLS 1.3 connection that presents NO client certificate at all is
// rejected - proving mTLS is mandatory for this listener, not merely
// available, against the real bootstrapped identity (real CA, real
// ca.BootstrapServer default of RequireAndVerifyClientCert - see
// pki.NewServer's own doc comment).
func TestBuildServerTLSConfig_RealCA_RejectsNoClientCert(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverToken := generateToken(ctx, t, caURL, container, "StorageService-itest-nocert-server")
	t.Setenv(pki.BootstrapTokenEnvVar, serverToken)
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	defer srv.Close()

	// Deliberately NOT pki.NewClient: a bare TLS client presenting no
	// certificate at all, standing in for an attacker or misconfigured
	// caller that skips mTLS entirely.
	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test client verifying server cert is not this test's concern
		},
	}
	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := noCertClient.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err == nil {
		t.Fatal("noCertClient.Get() with no client certificate error = nil, want a TLS handshake failure")
	}
}

// Requirement: CA-F-04
//
// A service that already holds a persisted mTLS identity must be able to
// start with no bootstrap token at all: after one real bootstrap persists
// an identity under RAM_USB_PKI_IDENTITY_DIR, a second buildServerTLSConfig
// call with RAM_USB_CA_BOOTSTRAP_TOKEN empty must still succeed, reusing the
// stored identity instead of failing closed (KI-126).
func TestBuildServerTLSConfig_RealCA_NoTokenReusesStoredIdentity(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Setenv(pki.IdentityDirEnvVar, t.TempDir())

	token := generateToken(ctx, t, caURL, container, "StorageService_itest-persist")
	t.Setenv(pki.BootstrapTokenEnvVar, token)
	if _, err := buildServerTLSConfig(ctx); err != nil {
		t.Fatalf("buildServerTLSConfig() first call (bootstrap) error = %v, want nil", err)
	}

	// Second start: no token, same identity directory - must succeed from
	// the persisted identity alone, per this file's own package doc comment
	// on buildServerTLSConfig.
	t.Setenv(pki.BootstrapTokenEnvVar, "")
	if _, err := buildServerTLSConfig(ctx); err != nil {
		t.Fatalf("buildServerTLSConfig() second call (no token) error = %v, want nil", err)
	}
}

// Requirement: CA-F-04
//
// With neither a persisted identity nor a bootstrap token, startup must
// fail with a message naming both RAM_USB_PKI_IDENTITY_DIR and
// RAM_USB_CA_BOOTSTRAP_TOKEN, not just the lower-level bootstrap-token
// parsing failure - an operator reading this message must be able to tell
// which of the two is missing (KI-126). No real Certificate-Authority is
// needed: an empty token fails token parsing before any network call.
func TestBuildServerTLSConfig_NoTokenNoStoredIdentity_FailsWithClearMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Setenv(pki.IdentityDirEnvVar, t.TempDir())
	t.Setenv(pki.BootstrapTokenEnvVar, "")

	_, err := buildServerTLSConfig(ctx)
	if err == nil {
		t.Fatal("buildServerTLSConfig() error = nil, want an error when neither a token nor a stored identity is available")
	}
	if !strings.Contains(err.Error(), pki.IdentityDirEnvVar) || !strings.Contains(err.Error(), pki.BootstrapTokenEnvVar) {
		t.Fatalf("buildServerTLSConfig() error = %q, want it to name both %s and %s",
			err.Error(), pki.IdentityDirEnvVar, pki.BootstrapTokenEnvVar)
	}
}
