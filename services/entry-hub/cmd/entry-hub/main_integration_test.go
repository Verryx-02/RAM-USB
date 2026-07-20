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

	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/securityswitch"
)

// This file verifies buildSecuritySwitchClient - EH-F-07's outbound mTLS
// call construction - against a REAL running Certificate-Authority
// container (deployments/docker-compose.dev.yml's certificate-authority
// service), mirroring services/database-vault/cmd/database-vault/
// main_integration_test.go's own real-CA pattern exactly (same
// env-var-gated skip, same docker-exec-based token minting). Unlike
// pkg/pki's own tests, this proves the specific claim this session's
// architecture decision rests on for Entry-Hub specifically: that
// buildSecuritySwitchClient's pki.NewClient-bootstrapped *http.Client,
// wrapped by mtls.WrapRoundTripper exactly as run() wires it, actually
// enforces PKI-F-02 against a real peer certificate from the same CA - not
// merely that a certificate was obtained.
//
// Requires the certificate-authority-init compose service (deployments/
// docker-compose.dev.yml) to have completed, which `docker compose up`
// now guarantees automatically - see this package's main.go doc comment
// and that service's own doc comment for why. Without it, every
// certificate this CA issues has an empty Subject.Organization and every
// case below would fail closed (RD-04).

const (
	caURLEnvVar        = "PKI_TEST_CA_URL"
	caContainerEnvVar  = "PKI_TEST_CA_CONTAINER"
	defaultCAContainer = "deployments-certificate-authority-1"

	containerRootCert     = "/home/step/certs/root_ca.crt"
	containerPasswordFile = "/run/secrets/ca-password.dev-only" //nolint:gosec // a file path, not a credential value
)

func skipUnlessCAConfigured(t *testing.T) (caURL, container string) {
	t.Helper()

	caURL = os.Getenv(caURLEnvVar)
	if caURL == "" {
		t.Skipf("%s not set; skipping the real-Certificate-Authority PKI-F-02 test. "+
			"Run `docker compose -f deployments/docker-compose.dev.yml up` "+
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
// deployments/docker-compose.dev.yml bootstrapped the container with -
// same technique as pkg/pki/stepca_test.go's generateTestToken and
// Database-Vault's own main_integration_test.go. subject becomes both the
// certificate's CommonName and (via third-party/certificate-authority/
// config/organization.x509.tpl) Subject.Organization.
func generateToken(t *testing.T, caURL, container, subject string) string {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not available: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	//nolint:gosec // container/caURL/subject come from this test's own env-gated
	// config and call sites, not untrusted request input.
	cmd := exec.CommandContext(ctx, "docker", "exec", container,
		"step", "ca", "token", subject,
		// subject alone is the only SAN - no "localhost" workaround needed
		// anymore. Every outbound client under test (buildSecuritySwitchClient,
		// via pki.ForceServerName) now forces its handshake's ServerName to
		// the expected peer organization instead of letting it default to
		// the dialed network address, so a certificate whose only SAN is
		// its organization name is exactly what production issues and
		// exactly what these tests should mint too - see pkg/pki's package
		// doc comment for the full reasoning.
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

// realCAServerTLSConfig bootstraps a real CA-issued server identity (via
// pki.NewServer) for use as an httptest.Server's own TLS config, standing
// in for a real Security-Switch instance's certificate (Security-Switch
// has not adopted pkg/pki yet) - same helper pattern as Database-Vault's
// own main_integration_test.go.
func realCAServerTLSConfig(t *testing.T, ctx context.Context, token string) *tls.Config {
	t.Helper()

	base := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	bootstrapped, err := pki.NewServer(ctx, token, base)
	if err != nil {
		t.Fatalf("pki.NewServer() error = %v, want nil", err)
	}
	return bootstrapped.TLSConfig
}

// Requirement: EH-F-07
// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// buildSecuritySwitchClient's *http.Client, built by pki.NewClient and
// wrapped by mtls.WrapRoundTripper exactly as it is in production, accepts
// a real CA-issued server certificate whose organization is SecuritySwitch
// and rejects a response from a server certificate with any other
// organization - end to end against the real CA, no fakes on either side.
func TestBuildSecuritySwitchClient_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("security-switch organization is accepted", func(t *testing.T) {
		serverToken := generateToken(t, caURL, container, securityswitch.OrganizationSecuritySwitch)
		serverTLSConfig := realCAServerTLSConfig(t, ctx, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))
		stub.TLS = serverTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(t, caURL, container, "EntryHub-itest-client")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		t.Setenv(envSecuritySwitchURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildSecuritySwitchClient(ctx)
		if err != nil {
			t.Fatalf("buildSecuritySwitchClient() error = %v, want nil", err)
		}

		resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
		if err != nil {
			t.Fatalf("client.Get() error = %v, want nil", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
		}
	})

	t.Run("other organization is rejected", func(t *testing.T) {
		serverToken := generateToken(t, caURL, container, "StorageService-itest-wrong-org")
		serverTLSConfig := realCAServerTLSConfig(t, ctx, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))
		stub.TLS = serverTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(t, caURL, container, "EntryHub-itest-client2")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		t.Setenv(envSecuritySwitchURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildSecuritySwitchClient(ctx)
		if err != nil {
			t.Fatalf("buildSecuritySwitchClient() error = %v, want nil", err)
		}

		resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			t.Fatalf("client.Get() error = nil, want an organization-mismatch error (status = %d)", resp.StatusCode)
		}
	})
}
