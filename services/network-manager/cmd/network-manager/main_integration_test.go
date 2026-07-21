package main

import (
	"context"
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
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/server"
)

// This file verifies buildServerTLSConfig - the function run wires
// together to satisfy PKI-F-01/PKI-F-02/CA-F-04 for Network-Manager's one
// inbound listener (NM-F-03) - against a REAL running Certificate-Authority
// container (deployments/docker-compose.dev.yml's certificate-authority
// service), mirroring services/database-vault/cmd/database-vault/
// main_integration_test.go's own real-CA pattern exactly (same
// env-var-gated skip, same docker-exec-based token minting). This proves
// the same specific claim that file proves for Database-Vault:
// RequireOrganization (pkg/mtls), layered on top of pki.NewServer's
// *tls.Config, actually enforces PKI-F-02 against a real peer certificate
// from the real CA - not merely that a certificate was obtained.
//
// Network-Manager has no outbound RAM-USB mTLS client role to verify here
// (see main.go's package doc comment for why: Headscale is not a RAM-USB
// peer under PKI-F-01/PKI-F-02) - unlike Database-Vault's
// TestBuildStorageServiceClient_RealCA_EnforcesOrganization, there is no
// second test in this file for an outbound role.
//
// Requires the certificate-authority-init compose service (deployments/
// docker-compose.dev.yml) to have completed, which `docker compose up`
// now guarantees automatically. Without it, every certificate this CA
// issues has an empty Subject.Organization and the case below would fail
// closed (RD-04).

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
// and mints a real, single-use bootstrap token via `step ca token`, same
// technique as pkg/pki/stepca_test.go's generateTestToken and
// Database-Vault's own main_integration_test.go generateToken. subject
// becomes both the certificate's CommonName and (via
// third-party/certificate-authority/config/organization.x509.tpl)
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
		// established "use localhost, not 127.0.0.1" convention), so
		// "localhost" must be an authorized SAN or the client's own
		// hostname verification (independent of, and prior to, the
		// PKI-F-02 organization check this test exists to prove) rejects
		// the connection before RequireOrganization ever runs.
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
// Requirement: NM-F-03
//
// buildServerTLSConfig's *tls.Config, wrapped by mtls.RequireOrganization
// exactly as run() wires it, accepts a real CA-issued client certificate
// whose organization matches server.AllowedClientOrganization
// ("SecuritySwitch") and rejects one whose organization doesn't - end to
// end against the real CA, no fakes on either side.
func TestBuildServerTLSConfig_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// buildServerTLSConfig reads pki.LoadBootstrapToken() internally (the
	// env var, not a parameter), same as production.
	serverToken := generateToken(ctx, t, caURL, container, "NetworkManager-itest-server")
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
		clientToken := generateToken(ctx, t, caURL, container, "CertificateAuthority-itest-wrong-org")
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
