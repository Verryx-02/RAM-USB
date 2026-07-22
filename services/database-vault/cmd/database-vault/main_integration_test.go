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
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/server"
)

// This file verifies buildServerTLSConfig/buildStorageServiceClient - the
// two functions run wires together to satisfy PKI-F-01/PKI-F-02/CA-F-04
// end to end - against a REAL running Certificate-Authority container
// (deployments/compose/certificate-authority.yml's certificate-authority service),
// mirroring pkg/pki/stepca_test.go's own real-CA pattern exactly (same
// env-var-gated skip, same docker-exec-based token minting). Unlike
// pkg/pki's own tests, this file additionally proves the specific claim
// this session's architecture decision rests on: that RequireOrganization/
// WrapRoundTripper (pkg/mtls), layered on top of pki.NewServer's
// *tls.Config/*http.Client, actually enforce PKI-F-02 - not merely that a
// certificate was obtained. TestBuildServerTLSConfigReusedAsOutboundClient_RealCA
// additionally proves the one-bootstrap-token architecture itself (see
// this package's main.go doc comment): that buildServerTLSConfig's
// *tls.Config, reused unmodified as an outbound Transport.TLSClientConfig,
// actually has a populated RootCAs and so can complete a real outbound TLS
// handshake against a peer certificate from the same CA - not merely
// present this server's own certificate correctly.
//
// Requires the certificate-authority-init compose service
// (deployments/compose/certificate-authority.yml) to have completed, which `docker compose up`
// now guarantees automatically - see this package's main.go doc comment
// and that service's own doc comment for why. Without it, every
// certificate this CA issues has an empty Subject.Organization and every
// case below would fail closed (RD-04) - confirmed empirically this
// session before the template fix existed.

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
// same technique as pkg/pki/stepca_test.go's generateTestToken. subject
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
		// subject alone is the only SAN - no "localhost" workaround needed
		// anymore. buildStorageServiceClient (via pki.ClientTLSConfig) now
		// forces its handshake's ServerName to the expected peer
		// organization instead of letting it default to the dialed network
		// address, and this file's own ad hoc test clients do the same via
		// pki.ForceServerName/pki.ClientTLSConfig - see pkg/pki's package
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

// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// buildServerTLSConfig's *tls.Config, wrapped by mtls.RequireOrganization
// exactly as run() wires it, accepts a real CA-issued client certificate
// whose organization matches and rejects one whose organization doesn't -
// end to end against the real CA, no fakes on either side.
func TestBuildServerTLSConfig_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// buildServerTLSConfig reads pki.LoadBootstrapToken() internally (the
	// env var, not a parameter), same as production.
	serverToken := generateToken(ctx, t, caURL, container, "DatabaseVault-itest-server")
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
		// Stand-in for what a real caller (Security-Switch's
		// buildDatabaseVaultClient) does after pki.NewClient: force this
		// handshake's ServerName to the exact subject serverToken was
		// minted with, since the server's certificate no longer carries
		// "localhost" as a SAN.
		if err := pki.ForceServerName(client, "DatabaseVault-itest-server"); err != nil {
			t.Fatalf("pki.ForceServerName() error = %v, want nil", err)
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
		clientToken := generateToken(ctx, t, caURL, container, "StorageService-itest-wrong-org")
		client, err := pki.NewClient(ctx, clientToken)
		if err != nil {
			t.Fatalf("pki.NewClient() error = %v, want nil", err)
		}
		if err := pki.ForceServerName(client, "DatabaseVault-itest-server"); err != nil {
			t.Fatalf("pki.ForceServerName() error = %v, want nil", err)
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

// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// buildStorageServiceClient's *http.Client, built by reusing
// buildServerTLSConfig's single bootstrapped *tls.Config (the
// one-bootstrap-token architecture this file's package doc comment
// describes, not a second independent bootstrap exchange) and wrapped by
// mtls.WrapRoundTripper exactly as it is in production, accepts a real
// CA-issued server certificate whose organization is StorageService and
// rejects a response from a server certificate with any other
// organization - end to end against the real CA.
func TestBuildStorageServiceClient_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("storage-service organization is accepted", func(t *testing.T) {
		serverToken := generateToken(ctx, t, caURL, container, organizationStorageService)
		stubTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))
		stub.TLS = stubTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "DatabaseVault-itest-client")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		clientTLSConfig, err := buildServerTLSConfig(ctx)
		if err != nil {
			t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
		}

		t.Setenv(envStorageServiceURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildStorageServiceClient(clientTLSConfig)
		if err != nil {
			t.Fatalf("buildStorageServiceClient() error = %v, want nil", err)
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
		serverToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-wrong-org")
		stubTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))
		stub.TLS = stubTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "DatabaseVault-itest-client2")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		clientTLSConfig, err := buildServerTLSConfig(ctx)
		if err != nil {
			t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
		}

		t.Setenv(envStorageServiceURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildStorageServiceClient(clientTLSConfig)
		if err != nil {
			t.Fatalf("buildStorageServiceClient() error = %v, want nil", err)
		}

		resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			t.Fatalf("client.Get() error = nil, want an organization-mismatch error (status = %d)", resp.StatusCode)
		}
	})
}

// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// This is the empirical verification the one-bootstrap-token architecture
// (this package's main.go doc comment) rests on: buildServerTLSConfig's
// *tls.Config, reused unmodified as an http.Transport's
// TLSClientConfig (no separate RootCAs assignment, no second bootstrap
// exchange), actually completes a real outbound TLS handshake against a
// peer certificate issued by the same CA - proving RootCAs is genuinely
// populated by pki.NewServer's underlying
// ca.Client.GetServerTLSConfig/TLSOptionCtx.apply, not merely present in
// vendored source reasoning. The peer here is a second real bootstrapped
// server identity from the same CA (standing in for Storage-Service, which
// has not adopted pkg/pki yet), not a fake/self-signed TLS server - same
// real-CA verification pattern as every other test in this file.
func TestBuildServerTLSConfigReusedAsOutboundClient_RealCA(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// peerTLSConfig stands in for Storage-Service's own bootstrapped
	// server identity, issued by the same CA.
	peerToken := generateToken(ctx, t, caURL, container, "DatabaseVault-itest-peer-standin")
	peerTLSConfig := realCAServerTLSConfig(ctx, t, peerToken)

	peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	peer.TLS = peerTLSConfig
	peer.StartTLS()
	defer peer.Close()

	// callerToken bootstraps this test's own client-side identity via
	// buildServerTLSConfig - exactly the function run() uses for its
	// single bootstrap token - to prove that *this same* *tls.Config,
	// reused verbatim, is a valid outbound Transport.TLSClientConfig.
	callerToken := generateToken(ctx, t, caURL, container, "DatabaseVault-itest-outbound-caller")
	t.Setenv(pki.BootstrapTokenEnvVar, callerToken)
	callerTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
	}

	if callerTLSConfig.RootCAs == nil {
		t.Fatal("buildServerTLSConfig()'s *tls.Config has a nil RootCAs; cannot verify an outbound peer's server certificate")
	}

	// Stand-in for buildStorageServiceClient's own pki.ClientTLSConfig
	// call: peerTLSConfig's certificate no longer carries "localhost" as a
	// SAN, only "DatabaseVault-itest-peer-standin".
	transport := &http.Transport{TLSClientConfig: pki.ClientTLSConfig(callerTLSConfig, "DatabaseVault-itest-peer-standin")}
	client := &http.Client{Transport: transport}

	peerURL := strings.Replace(peer.URL, "127.0.0.1", "localhost", 1)
	resp, err := client.Get(peerURL) //nolint:noctx // test, ctx already bounds the token mint above
	if err != nil {
		t.Fatalf("client.Get() error = %v, want nil - buildServerTLSConfig's *tls.Config, reused as an outbound TLSClientConfig, must be able to verify a real peer certificate from the same CA", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// realCAServerTLSConfig bootstraps a real CA-issued server identity
// (via pki.NewServer) for use as an httptest.Server's own TLS config,
// standing in for a real Storage-Service instance's certificate.
func realCAServerTLSConfig(ctx context.Context, t *testing.T, token string) *tls.Config {
	t.Helper()

	base := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	bootstrapped, err := pki.NewServer(ctx, token, base)
	if err != nil {
		t.Fatalf("pki.NewServer() error = %v, want nil", err)
	}
	return bootstrapped.TLSConfig
}
