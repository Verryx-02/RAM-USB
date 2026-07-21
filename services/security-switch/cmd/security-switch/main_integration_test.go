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
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/dbvault"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/networkmanager"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/server"
)

// This file verifies buildServerTLSConfig/buildDatabaseVaultClient/
// buildNetworkManagerClient - the functions run wires together to satisfy
// PKI-F-01/PKI-F-02/CA-F-04 end to end - against a REAL running
// Certificate-Authority container (deployments/docker-compose.dev.yml's
// certificate-authority service), mirroring
// services/database-vault/cmd/database-vault/main_integration_test.go's
// own real-CA pattern exactly (same env-var-gated skip, same
// docker-exec-based token minting). Unlike a synthetic-cert unit test,
// this file proves the specific claim Security-Switch's architecture rests
// on: that RequireOrganization/WrapRoundTripper (pkg/mtls), layered on top
// of pki.NewServer's *tls.Config/*http.Client, actually enforce PKI-F-02 -
// and that ONE bootstrapped identity, reused for the inbound listener and
// BOTH outbound clients (Database-Vault, Network-Manager), is sufficient -
// not merely that a certificate was obtained.
//
// Requires the certificate-authority-init compose service (deployments/
// docker-compose.dev.yml) to have completed, which `docker compose up`
// now guarantees automatically - see main.go's package doc comment and
// that service's own doc comment for why. Without it, every certificate
// this CA issues has an empty Subject.Organization and every case below
// would fail closed (RD-04).

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
// same technique as pkg/pki/stepca_test.go and Database-Vault's own
// main_integration_test.go. subject becomes both the certificate's
// CommonName and (via third-party/certificate-authority/config/
// organization.x509.tpl) Subject.Organization.
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
		// anymore. Every outbound client under test (buildDatabaseVaultClient/
		// buildNetworkManagerClient, via pki.ClientTLSConfig) now forces its
		// handshake's ServerName to the expected peer organization instead
		// of letting it default to the dialed network address, and this
		// file's own ad hoc test clients (dialing this service's own
		// inbound listener) do the same via pki.ForceServerName - see
		// pkg/pki's package doc comment for the full reasoning.
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
// in for a real Database-Vault/Network-Manager instance's certificate.
func realCAServerTLSConfig(ctx context.Context, t *testing.T, token string) *tls.Config {
	t.Helper()

	base := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	bootstrapped, err := pki.NewServer(ctx, token, base)
	if err != nil {
		t.Fatalf("pki.NewServer() error = %v, want nil", err)
	}
	return bootstrapped.TLSConfig
}

// Requirement: SS-F-01
// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// buildServerTLSConfig's *tls.Config, wrapped by mtls.RequireOrganization
// exactly as run() wires it, accepts a real CA-issued client certificate
// whose organization matches ("EntryHub") and rejects one whose
// organization doesn't - end to end against the real CA, no fakes on
// either side.
func TestBuildServerTLSConfig_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// buildServerTLSConfig reads pki.LoadBootstrapToken() internally (the
	// env var, not a parameter), same as production.
	serverToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-server")
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
		// Stand-in for what a real caller (Entry-Hub's
		// buildSecuritySwitchClient) does after pki.NewClient: force this
		// handshake's ServerName to the exact subject serverToken was
		// minted with, since the server's certificate no longer carries
		// "localhost" as a SAN.
		if err := pki.ForceServerName(client, "SecuritySwitch-itest-server"); err != nil {
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
		clientToken := generateToken(ctx, t, caURL, container, "DatabaseVault-itest-wrong-org")
		client, err := pki.NewClient(ctx, clientToken)
		if err != nil {
			t.Fatalf("pki.NewClient() error = %v, want nil", err)
		}
		if err := pki.ForceServerName(client, "SecuritySwitch-itest-server"); err != nil {
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

// Requirement: SS-F-04
// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// buildDatabaseVaultClient's *http.Client, built by reusing
// buildServerTLSConfig's single bootstrapped *tls.Config (the
// one-bootstrap-token architecture this file's package doc comment
// describes, not a second independent bootstrap exchange) and wrapped by
// mtls.WrapRoundTripper exactly as it is in production, accepts a real
// CA-issued server certificate whose organization is DatabaseVault and
// rejects a response from a server certificate with any other
// organization - end to end against the real CA.
func TestBuildDatabaseVaultClient_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("database-vault organization is accepted", func(t *testing.T) {
		serverToken := generateToken(ctx, t, caURL, container, dbvault.OrganizationDatabaseVault)
		stubTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		stub.TLS = stubTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-client")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		clientTLSConfig, err := buildServerTLSConfig(ctx)
		if err != nil {
			t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
		}

		t.Setenv(envDatabaseVaultURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildDatabaseVaultClient(clientTLSConfig)
		if err != nil {
			t.Fatalf("buildDatabaseVaultClient() error = %v, want nil", err)
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
	})

	t.Run("other organization is rejected", func(t *testing.T) {
		serverToken := generateToken(ctx, t, caURL, container, "NetworkManager-itest-wrong-org")
		stubTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		stub.TLS = stubTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-client2")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		clientTLSConfig, err := buildServerTLSConfig(ctx)
		if err != nil {
			t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
		}

		t.Setenv(envDatabaseVaultURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildDatabaseVaultClient(clientTLSConfig)
		if err != nil {
			t.Fatalf("buildDatabaseVaultClient() error = %v, want nil", err)
		}

		resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			t.Fatalf("client.Get() error = nil, want an organization-mismatch error (status = %d)", resp.StatusCode)
		}
	})
}

// Requirement: SS-F-05
// Requirement: SS-F-09
// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// buildNetworkManagerClient's *http.Client, built the same way as
// buildDatabaseVaultClient (same one bootstrapped identity, reused, not a
// second bootstrap exchange), accepts a real CA-issued server certificate
// whose organization is NetworkManager and rejects one with any other
// organization - end to end against the real CA.
func TestBuildNetworkManagerClient_RealCA_EnforcesOrganization(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("network-manager organization is accepted", func(t *testing.T) {
		serverToken := generateToken(ctx, t, caURL, container, networkmanager.OrganizationNetworkManager)
		stubTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		stub.TLS = stubTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-client3")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		clientTLSConfig, err := buildServerTLSConfig(ctx)
		if err != nil {
			t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
		}

		t.Setenv(envNetworkManagerURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildNetworkManagerClient(clientTLSConfig)
		if err != nil {
			t.Fatalf("buildNetworkManagerClient() error = %v, want nil", err)
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
	})

	t.Run("other organization is rejected", func(t *testing.T) {
		serverToken := generateToken(ctx, t, caURL, container, "DatabaseVault-itest-wrong-org2")
		stubTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		stub.TLS = stubTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-client4")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		clientTLSConfig, err := buildServerTLSConfig(ctx)
		if err != nil {
			t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
		}

		t.Setenv(envNetworkManagerURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, err := buildNetworkManagerClient(clientTLSConfig)
		if err != nil {
			t.Fatalf("buildNetworkManagerClient() error = %v, want nil", err)
		}

		resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			t.Fatalf("client.Get() error = nil, want an organization-mismatch error (status = %d)", resp.StatusCode)
		}
	})
}

// Requirement: SS-F-01
// Requirement: SS-F-04
// Requirement: SS-F-05
// Requirement: SS-F-09
// Requirement: PKI-F-01
// Requirement: PKI-F-02
// Requirement: CA-F-04
//
// This is the empirical verification the one-bootstrap-token architecture
// (main.go's package doc comment) rests on for Security-Switch
// specifically: buildServerTLSConfig's *tls.Config, reused unmodified as
// BOTH outbound clients' Transport.TLSClientConfig AND as the inbound
// listener's own TLSConfig, actually works in all three roles
// simultaneously from a single bootstrap exchange - one real CA
// certificate, three concurrent uses.
func TestBuildServerTLSConfigReusedForAllThreeRoles_RealCA(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// One single bootstrap exchange for Security-Switch's own identity -
	// exactly what run() does.
	ownToken := generateToken(ctx, t, caURL, container, "SecuritySwitch-itest-all-roles")
	t.Setenv(pki.BootstrapTokenEnvVar, ownToken)
	ownTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
	}

	if ownTLSConfig.RootCAs == nil {
		t.Fatal("buildServerTLSConfig()'s *tls.Config has a nil RootCAs; cannot verify an outbound peer's server certificate")
	}

	// Role 1: inbound listener, dialed by a real EntryHub-organization
	// client.
	inboundCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inboundCalled = true
		w.WriteHeader(http.StatusOK)
	})
	inboundSrv := httptest.NewUnstartedServer(mtls.RequireOrganization(server.AllowedClientOrganization, next))
	inboundSrv.TLS = ownTLSConfig
	inboundSrv.StartTLS()
	defer inboundSrv.Close()

	entryHubToken := generateToken(ctx, t, caURL, container, server.AllowedClientOrganization)
	entryHubClient, err := pki.NewClient(ctx, entryHubToken)
	if err != nil {
		t.Fatalf("pki.NewClient() error = %v, want nil", err)
	}
	// Stand-in for buildSecuritySwitchClient's own pki.ForceServerName
	// call: ownTLSConfig's certificate no longer carries "localhost" as a
	// SAN, only "SecuritySwitch-itest-all-roles".
	if err := pki.ForceServerName(entryHubClient, "SecuritySwitch-itest-all-roles"); err != nil {
		t.Fatalf("pki.ForceServerName() error = %v, want nil", err)
	}
	inboundURL := strings.Replace(inboundSrv.URL, "127.0.0.1", "localhost", 1)
	resp, err := entryHubClient.Get(inboundURL) //nolint:noctx // test, ctx already bounds the token mint above
	if err != nil {
		t.Fatalf("entryHubClient.Get() error = %v, want nil", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !inboundCalled {
		t.Fatalf("inbound role: status = %d, called = %v, want 200 and called", resp.StatusCode, inboundCalled)
	}

	// Role 2: outbound Database-Vault client, using the exact same
	// ownTLSConfig.
	dbVaultToken := generateToken(ctx, t, caURL, container, dbvault.OrganizationDatabaseVault)
	dbVaultStubTLSConfig := realCAServerTLSConfig(ctx, t, dbVaultToken)
	dbVaultStub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	dbVaultStub.TLS = dbVaultStubTLSConfig
	dbVaultStub.StartTLS()
	defer dbVaultStub.Close()

	t.Setenv(envDatabaseVaultURL, strings.Replace(dbVaultStub.URL, "127.0.0.1", "localhost", 1))
	dbVaultClient, dbVaultBaseURL, err := buildDatabaseVaultClient(ownTLSConfig)
	if err != nil {
		t.Fatalf("buildDatabaseVaultClient() error = %v, want nil", err)
	}
	dbResp, err := dbVaultClient.Get(dbVaultBaseURL) //nolint:noctx // test, ctx already bounds the token mint above
	if err != nil {
		t.Fatalf("dbVaultClient.Get() error = %v, want nil", err)
	}
	_, _ = io.Copy(io.Discard, dbResp.Body)
	_ = dbResp.Body.Close()
	if dbResp.StatusCode != http.StatusOK {
		t.Fatalf("database-vault role: status = %d, want %d", dbResp.StatusCode, http.StatusOK)
	}

	// Role 3: outbound Network-Manager client, using the exact same
	// ownTLSConfig again - proving all three roles work concurrently from
	// one bootstrap exchange.
	networkManagerToken := generateToken(ctx, t, caURL, container, networkmanager.OrganizationNetworkManager)
	networkManagerStubTLSConfig := realCAServerTLSConfig(ctx, t, networkManagerToken)
	networkManagerStub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	networkManagerStub.TLS = networkManagerStubTLSConfig
	networkManagerStub.StartTLS()
	defer networkManagerStub.Close()

	t.Setenv(envNetworkManagerURL, strings.Replace(networkManagerStub.URL, "127.0.0.1", "localhost", 1))
	networkManagerClient, networkManagerBaseURL, err := buildNetworkManagerClient(ownTLSConfig)
	if err != nil {
		t.Fatalf("buildNetworkManagerClient() error = %v, want nil", err)
	}
	nmResp, err := networkManagerClient.Get(networkManagerBaseURL) //nolint:noctx // test, ctx already bounds the token mint above
	if err != nil {
		t.Fatalf("networkManagerClient.Get() error = %v, want nil", err)
	}
	_, _ = io.Copy(io.Discard, nmResp.Body)
	_ = nmResp.Body.Close()
	if nmResp.StatusCode != http.StatusOK {
		t.Fatalf("network-manager role: status = %d, want %d", nmResp.StatusCode, http.StatusOK)
	}
}
