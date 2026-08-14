package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/securityswitch"
)

// This file verifies buildSecuritySwitchClient - EH-F-07's outbound mTLS
// call construction - against a REAL running Certificate-Authority
// container (deployments/compose/certificate-authority.yml's certificate-authority
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
// Requires the certificate-authority-init compose service
// (deployments/compose/certificate-authority.yml) to have completed, which `docker compose up`
// now guarantees automatically - see this package's main.go doc comment
// and that service's own doc comment for why. Without it, every
// certificate this CA issues has an empty Subject.Organization and every
// case below would fail closed (RD-04).

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
// Database-Vault's own main_integration_test.go. subject becomes both the
// certificate's CommonName and (via third-party/certificate-authority/
// config/organization.x509.tpl) Subject.Organization.
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
func realCAServerTLSConfig(ctx context.Context, t *testing.T, token string) *tls.Config {
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
		serverToken := generateToken(ctx, t, caURL, container, securityswitch.OrganizationSecuritySwitch)
		serverTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))
		stub.TLS = serverTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "EntryHub-itest-client")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		t.Setenv(envSecuritySwitchURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, _, err := buildSecuritySwitchClient(ctx)
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
		serverToken := generateToken(ctx, t, caURL, container, "StorageService-itest-wrong-org")
		serverTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

		stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))
		stub.TLS = serverTLSConfig
		stub.StartTLS()
		defer stub.Close()

		clientToken := generateToken(ctx, t, caURL, container, "EntryHub-itest-client2")
		t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
		t.Setenv(envSecuritySwitchURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

		client, baseURL, _, err := buildSecuritySwitchClient(ctx)
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

// Requirement: NET-F-02
//
// buildSecuritySwitchClient's *http.Client (pki.NewClient-bootstrapped)
// must enforce TLS 1.3 with no exceptions (pkg/pki's forceTLS13, applied
// unconditionally inside pki.NewClient): a real CA-issued peer certificate,
// served over a handshake explicitly capped at TLS 1.2, is rejected by
// this client - an actual dial attempt that fails, not merely a
// *tls.Config field assertion. Unlike the accept/reject-by-organization
// case above, here the client is left exactly as production builds it;
// only the peer stub's own *tls.Config (not this package's code) is
// downgraded, standing in for a legacy/downgraded Security-Switch
// instance.
func TestBuildSecuritySwitchClient_RealCA_RejectsTLS12(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Must be minted under securityswitch.OrganizationSecuritySwitch, same
	// as the "accepted" case above: buildSecuritySwitchClient's ServerName
	// is forced to that fixed organization, so any other subject would
	// fail the hostname/SAN check before TLS version even matters, making
	// this test pass for the wrong reason.
	serverToken := generateToken(ctx, t, caURL, container, securityswitch.OrganizationSecuritySwitch)
	stubTLSConfig := realCAServerTLSConfig(ctx, t, serverToken)

	// pki.NewServer's returned *tls.Config sets GetConfigForClient
	// (github.com/smallstep/certificates@v0.30.2/ca/tls.go's own root/
	// federated-root rotation mechanism): per crypto/tls's documented
	// behavior, whenever GetConfigForClient is non-nil its returned
	// *tls.Config is used for the connection INSTEAD of the outer one, so
	// mutating stubTLSConfig.MinVersion/MaxVersion directly here would be a
	// silent no-op against the real per-connection config. Call it once to
	// get that real per-connection snapshot (already carrying the real
	// certificate, ClientCAs, and forceTLS13's MinVersion - confirmed by
	// reading TLSOptionCtx.apply: options run, THEN the mutable snapshot is
	// taken), clear its own GetConfigForClient so nothing overrides our cap
	// again, and downgrade that snapshot instead.
	cappedConfig, err := stubTLSConfig.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("stubTLSConfig.GetConfigForClient() error = %v, want nil", err)
	}
	cappedConfig.GetConfigForClient = nil
	cappedConfig.MinVersion = 0
	cappedConfig.MaxVersion = tls.VersionTLS12

	stub := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	stub.TLS = cappedConfig
	stub.StartTLS()
	defer stub.Close()

	clientToken := generateToken(ctx, t, caURL, container, "EntryHub-itest-tls12-client")
	t.Setenv(pki.BootstrapTokenEnvVar, clientToken)
	t.Setenv(envSecuritySwitchURL, strings.Replace(stub.URL, "127.0.0.1", "localhost", 1))

	client, baseURL, _, err := buildSecuritySwitchClient(ctx)
	if err != nil {
		t.Fatalf("buildSecuritySwitchClient() error = %v, want nil", err)
	}

	resp, err := client.Get(baseURL) //nolint:noctx // test, ctx already bounds the token mint above
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err == nil {
		t.Fatal("client.Get() against a TLS-1.2-capped peer error = nil, want a version-negotiation failure")
	}
}

// writeSelfSignedKeyPair generates a throwaway self-signed certificate/key
// pair (standing in for EH-F-01/02/03's public Let's Encrypt-issued
// certificate in this dev/test environment) and writes both as PEM files
// under a fresh t.TempDir(), returning their paths for envServerCert/
// envServerKey.
func writeSelfSignedKeyPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v, want nil", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "entry-hub-itest"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v, want nil", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey() error = %v, want nil", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath) //nolint:gosec // test-only, path is t.TempDir()-derived, not attacker input
	if err != nil {
		t.Fatalf("os.Create(cert) error = %v, want nil", err)
	}
	defer func() { _ = certOut.Close() }()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem.Encode(cert) error = %v, want nil", err)
	}

	keyOut, err := os.Create(keyPath) //nolint:gosec // test-only, path is t.TempDir()-derived, not attacker input
	if err != nil {
		t.Fatalf("os.Create(key) error = %v, want nil", err)
	}
	defer func() { _ = keyOut.Close() }()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("pem.Encode(key) error = %v, want nil", err)
	}

	return certPath, keyPath
}

// Requirement: EH-F-03
// Requirement: RNF-SEC-04
//
// This is a deliberate, documented EXCEPTION check, not a bug hunt:
// EH-F-03 requires Entry-Hub's login listener (like /api/health and
// /api/users) to be reachable by ordinary registered users holding a
// certificate signed by the PUBLIC Let's Encrypt CA - end users are never
// enrolled in RAM-USB's internal PKI (CA-F-01..04) and so can never
// present an mTLS client certificate. buildServerTLSConfig's own doc
// comment already states this plainly ("no client-CA to load - accepts
// any client, by requirement"). RNF-SEC-04 mandates mTLS for
// INTER-SERVICE communication; user-to-Entry-Hub login is client-to-server
// traffic, not inter-service, so this listener accepting a connection with
// no client certificate is correct, spec-conformant behavior - unlike the
// Database-Vault/Storage-Service/Security-Switch/Network-Manager
// "RejectsNoClientCert" tests (which verify the opposite for genuine
// inter-service listeners), this test asserts ACCEPTANCE, confirming the
// real running behavior matches the documented design rather than
// silently assuming it.
func TestBuildServerTLSConfig_RealListener_AcceptsNoClientCertOnLogin(t *testing.T) {
	certPath, keyPath := writeSelfSignedKeyPair(t)
	t.Setenv(envServerCert, certPath)
	t.Setenv(envServerKey, keyPath)

	serverTLSConfig, err := buildServerTLSConfig()
	if err != nil {
		t.Fatalf("buildServerTLSConfig() error = %v, want nil", err)
	}

	called := false
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLSConfig
	srv.StartTLS()
	defer srv.Close()

	// Deliberately NOT pki.NewClient/pki.NewServer - a bare TLS client
	// presenting no certificate, exactly like a real end-user's browser or
	// the user-client CLI hitting /api/login.
	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test cert, server identity not this test's concern
		},
	}
	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := noCertClient.Get(baseURL) //nolint:noctx // test
	if err != nil {
		t.Fatalf("noCertClient.Get() with no client certificate error = %v, want nil (login listener must accept unauthenticated-by-mTLS end users, EH-F-03)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK || !called {
		t.Fatalf("status = %d, called = %v, want 200 and called", resp.StatusCode, called)
	}
}
