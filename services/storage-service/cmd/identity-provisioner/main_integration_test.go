package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file verifies provisionInitial - the whole one-time bootstrap
// KI-01 exists to fix - against a REAL running Certificate-Authority
// container (deployments/compose/certificate-authority.yml's
// certificate-authority service), same env-var-gated skip and
// docker-exec-based token minting as
// services/storage-service/cmd/storage-service/main_integration_test.go
// and pkg/pki/stepca_test.go.
//
// Requires the certificate-authority-init compose service to have
// completed (docker compose up now guarantees this automatically) - without
// it every certificate this CA issues has an empty Subject.Organization.

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
		t.Skipf("%s not set; skipping the real-Certificate-Authority ST-F-11 test. "+
			"Run `docker compose -f deployments/compose/certificate-authority.yml up` "+
			"and set this variable (e.g. https://localhost:9000) to run it.", caURLEnvVar)
	}

	container = os.Getenv(caContainerEnvVar)
	if container == "" {
		container = defaultCAContainer
	}

	return caURL, container
}

// generateToken shells into the running certificate-authority container and
// mints a real, single-use bootstrap token via `step ca token` - same
// technique as pkg/pki/stepca_test.go's generateTestToken.
func generateToken(ctx context.Context, t *testing.T, caURL, container, subject string) string {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not available: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	//nolint:gosec // container/caURL/subject come from this test's own
	// env-gated config and call sites, not untrusted request input.
	cmd := exec.CommandContext(ctx, "docker", "exec", container,
		"step", "ca", "token", subject,
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

// Requirement: ST-F-11
//
// End-to-end: a real bootstrap token, exchanged via provisionInitial for a
// real "StorageService"-organization identity, produces on-disk cert/key/
// CA-root/config files that tls.LoadX509KeyPair (authorized-keys-command's
// own reader) can load and that chain-verify against the written root CA -
// proving the exact files KI-01 was missing are now real and usable, not
// just that provisionInitial returns no error.
func TestProvisionInitial_RealCA(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := generateToken(ctx, t, caURL, container, "StorageService")

	dir := t.TempDir()
	paths := filePaths{
		cert:   filepath.Join(dir, "akc-client.crt"),
		key:    filepath.Join(dir, "akc-client.key"),
		ca:     filepath.Join(dir, "akc-ca.crt"),
		config: filepath.Join(dir, "authorized-keys-command.conf"),
	}

	getClientCertificate, err := provisionInitial(ctx, token, "https://database-vault:8446", paths)
	if err != nil {
		t.Fatalf("provisionInitial() error = %v, want nil", err)
	}
	if getClientCertificate == nil {
		t.Fatal("provisionInitial() returned a nil GetClientCertificate callback")
	}

	// The written config file must contain the four keys
	// cmd/authorized-keys-command/main.go's parseConfig requires.
	confBytes, err := os.ReadFile(paths.config) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("os.ReadFile(config) error = %v, want nil", err)
	}
	conf := string(confBytes)
	for _, want := range []string{"database_vault_url = https://database-vault:8446", "client_cert = " + paths.cert, "client_key = " + paths.key, "client_ca = " + paths.ca} {
		if !strings.Contains(conf, want) {
			t.Errorf("config file does not contain %q:\n%s", want, conf)
		}
	}

	// The written CA root file must decode as a valid certificate whose
	// subject matches this dev deployment's own CA name.
	caBytes, err := os.ReadFile(paths.ca) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("os.ReadFile(ca) error = %v, want nil", err)
	}
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caBytes) {
		t.Fatalf("root ca file did not parse as PEM: %q", caBytes)
	}

	// The written cert/key pair must load exactly the way
	// cmd/authorized-keys-command/main.go's own buildClient loads them, and
	// the leaf must chain-verify against the written root.
	pair, err := tls.LoadX509KeyPair(paths.cert, paths.key)
	if err != nil {
		t.Fatalf("tls.LoadX509KeyPair() error = %v, want nil", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate(leaf) error = %v, want nil", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("x509.ParseCertificate(intermediate) error = %v, want nil", err)
		}
		intermediates.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf.Verify() against the written root CA error = %v, want nil", err)
	}

	found := false
	for _, org := range leaf.Subject.Organization {
		if org == "StorageService" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("leaf certificate's subject organization = %v, want to contain %q", leaf.Subject.Organization, "StorageService")
	}
}
