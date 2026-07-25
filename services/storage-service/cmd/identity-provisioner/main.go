// Command identity-provisioner closes KI-01: ST-F-11's
// cmd/authorized-keys-command binary expects its own mTLS identity and
// Database-Vault's URL at a fixed config file path
// (/etc/storage-service/authorized-keys-command.conf), but that file's
// real contents were never actually provisioned by anything - only the
// empty containing directory was created.
//
// This is a separate, long-lived process from both storage-service and
// authorized-keys-command (see services/storage-service/internal/akcidentity's
// package doc comment for why authorized-keys-command itself cannot do
// this work): it bootstraps its OWN mTLS identity from the
// Certificate-Authority via pkg/pki (CA-F-04, PKI-F-01), organization
// "StorageService" - the same organization Database-Vault's ST-F-11 lookup
// endpoint already requires (services/database-vault/internal/server/
// pubkey_server.go's AllowedPublicKeyClientOrganization) - using its own
// dedicated single-use bootstrap token (envBootstrapToken below), distinct
// from cmd/storage-service's own RAM_USB_CA_BOOTSTRAP_TOKEN: two processes
// in the same container both need a bootstrapped identity, and a
// bootstrap token is single-use, so each needs its own.
//
// It then writes that identity to disk once (the CA root - RootCA does not
// consume the bootstrap token's single use, see pkg/pki's own doc comment
// - and the static config file, both of which never change again for this
// process's lifetime) and re-encodes the CURRENT certificate/key to disk
// on every certRefreshInterval tick thereafter, via pkg/pki's own
// automatic-renewal mechanism (already running in the background once
// pki.NewClient returns) - so authorized-keys-command, which reads these
// exact files fresh on every SFTP connection attempt, never sees an
// expired identity.
//
// Supervised by s6-overlay as its own longrun, running as the same
// dedicated unprivileged sshd-authkeys system account
// authorized-keys-command itself runs as (see this container's Dockerfile)
// - this process never needs root, only the ability to make outbound mTLS
// calls and write to /etc/storage-service.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/env"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/akcidentity"
)

// Env var names this task introduces.
const (
	// envBootstrapToken is this process's OWN single-use CA-F-04 bootstrap
	// token - deliberately not pki.BootstrapTokenEnvVar
	// (RAM_USB_CA_BOOTSTRAP_TOKEN), which cmd/storage-service's own main
	// process already reads in this same container (see this file's
	// package doc comment for why they must differ).
	envBootstrapToken = "RAM_USB_STORAGE_SERVICE_AKC_BOOTSTRAP_TOKEN" //nolint:gosec // an env var *name*, not a credential value

	// envDatabaseVaultURL is Database-Vault's ST-F-11 public-key lookup
	// base URL (e.g. "https://database-vault:8446" - see
	// deployments/compose/database-vault.yml's
	// RAM_USB_DATABASE_VAULT_PUBLIC_KEY_LISTEN_ADDR for the port this must
	// match), written verbatim into authorized-keys-command.conf's
	// database_vault_url key.
	envDatabaseVaultURL = "RAM_USB_DATABASE_VAULT_PUBLIC_KEY_URL"
)

// Filesystem layout this process owns entirely - authorized-keys-command
// never hardcodes any of these, it reads them back out of configPath's own
// client_cert/client_key/client_ca values (see
// cmd/authorized-keys-command/main.go's config/parseConfig), so the two
// binaries stay coupled only through configPath itself, not through any of
// these three.
const (
	configDir = "/etc/storage-service"
	certPath  = configDir + "/akc-client.crt"
	keyPath   = configDir + "/akc-client.key"
	caPath    = configDir + "/akc-ca.crt"
	// configPath must stay identical to cmd/authorized-keys-command/main.go's
	// own configPath constant.
	configPath = configDir + "/authorized-keys-command.conf"
)

// certFilePerm/keyFilePerm mirror the sensitivity split already applied
// throughout this project (RD-01): the certificate chain is not sensitive
// (0644, world-readable), the private key is (0600, owner-only) - the
// owner here being sshd-authkeys, the same unprivileged account both this
// process and authorized-keys-command run as.
const (
	certFilePerm os.FileMode = 0o644
	keyFilePerm  os.FileMode = 0o600
)

// certRefreshInterval bounds how stale the on-disk certificate/key can be
// relative to pkg/pki's own in-memory renewed identity. No SRS requirement
// mandates a specific value; five minutes keeps the on-disk copy well
// inside any realistic certificate lifetime margin without writing to
// disk needlessly often.
const certRefreshInterval = 5 * time.Minute

func main() {
	if err := run(); err != nil {
		slog.Error("identity-provisioner: fatal startup error", "error", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	token, err := env.Require(envBootstrapToken)
	if err != nil {
		return err
	}
	databaseVaultURL, err := env.Require(envDatabaseVaultURL)
	if err != nil {
		return err
	}

	paths := filePaths{cert: certPath, key: keyPath, ca: caPath, config: configPath}

	getClientCertificate, err := provisionInitial(ctx, token, databaseVaultURL, paths)
	if err != nil {
		return err
	}
	slog.Info("identity-provisioner: initial identity provisioned", "configPath", configPath)

	ticker := time.NewTicker(certRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := refreshCertificate(getClientCertificate, paths.cert, paths.key); err != nil {
				slog.Error("identity-provisioner: certificate refresh failed", "error", logging.Sanitize(err.Error()))
			}
		}
	}
}

// filePaths is the on-disk layout provisionInitial/refreshCertificate write
// to - a struct rather than four loose parameters purely for call-site
// readability; run always populates it from the certPath/keyPath/caPath/
// configPath package consts, a test can substitute a t.TempDir()-rooted
// set instead.
type filePaths struct {
	cert   string
	key    string
	ca     string
	config string
}

// provisionInitial performs this process's entire one-time setup: bootstrap
// this identity from the Certificate-Authority (CA-F-04, PKI-F-01, using
// token exactly once), fetch and write the CA's own root certificate
// (pki.RootCA - does not consume token's single use), write the first
// certificate/key pair, and write authorized-keys-command's static config
// file LAST - so its existence on disk is itself the "every file this
// process writes is now ready" signal a readiness-gate oneshot (this
// container's identity-provisioner-ready) can poll for, without needing to
// separately check for the other three files it references. Returns the
// tls.Config.GetClientCertificate callback the caller's periodic refresh
// loop keeps polling afterward - pkg/pki's own background renewal (started
// inside pki.NewClient) keeps that callback's return value current for the
// life of ctx.
func provisionInitial(ctx context.Context, token, databaseVaultURL string, paths filePaths) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	client, err := pki.NewClient(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("bootstrap identity-provisioner identity from certificate-authority: %w", err)
	}
	tlsConfig, err := pki.TLSConfig(client)
	if err != nil {
		return nil, fmt.Errorf("extract tls config: %w", err)
	}
	if tlsConfig.GetClientCertificate == nil {
		return nil, fmt.Errorf("bootstrapped tls config has no GetClientCertificate callback")
	}

	rootPEM, err := pki.RootCA(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("fetch certificate-authority root certificate: %w", err)
	}
	if err := akcidentity.WriteFileAtomic(paths.ca, rootPEM, certFilePerm); err != nil {
		return nil, fmt.Errorf("write root ca file: %w", err)
	}

	if err := refreshCertificate(tlsConfig.GetClientCertificate, paths.cert, paths.key); err != nil {
		return nil, fmt.Errorf("write initial certificate/key: %w", err)
	}

	conf := akcidentity.RenderConfig(databaseVaultURL, paths.cert, paths.key, paths.ca)
	if err := akcidentity.WriteFileAtomic(paths.config, []byte(conf), certFilePerm); err != nil {
		return nil, fmt.Errorf("write authorized-keys-command config file: %w", err)
	}

	return tlsConfig.GetClientCertificate, nil
}

// refreshCertificate fetches the CURRENT certificate/key from
// getClientCertificate (pkg/pki's own automatically-renewing identity,
// see this file's package doc comment) and re-encodes both to
// certFilePath/keyFilePath. certFilePath/keyFilePath are parameters
// (rather than reading the package-level certPath/keyPath consts
// directly), purely so this function is unit-testable against a t.TempDir()
// - run always calls it with those two consts.
func refreshCertificate(getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error), certFilePath, keyFilePath string) error {
	cert, err := getClientCertificate(nil)
	if err != nil {
		return fmt.Errorf("get current client certificate: %w", err)
	}

	certPEM := akcidentity.EncodeCertificateChain(cert.Certificate)
	if err := akcidentity.WriteFileAtomic(certFilePath, certPEM, certFilePerm); err != nil {
		return fmt.Errorf("write certificate file: %w", err)
	}

	keyPEM, err := akcidentity.EncodePrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	if err := akcidentity.WriteFileAtomic(keyFilePath, keyPEM, keyFilePerm); err != nil {
		return fmt.Errorf("write private key file: %w", err)
	}

	return nil
}
