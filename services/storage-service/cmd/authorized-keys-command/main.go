// Command authorized-keys-command is ST-F-11's consumer side: sshd's
// AuthorizedKeysCommand directive invokes this binary on every SFTP
// connection attempt, passing the connecting/target username as %u
// (os.Args[1]). It looks up that user's current SSH public key from
// Database-Vault, over mTLS, via
// services/storage-service/internal/pubkeylookup, and reports it back to
// sshd the only way OpenSSH's AuthorizedKeysCommand contract allows: one
// authorized_keys-formatted line on stdout.
//
// Fail-secure (RD-04) on every error path: a malformed %u, a config-load
// failure, or any pubkeylookup failure (invalid username, not found, or the
// call itself failing/timing out) all result in identical observable
// behavior — nothing printed to stdout, exit code 0. OpenSSH's own
// documented contract for "no keys available for this user" is empty
// stdout, not a nonzero exit code, so a nonzero exit here would not deny
// the connection any more strongly; it would only make troubleshooting
// (this binary's own stderr, never stdout) marginally different, which is
// why every failure path converges on exit 0 rather than being tempted to
// signal severity via a distinct exit status.
//
// stdout is sshd's key-source channel and carries nothing but the fetched
// key line (or nothing at all) — never a log line, even on success. All
// operational logging goes to stderr, and never includes the fetched key
// material itself (RD-01: plaintext/sensitive material stays confined to
// where it's strictly needed, which for a fetched public key is sshd's own
// key-parsing step, not this process's own log stream).
//
// This binary reads its own mTLS client identity (certificate, key, CA
// bundle) and Database-Vault's base URL from a fixed config file path
// (configPath below), not environment variables: unlike a long-running
// server process, sshd's AuthorizedKeysCommand invocation does not reliably
// hand this process the environment an operator might expect (OpenSSH
// deliberately runs it with a minimal, sanitized environment for the same
// reason it drops privileges before invoking it). The config file's actual
// contents are supplied by the container's deployment/Dockerfile setup, a
// separate, not-yet-scoped task — this binary only defines the format and
// reads it.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/pubkeylookup"
)

// configPath is the fixed location this binary reads its configuration
// from (see the package doc comment for why a file, not an environment
// variable). Exported as a named constant, not inlined, so a future
// deployment/ops document or test can reference the exact same value.
const configPath = "/etc/storage-service/authorized-keys-command.conf"

// databaseVaultLookupTimeout bounds how long this process waits for
// Database-Vault's response before giving up and denying the connection
// (RD-04) — sshd blocks the connecting client on this call, so it must not
// hang indefinitely. Confirmed with the user: 10 seconds.
const databaseVaultLookupTimeout = 10 * time.Second

// organizationDatabaseVault is the required Subject.Organization value on
// Database-Vault's server certificate, verified during the mTLS handshake
// (PKI-F-02). Matches the same "DatabaseVault" convention already
// established by services/security-switch/internal/dbvault
// (OrganizationDatabaseVault) — repeated here rather than imported, since
// that package is internal to security-switch and Go's internal-package
// rule blocks importing it from here even within the same module.
const organizationDatabaseVault = "DatabaseVault"

// posixUsernamePattern re-validates sshd's %u argument against DV-F-09's
// exact "user<xxxxxx>" format before it is ever used to build a request —
// RNF-SEC-02/03's zero-trust/defense-in-depth principle applied at this
// layer too, even though pubkeylookup.FetchAuthorizedKeysLine independently
// re-validates the same shape itself. Mirrors the identical pattern already
// duplicated in database-vault/internal/httpapi/pubkey_handler.go,
// storage-service/internal/httpapi/httpapi.go, and
// storage-service/internal/pubkeylookup/lookup.go.
var posixUsernamePattern = regexp.MustCompile(`^user[0-9a-z]{6}$`)

func main() {
	if len(os.Args) < 2 {
		slog.Warn("authorized-keys-command: missing username argument")
		os.Exit(0)
	}
	arg := os.Args[1]

	cfg, err := loadConfig(configPath)
	if err != nil {
		slog.Error("authorized-keys-command: config load failed", "error", err)
		os.Exit(0)
	}

	client, err := buildClient(cfg)
	if err != nil {
		slog.Error("authorized-keys-command: build mTLS client failed", "error", err)
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), databaseVaultLookupTimeout)
	line, ok := Resolve(ctx, client, cfg.databaseVaultURL, arg)
	// Resolve runs and completes synchronously above; cancel() is called
	// explicitly here (not deferred) because every path below ends in
	// os.Exit, which skips deferred calls entirely - a deferred cancel()
	// would never run. There is no in-flight request left needing this
	// cancellation by this point (Resolve already returned), so this is
	// routine context-resource hygiene before process exit, not a
	// safety-critical cleanup step.
	cancel()
	if !ok {
		os.Exit(0)
	}

	fmt.Println(line)
	os.Exit(0)
}

// Resolve decides what, if anything, should be printed to stdout for the
// connecting username arg: re-validates arg, then calls
// pubkeylookup.FetchAuthorizedKeysLine over client against baseURL. A true
// ok means line is the authorized_keys line to print; a false ok means
// nothing should be printed (RD-04, fail-secure) — the specific reason
// (invalid username, not found, or the lookup call itself failing/timing
// out via ctx) is logged to stderr here, never returned to main for
// printing, since stdout must carry only a successfully fetched key line or
// nothing at all.
func Resolve(ctx context.Context, client *http.Client, baseURL, arg string) (line string, ok bool) {
	if !posixUsernamePattern.MatchString(arg) {
		slog.Warn("authorized-keys-command: rejected malformed username argument")
		return "", false
	}

	key, err := pubkeylookup.FetchAuthorizedKeysLine(ctx, client, baseURL, arg)
	if err != nil {
		switch {
		case errors.Is(err, pubkeylookup.ErrPublicKeyNotFound):
			slog.Info("authorized-keys-command: no public key on record, denying connection")
		case errors.Is(err, pubkeylookup.ErrInvalidPosixUsername):
			slog.Warn("authorized-keys-command: rejected malformed username argument")
		default:
			slog.Error("authorized-keys-command: public key lookup failed, denying connection", "error", err)
		}
		return "", false
	}

	return key, true
}

// config holds every value authorized-keys-command.conf must supply.
type config struct {
	// databaseVaultURL is Database-Vault's dedicated ST-F-11 public-key
	// lookup base URL (e.g. "https://database-vault.internal:8444").
	databaseVaultURL string
	// clientCertPath/clientKeyPath locate this binary's own mTLS client
	// certificate/key, presented to Database-Vault during the mTLS
	// handshake.
	clientCertPath string
	clientKeyPath  string
	// clientCAPath locates the CA certificate bundle (PEM) trusted to have
	// issued Database-Vault's server certificate.
	clientCAPath string
}

// loadConfig reads and parses the config file at path.
func loadConfig(path string) (config, error) {
	f, err := os.Open(path) //nolint:gosec // path is this process's own fixed, operator-controlled constant, not request input
	if err != nil {
		return config{}, fmt.Errorf("open config file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	return parseConfig(f)
}

// parseConfig parses r as a simple "key = value" configuration format: one
// assignment per line, blank lines and lines starting with "#" ignored,
// whitespace around key/value trimmed. This format (rather than JSON or a
// more structured alternative) is this binary's own judgment call — no SRS
// or design doc specifies one, and a flat four-key file has no need for
// JSON's nesting/quoting overhead; a human operator hand-editing this file
// in a container image (the deployment task that will supply its real
// contents) benefits from the simpler, more forgiving syntax.
//
// All four keys below are required; a missing one is a fail-secure error
// (RD-04), not a silently-defaulted value, since every one of them is
// security-relevant (the mTLS identity this process presents, and which
// server it trusts).
func parseConfig(r io.Reader) (config, error) {
	values := make(map[string]string, 4)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			return config{}, fmt.Errorf("malformed config line (expected key = value): %q", line)
		}

		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}

	cfg := config{
		databaseVaultURL: values["database_vault_url"],
		clientCertPath:   values["client_cert"],
		clientKeyPath:    values["client_key"],
		clientCAPath:     values["client_ca"],
	}

	if cfg.databaseVaultURL == "" || cfg.clientCertPath == "" || cfg.clientKeyPath == "" || cfg.clientCAPath == "" {
		return config{}, errors.New("config missing one or more required keys: database_vault_url, client_cert, client_key, client_ca")
	}

	return cfg, nil
}

// buildClient assembles the *http.Client this binary uses to call
// Database-Vault over mTLS, verifying organization="DatabaseVault" on
// Database-Vault's server certificate. Mirrors the identical
// tls.LoadX509KeyPair + x509.CertPool + mtls.ClientConfig pattern already
// used by database-vault/cmd/database-vault/main.go's own
// buildStorageServiceClient, the established precedent for building an
// outbound mTLS *http.Client in this codebase.
func buildClient(cfg config) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.clientCertPath, cfg.clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate/key: %w", err)
	}

	caData, err := os.ReadFile(cfg.clientCAPath) //nolint:gosec // path comes from this process's own operator-controlled config file, not from request input
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", cfg.clientCAPath, err)
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("no certificates found in CA bundle %s", cfg.clientCAPath)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtls.ClientConfig(cert, rootCAs, organizationDatabaseVault),
		},
	}, nil
}
