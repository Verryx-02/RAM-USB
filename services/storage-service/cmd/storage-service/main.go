// Command storage-service wires every already-implemented Storage-Service
// package into a running mTLS HTTP server: ST-F-01's connection-acceptance
// TLS config, the httpapi handler (ST-F-06, ST-F-10), and the real
// OS-level POSIX-user creation (ST-F-06, ST-F-08) via execrunner.Real and
// posixuser.RealDirMaker.
//
// Storage-Service has only one mTLS listener here, unlike Database-Vault's
// two: its other inbound surface is SFTP itself (ST-F-03/ST-F-04),
// handled entirely by sshd outside this Go process, not by an HTTP
// listener. ST-F-11's AuthorizedKeysCommand is a separate, already-scoped
// binary (services/storage-service/internal/pubkeylookup), not wired here.
// ST-F-12/ST-F-13 (metrics) have no implementation anywhere in
// Storage-Service yet and are deliberately not wired here either.
//
// This server makes no outbound mTLS call of its own: ST-F-10 ("report
// the outcome back to Database-Vault") is satisfied entirely by this
// listener's own HTTP response to the inbound create-user request
// (httpapi.Handler.CreateUser's {"success":...} body, confirmed by
// reading that handler) - there is no separate outbound call anywhere in
// this service. So only one identity role needs bootstrapping here
// (inbound server), unlike Database-Vault, which also needed an outbound
// client role for DV-F-09.
//
// TLS/mTLS setup (PKI-F-01/PKI-F-02, CA-F-04): this server's identity is
// obtained from the Certificate-Authority via pkg/pki's bootstrap-token
// flow (CA-F-04), not from pre-existing cert/key files on disk. pkg/pki's
// *tls.Config is not composable with pkg/mtls.ServerConfig's
// handshake-level VerifyConnection organization check (see pkg/pki's
// package doc comment: ca.BootstrapServer hard-errors if
// TLSConfig.VerifyConnection is already set, and exposes no hook to
// install one) - so PKI-F-02's organization check runs at the
// HTTP-request level instead, via pkg/mtls.RequireOrganization wrapping
// the handler. This relies on net/http.Request.TLS, which net/http
// populates from the completed handshake regardless of which library
// built the tls.Config. Same architecture as Database-Vault's
// buildServerTLSConfig (services/database-vault/cmd/database-vault/
// main.go), reused here for a single inbound-only role.
//
// See also deployments/docker-compose.dev.yml's certificate-authority-init
// service: the dev Certificate-Authority container needs a one-time,
// idempotent setup step (a custom x509 template on its bootstrap-token
// provisioner) before any certificate it issues carries a non-empty
// Subject.Organization at all - without it, PKI-F-02's organization check
// would reject every connection. `docker compose up` applies it
// automatically now; no manual step is required.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." Env var names not already
// established by an earlier requirement (pki.BootstrapTokenEnvVar) follow
// the same RAM_USB_STORAGE_SERVICE_* convention already established by
// database-vault/cmd/database-vault/main.go's own
// RAM_USB_DATABASE_VAULT_* names.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/execrunner"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/posixuser"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/server"
)

// Env var names this task introduces. pki.BootstrapTokenEnvVar
// (RAM_USB_CA_BOOTSTRAP_TOKEN) is already established by CA-F-04 and is
// not redefined here - it is this server's own single-use bootstrap
// token.
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Database-Vault (ST-F-01, ST-F-06).
	envListenAddr = "RAM_USB_STORAGE_SERVICE_LISTEN_ADDR"
)

func main() {
	if err := run(); err != nil {
		slog.Error("storage-service: fatal startup error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenAddr, err := requireEnv(envListenAddr)
	if err != nil {
		return err
	}

	tlsConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	creator := &posixuser.Creator{
		Runner:   execrunner.Real{},
		DirMaker: posixuser.RealDirMaker{},
	}

	handler := &httpapi.Handler{
		Creator: creator,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(httpapi.CreateUserPath, handler.CreateUser)

	httpServer := &http.Server{
		Addr: listenAddr,
		// PKI-F-02's organization check runs here, at the HTTP-request
		// level (mtls.RequireOrganization), not inside tlsConfig's
		// handshake - see this file's package doc comment for why.
		Handler:           mtls.RequireOrganization(server.AllowedClientOrganization, mux),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("storage-service: listening", "addr", listenAddr)
		// TLSConfig already carries the bootstrapped certificate (via
		// buildServerTLSConfig's GetCertificate callback, not a static
		// Certificates slice), so ListenAndServeTLS is called with empty
		// file paths per net/http's documented convention for that case.
		serveErr <- httpServer.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown listener: %w", err)
		}
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve listener: %w", err)
	}
}

// requireEnv reads name from the environment, failing closed (RD-04) if
// it is unset or empty.
func requireEnv(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return value, nil
}

// buildServerTLSConfig bootstraps this server's one TLS identity from the
// Certificate-Authority (CA-F-04, PKI-F-01), using pki.LoadBootstrapToken's
// single-use token exactly once. The returned *tls.Config carries no
// organization restriction of its own (that runs at the HTTP-request
// level, via mtls.RequireOrganization in run); ca.BootstrapServer's
// default (tls.RequireAndVerifyClientCert) still ensures only a
// certificate this CA itself issued can complete an inbound handshake at
// all.
//
// base is a throwaway *http.Server: pki.NewServer only ever reads/writes
// its TLSConfig field (confirmed by reading
// github.com/smallstep/certificates/ca/bootstrap.go's BootstrapServer, see
// database-vault/cmd/database-vault/main.go's identical buildServerTLSConfig
// for the same finding), so a minimal value discarded immediately after
// extracting TLSConfig is sufficient - the real *http.Server run actually
// serves (httpServer) is constructed separately in run.
func buildServerTLSConfig(ctx context.Context) (*tls.Config, error) {
	token, err := pki.LoadBootstrapToken()
	if err != nil {
		return nil, fmt.Errorf("load ca bootstrap token: %w", err)
	}

	base := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	bootstrapped, err := pki.NewServer(ctx, token, base)
	if err != nil {
		return nil, fmt.Errorf("bootstrap server identity from certificate-authority: %w", err)
	}

	return bootstrapped.TLSConfig, nil
}
