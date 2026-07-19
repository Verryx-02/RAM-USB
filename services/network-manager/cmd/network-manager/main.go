// Command network-manager wires Network-Manager's already-implemented
// packages into a running mTLS HTTP server: NM-F-03's connection-acceptance
// TLS config (only Security-Switch may reach the HTTP API this process
// exposes), the httpapi handlers for NM-F-08 (mesh-user + pre-auth-key
// creation) and NM-F-09 (storage-access ACL grant), and the outbound gRPC
// connection to Headscale those handlers call through internal/headscale.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." Env var names not already
// established by an earlier requirement (RAM_USB_CA_BOOTSTRAP_TOKEN,
// CA-F-04) are this session's invented judgment call, documented on each
// constant below - revisit if a future deployment/ops document fixes
// different names.
//
// TLS/mTLS setup (PKI-F-01/PKI-F-02, CA-F-04): this server's one identity -
// its single inbound listener, organization=SecuritySwitch (NM-F-03) - is
// obtained from the Certificate-Authority via pkg/pki's bootstrap-token
// flow, not from pre-existing cert/key files on disk. pkg/pki's *tls.Config
// is not composable with pkg/mtls.ServerConfig/ClientConfig's
// handshake-level VerifyConnection organization check (see pkg/pki's
// package doc comment: ca.BootstrapServer hard-errors if
// TLSConfig.VerifyConnection is already set, and exposes no hook to install
// one) - so PKI-F-02's organization check runs at the HTTP-request level
// instead, via pkg/mtls.RequireOrganization wrapping this process's one
// mux. This is the same pattern Database-Vault's cmd/database-vault/main.go
// established first (PKI-F-01, PKI-F-02, CA-F-04 session).
//
// No outbound mTLS client role exists in this file. Confirmed against the
// SRS before writing this: NM-F-03 only names Network-Manager as an mTLS
// *server* ("only Security-Switch and Certificate-Authority can contact
// Network-Manager" - Certificate-Authority's own contact is the separate
// bootstrap-token flow, not an mTLS client of this HTTP API, per
// internal/server's own doc comment). No other built NM-F-* requirement has
// Network-Manager call out, over mTLS, to another RAM-USB service; NM-F-08/
// NM-F-09 are both requests Network-Manager *receives* from Security-Switch
// and answers synchronously - Network-Manager's own outbound work for them
// is entirely toward Headscale (buildHeadscaleConn, below), a third-party
// mesh-coordination server, not a RAM-USB peer under PKI-F-01/PKI-F-02's
// mTLS rules (see internal/headscale/client.go's package doc comment: a
// gRPC bearer-API-key credential, not a client certificate). Revisit this
// note if a future NM-F-* requirement (e.g. NM-F-10's expiry sweep, or an
// admin interface) is ever built such that Network-Manager itself becomes
// an outbound mTLS caller of another RAM-USB service.
//
// See also deployments/docker-compose.dev.yml's certificate-authority-init
// service: the dev Certificate-Authority container needs a one-time,
// idempotent setup step before any certificate it issues carries a
// non-empty Subject.Organization at all - without it, PKI-F-02's
// organization check would reject every connection. `docker compose up`
// applies it automatically; no manual step is required.
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
	"strconv"
	"syscall"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/server"
)

// Env var names for values this task introduces. pki.BootstrapTokenEnvVar
// (RAM_USB_CA_BOOTSTRAP_TOKEN) is already established by CA-F-04 and is not
// redefined here - it is this server's single-use bootstrap token, used
// for its one inbound listener.
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Security-Switch (NM-F-03).
	envListenAddr = "RAM_USB_NETWORK_MANAGER_LISTEN_ADDR"

	// envHeadscaleAddr is Headscale's gRPC coordination endpoint address
	// (internal/headscale.Dial), e.g.
	// "network-manager-headscale:50443". Not part of any RAM-USB
	// mTLS/PKI-F-01/PKI-F-02 role - see this file's package doc comment.
	envHeadscaleAddr = "RAM_USB_HEADSCALE_ADDR"

	// envHeadscaleAPIKey is the bearer API key internal/headscale.Dial
	// authenticates with (a Headscale-issued credential, minted
	// out-of-band by a CA/ops process - "headscale apikeys create" -
	// distinct from any RAM-USB mTLS certificate).
	envHeadscaleAPIKey = "RAM_USB_HEADSCALE_API_KEY" //nolint:gosec // an env var *name*, not a credential value

	// envHeadscaleInsecureSkipVerify, if set to "true", skips verifying
	// Headscale's server certificate. Optional, defaults to false.
	// third-party/network-manager/headscale/dev-tls/README.txt documents
	// why this dev-only toggle exists: the dev-compose Headscale
	// deployment uses a self-signed certificate not chained to any
	// trusted root - never appropriate for a real deployment.
	envHeadscaleInsecureSkipVerify = "RAM_USB_HEADSCALE_INSECURE_SKIP_VERIFY"
)

func main() {
	if err := run(); err != nil {
		slog.Error("network-manager: fatal startup error", "error", err)
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

	// serverTLSConfig is this server's one bootstrapped TLS identity
	// (PKI-F-01, CA-F-04), used only by its one inbound listener - see
	// this file's package doc comment for why no outbound mTLS role
	// exists here, unlike Database-Vault's own buildServerTLSConfig
	// (which is also reused as an outbound Storage-Service client).
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	conn, err := buildHeadscaleConn()
	if err != nil {
		return fmt.Errorf("dial headscale: %w", err)
	}
	defer func() { _ = conn.Close() }()

	handler := &httpapi.Handler{
		Mesh: httpapi.HeadscaleAdapter{Service: v1.NewHeadscaleServiceClient(conn)},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(httpapi.MeshUserPath, handler.CreateMeshUser)
	mux.HandleFunc(httpapi.GrantPath, handler.Grant)

	httpServer := &http.Server{
		Addr: listenAddr,
		// PKI-F-02's organization check runs here, at the HTTP-request
		// level (mtls.RequireOrganization), not inside serverTLSConfig's
		// handshake - see this file's package doc comment for why.
		Handler:           mtls.RequireOrganization(server.AllowedClientOrganization, mux),
		TLSConfig:         serverTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("network-manager: listening", "addr", listenAddr)
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

// getEnvBool reads name from the environment as a bool, defaulting to
// false if unset or empty. A value present but not parseable as a bool
// (strconv.ParseBool's accepted forms: 1/t/T/TRUE/true/True,
// 0/f/F/FALSE/false/False) is a startup failure (RD-04, fail-secure) -
// not silently treated as false.
func getEnvBool(name string) (bool, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("environment variable %s is not a valid bool: %w", name, err)
	}
	return parsed, nil
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
// github.com/smallstep/certificates/ca/bootstrap.go's BootstrapServer, per
// this session's memory of Database-Vault's identical prior finding), so a
// minimal value discarded immediately after extracting TLSConfig is
// sufficient - the real *http.Server run actually serves (httpServer) is
// constructed separately in run.
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

// buildHeadscaleConn dials Headscale's gRPC coordination endpoint
// (internal/headscale.Dial), the private, non-RAM-USB dependency NM-F-08/
// NM-F-09's handlers call through - not a PKI-F-01/PKI-F-02 mTLS role, see
// this file's package doc comment.
func buildHeadscaleConn() (*grpc.ClientConn, error) {
	addr, err := requireEnv(envHeadscaleAddr)
	if err != nil {
		return nil, err
	}
	apiKey, err := requireEnv(envHeadscaleAPIKey)
	if err != nil {
		return nil, err
	}
	insecureSkipVerify, err := getEnvBool(envHeadscaleInsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: insecureSkipVerify} //nolint:gosec // operator-controlled dev-only toggle (envHeadscaleInsecureSkipVerify), defaults to false; see third-party/network-manager/headscale/dev-tls/README.txt

	return headscale.Dial(addr, apiKey, tlsConfig)
}
