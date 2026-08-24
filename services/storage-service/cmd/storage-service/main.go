// Command storage-service wires every already-implemented Storage-Service
// package into a running mTLS HTTP server: ST-F-01's connection-acceptance
// TLS config, the httpapi handler (ST-F-06, ST-F-10, ST-F-16), and the
// real OS-level POSIX-user creation (ST-F-06, ST-F-08) via execrunner.Real
// and posixuser.RealDirMaker. readHostPublicKey loads ST-F-16's SSH host
// public key from disk once, here, at startup - see its own doc comment
// for why.
//
// Storage-Service has only one mTLS listener here, unlike Database-Vault's
// two: its other inbound surface is SFTP itself (ST-F-03/ST-F-04),
// handled entirely by sshd outside this Go process, not by an HTTP
// listener. ST-F-11's AuthorizedKeysCommand is a separate, already-scoped
// binary (services/storage-service/internal/pubkeylookup), not wired here.
// ST-F-12/ST-F-13's periodic MQTT metrics publish is wired here, same
// shape as Database-Vault's and Network-Manager's own metrics wiring
// (DV-F-16/DV-F-17, NM-F-17/NM-F-18).
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
// See also deployments/compose/certificate-authority.yml's certificate-authority-init
// service: the dev Certificate-Authority container needs a one-time,
// idempotent setup step (a custom x509 template on its bootstrap-token
// provisioner) before any certificate it issues carries a non-empty
// Subject.Organization at all - without it, PKI-F-02's organization check
// would reject every connection. `docker compose up` applies it
// automatically now; no manual step is required.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md section 7's "cmd/<service>/main.go: wiring, config loading,
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
	"strings"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/env"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
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

	// envMQTTBrokerURL is ST-F-12's metrics-publish MQTT connection - same
	// optional-if-unset convention as Database-Vault's and Network-
	// Manager's own cmd/<service>/main.go. No separate
	// RAM_USB_MQTT_CLIENT_CERT/RAM_USB_MQTT_CLIENT_KEY/RAM_USB_MQTT_CA env
	// vars exist anymore - this server's MQTT identity and root trust are
	// both derived from tlsConfig, the same bootstrapped identity already
	// used for the inbound listener (see this file's package doc
	// comment).
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"
)

// serviceName is Storage-Service's identifier in every metrics payload it
// publishes and the "<Service-Name>" half of its dedicated MQTT topic
// (ST-F-12), reproduced verbatim from the SRS's literal
// `metrics/Storage-Service` quote.
const serviceName = "Storage-Service"

// metricsClientID is the MQTT client identifier this process connects
// with (ST-F-12).
const metricsClientID = "storage-service"

// metricsPublishInterval is ST-F-12's "every minute, and only."
const metricsPublishInterval = time.Minute

// connectTimeout bounds how long this process waits for the MQTT broker
// connection (metrics) to complete.
const connectTimeout = 10 * time.Second

// hostPublicKeyPath is where sshd's own Ed25519 host key public half lives
// (ST-F-16), generated once by `ssh-keygen -A` in the sshd-hostkeys s6
// oneshot (deployments/docker/storage-service/rootfs/etc/s6-overlay/
// s6-rc.d/sshd-hostkeys/up), which this longrun depends on and which
// therefore always runs first (see this longrun's own
// dependencies.d/sshd-hostkeys entry). Ed25519 is preferred over the
// RSA/ECDSA host keys ssh-keygen -A also generates - it is the smallest,
// most current key type and the one CL-F-11's pinning is meant to check
// against.
const hostPublicKeyPath = "/etc/ssh/ssh_host_ed25519_key.pub"

func main() {
	if err := run(); err != nil {
		slog.Error("storage-service: fatal startup error", "error", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenAddr, err := env.Require(envListenAddr)
	if err != nil {
		return err
	}

	tlsConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	hostPublicKey, err := readHostPublicKey(hostPublicKeyPath)
	if err != nil {
		// ST-F-16: read once at startup, not per-request. The host key is
		// generated once (before this process ever starts, see
		// hostPublicKeyPath's doc comment) and never changes for the
		// container's lifetime, so there is nothing to gain from a
		// per-request read - and failing here means this server never
		// starts accepting create-user requests it could not answer
		// correctly (RD-04, fail-secure), rather than deferring the
		// failure to the first registration.
		return fmt.Errorf("read ssh host public key: %w", err)
	}

	creator := &posixuser.Creator{
		Runner:   execrunner.Real{},
		DirMaker: posixuser.RealDirMaker{},
	}

	counters := &metrics.RequestCounters{}

	handler := &httpapi.Handler{
		Creator:       creator,
		Metrics:       counters,
		HostPublicKey: hostPublicKey,
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

	metricsClient, err := buildMetricsClient(tlsConfig)
	if err != nil {
		return fmt.Errorf("build metrics client: %w", err)
	}
	if metricsClient != nil {
		defer metricsClient.Disconnect(250)
		go metrics.Run(ctx, metricsPublishInterval, func(publishCtx context.Context) error {
			return metrics.PublishOnce(publishCtx, metricsClient, serviceName, counters.Snapshot())
		})
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("storage-service: listening", "addr", logging.Sanitize(listenAddr))
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

// readHostPublicKey reads and returns sshd's host public key from path, in
// its on-disk authorized_keys one-line format (ST-F-16), with any trailing
// newline trimmed. A non-nil error means the file is missing, unreadable,
// or empty - all treated identically by the caller (run), which aborts
// startup rather than let this server ever answer a create-user request
// without a key to return (CL-F-11 depends on the Client always receiving
// one).
func readHostPublicKey(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is always the hostPublicKeyPath constant, never external input
	if err != nil {
		return "", err
	}

	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("%s is empty", path)
	}

	return key, nil
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
	// A missing bootstrap token is not fatal on its own (CA-F-04's
	// persistence clause, KI-126): pki.NewServer falls back to an
	// already-persisted identity when one exists on disk, and the token is
	// only ever consulted on a genuine first run. Any other LoadBootstrapToken
	// error (e.g. a value set but unreadable) still fails fast here. tokenErr
	// is kept so the error below can name the missing variable specifically,
	// instead of surfacing only the lower-level bootstrap-token-parse failure.
	token, tokenErr := pki.LoadBootstrapToken()
	if tokenErr != nil && !errors.Is(tokenErr, pki.ErrBootstrapTokenMissing) {
		return nil, fmt.Errorf("load ca bootstrap token: %w", tokenErr)
	}

	base := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	bootstrapped, err := pki.NewServer(ctx, token, base)
	if err != nil {
		if errors.Is(tokenErr, pki.ErrBootstrapTokenMissing) {
			return nil, fmt.Errorf(
				"bootstrap server identity from certificate-authority: neither a persisted identity under %s nor a token in %s is available (the token is only needed on this service's very first start): %w",
				pki.IdentityDirEnvVar, pki.BootstrapTokenEnvVar, err)
		}
		return nil, fmt.Errorf("bootstrap server identity from certificate-authority: %w", err)
	}

	return bootstrapped.TLSConfig, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// ST-F-12/ST-F-13's periodic publish uses, reusing tlsConfig - this
// server's one bootstrapped TLS identity (see buildServerTLSConfig and
// this file's package doc comment) - as the source of this connection's
// client certificate, cloned via pki.ClientTLSConfig with ServerName
// forced to metrics.OrganizationMQTTBroker and layered with PKI-F-02's
// organization check via metrics.TLSConfig. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still serves POSIX-user-creation traffic without it.
func buildMetricsClient(tlsConfig *tls.Config) (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("storage-service: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	mqttTLSConfig := metrics.TLSConfig(pki.ClientTLSConfig(tlsConfig, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, mqttTLSConfig, metricsClientID, connectTimeout, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}
