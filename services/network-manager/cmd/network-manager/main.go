// Command network-manager wires Network-Manager's already-implemented
// packages into a running mTLS HTTP server (NM-F-03's connection-
// acceptance TLS config, NM-F-08's mesh-user creation, NM-F-09's
// storage-access grant), plus the outbound gRPC connection to Headscale
// those handlers call through internal/headscale, the SQLite-backed grant
// store (NM-F-11) - which also backs the permanent email -> Headscale
// pre-auth-key-ID mapping a later bug fix session added (see
// internal/grants' own doc comment and internal/headscale/client.go's
// "Bug fix" section) - its periodic expiry sweep (NM-F-10), and the
// periodic MQTT metrics publish (NM-F-17, NM-F-18).
//
// NM-F-12 ("expose an administration interface for creating pre-auth keys
// and managing ACL tags, reachable only from the private network") needs
// no RAM-USB code: Headscale's own CLI, already running inside the
// network-manager-headscale container, provides this exact capability
// (`docker exec <container> headscale preauthkeys create --user <ID>`,
// `docker exec <container> headscale nodes tag -i <NODE_ID> -t <TAG>`)
// over a local Unix socket with no network listener at all - satisfying
// "reachable only from the private network" more strictly than a second
// mTLS listener would, with zero new attack surface. A prior session built
// a separate admin mTLS listener for this; it was removed after
// confirming with the user that Headscale's CLI already covers it.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." Env var names not already
// established by an earlier requirement (RAM_USB_CA_BOOTSTRAP_TOKEN,
// CA-F-04) are this session's invented judgment call, documented on each
// constant below - revisit if a future deployment/ops document fixes
// different names.
//
// TLS/mTLS setup (PKI-F-01/PKI-F-02, CA-F-04): this server's one identity
// is obtained from the Certificate-Authority via pkg/pki's bootstrap-token
// flow, not from pre-existing cert/key files on disk. pkg/pki's
// *tls.Config is not composable with pkg/mtls.ServerConfig/ClientConfig's
// handshake-level VerifyConnection organization check (see pkg/pki's
// package doc comment: ca.BootstrapServer hard-errors if
// TLSConfig.VerifyConnection is already set, and exposes no hook to
// install one) - so PKI-F-02's organization check runs at the HTTP-request
// level instead, via pkg/mtls.RequireOrganization wrapping the listener's
// mux with server.AllowedClientOrganization. This is the same pattern
// Database-Vault's cmd/database-vault/main.go established first
// (PKI-F-01, PKI-F-02, CA-F-04 session).
//
// Headscale (internal/headscale.Dial) remains Network-Manager's one
// outbound dependency that is NOT a RAM-USB mTLS peer under
// PKI-F-01/PKI-F-02's rules (a gRPC bearer-API-key credential instead -
// see internal/headscale/client.go's package doc comment). NM-F-10's
// sweep calls back into internal/headscale through that same connection.
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
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/grants"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/metrics"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/server"
)

// Env var names for values this task introduces. pki.BootstrapTokenEnvVar
// (RAM_USB_CA_BOOTSTRAP_TOKEN) is already established by CA-F-04 and is not
// redefined here - it is this server's single-use bootstrap token.
const (
	// envListenAddr is the address the listener accepts incoming
	// mTLS connections from Security-Switch on (NM-F-03).
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

	// envGrantsDBPath is the filesystem path to NM-F-11's SQLite grant
	// store (internal/grants.Open). Required, not optional: NM-F-11 is a
	// hard requirement, so this process refuses to start without an
	// explicit, operator-chosen path (RD-04, fail-secure) rather than
	// silently defaulting to some in-container path that may not survive
	// a restart. See internal/grants' own package doc comment for why
	// this path's durability (surviving a *container* restart, not just
	// a process restart) is the caller's/deployment's responsibility,
	// not this package's.
	envGrantsDBPath = "RAM_USB_NETWORK_MANAGER_GRANTS_DB_PATH"

	// envMQTTBrokerURL/envMQTTClientCert/envMQTTClientKey/envMQTTCA are
	// NM-F-17's metrics-publish MQTT connection - same four env vars,
	// same optional-if-envMQTTBrokerURL-unset convention, as Database-
	// Vault's own cmd/database-vault/main.go (DV-F-16/17 session).
	envMQTTBrokerURL  = "RAM_USB_MQTT_BROKER_URL"
	envMQTTClientCert = "RAM_USB_MQTT_CLIENT_CERT"
	envMQTTClientKey  = "RAM_USB_MQTT_CLIENT_KEY"
	envMQTTCA         = "RAM_USB_MQTT_CA"
)

// metricsClientID is the MQTT client identifier this process connects
// with (NM-F-17).
const metricsClientID = "network-manager"

// metricsPublishInterval is NM-F-17's "every minute, and only."
const metricsPublishInterval = time.Minute

// connectTimeout bounds how long this process waits for the MQTT broker
// connection (metrics) to complete.
const connectTimeout = 10 * time.Second

// sweepInterval is NM-F-10's "periodically check recorded expiries."
// NM-F-10 gives no concrete number - this session's judgment call: short
// enough that an expired grant's real-world exposure window past its
// 12-hour NM-F-09 expiry stays small, long enough not to hammer Headscale
// with an ExpiredGrants query far more often than any grant could
// plausibly expire. Revisit if a human/ops decision fixes a different
// value.
const sweepInterval = 5 * time.Minute

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
	grantsDBPath, err := requireEnv(envGrantsDBPath)
	if err != nil {
		return err
	}

	// serverTLSConfig is this process's one bootstrapped TLS identity
	// (PKI-F-01, CA-F-04) - see this file's package doc comment for why
	// no outbound RAM-USB mTLS client role exists here.
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	conn, err := buildHeadscaleConn()
	if err != nil {
		return fmt.Errorf("dial headscale: %w", err)
	}
	defer func() { _ = conn.Close() }()

	headscaleService := v1.NewHeadscaleServiceClient(conn)

	// pushStartupPolicy applies NM-F-01/02/03/04/05/06/07's static ACL
	// policy to Headscale exactly once, before this process serves any
	// mesh-provisioning traffic. Fatal on failure, same as every other
	// startup dependency above (buildServerTLSConfig, buildHeadscaleConn):
	// Headscale's ACL model is default-allow (open, unrestricted mesh
	// reachability) until a policy is actively pushed, and only becomes
	// default-deny once one exists - so a process that started serving
	// without a successfully-applied policy would leave the mesh network
	// with NONE of NM-F-01 through NM-F-07's reachability restrictions
	// enforced, which is a worse outcome than refusing to start at all
	// (RD-04, fail-secure). This is corroborated by this session's own
	// live reproduction: with no active policy, Headscale's CreatePreAuthKey
	// still silently succeeds in tagging a new node (NM-F-08 keeps
	// "working" in a broken, unenforced state), while the separate
	// SetTags admin call NM-F-09 depends on is rejected outright - neither
	// behavior is safe to serve traffic under, so this failure aborts run()
	// exactly like the other three startup dependencies above it.
	if err := pushStartupPolicy(ctx, headscaleService); err != nil {
		return fmt.Errorf("push headscale acl policy (NM-F-01/02/03/04/05/06/07): %w", err)
	}

	// grantStore backs both NM-F-11's grants table and the mesh_users
	// table this session's bug fix adds (permanent email -> Headscale
	// pre-auth-key-ID mapping, internal/grants/meshusers.go) - one SQLite
	// file, one Store, two conceptually distinct tables with different
	// row lifecycles. See that package's own doc comment for why.
	grantStore, err := grants.Open(ctx, grantsDBPath)
	if err != nil {
		return fmt.Errorf("open grants store (NM-F-11): %w", err)
	}
	defer func() { _ = grantStore.Close() }()

	counters := &httpapi.Counters{}

	handler := &httpapi.Handler{
		Mesh:      httpapi.HeadscaleAdapter{Service: headscaleService},
		Grants:    grantStore,
		MeshUsers: grantStore,
		Metrics:   counters,
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

	// NM-F-10's sweep: periodically revoke every expired grant
	// (grantStore.ExpiredGrants) via Headscale (headscaleRevoker) and
	// delete its persisted row.
	sweepCtx, stopSweep := context.WithCancel(ctx)
	defer stopSweep()
	go grants.Run(sweepCtx, sweepInterval, grantStore, headscaleRevoker{svc: headscaleService})

	metricsClient, err := buildMetricsClient()
	if err != nil {
		return fmt.Errorf("build metrics client: %w", err)
	}
	if metricsClient != nil {
		defer metricsClient.Disconnect(250)
		go metrics.Run(ctx, metricsPublishInterval, func(publishCtx context.Context) error {
			return metrics.PublishOnce(publishCtx, metricsClient, counters.Snapshot())
		})
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

// headscaleRevoker adapts internal/headscale's free functions into
// grants.Revoker, letting NM-F-10's sweep call back into Headscale
// without internal/grants needing to depend on internal/headscale's
// types directly - see grants.Revoker's own doc comment for why this
// adapter lives in main.go (dependency construction/wiring), not in
// internal/grants itself.
type headscaleRevoker struct {
	svc headscale.Service
}

func (r headscaleRevoker) Revoke(ctx context.Context, nodeID uint64, tag string) error {
	return headscale.RemoveNodeTag(ctx, r.svc, nodeID, tag)
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

// buildServerTLSConfig bootstraps this process's one TLS identity from the
// Certificate-Authority (CA-F-04, PKI-F-01), using pki.LoadBootstrapToken's
// single-use token exactly once. The returned *tls.Config carries no
// organization restriction of its own (that runs at the HTTP-request
// level, via mtls.RequireOrganization in run); ca.BootstrapServer's default
// (tls.RequireAndVerifyClientCert) still ensures only a certificate this CA
// itself issued can complete an inbound handshake at all.
//
// base is a throwaway *http.Server: pki.NewServer only ever reads/writes
// its TLSConfig field (confirmed by reading
// github.com/smallstep/certificates/ca/bootstrap.go's BootstrapServer),
// so a minimal value discarded immediately after extracting TLSConfig is
// sufficient - the real *http.Server value run actually serves
// (httpServer) is constructed separately in run.
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
// NM-F-09's handlers and NM-F-10's sweep call through - not a
// PKI-F-01/PKI-F-02 mTLS role, see this file's package doc comment.
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

// pushStartupPolicy is a thin, separately-testable wrapper over
// headscale.PushPolicy - same "small named function wrapping one startup
// dependency" shape as buildServerTLSConfig/buildHeadscaleConn/
// buildMetricsClient above, so a unit test can exercise it against a
// hand-written fake without needing run()'s full real-listener/real-CA
// setup. svc is typed as headscale.PolicyPusher (not the concrete
// *v1.HeadscaleServiceClient run() passes in) precisely so a test can
// substitute a fake here.
func pushStartupPolicy(ctx context.Context, svc headscale.PolicyPusher) error {
	return headscale.PushPolicy(ctx, svc)
}

// loadCertPool reads a PEM certificate bundle from path and returns a
// pool containing it. Same shape as Database-Vault's identically-named
// helper.
func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from this process's own operator-controlled env var config, not from any request input
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found in CA bundle %s", path)
	}
	return pool, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// NM-F-17/NM-F-18's periodic publish uses. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still serves mesh-provisioning traffic without it.
// Same shape as Database-Vault's identically-named helper.
func buildMetricsClient() (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("network-manager: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	certPath, err := requireEnv(envMQTTClientCert)
	if err != nil {
		return nil, err
	}
	keyPath, err := requireEnv(envMQTTClientKey)
	if err != nil {
		return nil, err
	}
	caPath, err := requireEnv(envMQTTCA)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load mqtt client certificate/key: %w", err)
	}

	rootCAs, err := loadCertPool(caPath)
	if err != nil {
		return nil, err
	}

	client, err := metrics.NewClient(brokerURL, cert, rootCAs, metricsClientID, connectTimeout)
	if err != nil {
		return nil, err
	}

	return client, nil
}
