// Command network-manager wires Network-Manager's already-implemented
// packages into a running mTLS HTTP server (NM-F-03's connection-
// acceptance TLS config, NM-F-08's mesh-user creation, NM-F-09's
// storage-access grant), plus the outbound REST connection to Headscale
// those handlers call through internal/headscale, the SQLite-backed grant
// store (NM-F-11) - which also backs the permanent email -> Headscale
// pre-auth-key-ID mapping a later bug fix session added (see
// internal/grants' own doc comment and internal/headscale/client.go's
// "Bug fix" section) - its periodic expiry sweep (NM-F-10), and the
// periodic MQTT metrics publish (NM-F-17, NM-F-18).
//
// # Headscale is a separate deployment, reached over the public network
// (NM-F-12, NM-F-14 - this session's architectural change)
//
// An earlier version of this file dialed a Headscale instance CO-LOCATED
// inside this same container, over gRPC, loopback-only. That design was
// withdrawn after finding Headscale's own documented limitation
// (headscale.net's FAQ): "running headscale on a machine that is also in
// the tailnet it coordinates... is not supported" - Headscale's own
// coordination server can never safely be a member of the mesh it
// coordinates, which co-location assumed it effectively would be (both
// processes sharing one container/network identity). Headscale is now a
// fully separate deployment (deployments/compose/headscale.yml,
// deployments/docker/headscale/ - a reverse proxy plus Headscale itself,
// no Network-Manager code), reachable ONLY over the public network - the
// same network EH-F-01/EH-F-02 and NM-F-14 already use, since Headscale's
// own coordination endpoint must be reachable before a client has even
// joined the mesh. NM-F-12 was reworded to match: pre-auth-key/ACL-tag
// administration is restricted by mutual TLS (organization=NetworkManager,
// PKI-F-02, RNF-SEC-04) rather than by network placement, since no
// network-placement-based restriction can apply to a component that
// cannot itself join the network it would otherwise be restricted to.
//
// buildHeadscaleAPIClient assembles the *http.Client
// internal/headscale.NewClient uses for every admin call (NM-F-08/NM-F-09/
// NM-F-10's mesh-user creation, tag grants/revokes, and NM-F-01..07's ACL
// policy push): it presents this process's own already-bootstrapped mTLS
// client certificate (reusing serverTLSConfig - the SAME CA-F-04 identity
// this process's own inbound listener uses, exactly the same "one
// bootstrapped identity, multiple outbound/inbound roles" pattern
// Database-Vault's buildStorageServiceClient and Entry-Hub's
// buildMetricsClient already establish) to the reverse proxy fronting
// Headscale, which requires and verifies it (organization=NetworkManager)
// ONLY on the `/api/v1/*` path this client calls - see that reverse
// proxy's own Dockerfile doc comment for the full per-path mTLS design.
// This is NOT the RAM-USB-internal-CA-to-RAM-USB-internal-CA trust model
// pkg/pki's ClientTLSConfig/ForceServerName assume (both peers issued by
// the same internal CA, SAN=organization) - the reverse proxy's OWN
// server-facing TLS certificate is an ordinary public-style certificate
// (self-signed dev-only in this Compose stack, Let's Encrypt in
// production - the exact same scheme Entry-Hub's own public listener
// uses), deliberately NOT issued by RAM-USB's internal Certificate-
// Authority: real end-user Tailscale clients (CL-F-04) must be able to
// trust this same certificate too, and have no reason to ever trust
// RAM-USB's private internal CA. So this client's own RootCAs trust
// decision is independent of pki.ClientTLSConfig's organization-SAN
// matching entirely - see buildHeadscaleAPIClient's own doc comment for
// exactly how that trust is established (envHeadscaleAPICAFile, optional,
// same "trust one specific dev-only PEM file" mechanism pkg/mesh.Config.
// ControlCAFile already established, empty in any deployment where the
// reverse proxy's certificate already chains to a real, publicly trusted
// root).
//
// This is the ONE call in the entire system that crosses the public
// network instead of the private mesh - flagged here explicitly, and
// again on buildHeadscaleAPIClient/buildHeadscaleService's own doc
// comments, as a deliberate, accepted architectural exception forced by
// Headscale's own limitation, not an oversight or a shortcut.
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
// See also deployments/compose/certificate-authority.yml's certificate-authority-init
// service: the dev Certificate-Authority container needs a one-time,
// idempotent setup step before any certificate it issues carries a
// non-empty Subject.Organization at all - without it, PKI-F-02's
// organization check would reject every connection. `docker compose up`
// applies it automatically; no manual step is required.
//
// Mesh membership (NM-F-03's "only Security-Switch and Certificate-Authority
// can contact Network-Manager" clause): this container joins the Headscale
// mesh via a REAL, kernel-level OS tailscaled daemon (s6-supervised, see
// deployments/docker/network-manager/rootfs/etc/s6-overlay/s6-rc.d/
// tailscaled/ and tailscale-up/), not pkg/mesh's in-process tsnet - this
// process also needs Certificate-Authority-bootstrap traffic (pkg/pki) and
// MQTT metrics-publish traffic (pkg/metrics) to go through the mesh, and
// neither of those libraries exposes a way to route through an
// in-process-only netstack for their internal/background traffic
// (confirmed by direct source reading, a hard library limitation - see
// .claude/agent-memory/code-agent.md's "pkg/pki dialer routing" entry).
// Once the container's only network egress is a real tailscale0
// interface, every outbound connection this process makes THROUGH THE
// MESH is forced through it automatically, with zero application-level
// dial injection needed - the same mechanism Storage-Service already uses
// (see its own Dockerfile package doc comment) for the identical reason
// (sshd needs a kernel TUN device; here it is pkg/pki and pkg/metrics that
// need OS-level routing instead). The one exception is
// buildHeadscaleAPIClient's own outbound call above, which deliberately
// goes over the public network, not the mesh - Headscale is not itself a
// mesh member (see this file's own top-level doc comment). envListenAddr
// is therefore a real host:port (assembled by the tailscale-up s6 oneshot
// from this node's Tailscale-assigned IPv4 address, exactly like
// Storage-Service's own storage-service/run script - see that file for
// the identical pattern), and httpServer below binds it directly via
// net/http.Server.Addr + ListenAndServeTLS, never a tsnet-specific Listen
// call.
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
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/env"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/grants"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/server"
)

// Env var names for values this task introduces. pki.BootstrapTokenEnvVar
// (RAM_USB_CA_BOOTSTRAP_TOKEN) is already established by CA-F-04 and is not
// redefined here - it is this server's single-use bootstrap token.
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Security-Switch (NM-F-03) - a real host:port,
	// assembled by the tailscale-up s6 oneshot from this node's real
	// Tailscale-assigned IPv4 address before this binary is ever exec'd
	// (see deployments/docker/network-manager/rootfs/etc/s6-overlay/
	// s6-rc.d/network-manager/run), exactly like Storage-Service's own
	// envListenAddr.
	envListenAddr = "RAM_USB_NETWORK_MANAGER_LISTEN_ADDR"

	// envHeadscaleAPIURL is the PUBLIC base URL of the reverse proxy
	// fronting the separately-deployed Headscale instance (e.g.
	// "https://headscale.ram-usb.example:8080" in production, ideally on
	// its own dedicated VPS per NM-F-14; "https://headscale:8080" in this
	// project's dev/test Compose stack) - see this file's own package doc
	// comment for the full "why public, not mesh" reasoning.
	envHeadscaleAPIURL = "RAM_USB_NETWORK_MANAGER_HEADSCALE_API_URL"

	// envHeadscaleAPIKey is Headscale's own bearer API key
	// (internal/headscale.NewClient's apiKey parameter), minted
	// out-of-band by the operator on the Headscale container/VPS itself
	// ("headscale apikeys create" - see deployments/scripts/headscale.sh)
	// and distributed to Network-Manager out-of-band as this env var, the
	// same out-of-band-distribution pattern SRS §2.6 already establishes
	// for RAM_USB_MASTER_KEY/RAM_USB_PASSWORD_PEPPER/CA-F-04's bootstrap
	// token. Distinct from, and layered independently on top of, this
	// process's own mTLS client certificate (NM-F-12) - Headscale's own
	// httpAuthenticationMiddleware requires this bearer token regardless
	// of the reverse proxy's separate mTLS check (see internal/headscale/
	// client.go's package doc comment).
	envHeadscaleAPIKey = "RAM_USB_NETWORK_MANAGER_HEADSCALE_API_KEY" //nolint:gosec // an env var *name*, not a credential value

	// envHeadscaleAPICAFile optionally names a PEM file trusting the
	// reverse proxy's OWN public-facing TLS server certificate (NOT
	// RAM-USB's internal Certificate-Authority - see this file's own
	// package doc comment for why those are deliberately different trust
	// roots). Left unset in any deployment where that certificate already
	// chains to a real, publicly trusted root (a real Let's Encrypt
	// certificate in production); only this project's dev-only
	// self-signed reverse-proxy certificate
	// (third-party/headscale/dev-tls) needs it set - same "trust one
	// specific dev-only PEM file" mechanism pkg/mesh.Config.ControlCAFile
	// already established for the exact same class of problem.
	envHeadscaleAPICAFile = "RAM_USB_NETWORK_MANAGER_HEADSCALE_API_CA_FILE" //nolint:gosec // a file path, not a credential value

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

	// envMQTTBrokerURL is NM-F-17's metrics-publish MQTT connection - same
	// optional-if-unset convention as Database-Vault's own
	// cmd/database-vault/main.go (DV-F-16/17 session). No separate
	// RAM_USB_MQTT_CLIENT_CERT/RAM_USB_MQTT_CLIENT_KEY/RAM_USB_MQTT_CA env
	// vars exist anymore - this process's MQTT identity and root trust
	// are both derived from serverTLSConfig, the same bootstrapped
	// identity already used for the inbound listener (see this file's
	// package doc comment).
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"
)

// serviceName is Network-Manager's identifier in every metrics payload it
// publishes and the "<Service-Name>" half of its dedicated MQTT topic
// (NM-F-17), reproduced verbatim from the SRS's literal
// `metrics/Network-Manager` quote.
const serviceName = "Network-Manager"

// metricsClientID is the MQTT client identifier this process connects
// with (NM-F-17).
const metricsClientID = "network-manager"

// metricsPublishInterval is NM-F-17's "every minute, and only."
const metricsPublishInterval = time.Minute

// connectTimeout bounds how long this process waits for the MQTT broker
// connection (metrics) to complete.
const connectTimeout = 10 * time.Second

// headscaleAPITimeout bounds every individual outbound call to Headscale's
// admin API (buildHeadscaleAPIClient) - this crosses the public network
// (see this file's package doc comment), so it gets its own explicit,
// generous-but-finite budget rather than an unbounded call.
const headscaleAPITimeout = 15 * time.Second

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
		slog.Error("network-manager: fatal startup error", "error", logging.Sanitize(err.Error()))
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
	grantsDBPath, err := env.Require(envGrantsDBPath)
	if err != nil {
		return err
	}

	// serverTLSConfig is this process's one bootstrapped TLS identity
	// (PKI-F-01, CA-F-04) - reused both for the inbound NM-F-03 listener
	// AND as the outbound mTLS client certificate presented to Headscale's
	// reverse proxy (NM-F-12) - see this file's own package doc comment.
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	headscaleClient, err := buildHeadscaleService(serverTLSConfig)
	if err != nil {
		return fmt.Errorf("build headscale api client: %w", err)
	}

	// pushStartupPolicy applies NM-F-01/02/03/04/05/06/07's static ACL
	// policy to Headscale exactly once, before this process serves any
	// mesh-provisioning traffic. Fatal on failure, same as every other
	// startup dependency above (buildServerTLSConfig, buildHeadscaleService):
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
	// exactly like the other startup dependencies above it.
	if err := pushStartupPolicy(ctx, headscaleClient); err != nil {
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

	counters := &metrics.RequestCounters{}

	handler := &httpapi.Handler{
		Mesh:      httpapi.HeadscaleAdapter{Service: headscaleClient},
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

	// background owns every long-lived goroutine this function starts, so
	// each one is known to have returned before the resources it uses are
	// released. Canceling backgroundCtx only *asks* them to stop: without
	// the Wait, an in-flight grants.SweepOnce would still be querying the
	// SQLite handle while the deferred grantStore.Close ran, and an
	// in-flight metrics publish would still hold the MQTT client while
	// Disconnect ran.
	backgroundCtx, stopBackground := context.WithCancel(ctx)
	var background sync.WaitGroup

	// NM-F-10's sweep: periodically revoke every expired grant
	// (grantStore.ExpiredGrants) via Headscale (headscaleRevoker) and
	// delete its persisted row.
	background.Go(func() {
		grants.Run(backgroundCtx, sweepInterval, grantStore, headscaleRevoker{svc: headscaleClient})
	})

	metricsClient, err := buildMetricsClient(serverTLSConfig)
	if err != nil {
		stopBackground()
		background.Wait()
		return fmt.Errorf("build metrics client: %w", err)
	}
	if metricsClient != nil {
		defer metricsClient.Disconnect(250)
		background.Go(func() {
			metrics.Run(backgroundCtx, metricsPublishInterval, func(publishCtx context.Context) error {
				return metrics.PublishOnce(publishCtx, metricsClient, serviceName, counters.Snapshot())
			})
		})
	}

	// Registered last of the three (grantStore.Close, metricsClient.
	// Disconnect, this): defers run LIFO, so the goroutines are stopped
	// and joined first, then the MQTT client disconnects, then the store
	// closes.
	defer func() {
		stopBackground()
		background.Wait()
	}()

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("network-manager: listening", "addr", logging.Sanitize(listenAddr))
		// TLSConfig already carries the bootstrapped certificate (via
		// buildServerTLSConfig's GetCertificate callback, not a static
		// Certificates slice), so ListenAndServeTLS is called with empty
		// file paths per net/http's documented convention for that case -
		// same pattern as Storage-Service's own cmd/storage-service/main.go.
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

// buildHeadscaleAPIClient assembles the *http.Client
// internal/headscale.NewClient sends every admin-API request through - see
// this file's own package doc comment for the full design (why this is
// the one deliberately-public-network call in the system, and why its
// trust model is NOT pki.ClientTLSConfig's internal-CA-to-internal-CA
// pattern). serverTLSConfig.GetClientCertificate presents this process's
// own already-bootstrapped mTLS identity (organization=NetworkManager) as
// the OUTBOUND client certificate the reverse proxy's `/api/v1/*` location
// requires and verifies - reusing it here is safe for the exact reason
// Database-Vault's buildStorageServiceClient/Entry-Hub's
// buildMetricsClient already established: github.com/smallstep/
// certificates/ca.Client.GetServerTLSConfig (what pki.NewServer calls
// internally) unconditionally sets BOTH GetCertificate and
// GetClientCertificate on the same *tls.Config, wired to the same
// certificate renewer, so the resulting value already presents this
// server's own certificate whether it is dialed as a TLS server or dials
// out as a TLS client.
//
// RootCAs is deliberately NOT serverTLSConfig's own RootCAs (RAM-USB's
// internal Certificate-Authority root) - the reverse proxy's OWN
// server-facing certificate is never issued by that CA (see this file's
// package doc comment for why). A nil RootCAs (envHeadscaleAPICAFile
// unset) falls back to crypto/tls's own default, the host's real system
// trust store - correct for a production deployment where that
// certificate is a real, publicly trusted one (Let's Encrypt).
func buildHeadscaleAPIClient(serverTLSConfig *tls.Config) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: serverTLSConfig.GetClientCertificate,
	}

	caFile := os.Getenv(envHeadscaleAPICAFile)
	if caFile != "" {
		pool, err := mtls.TrustPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envHeadscaleAPICAFile, err)
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   headscaleAPITimeout,
	}, nil
}

// buildHeadscaleService assembles internal/headscale.NewClient - the REST
// connection to Headscale's admin API NM-F-08/NM-F-09/NM-F-10's handlers
// and NM-F-01..07's ACL policy push all call through - from
// buildHeadscaleAPIClient's *http.Client plus envHeadscaleAPIURL/
// envHeadscaleAPIKey.
func buildHeadscaleService(serverTLSConfig *tls.Config) (*headscale.Client, error) {
	apiURL, err := env.Require(envHeadscaleAPIURL)
	if err != nil {
		return nil, err
	}
	apiKey, err := env.Require(envHeadscaleAPIKey)
	if err != nil {
		return nil, err
	}

	httpClient, err := buildHeadscaleAPIClient(serverTLSConfig)
	if err != nil {
		return nil, err
	}

	return headscale.NewClient(apiURL, httpClient, apiKey), nil
}

// pushStartupPolicy is a thin, separately-testable wrapper over
// headscale.PushPolicy - same "small named function wrapping one startup
// dependency" shape as buildServerTLSConfig/buildHeadscaleAPIClient/
// buildMetricsClient above, so a unit test can exercise it against a
// hand-written fake without needing run()'s full real-listener/real-CA
// setup. svc is typed as headscale.PolicyPusher (not the concrete
// *headscale.Client run() passes in) precisely so a test can substitute a
// fake here.
func pushStartupPolicy(ctx context.Context, svc headscale.PolicyPusher) error {
	return headscale.PushPolicy(ctx, svc)
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// NM-F-17/NM-F-18's periodic publish uses, reusing serverTLSConfig - this
// process's one bootstrapped TLS identity (see buildServerTLSConfig and
// this file's package doc comment) - as the source of this connection's
// client certificate, cloned via pki.ClientTLSConfig with ServerName
// forced to metrics.OrganizationMQTTBroker and layered with PKI-F-02's
// organization check via metrics.TLSConfig. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still serves mesh-provisioning traffic without it.
func buildMetricsClient(serverTLSConfig *tls.Config) (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("network-manager: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(serverTLSConfig, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}
