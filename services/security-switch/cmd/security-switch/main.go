// Command security-switch wires every already-implemented Security-Switch
// package into a running mTLS HTTP server: SS-F-01's connection-acceptance
// TLS config (accepting only organization="EntryHub"), outbound mTLS
// clients to Database-Vault (SS-F-04) and Network-Manager (SS-F-05,
// SS-F-09), the httpapi handlers (SS-F-02, SS-F-03, SS-F-06, and the
// request-relay control flow they call), and SS-F-07/SS-F-08's periodic
// metrics publish over MQTT.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." Env var names not already
// established by an earlier requirement follow the same RAM_USB_<SERVICE>_*
// convention Database-Vault's main.go introduced - this session's invented
// judgment call, documented on each constant below.
//
// TLS/mTLS setup (PKI-F-01/PKI-F-02, CA-F-04): this server's own identity -
// its inbound listener (SS-F-01, organization=EntryHub) and both outbound
// clients (SS-F-04 to Database-Vault, organization=DatabaseVault; SS-F-05/
// SS-F-09 to Network-Manager, organization=NetworkManager) - is obtained
// from the Certificate-Authority via pkg/pki's bootstrap-token flow
// (CA-F-04), not from pre-existing cert/key files on disk. This mirrors
// Database-Vault's own pkg/pki adoption exactly (see
// services/database-vault/cmd/database-vault/main.go's package doc
// comment for the full reasoning), including its two governing findings:
//
//  1. pkg/pki's *tls.Config is not composable with
//     pkg/mtls.ServerConfig/ClientConfig's handshake-level VerifyConnection
//     organization check (ca.BootstrapServer/BootstrapClient hard-error if
//     TLSConfig.VerifyConnection is already set, and expose no hook to
//     install one) - so PKI-F-02's organization check runs at the
//     HTTP-request level instead, via pkg/mtls.RequireOrganization
//     (wrapping the inbound listener's handler) and
//     pkg/mtls.WrapRoundTripper (wrapping each outbound client's
//     Transport).
//
//  2. One bootstrap token only, per SRS §2.6 ("a single-use bootstrap
//     token," singular, one per service): this server's single identity is
//     bootstrapped once (pki.BootstrapTokenEnvVar, via pki.NewServer, see
//     buildServerTLSConfig) and its resulting *tls.Config is reused for
//     three roles - the inbound EntryHub-facing listener and both outbound
//     clients (Database-Vault, Network-Manager) - because
//     github.com/smallstep/certificates/ca.Client.GetServerTLSConfig
//     (what pki.NewServer calls internally) unconditionally sets both
//     GetCertificate and GetClientCertificate on the same *tls.Config,
//     wired to the same certificate renewer, and unconditionally populates
//     RootCAs too (confirmed empirically against the real
//     Certificate-Authority container in the Database-Vault session that
//     established this pattern - see that package's doc comment and
//     main_integration_test.go for the source-level and empirical proof).
//     Do not call pki.NewClient for either outbound role: that would spend
//     a second single-use bootstrap token for no benefit, since
//     buildServerTLSConfig's *tls.Config is already valid to reuse as an
//     outbound Transport.TLSClientConfig directly.
//
// See also deployments/compose/certificate-authority.yml's certificate-authority-init
// service: the dev Certificate-Authority container needs a one-time,
// idempotent setup step (a custom x509 template on its bootstrap-token
// provisioner, third-party/certificate-authority/config/
// organization.x509.tpl) before any certificate it issues carries a
// non-empty Subject.Organization at all - without it, PKI-F-02's
// organization check would reject every connection. `docker compose up`
// applies it automatically now; no manual step is required.
//
// Mesh membership (completed via pkg/mesh): this process now also joins
// Headscale as a real tsnet mesh node (buildMeshNode), used for BOTH
// outbound mTLS clients this server owns - SS-F-04's call to Database-Vault
// (buildDatabaseVaultClient's Transport.DialContext), completing DV-F-01's
// "access to the private mesh network" clause on the calling side, and
// SS-F-05/SS-F-09's call to Network-Manager
// (buildNetworkManagerClient's Transport.DialContext, once Network-Manager
// itself joined the mesh, see
// services/network-manager/cmd/network-manager/main.go's package doc
// comment), completing NM-F-03's mesh-reachability restriction on the
// calling side - both share this one meshNode instance, not a second one
// per outbound peer. Both calls now pass exclusively through the mesh
// (pkg/mesh's own package doc comment, "Reachability guarantee").
// Deliberately NOT changed in this task: this server's own inbound
// listener (httpServer below, receiving Entry-Hub's calls) stays exactly
// as before - a ramusb-net TLS listener via ListenAndServeTLS - because
// Entry-Hub is not itself a mesh node yet (out of this task's scope: Entry-Hub
// has its own separate, larger dual public/mesh-path problem, not addressed
// here). Moving this listener to tsnet-only in isolation would sever
// Entry-Hub's ability to reach Security-Switch at all - so this file
// intentionally keeps two separate network identities: the pre-existing
// ramusb-net one (inbound, from Entry-Hub) and the mesh one (outbound only,
// to Database-Vault and Network-Manager).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/mesh"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/dbvault"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/networkmanager"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/server"
)

// Env var names for values this task introduces. pki.BootstrapTokenEnvVar
// (RAM_USB_CA_BOOTSTRAP_TOKEN) is already established by CA-F-04 and is
// not redefined here - it is this server's own single-use bootstrap
// token, used for the inbound listener and both outbound clients alike
// (see buildServerTLSConfig).
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Entry-Hub (SS-F-01).
	envListenAddr = "RAM_USB_SECURITY_SWITCH_LISTEN_ADDR"

	// envDatabaseVaultURL is Database-Vault's base URL (SS-F-04), e.g.
	// "https://database-vault:8445" - "database-vault" here is
	// Database-Vault's MagicDNS short name within the Headscale mesh
	// (RAM_USB_DATABASE_VAULT_MESH_HOSTNAME in
	// deployments/compose/database-vault.yml), not a ramusb-net Docker
	// DNS name: buildDatabaseVaultClient's Transport.DialContext routes
	// every dial through meshNode.Dial (pkg/mesh), which resolves and
	// connects entirely inside tsnet's own userspace netstack - never via
	// the container's real network interfaces/OS resolver, regardless of
	// what this hostname string happens to also resolve to on
	// ramusb-net.
	envDatabaseVaultURL = "RAM_USB_DATABASE_VAULT_URL"

	// envMeshDir is the persistent directory this node's tsnet mesh
	// identity/state lives in (see pkg/mesh.Config.Dir) - backed by a
	// dedicated Docker volume (deployments/compose/security-switch.yml).
	envMeshDir = "RAM_USB_SECURITY_SWITCH_MESH_DIR"

	// envMeshHostname is this node's MagicDNS short name within the
	// tailnet (see pkg/mesh.Config.Hostname). No other service dials
	// Security-Switch over the mesh in this task's cut (see this file's
	// package doc comment) - this node only ever dials out - but tsnet
	// still requires a Hostname to join at all.
	envMeshHostname = "RAM_USB_SECURITY_SWITCH_MESH_HOSTNAME"

	// envMeshControlURL is the self-hosted Headscale server's
	// coordination URL (see pkg/mesh.Config.ControlURL), the same env var
	// name Database-Vault's own main.go uses (shared, not
	// service-specific).
	envMeshControlURL = "RAM_USB_TAILSCALE_CONTROL_URL"

	// envMeshAuthKey is this node's single-use Headscale pre-auth key
	// (see pkg/mesh.Config.AuthKey and pkg/mesh's package doc comment,
	// "Key distribution"), minted manually by the operator - see
	// deployments/compose/security-switch.yml for the exact minting
	// command.
	envMeshAuthKey = "RAM_USB_SECURITY_SWITCH_TAILSCALE_AUTHKEY" //nolint:gosec // an env var *name*, not a credential value

	// envMeshControlCAFile optionally names a PEM file this process
	// should trust for envMeshControlURL's TLS certificate (see
	// pkg/mesh.Config.ControlCAFile) - shared across services exactly
	// like envMeshControlURL, since it exists solely to trust that same
	// URL's certificate. Left unset in any deployment where ControlURL's
	// certificate already chains to a real, publicly trusted root; only
	// this project's dev-only self-signed Headscale certificate
	// (third-party/network-manager/headscale/dev-tls) needs it, per this
	// project's convention of mounting dev-only secrets/certificates at
	// runtime rather than baking them into the image (see
	// deployments/compose/security-switch.yml).
	envMeshControlCAFile = "RAM_USB_TAILSCALE_CONTROL_CA_FILE"

	// envNetworkManagerURL is Network-Manager's base URL (SS-F-05,
	// SS-F-09), e.g. "https://network-manager:8447" - "network-manager"
	// here is Network-Manager's MagicDNS short name within the Headscale
	// mesh (RAM_USB_NETWORK_MANAGER_MESH_HOSTNAME in
	// deployments/compose/network-manager.yml), not a ramusb-net Docker DNS
	// name - same reasoning as envDatabaseVaultURL above:
	// buildNetworkManagerClient's Transport.DialContext routes every dial
	// through meshNode.Dial (pkg/mesh), never via ramusb-net.
	envNetworkManagerURL = "RAM_USB_NETWORK_MANAGER_URL"

	// envMQTTBrokerURL is the MQTT broker's address (SS-F-07), e.g.
	// "tls://mqtt-broker.internal:8883". Reuses the exact same env var
	// name Database-Vault's main.go already established
	// (RAM_USB_MQTT_BROKER_URL), not a security-switch-specific prefix:
	// each service is its own OS process (its own container/systemd unit
	// with its own environment), so there is no real collision risk from
	// two different processes both reading a same-named env var from
	// their own separate environments - and every metrics publisher in
	// this codebase connects to the one same MQTT broker with the one
	// same required certificate organization
	// (metrics.OrganizationMQTTBroker = "MQTTBroker"), so reusing the
	// identical name is also the more consistent choice, not just the
	// safe one. Unlike before, no separate RAM_USB_MQTT_CLIENT_CERT/
	// RAM_USB_MQTT_CLIENT_KEY/RAM_USB_MQTT_CA env vars exist anymore -
	// this server's MQTT identity and root trust are both derived from
	// serverTLSConfig, the same bootstrapped identity already reused for
	// the inbound listener and both outbound clients above (see this
	// file's package doc comment).
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"
)

// serviceName is Security-Switch's identifier in every metrics payload it
// publishes and the "<Service-Name>" half of its dedicated MQTT topic
// (SS-F-07), reproduced verbatim from the SRS's literal
// `metrics/Security-Switch` quote.
const serviceName = "Security-Switch"

// metricsClientID is the MQTT client identifier this server connects
// with (SS-F-07). No SRS/design doc specifies one; a fixed, readable
// value is this session's judgment call, distinct from Database-Vault's
// own "database-vault" client ID so the broker can tell the two
// processes' connections apart.
const metricsClientID = "security-switch"

// metricsPublishInterval is SS-F-07's "every minute, and only."
const metricsPublishInterval = time.Minute

// connectTimeout bounds how long this process waits for the MQTT
// broker's connection handshake at startup.
const connectTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("security-switch: fatal startup error", "error", logging.Sanitize(err.Error()))
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

	// meshNode is this process's own Headscale mesh identity (completed by
	// pkg/mesh - see this file's package doc comment, "Mesh membership"),
	// used to dial out to Database-Vault (completing DV-F-01's "access to
	// the private mesh network" clause on the calling side) and to
	// Network-Manager (completing NM-F-03's mesh-reachability restriction
	// on the calling side) below.
	meshNode, err := buildMeshNode(ctx)
	if err != nil {
		return fmt.Errorf("join mesh: %w", err)
	}
	defer func() {
		if closeErr := meshNode.Close(); closeErr != nil {
			slog.Warn("security-switch: mesh node close error", "error", logging.Sanitize(closeErr.Error()))
		}
	}()

	// serverTLSConfig is this server's one bootstrapped TLS identity
	// (PKI-F-01, CA-F-04), shared by the inbound EntryHub-facing listener
	// and both outbound clients below - see buildServerTLSConfig and this
	// file's package doc comment for why one bootstrap exchange, reused,
	// is correct here.
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	dbVaultClient, dbVaultURL, err := buildDatabaseVaultClient(serverTLSConfig, meshNode.Dial)
	if err != nil {
		return fmt.Errorf("build database-vault client: %w", err)
	}

	networkManagerClient, networkManagerURL, err := buildNetworkManagerClient(serverTLSConfig, meshNode.Dial)
	if err != nil {
		return fmt.Errorf("build network-manager client: %w", err)
	}

	counters := &httpapi.Counters{}

	handler := &httpapi.Handler{
		DBVault:        httpapi.DBVaultAdapter{Client: dbVaultClient, BaseURL: dbVaultURL},
		NetworkManager: httpapi.NetworkManagerAdapter{Client: networkManagerClient, BaseURL: networkManagerURL},
		Metrics:        counters,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(httpapi.RegisterPath, handler.Register)
	mux.HandleFunc(httpapi.LoginPath, handler.Login)

	httpServer := &http.Server{
		Addr: listenAddr,
		// PKI-F-02's organization check runs here, at the HTTP-request
		// level (mtls.RequireOrganization), not inside serverTLSConfig's
		// handshake - see this file's package doc comment for why.
		Handler:           mtls.RequireOrganization(server.AllowedClientOrganization, mux),
		TLSConfig:         serverTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	metricsClient, err := buildMetricsClient(serverTLSConfig)
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
		slog.Info("security-switch: listening", "addr", logging.Sanitize(listenAddr))
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
		return httpServer.Shutdown(shutdownCtx)
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
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
// single-use token exactly once. The returned *tls.Config is shared by the
// inbound EntryHub-facing listener and by both outbound clients built
// below (see run and this file's package doc comment for why reusing it
// for outbound calls is safe) - it carries no organization restriction of
// its own (that runs at the HTTP-request level, via
// mtls.RequireOrganization/mtls.WrapRoundTripper in run);
// ca.BootstrapServer's default (tls.RequireAndVerifyClientCert) still
// ensures only a certificate this CA itself issued can complete an
// inbound handshake at all.
//
// base is a throwaway *http.Server: pki.NewServer only ever reads/writes
// its TLSConfig field (confirmed by reading
// github.com/smallstep/certificates/ca/bootstrap.go's BootstrapServer, see
// Database-Vault's own buildServerTLSConfig doc comment for the full
// citation), so a minimal value discarded immediately after extracting
// TLSConfig is sufficient - the real *http.Server that actually serves
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

// buildDatabaseVaultClient assembles the *http.Client SS-F-04 uses to call
// Database-Vault over mTLS, reusing serverTLSConfig - this server's one
// bootstrapped TLS identity (see buildServerTLSConfig and this file's
// package doc comment for why one bootstrap token, reused, is correct
// here rather than a second independent bootstrap exchange) - as the
// outbound Transport.TLSClientConfig, then wraps the resulting
// *http.Client's Transport with mtls.WrapRoundTripper so PKI-F-02's
// organization check (organization=dbvault.OrganizationDatabaseVault)
// runs at the HTTP-response level.
//
// pki.ClientTLSConfig clones serverTLSConfig (never mutating the shared
// object itself - see this file's package doc comment on why
// serverTLSConfig is reused for three roles at once) and forces this
// handshake's ServerName to dbvault.OrganizationDatabaseVault instead of
// the dialed network address (envDatabaseVaultURL's host, which differs
// between dev/compose and production) - see pkg/pki's package doc comment
// for why this is required, not merely defensive.
//
// dial is set as Transport.DialContext (completing DV-F-01's "access to
// the private mesh network" clause on the calling side): run passes
// meshNode.Dial in production, so every TCP dial this client makes goes
// through pkg/mesh's tsnet node instead of the default net.Dialer - this
// call physically cannot reach Database-Vault any other way than through
// the mesh, see pkg/mesh's own package doc comment ("Reachability
// guarantee"). A func-typed parameter
// rather than a *mesh.Server one deliberately decouples this function
// from requiring a live Headscale join in tests that exist only to prove
// PKI-F-02's organization enforcement (main_integration_test.go, which
// passes a plain (&net.Dialer{}).DialContext instead) - pkg/mesh's own
// real-Headscale integration test is what proves the mesh-only
// reachability property itself.
func buildDatabaseVaultClient(serverTLSConfig *tls.Config, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*http.Client, string, error) {
	baseURL, err := requireEnv(envDatabaseVaultURL)
	if err != nil {
		return nil, "", err
	}

	transport := &http.Transport{
		TLSClientConfig: pki.ClientTLSConfig(serverTLSConfig, dbvault.OrganizationDatabaseVault),
		DialContext:     dial,
	}
	client := &http.Client{Transport: mtls.WrapRoundTripper(transport, dbvault.OrganizationDatabaseVault)}
	return client, baseURL, nil
}

// buildMeshNode joins this process to the private Headscale mesh (pkg/mesh)
// using envMeshDir/envMeshHostname/envMeshControlURL/envMeshAuthKey, failing
// closed (RD-04) if any is unset. The returned node's Dial is what completes
// DV-F-01's and NM-F-03's mesh-reachability clauses on the calling side for
// this server's two outbound clients (see buildDatabaseVaultClient and
// buildNetworkManagerClient). ctx bounds only the join itself; the returned
// node lives for this process's whole lifetime (closed via a deferred call
// in run).
func buildMeshNode(ctx context.Context) (*mesh.Server, error) {
	dir, err := requireEnv(envMeshDir)
	if err != nil {
		return nil, err
	}
	hostname, err := requireEnv(envMeshHostname)
	if err != nil {
		return nil, err
	}
	controlURL, err := requireEnv(envMeshControlURL)
	if err != nil {
		return nil, err
	}
	authKey, err := requireEnv(envMeshAuthKey)
	if err != nil {
		return nil, err
	}
	// Optional (empty in any deployment where ControlURL's certificate
	// already chains to a real, publicly trusted root) - see
	// envMeshControlCAFile's own doc comment.
	controlCAFile := os.Getenv(envMeshControlCAFile)

	return mesh.Up(ctx, mesh.Config{
		Dir:           dir,
		Hostname:      hostname,
		ControlURL:    controlURL,
		AuthKey:       authKey,
		ControlCAFile: controlCAFile,
	})
}

// buildNetworkManagerClient assembles the *http.Client SS-F-05/SS-F-09 use
// to call Network-Manager over mTLS, reusing serverTLSConfig exactly as
// buildDatabaseVaultClient does (same one bootstrapped identity, same
// reasoning), wrapped with mtls.WrapRoundTripper so PKI-F-02's
// organization check (organization=
// networkmanager.OrganizationNetworkManager) runs at the HTTP-response
// level.
//
// pki.ClientTLSConfig clones serverTLSConfig and forces this handshake's
// ServerName to networkmanager.OrganizationNetworkManager, same reasoning
// as buildDatabaseVaultClient above.
//
// dial is set as Transport.DialContext (completing NM-F-03's
// mesh-reachability restriction on the calling side, once Network-Manager
// itself became a mesh node - see this file's package doc comment, "Mesh
// membership"): run passes meshNode.Dial in production, the SAME mesh node
// instance already joined for buildDatabaseVaultClient above, not a second
// one - see pkg/mesh's own package doc comment ("Reachability guarantee").
// A func-typed parameter rather than a *mesh.Server one, same reasoning as
// buildDatabaseVaultClient's own dial parameter.
func buildNetworkManagerClient(serverTLSConfig *tls.Config, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*http.Client, string, error) {
	baseURL, err := requireEnv(envNetworkManagerURL)
	if err != nil {
		return nil, "", err
	}

	transport := &http.Transport{
		TLSClientConfig: pki.ClientTLSConfig(serverTLSConfig, networkmanager.OrganizationNetworkManager),
		DialContext:     dial,
	}
	client := &http.Client{Transport: mtls.WrapRoundTripper(transport, networkmanager.OrganizationNetworkManager)}
	return client, baseURL, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// SS-F-07/SS-F-08's periodic publish uses, reusing serverTLSConfig - this
// server's one bootstrapped TLS identity (see buildServerTLSConfig and
// this file's package doc comment) - as the source of this connection's
// client certificate, cloned via pki.ClientTLSConfig with ServerName
// forced to metrics.OrganizationMQTTBroker and layered with PKI-F-02's
// organization check via metrics.TLSConfig. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still relays registration/login traffic without it, since
// SS-F-07/SS-F-08 are about what gets published when metrics are
// published, not a hard dependency of the request-relay control flow
// itself.
func buildMetricsClient(serverTLSConfig *tls.Config) (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("security-switch: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(serverTLSConfig, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout)
	if err != nil {
		return nil, err
	}

	return client, nil
}
