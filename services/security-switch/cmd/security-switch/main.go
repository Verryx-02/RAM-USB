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
// Mesh membership (real, OS-level tailscaled - not pkg/mesh): this process
// no longer embeds pkg/mesh's in-process tsnet client. The container this
// binary runs in (deployments/docker/security-switch/) instead runs a real
// tailscaled daemon, supervised by s6-overlay alongside this Go binary
// (see that directory's Dockerfile and rootfs/etc/s6-overlay/s6-rc.d/ tree)
// - the same mechanism already proven for Storage-Service. Once the
// container's only network egress is a real tailscale0 kernel interface,
// every outbound connection this process makes - both outbound mTLS
// clients below (SS-F-04's call to Database-Vault, SS-F-05/SS-F-09's call
// to Network-Manager) AND every internal library call neither of them
// exposes a dial hook for (pkg/pki's Certificate-Authority bootstrap and
// renewal traffic, pkg/metrics' MQTT publish connection) - is forced
// through the mesh automatically by the OS, with zero application-level
// dial injection needed. This is why buildDatabaseVaultClient and
// buildNetworkManagerClient below take no dial parameter at all anymore:
// a plain *http.Transport with no DialContext override already routes
// correctly. This server's own inbound listener (httpServer below,
// receiving Entry-Hub's calls) binds to this node's real Tailscale IPv4
// address too - RAM_USB_SECURITY_SWITCH_LISTEN_ADDR is assembled at
// container start by the security-switch longrun's own run script (see
// rootfs/etc/s6-overlay/s6-rc.d/security-switch/run) from
// RAM_USB_SECURITY_SWITCH_TAILSCALE_IP (written by the tailscale-up
// oneshot once this node joins) and a plain port number, never from
// 0.0.0.0/ramusb-net, per NET-F-01; this main.go itself only ever reads
// the resulting host:port string, with no tsnet/mesh awareness of its own.
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

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/env"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
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
	// mTLS connections from Entry-Hub (SS-F-01). Assembled at container
	// start by the security-switch longrun's own run script from this
	// node's real Tailscale IPv4 address and a plain port number (see
	// this file's package doc comment, "Mesh membership") - this process
	// only ever reads the resulting host:port string.
	envListenAddr = "RAM_USB_SECURITY_SWITCH_LISTEN_ADDR"

	// envDatabaseVaultURL is Database-Vault's base URL (SS-F-04), e.g.
	// "https://database-vault:8445" - "database-vault" here is
	// Database-Vault's MagicDNS short name within the Headscale mesh
	// (RAM_USB_DATABASE_VAULT_MESH_HOSTNAME in
	// deployments/compose/database-vault.yml), resolved and dialed
	// entirely through the container's real Tailscale network interface
	// (see this file's package doc comment, "Mesh membership") - not
	// through any application-level dial injection.
	envDatabaseVaultURL = "RAM_USB_DATABASE_VAULT_URL"

	// envNetworkManagerURL is Network-Manager's base URL (SS-F-05,
	// SS-F-09), e.g. "https://network-manager:8447" - "network-manager"
	// here is Network-Manager's MagicDNS short name within the Headscale
	// mesh (RAM_USB_NETWORK_MANAGER_MESH_HOSTNAME in
	// deployments/compose/network-manager.yml) - same reasoning as
	// envDatabaseVaultURL above: resolved and dialed through the
	// container's real Tailscale network interface, not through any
	// application-level dial injection.
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

	listenAddr, err := env.Require(envListenAddr)
	if err != nil {
		return err
	}

	// serverTLSConfig is this server's one bootstrapped TLS identity
	// (PKI-F-01, CA-F-04), shared by the inbound EntryHub-facing listener
	// and both outbound clients below - see buildServerTLSConfig and this
	// file's package doc comment for why one bootstrap exchange, reused,
	// is correct here.
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	// No dial injection for either outbound client below (see this file's
	// package doc comment, "Mesh membership"): the container this process
	// runs in has a real, OS-level tailscaled interface as its only
	// network egress, so a plain *http.Transport with no DialContext
	// override already routes both calls through the mesh.
	dbVaultClient, dbVaultURL, err := buildDatabaseVaultClient(serverTLSConfig)
	if err != nil {
		return fmt.Errorf("build database-vault client: %w", err)
	}

	networkManagerClient, networkManagerURL, err := buildNetworkManagerClient(serverTLSConfig)
	if err != nil {
		return fmt.Errorf("build network-manager client: %w", err)
	}

	counters := &metrics.RequestCounters{}

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
// No DialContext override (completing DV-F-01's "access to the private
// mesh network" clause on the calling side): the container this process
// runs in has a real, OS-level tailscaled interface as its only network
// egress (see this file's package doc comment, "Mesh membership"), so a
// plain *http.Transport already routes every TCP dial through the mesh -
// this call physically cannot reach Database-Vault any other way.
func buildDatabaseVaultClient(serverTLSConfig *tls.Config) (*http.Client, string, error) {
	baseURL, err := env.Require(envDatabaseVaultURL)
	if err != nil {
		return nil, "", err
	}

	transport := &http.Transport{
		TLSClientConfig: pki.ClientTLSConfig(serverTLSConfig, dbvault.OrganizationDatabaseVault),
	}
	client := &http.Client{Transport: mtls.WrapRoundTripper(transport, dbvault.OrganizationDatabaseVault)}
	return client, baseURL, nil
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
// No DialContext override (completing NM-F-03's mesh-reachability
// restriction on the calling side), same reasoning as
// buildDatabaseVaultClient above.
func buildNetworkManagerClient(serverTLSConfig *tls.Config) (*http.Client, string, error) {
	baseURL, err := env.Require(envNetworkManagerURL)
	if err != nil {
		return nil, "", err
	}

	transport := &http.Transport{
		TLSClientConfig: pki.ClientTLSConfig(serverTLSConfig, networkmanager.OrganizationNetworkManager),
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

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}
