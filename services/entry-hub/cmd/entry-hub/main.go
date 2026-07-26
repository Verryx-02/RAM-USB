// Command entry-hub wires every already-implemented Entry-Hub package into
// a running HTTPS server: EH-F-01/EH-F-02's public (non-mTLS) connection-
// acceptance TLS config, EH-F-03's mesh-only login listener, an outbound
// mTLS client to Security-Switch (EH-F-07), the httpapi handlers
// (EH-F-04/EH-F-05/EH-F-06/EH-F-08/EH-F-09 and the health check EH-F-01),
// and EH-F-10/EH-F-11's periodic metrics publish over MQTT.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." This mirrors
// services/security-switch/cmd/security-switch/main.go's structure
// exactly, adapted to Entry-Hub's own inbound listeners (see "Listener
// topology" below) and its single outbound direction (Security-Switch, in
// place of Security-Switch's own two: Database-Vault and Network-Manager).
//
// # Listener topology (NET-F-01, EH-F-01/EH-F-02/EH-F-03)
//
// This process binds two listeners. EH-F-01 (health) and EH-F-02
// (register) are served on envListenAddr, a real host-level public socket
// (NET-F-01: one of this system's deliberately public-facing surfaces,
// alongside Network-Manager's own Headscale coordination endpoint,
// NM-F-14) - reachable by anyone, since unauthenticated registration must
// be reachable before a client has ever joined the mesh. EH-F-03 (login)
// is served on a SEPARATE, mesh-only listener instead (meshNode.Listen,
// not envListenAddr at all) - an explicit architecture decision made
// together with this task's requester, independent of NM-F-14/EH-F-12's
// own (separate, later reverted) history: once a client can complete
// UC-01 registration and its own mesh join (CL-F-04, against Network-
// Manager's now-directly-public Headscale endpoint), there is no
// remaining reason for login itself to be reachable from outside the
// mesh, and keeping it mesh-only removes a whole class of unauthenticated-
// login-endpoint exposure. Both listeners present the identical Let's
// Encrypt-issued certificate (EH-F-03's own literal requirement) and
// require no client certificate (authentication stays email+password, not
// mTLS) - only which network they are reachable from differs.
//
// (An earlier version of this file also served a third role - an EH-F-12
// reverse proxy for Headscale coordination traffic toward Network-Manager,
// dispatched by TLS SNI on envListenAddr - since removed: EH-F-12 was
// withdrawn from the SRS once NM-F-14 was reworded to make Network-
// Manager's own Headscale endpoint directly public-facing instead, making
// the proxy redundant. See services/network-manager/cmd/network-manager/
// main.go's own package doc comment for NM-F-14's current shape.)
//
// # Mesh membership (pkg/mesh, NOT a real OS tailscaled)
//
// This process embeds pkg/mesh's in-process tsnet mesh node, the same
// mechanism Database-Vault/Security-Switch used before their own later
// conversion to a real OS tailscaled (see .claude/agent-memory/
// code-agent.md's "pkg/mesh" and "pkg/pki dialer routing" entries) - and
// deliberately stays there rather than following that same later
// conversion. The reason those two services converted was that pkg/pki's
// CA-bootstrap/renewal traffic and pkg/metrics' MQTT traffic have no way to
// route through an in-process-only tsnet netstack when either service also
// holds a SERVER role (ca.BootstrapServer's returned *http.Server exposes
// no interceptable dial path at all - a confirmed, version-pinned
// smallstep/certificates library limitation, not a code gap). Entry-Hub
// holds no server role at all: pkg/pki's ONLY use here is pki.NewClient
// (via buildSecuritySwitchClient), and ca.BootstrapClient's returned
// *http.Client.Transport IS directly interceptable (see pkg/pki/dialer.go's
// RouteThroughDialer/NewClientWithDialer) - so this process's one CA-client
// identity, its outbound Security-Switch mTLS calls, AND its MQTT metrics
// connection can all be routed through pkg/mesh's meshNode.Dial with no
// library limitation standing in the way. Converting to a real tailscaled
// here would trade away tsnet's no-root/no-kernel-TUN footprint for
// nothing this process actually needs.
//
// mTLS to Security-Switch (EH-F-07, PKI-F-01/PKI-F-02, CA-F-04): Entry-Hub
// has no inbound mTLS listener at all - its public/mesh-only endpoints
// (EH-F-01/02/03) are served over a separate, unrelated Let's Encrypt-
// issued HTTPS certificate (buildServerTLSConfig/envServerCert/
// envServerKey below, untouched by this file's mesh changes). Entry-Hub
// therefore needs exactly one identity role: an outbound mTLS client. It
// obtains that identity from the Certificate-Authority via pkg/pki's
// bootstrap-token flow (pki.LoadBootstrapToken + pki.NewClientWithDialer,
// routed through meshNode.Dial), the same CA-F-04 mechanism Database-Vault
// uses, but calling pki.NewClientWithDialer directly rather than reusing a
// pki.NewServer-bootstrapped *tls.Config - see pkg/pki's package doc
// comment and Database-Vault's own main.go doc comment: reusing a server
// identity for an outbound call is only the right pattern when a
// corresponding inbound listener already exists for that identity: none
// does here. The resulting *http.Client's Transport is wrapped with
// mtls.WrapRoundTripper for PKI-F-02's organization check
// (organization=securityswitch.OrganizationSecuritySwitch) at the
// HTTP-response level, since pkg/pki's *tls.Config is not composable with
// pkg/mtls.ClientConfig's handshake-level VerifyConnection check (see
// pkg/pki's package doc comment). Note that pki.NewClientWithDialer's mesh
// routing covers every outbound call THROUGH the returned *http.Client
// (including its own background certificate renewal) but not the single
// initial bootstrap-token exchange itself, which the vendored library
// gives no hook to reach - that one call still goes out over this
// container's default network path (ramusb-net), which is why Entry-Hub
// still keeps a ramusb-net attachment for Certificate-Authority
// reachability at startup (see deployments/compose/entry-hub.yml).
//
// EH-F-10/EH-F-11's MQTT metrics identity (buildMetricsClient) reuses this
// SAME bootstrapped *http.Client's *tls.Config - pki.TLSConfig extracts it,
// pki.ClientTLSConfig clones it with ServerName forced to
// metrics.OrganizationMQTTBroker, and metrics.TLSConfig layers PKI-F-02's
// organization check on top (mtls.WithOrganization, the MQTT-connection
// counterpart of WrapRoundTripper's HTTP-level check above) - instead of a
// second, independent bootstrap-token exchange or the static cert/key
// files this process used before. The MQTT connection itself is routed
// through meshNode.Dial too (metrics.NewClient's dial parameter), now that
// the MQTT broker's mesh identity is reachable that way (see policy.go's
// TagMQTTBroker rule).
//
// See also deployments/compose/certificate-authority.yml's certificate-authority-init
// service: the dev Certificate-Authority container needs a one-time,
// idempotent setup step (a custom x509 template on its bootstrap-token
// provisioner) before any certificate it issues carries a non-empty
// Subject.Organization at all - without it, PKI-F-02's organization check
// would reject every connection. `docker compose up` applies it
// automatically; no manual step is required.
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

	"github.com/Verryx-02/RAM-USB/pkg/env"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/mesh"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/securityswitch"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/server"
)

// Env var names for values this task introduces.
const (
	// envListenAddr is the address this server's public listener binds
	// for EH-F-01/EH-F-02 (NET-F-01) - a real host:port on this
	// container's ordinary network interface, unlike every mesh-joined
	// service's own listener.
	envListenAddr = "RAM_USB_ENTRY_HUB_LISTEN_ADDR"

	// envServerCert/envServerKey locate this server's own TLS certificate
	// and private key, presented to every connecting client on BOTH the
	// public listener and the mesh-only login listener (EH-F-03's own
	// literal "certificates signed by the public Let's Encrypt CA"
	// requirement applies to login too). In production these are issued
	// by the public Let's Encrypt CA; for local development an
	// operator-provided self-signed pair at the same paths is this
	// service's own operator's responsibility, same convention as every
	// other service's server certificate env vars.
	envServerCert = "RAM_USB_ENTRY_HUB_TLS_CERT"
	envServerKey  = "RAM_USB_ENTRY_HUB_TLS_KEY"

	// envLoginListenAddr is the bare ":port" (tsnet.Server.Listen only
	// ever announces on this node's own mesh address, so a host part is
	// meaningless here - same shape as Database-Vault's own pre-real-
	// tailscaled envListenAddr) this server's mesh-only login listener
	// (EH-F-03) binds. Distinct from envListenAddr's public socket - see
	// this file's package doc comment, "Listener topology".
	envLoginListenAddr = "RAM_USB_ENTRY_HUB_LOGIN_LISTEN_ADDR"

	// envMeshDir is the persistent directory this node's tsnet mesh
	// identity/state lives in (see pkg/mesh.Config.Dir) - backed by a
	// dedicated Docker volume (deployments/compose/entry-hub.yml), so
	// this node keeps the same mesh identity across container restarts
	// instead of re-joining as a new machine every time.
	envMeshDir = "RAM_USB_ENTRY_HUB_MESH_DIR"

	// envMeshHostname is this node's MagicDNS short name within the
	// tailnet (see pkg/mesh.Config.Hostname) - services/network-manager/
	// internal/headscale/policy.go's TagEntryHub ACL rules apply to
	// whichever pre-auth key's --tags this node's envMeshAuthKey was
	// minted with, not to this hostname directly, but the hostname is
	// still how a human operator (and this file's own doc comments)
	// identify this node in `headscale nodes list`.
	envMeshHostname = "RAM_USB_ENTRY_HUB_MESH_HOSTNAME"

	// envMeshControlURL is the self-hosted Headscale server's
	// coordination URL (see pkg/mesh.Config.ControlURL), shared by every
	// service that joins the mesh - not service-specific, so this same
	// env var name is reused verbatim by every other mesh-joined
	// service's own main.go/rootfs scripts.
	envMeshControlURL = "RAM_USB_TAILSCALE_CONTROL_URL"

	// envMeshAuthKey is this node's single-use Headscale pre-auth key
	// (see pkg/mesh.Config.AuthKey and pkg/mesh's package doc comment,
	// "Key distribution"), minted manually by the operator with
	// --tags tag:entry-hub (services/network-manager/internal/headscale/
	// policy.go's TagEntryHub) - see deployments/compose/entry-hub.yml
	// for the exact minting command.
	envMeshAuthKey = "RAM_USB_ENTRY_HUB_TAILSCALE_AUTHKEY" //nolint:gosec // an env var *name*, not a credential value

	// envMeshControlCAFile optionally names a PEM file this process
	// should trust for envMeshControlURL's TLS certificate (see
	// pkg/mesh.Config.ControlCAFile) - shared across services exactly
	// like envMeshControlURL, since it exists solely to trust that same
	// URL's certificate. Left unset in any deployment where ControlURL's
	// certificate already chains to a real, publicly trusted root; only
	// this project's dev-only self-signed Headscale certificate
	// (third-party/headscale/dev-tls) needs it.
	envMeshControlCAFile = "RAM_USB_TAILSCALE_CONTROL_CA_FILE"

	// envSecuritySwitchURL is Security-Switch's base URL (EH-F-07), e.g.
	// "https://security-switch:8444" - Security-Switch's own MagicDNS
	// short mesh hostname now that it is mesh-only reachable, not a
	// ramusb-net Docker DNS name. This server's mTLS client identity
	// itself is no longer read from cert/key/CA files - see this file's
	// package doc comment - it comes from
	// pki.LoadBootstrapToken/pki.BootstrapTokenEnvVar
	// (RAM_USB_CA_BOOTSTRAP_TOKEN), already established by CA-F-04 and not
	// redefined here.
	envSecuritySwitchURL = "RAM_USB_SECURITY_SWITCH_URL"

	// envMQTTBrokerURL reuses the exact same env var name Database-Vault's
	// and Security-Switch's main.go already established
	// (RAM_USB_MQTT_BROKER_URL) - same judgment call, documented
	// identically in both of those files: every service's metrics client
	// connects to the one same broker with the one same required
	// certificate organization (metrics.OrganizationMQTTBroker =
	// "MQTTBroker"), and each service is its own OS process reading its
	// own separate environment, so reusing the identical name is the
	// consistent choice, not a collision risk. No separate
	// RAM_USB_MQTT_CLIENT_CERT/RAM_USB_MQTT_CLIENT_KEY/RAM_USB_MQTT_CA env
	// vars exist - this process's MQTT identity and root trust are both
	// derived from the same pki.NewClientWithDialer bootstrap already
	// performed for Security-Switch (see this file's package doc comment).
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"
)

// serviceName is Entry-Hub's identifier in every metrics payload it
// publishes and the "<Service-Name>" half of its dedicated MQTT topic
// (EH-F-10), reproduced verbatim from the SRS's literal `metrics/Entry-Hub`
// quote - not PascalCased the way this codebase's mTLS
// Subject.Organization values are, since this is the SRS's literal quoted
// value, not this codebase's own naming convention.
const serviceName = "Entry-Hub"

// metricsClientID is the MQTT client identifier this server connects
// with (EH-F-10). Distinct from Database-Vault's/Security-Switch's own
// client IDs so the broker can tell every process's connection apart.
const metricsClientID = "entry-hub"

// metricsPublishInterval is EH-F-10's "every minute, and only."
const metricsPublishInterval = time.Minute

// connectTimeout bounds how long this process waits for the MQTT
// broker's connection handshake at startup.
const connectTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("entry-hub: fatal startup error", "error", logging.Sanitize(err.Error()))
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
	loginListenAddr, err := env.Require(envLoginListenAddr)
	if err != nil {
		return err
	}

	// meshNode is this process's own Headscale mesh identity (see this
	// file's package doc comment, "Mesh membership") - reused below for
	// the login listener, the outbound Security-Switch client, and the
	// MQTT metrics connection, never a second node.
	meshNode, err := buildMeshNode(ctx)
	if err != nil {
		return fmt.Errorf("join mesh: %w", err)
	}
	defer func() {
		if closeErr := meshNode.Close(); closeErr != nil {
			slog.Warn("entry-hub: mesh node close error", "error", logging.Sanitize(closeErr.Error()))
		}
	}()

	serverTLSConfig, err := buildServerTLSConfig()
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	securitySwitchClient, securitySwitchURL, mqttTLSBase, err := buildSecuritySwitchClient(ctx, meshNode.Dial)
	if err != nil {
		return fmt.Errorf("build security-switch client: %w", err)
	}

	counters := &metrics.RequestCounters{}

	handler := &httpapi.Handler{
		SecuritySwitch: httpapi.SecuritySwitchAdapter{Client: securitySwitchClient, BaseURL: securitySwitchURL},
		Metrics:        counters,
	}

	publicMux := http.NewServeMux()
	publicMux.HandleFunc("POST "+httpapi.HealthPath, handler.Health)
	publicMux.HandleFunc("POST "+httpapi.RegisterPath, handler.Register)

	loginMux := http.NewServeMux()
	loginMux.HandleFunc("POST "+httpapi.LoginPath, handler.Login)

	publicServer := &http.Server{
		Handler:           publicMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	loginServer := &http.Server{
		Handler:           loginMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	metricsClient, err := buildMetricsClient(mqttTLSBase, meshNode.Dial)
	if err != nil {
		return fmt.Errorf("build metrics client: %w", err)
	}
	if metricsClient != nil {
		defer metricsClient.Disconnect(250)
		go metrics.Run(ctx, metricsPublishInterval, func(publishCtx context.Context) error {
			return metrics.PublishOnce(publishCtx, metricsClient, serviceName, counters.Snapshot())
		})
	}

	rawListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
	tlsPublicListener := tls.NewListener(rawListener, serverTLSConfig)

	meshListener, err := meshNode.Listen("tcp", loginListenAddr)
	if err != nil {
		return fmt.Errorf("mesh listen on %s: %w", loginListenAddr, err)
	}
	tlsLoginListener := tls.NewListener(meshListener, serverTLSConfig)

	serveErr := make(chan error, 1)
	go func() {
		// codeql[go/log-injection] logging.Sanitize maps every unicode.IsControl rune (including CR/LF/NUL/tab)
		// to a space, so no forged newline can reach the log sink - a custom sanitizer CodeQL doesn't recognize.
		slog.Info("entry-hub: listening", "addr", logging.Sanitize(listenAddr))
		serveErr <- publicServer.Serve(tlsPublicListener)
	}()

	loginServeErr := make(chan error, 1)
	go func() {
		// codeql[go/log-injection] logging.Sanitize maps every unicode.IsControl rune (including CR/LF/NUL/tab)
		// to a space, so no forged newline can reach the log sink - a custom sanitizer CodeQL doesn't recognize.
		slog.Info("entry-hub: listening on the mesh for login", "addr", logging.Sanitize(loginListenAddr))
		loginServeErr <- loginServer.Serve(tlsLoginListener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := publicServer.Shutdown(shutdownCtx)
		if loginErr := loginServer.Shutdown(shutdownCtx); err == nil {
			err = loginErr
		}
		return err
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case err := <-loginServeErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve login: %w", err)
	}
}

// buildMeshNode joins this process to the private Headscale mesh (see this
// file's package doc comment, "Mesh membership") using envMeshDir/
// envMeshHostname/envMeshControlURL/envMeshAuthKey, failing closed (RD-04)
// if any is unset. ctx bounds only the join itself; the returned node
// lives for this process's whole lifetime (closed via a deferred call in
// run).
func buildMeshNode(ctx context.Context) (*mesh.Server, error) {
	dir, err := env.Require(envMeshDir)
	if err != nil {
		return nil, err
	}
	hostname, err := env.Require(envMeshHostname)
	if err != nil {
		return nil, err
	}
	controlURL, err := env.Require(envMeshControlURL)
	if err != nil {
		return nil, err
	}
	authKey, err := env.Require(envMeshAuthKey)
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

// buildServerTLSConfig assembles EH-F-01/EH-F-02/EH-F-03's public TLS
// configuration from this server's own certificate/key. Unlike every
// other service's buildServerTLSConfig, this has no client-CA to load -
// server.NewTLSConfig accepts any client, by requirement (see
// internal/server's doc comment).
func buildServerTLSConfig() (*tls.Config, error) {
	certPath, err := env.Require(envServerCert)
	if err != nil {
		return nil, err
	}
	keyPath, err := env.Require(envServerKey)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate/key: %w", err)
	}

	return server.NewTLSConfig(cert), nil
}

// buildSecuritySwitchClient assembles the *http.Client EH-F-07 uses to
// call Security-Switch over mTLS (PKI-F-01, CA-F-04), verifying
// organization=securityswitch.OrganizationSecuritySwitch on
// Security-Switch's certificate (PKI-F-02). It also returns mqttTLSBase -
// this same bootstrapped identity's *tls.Config, extracted via
// pki.TLSConfig BEFORE client.Transport is wrapped below - for
// buildMetricsClient to reuse for EH-F-10/EH-F-11's MQTT connection (see
// this file's package doc comment). This extraction must happen before
// mtls.WrapRoundTripper runs: pki.TLSConfig type-asserts
// client.Transport.(*http.Transport), which only holds before the wrap -
// afterward client.Transport is a *mtls.organizationRoundTripper instead
// (confirmed live: extracting after the wrap fails closed with "client.
// Transport is *mtls.organizationRoundTripper, want *http.Transport"),
// and WrapRoundTripper's own wrapping is otherwise entirely orthogonal to
// the *tls.Config buildMetricsClient needs.
//
// This is Entry-Hub's one and only mTLS identity (see this file's package
// doc comment: Entry-Hub has no inbound mTLS listener to reuse an
// identity from), so it bootstraps it directly via pki.NewClientWithDialer
// rather than deriving it from a pki.NewServer call the way Database-
// Vault's buildStorageServiceClient does. dial is set to meshNode.Dial by
// run() (nil in tests exercising only PKI-F-02's organization enforcement,
// e.g. main_integration_test.go, which behaves identically to a direct
// pki.NewClient call - see NewClientWithDialer's own doc comment) so every
// call this client makes, including its own background certificate
// renewal, is routed through the mesh (see this file's package doc
// comment, "Mesh membership").
func buildSecuritySwitchClient(ctx context.Context, dial mesh.DialFunc) (client *http.Client, baseURL string, mqttTLSBase *tls.Config, err error) {
	baseURL, err = env.Require(envSecuritySwitchURL)
	if err != nil {
		return nil, "", nil, err
	}

	token, err := pki.LoadBootstrapToken()
	if err != nil {
		return nil, "", nil, fmt.Errorf("load ca bootstrap token: %w", err)
	}

	client, err = pki.NewClientWithDialer(ctx, token, dial)
	if err != nil {
		return nil, "", nil, fmt.Errorf("bootstrap security-switch client identity from certificate-authority: %w", err)
	}

	// Force this handshake's ServerName to the organization Security-Switch
	// is expected to present, instead of the dialed network address
	// (envSecuritySwitchURL's host, which differs between dev/compose and
	// production) - see pkg/pki's package doc comment and
	// pki.ForceServerName's own doc comment for why this is required (not
	// merely defensive) and verified safe (chain validation against the
	// bootstrapped RootCAs, and certificate renewal, are both unaffected).
	if err := pki.ForceServerName(client, securityswitch.OrganizationSecuritySwitch); err != nil {
		return nil, "", nil, fmt.Errorf("force security-switch client TLS server name: %w", err)
	}

	mqttTLSBase, err = pki.TLSConfig(client)
	if err != nil {
		return nil, "", nil, fmt.Errorf("extract mqtt tls config: %w", err)
	}

	// PKI-F-02's organization check runs here, at the HTTP-response
	// level (mtls.WrapRoundTripper), not inside client's *tls.Config's
	// handshake - see this file's package doc comment for why.
	client.Transport = mtls.WrapRoundTripper(client.Transport, securityswitch.OrganizationSecuritySwitch)
	return client, baseURL, mqttTLSBase, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// EH-F-10/EH-F-11's periodic publish uses, reusing mqttTLSBase -
// buildSecuritySwitchClient's own bootstrapped identity, extracted before
// that client's Transport was wrapped (see buildSecuritySwitchClient's own
// doc comment for why one bootstrap token, reused, is correct here rather
// than a second independent bootstrap exchange) - as the source of this
// connection's client certificate. dial routes the connection itself
// through the mesh (metrics.WithDial), same reasoning as
// buildSecuritySwitchClient's own dial parameter. A nil, nil return (no
// error) means metrics publishing is not configured (envMQTTBrokerURL
// unset) - this process still relays registration/login traffic without
// it.
func buildMetricsClient(mqttTLSBase *tls.Config, dial mesh.DialFunc) (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("entry-hub: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(mqttTLSBase, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout, dial)
	if err != nil {
		return nil, err
	}

	return client, nil
}
