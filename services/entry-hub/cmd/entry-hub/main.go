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
// is served on a SEPARATE, mesh-only listener instead (bound explicitly to
// this node's own mesh IPv4 address, see meshIPv4 below - never
// envListenAddr) - an explicit architecture decision made together with
// this task's requester, independent of NM-F-14/EH-F-12's own (separate,
// later reverted) history: once a client can complete UC-01 registration
// and its own mesh join (CL-F-04, against Network-Manager's now-directly-
// public Headscale endpoint), there is no remaining reason for login
// itself to be reachable from outside the mesh, and keeping it mesh-only
// removes a whole class of unauthenticated-login-endpoint exposure. Both
// listeners present the identical Let's Encrypt-issued certificate
// (EH-F-03's own literal requirement) and require no client certificate
// (authentication stays email+password, not mTLS) - only which network
// they are reachable from differs.
//
// (An earlier version of this file also served a third role - an EH-F-12
// reverse proxy for Headscale coordination traffic toward Network-Manager,
// dispatched by TLS SNI on envListenAddr - since removed: EH-F-12 was
// withdrawn from the SRS once NM-F-14 was reworded to make Network-
// Manager's own Headscale endpoint directly public-facing instead, making
// the proxy redundant. See services/network-manager/cmd/network-manager/
// main.go's own package doc comment for NM-F-14's current shape.)
//
// # Mesh membership (real OS tailscaled, via a sidecar - KI-27)
//
// This process no longer embeds pkg/mesh's in-process tsnet mesh node - it
// was the one remaining backend service on it, and converted away for
// exactly the reason Database-Vault/Security-Switch/Storage-Service/
// Network-Manager already did (see .claude/agent-memory/code-agent/
// pkg-mesh.md and pkg-pki-dialer-routing.md): pkg/pki's stepca.BootstrapClient
// performs its FIRST bootstrap-token exchange internally, before either
// pki.NewClient or pki.NewClientWithDialer ever returns anything to the
// caller, with no hook to route that one call through any application-level
// dialer at all - it always goes out over this process's ordinary default
// network route. In dev, that route is ramusb-net, where Certificate-
// Authority is deliberately dual-reachable (KI-05), so the call always
// succeeded there regardless. In production, per deployments/vps/
// entry-hub.md, Entry-Hub's default route is the public internet and
// Certificate-Authority is mesh-only reachable - so that one call had no
// address to dial at all (KI-27, docs/Known_Issues.md).
//
// The fix is deployments/compose/entry-hub.yml's entry-hub-mesh sidecar: a
// real tailscale/tailscale container sharing this container's network
// namespace (network_mode: "service:entry-hub", TS_USERSPACE=false, the
// same sidecar pattern already used for step-ca/Mosquitto/Grafana - see
// .claude/agent-memory/code-agent/sidecar-mesh-pattern.md). Once that
// sidecar joins the mesh, this container's kernel gains a real tailscale0
// interface and (via --accept-dns, left at its default true, matching
// Database-Vault/Security-Switch/Storage-Service's own tailscale-up.sh) a
// resolv.conf pointed at MagicDNS - so Certificate-Authority's hostname now
// resolves to its real mesh IP, and the OS routes every call to it,
// including the one bootstrap-token exchange pkg/pki gives no dial hook
// for, through tailscale0 automatically. This closes KI-27 with zero
// application-level dial-interception code, the same way Database-Vault's
// own real-tailscaled conversion closed the equivalent gap for its own
// CA-token/MQTT calls (see pkg-pki-dialer-routing.md's "why every
// server-role service runs a real tailscaled" reasoning - it now extends to
// Entry-Hub too, even though Entry-Hub itself holds no server role).
//
// pkg/mesh's meshNode.Dial/meshNode.Listen have no remaining purpose here:
// the OS-level interface routes every outbound call (Security-Switch,
// MQTT, the CA bootstrap exchange) transparently, with no dialer
// injection needed - see buildSecuritySwitchClient/buildMetricsClient
// below, both now built with pki.NewClient/a nil metrics dial, exactly
// like Database-Vault's own post-conversion buildStorageServiceClient/
// buildMetricsClient. The one piece that DOES still need explicit code is
// EH-F-03's login listener: unlike Database-Vault/Security-Switch/
// Storage-Service, which discover their own mesh IPv4 address via a shell
// "tailscale ip -4" call inside their own container (real tailscaled runs
// IN that same container, via s6-overlay), Entry-Hub's real tailscaled
// runs in a SEPARATE sidecar container, and Entry-Hub's own distroless
// runtime image has no shell to run that command even if it could. Instead
// meshIPv4 (below) reads the shared network namespace's own tailscale0
// interface directly via net.InterfaceByName - a syscall, not a shell
// command, so it works identically in a distroless image - and run() binds
// the login listener to that specific address rather than 0.0.0.0, so
// login stays reachable only from the mesh even though this container's
// own ramusb-net attachment (a dev-only convenience, KI-26) is still
// present.
//
// mTLS to Security-Switch (EH-F-07, PKI-F-01/PKI-F-02, CA-F-04): Entry-Hub
// has no inbound mTLS listener at all - its public/mesh-only endpoints
// (EH-F-01/02/03) are served over a separate, unrelated Let's Encrypt-
// issued HTTPS certificate (buildServerTLSConfig/envServerCert/
// envServerKey below, untouched by this file's mesh changes). Entry-Hub
// therefore needs exactly one identity role: an outbound mTLS client. It
// obtains that identity from the Certificate-Authority via pkg/pki's
// bootstrap-token flow (pki.LoadBootstrapToken + pki.NewClient), the same
// CA-F-04 mechanism Database-Vault uses, but calling pki.NewClient
// directly rather than reusing a pki.NewServer-bootstrapped *tls.Config -
// see pkg/pki's package doc comment and Database-Vault's own main.go doc
// comment: reusing a server identity for an outbound call is only the
// right pattern when a corresponding inbound listener already exists for
// that identity: none does here. The resulting *http.Client's Transport is
// wrapped with mtls.WrapRoundTripper for PKI-F-02's organization check
// (organization=securityswitch.OrganizationSecuritySwitch) at the
// HTTP-response level, since pkg/pki's *tls.Config is not composable with
// pkg/mtls.ClientConfig's handshake-level VerifyConnection check (see
// pkg/pki's package doc comment).
//
// EH-F-10/EH-F-11's MQTT metrics identity (buildMetricsClient) reuses this
// SAME bootstrapped *http.Client's *tls.Config - pki.TLSConfig extracts it,
// pki.ClientTLSConfig clones it with ServerName forced to
// metrics.OrganizationMQTTBroker, and metrics.TLSConfig layers PKI-F-02's
// organization check on top (mtls.WithOrganization, the MQTT-connection
// counterpart of WrapRoundTripper's HTTP-level check above) - instead of a
// second, independent bootstrap-token exchange or the static cert/key
// files this process used before. The MQTT connection itself needs no
// dial injection either, now that the MQTT broker's mesh identity is
// reachable transparently through this container's own real tailscale0
// interface (see policy.go's TagMQTTBroker rule).
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

	// envLoginListenAddr is the bare ":port" this server's mesh-only login
	// listener (EH-F-03) binds - meshIPv4 (below) supplies the host part
	// at runtime, once this container's own real tailscale0 interface
	// (entry-hub-mesh's sidecar, see this file's package doc comment) has
	// an address, since that address is not known until then. Distinct
	// from envListenAddr's public socket - see this file's package doc
	// comment, "Listener topology".
	envLoginListenAddr = "RAM_USB_ENTRY_HUB_LOGIN_LISTEN_ADDR"

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
	// derived from the same pki.NewClient bootstrap already performed for
	// Security-Switch (see this file's package doc comment).
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

// meshInterfaceName is the network interface entry-hub-mesh's real
// tailscaled sidecar creates inside this container's shared network
// namespace (network_mode: "service:entry-hub", TS_USERSPACE=false - see
// deployments/compose/entry-hub.yml and this file's package doc comment,
// "Mesh membership") - the same real kernel tailscale0 interface every
// other mesh-joined service's own in-container tailscaled creates, just
// owned by a separate sidecar process here instead of a process inside
// this same container.
const meshInterfaceName = "tailscale0"

// meshInterfacePollInterval/meshInterfaceTimeout bound how long run()
// waits, at startup, for entry-hub-mesh's sidecar to actually create
// meshInterfaceName inside the shared network namespace - Compose starts
// this container before its sidecar can even attach to it (network_mode:
// "service:entry-hub" requires this container to already exist), so this
// process's own first few seconds normally race the sidecar's own
// "tailscale up" join.
const (
	meshInterfacePollInterval = 500 * time.Millisecond
	meshInterfaceTimeout      = 30 * time.Second
)

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
	_, loginPort, err := net.SplitHostPort(loginListenAddr)
	if err != nil {
		return fmt.Errorf("parse %s %q: %w", envLoginListenAddr, loginListenAddr, err)
	}

	// meshIP is this container's own mesh IPv4 address (see meshIPv4's own
	// doc comment). Discovered FIRST, before buildSecuritySwitchClient's
	// own CA-bootstrap-token exchange below - that exchange has no
	// interceptable dial path (see this file's package doc comment,
	// "Mesh membership") and relies entirely on entry-hub-mesh's sidecar
	// having already rewritten this container's own DNS resolution and
	// kernel routing table by the time it runs. Confirmed live (KI-27):
	// calling buildSecuritySwitchClient before this wait lets the
	// bootstrap call race the sidecar's own join and silently fall back to
	// this container's ordinary default route (ramusb-net in dev) instead
	// of the mesh - harmless in dev (Certificate-Authority is
	// dual-reachable, KI-05), but exactly the gap KI-27 exists to close in
	// production, where no such fallback route exists at all.
	meshIP, err := meshIPv4(ctx)
	if err != nil {
		return fmt.Errorf("discover mesh ipv4 address: %w", err)
	}

	serverTLSConfig, err := buildServerTLSConfig()
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	securitySwitchClient, securitySwitchURL, mqttTLSBase, err := buildSecuritySwitchClient(ctx)
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

	metricsClient, err := buildMetricsClient(mqttTLSBase)
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

	// EH-F-03's login listener binds to meshIP explicitly (discovered
	// above, before buildSecuritySwitchClient), never 0.0.0.0, so login
	// stays reachable only from the mesh even though this container's own
	// ramusb-net attachment is still present (see this file's package doc
	// comment, "Mesh membership").
	meshLoginAddr := net.JoinHostPort(meshIP.String(), loginPort)
	rawLoginListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", meshLoginAddr)
	if err != nil {
		return fmt.Errorf("mesh listen on %s: %w", meshLoginAddr, err)
	}
	tlsLoginListener := tls.NewListener(rawLoginListener, serverTLSConfig)

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
		slog.Info("entry-hub: listening on the mesh for login", "addr", logging.Sanitize(meshLoginAddr))
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

// meshIPv4 blocks until entry-hub-mesh's sidecar (see this file's package
// doc comment, "Mesh membership") creates meshInterfaceName inside this
// container's shared network namespace and assigns it an IPv4 address,
// returning that address. Unlike Database-Vault/Security-Switch/
// Storage-Service, which discover their own mesh IPv4 address via a shell
// "tailscale ip -4" call inside their own container's tailscale-up.sh
// (real tailscaled runs IN that same container), Entry-Hub's distroless
// runtime image has no shell and its real tailscaled runs in a SEPARATE
// sidecar container - so this process discovers the address itself, via
// net.InterfaceByName (a syscall, not a shell command - works identically
// in a distroless image), reading the same shared-namespace interface
// that shell command would have read.
func meshIPv4(ctx context.Context) (net.IP, error) {
	deadline := time.Now().Add(meshInterfaceTimeout)
	for {
		if ip := lookupMeshIPv4(); ip != nil {
			return ip, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("interface %s has no IPv4 address after %s", meshInterfaceName, meshInterfaceTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(meshInterfacePollInterval):
		}
	}
}

// lookupMeshIPv4 returns meshInterfaceName's first IPv4 address, or nil if
// the interface does not exist yet or has none - a nil return means "poll
// again," never an error, since both are expected transiently at startup
// (see meshIPv4).
func lookupMeshIPv4() net.IP {
	iface, err := net.InterfaceByName(meshInterfaceName)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4
		}
	}
	return nil
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
// identity from), so it bootstraps it directly via pki.NewClient rather
// than deriving it from a pki.NewServer call the way Database-Vault's
// buildStorageServiceClient does. No dial injection is used (see this
// file's package doc comment, "Mesh membership") - this container's own
// real tailscale0 interface (entry-hub-mesh's sidecar) already routes
// every call this client makes, including its own background certificate
// renewal, through the mesh.
func buildSecuritySwitchClient(ctx context.Context) (client *http.Client, baseURL string, mqttTLSBase *tls.Config, err error) {
	baseURL, err = env.Require(envSecuritySwitchURL)
	if err != nil {
		return nil, "", nil, err
	}

	token, err := pki.LoadBootstrapToken()
	if err != nil {
		return nil, "", nil, fmt.Errorf("load ca bootstrap token: %w", err)
	}

	client, err = pki.NewClient(ctx, token)
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
// connection's client certificate. No dial injection is used (see this
// file's package doc comment, "Mesh membership") - this container's own
// real tailscale0 interface already routes this connection through the
// mesh. A nil, nil return (no error) means metrics publishing is not
// configured (envMQTTBrokerURL unset) - this process still relays
// registration/login traffic without it.
func buildMetricsClient(mqttTLSBase *tls.Config) (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("entry-hub: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(mqttTLSBase, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}
