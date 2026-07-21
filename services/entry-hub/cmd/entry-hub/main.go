// Command entry-hub wires every already-implemented Entry-Hub package into
// a running HTTPS server: EH-F-01/EH-F-02/EH-F-03's public (non-mTLS)
// connection-acceptance TLS config, an outbound mTLS client to
// Security-Switch (EH-F-07), the httpapi handlers (EH-F-04/EH-F-05/
// EH-F-06/EH-F-08/EH-F-09 and the health check EH-F-01), and
// EH-F-10/EH-F-11's periodic metrics publish over MQTT.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." This mirrors
// services/security-switch/cmd/security-switch/main.go's structure
// exactly, adapted to Entry-Hub's own inbound listener (public HTTPS, no
// client certificate requirement - see internal/server's doc comment) and
// its single outbound direction (Security-Switch, in place of
// Security-Switch's own two: Database-Vault and Network-Manager).
//
// EH-F-12 (acting as a reverse proxy for Headscale coordination traffic)
// is explicitly out of scope for this entrypoint - it is a distinct,
// not-yet-built requirement, not part of the request-relay flow wired
// here.
//
// mTLS to Security-Switch (EH-F-07, PKI-F-01/PKI-F-02, CA-F-04): unlike
// every other service in this codebase, Entry-Hub has no inbound mTLS
// listener at all - its public endpoints (EH-F-01/02/03) are served over a
// separate, unrelated Let's Encrypt-issued HTTPS certificate
// (buildServerTLSConfig/envServerCert/envServerKey below, untouched by
// this change). Entry-Hub therefore needs exactly one identity role: an
// outbound mTLS client. It obtains that identity from the
// Certificate-Authority via pkg/pki's bootstrap-token flow
// (pki.LoadBootstrapToken + pki.NewClient), the same CA-F-04 mechanism
// Database-Vault uses, but calling pki.NewClient directly rather than
// reusing a pki.NewServer-bootstrapped *tls.Config - see pkg/pki's package
// doc comment and Database-Vault's own main.go doc comment: reusing a
// server identity for an outbound call is only the right pattern when a
// corresponding inbound listener already exists for that identity: none
// does here. The resulting *http.Client's Transport is wrapped with
// mtls.WrapRoundTripper for PKI-F-02's organization check
// (organization=securityswitch.OrganizationSecuritySwitch) at the
// HTTP-response level, since pkg/pki's *tls.Config is not composable with
// pkg/mtls.ClientConfig's handshake-level VerifyConnection check (see
// pkg/pki's package doc comment).
//
// See also deployments/docker-compose.dev.yml's certificate-authority-init
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
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

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
	// envListenAddr is the address this server listens on for incoming
	// public HTTPS connections from clients (EH-F-01/EH-F-02/EH-F-03).
	envListenAddr = "RAM_USB_ENTRY_HUB_LISTEN_ADDR"

	// envServerCert/envServerKey locate this server's own TLS certificate
	// and private key, presented to every connecting client. In
	// production these are issued by the public Let's Encrypt CA
	// (EH-F-01/02/03's literal requirement); for local development an
	// operator-provided self-signed pair at the same paths is this
	// service's own operator's responsibility, same convention as every
	// other service's server certificate env vars.
	envServerCert = "RAM_USB_ENTRY_HUB_TLS_CERT"
	envServerKey  = "RAM_USB_ENTRY_HUB_TLS_KEY"

	// envSecuritySwitchURL is Security-Switch's base URL (EH-F-07), e.g.
	// "https://security-switch.internal:8443". This server's mTLS client
	// identity itself is no longer read from cert/key/CA files - see this
	// file's package doc comment - it comes from
	// pki.LoadBootstrapToken/pki.BootstrapTokenEnvVar
	// (RAM_USB_CA_BOOTSTRAP_TOKEN), already established by CA-F-04 and not
	// redefined here.
	envSecuritySwitchURL = "RAM_USB_SECURITY_SWITCH_URL"

	// envMQTTBrokerURL/envMQTTClientCert/envMQTTClientKey/envMQTTCA reuse
	// the exact same env var names Database-Vault's and Security-Switch's
	// main.go already established (RAM_USB_MQTT_*) - same judgment call,
	// documented identically in both of those files: every service's
	// metrics client connects to the one same broker with the one same
	// required certificate organization
	// (metrics.OrganizationMQTTBroker = "MQTTBroker"), and each service
	// is its own OS process reading its own separate environment, so
	// reusing the identical name is the consistent choice, not a
	// collision risk.
	envMQTTBrokerURL  = "RAM_USB_MQTT_BROKER_URL"
	envMQTTClientCert = "RAM_USB_MQTT_CLIENT_CERT"
	envMQTTClientKey  = "RAM_USB_MQTT_CLIENT_KEY"
	envMQTTCA         = "RAM_USB_MQTT_CA"
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

	listenAddr, err := requireEnv(envListenAddr)
	if err != nil {
		return err
	}

	serverTLSConfig, err := buildServerTLSConfig()
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	securitySwitchClient, securitySwitchURL, err := buildSecuritySwitchClient(ctx)
	if err != nil {
		return fmt.Errorf("build security-switch client: %w", err)
	}

	counters := &httpapi.Counters{}

	handler := &httpapi.Handler{
		SecuritySwitch: httpapi.SecuritySwitchAdapter{Client: securitySwitchClient, BaseURL: securitySwitchURL},
		Metrics:        counters,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+httpapi.HealthPath, handler.Health)
	mux.HandleFunc("POST "+httpapi.RegisterPath, handler.Register)
	mux.HandleFunc("POST "+httpapi.LoginPath, handler.Login)

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		TLSConfig:         serverTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	metricsClient, err := buildMetricsClient()
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
		slog.Info("entry-hub: listening", "addr", logging.Sanitize(listenAddr))
		// TLSConfig already carries the certificate/key pair (via
		// server.NewTLSConfig), so ListenAndServeTLS is called with empty
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

// loadCertPool reads a PEM certificate bundle from path and returns a
// pool containing it.
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

// buildServerTLSConfig assembles EH-F-01/EH-F-02/EH-F-03's public TLS
// configuration from this server's own certificate/key. Unlike every
// other service's buildServerTLSConfig, this has no client-CA to load -
// server.NewTLSConfig accepts any client, by requirement (see
// internal/server's doc comment).
func buildServerTLSConfig() (*tls.Config, error) {
	certPath, err := requireEnv(envServerCert)
	if err != nil {
		return nil, err
	}
	keyPath, err := requireEnv(envServerKey)
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
// Security-Switch's certificate (PKI-F-02).
//
// This is Entry-Hub's one and only mTLS identity (see this file's package
// doc comment: Entry-Hub has no inbound mTLS listener to reuse an
// identity from), so it bootstraps it directly via pki.NewClient rather
// than deriving it from a pki.NewServer call the way Database-Vault's
// buildStorageServiceClient does.
func buildSecuritySwitchClient(ctx context.Context) (*http.Client, string, error) {
	baseURL, err := requireEnv(envSecuritySwitchURL)
	if err != nil {
		return nil, "", err
	}

	token, err := pki.LoadBootstrapToken()
	if err != nil {
		return nil, "", fmt.Errorf("load ca bootstrap token: %w", err)
	}

	client, err := pki.NewClient(ctx, token)
	if err != nil {
		return nil, "", fmt.Errorf("bootstrap security-switch client identity from certificate-authority: %w", err)
	}

	// Force this handshake's ServerName to the organization Security-Switch
	// is expected to present, instead of the dialed network address
	// (envSecuritySwitchURL's host, which differs between dev/compose and
	// production) - see pkg/pki's package doc comment and
	// pki.ForceServerName's own doc comment for why this is required (not
	// merely defensive) and verified safe (chain validation against the
	// bootstrapped RootCAs, and certificate renewal, are both unaffected).
	if err := pki.ForceServerName(client, securityswitch.OrganizationSecuritySwitch); err != nil {
		return nil, "", fmt.Errorf("force security-switch client TLS server name: %w", err)
	}

	// PKI-F-02's organization check runs here, at the HTTP-response
	// level (mtls.WrapRoundTripper), not inside client's *tls.Config's
	// handshake - see this file's package doc comment for why.
	client.Transport = mtls.WrapRoundTripper(client.Transport, securityswitch.OrganizationSecuritySwitch)
	return client, baseURL, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// EH-F-10/EH-F-11's periodic publish uses. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still relays registration/login traffic without it.
func buildMetricsClient() (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("entry-hub: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
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
