// Command database-vault wires every already-implemented Database-Vault
// package into a running mTLS HTTP server: DV-F-01's connection-acceptance
// TLS config, DV-F-05/DV-F-06's master key and pepper, a Postgres
// connection pool for DV-F-08/DV-F-10/DV-F-13, an outbound mTLS client to
// Storage-Service for DV-F-09, the httpapi handlers (DV-F-02, DV-F-20, and
// the registration/login orchestration they call), and DV-F-16/DV-F-17's
// periodic metrics publish over MQTT.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." Env var names not already
// established by an earlier requirement (RAM_USB_MASTER_KEY,
// RAM_USB_PASSWORD_PEPPER) are this session's invented judgment call,
// documented on each constant below — revisit if a future
// deployment/ops document fixes different names.
//
// TLS/mTLS setup (PKI-F-01/PKI-F-02, CA-F-04): this server's own identity
// - both its inbound listeners (the register/login one, organization=
// SecuritySwitch, and ST-F-11's public-key one, organization=
// StorageService) and its outbound call to Storage-Service (DV-F-09,
// organization=StorageService) - is obtained from the Certificate-Authority
// via pkg/pki's bootstrap-token flow (CA-F-04), not from pre-existing
// cert/key files on disk. pkg/pki's *tls.Config is not composable with
// pkg/mtls.ServerConfig/ClientConfig's handshake-level VerifyConnection
// organization check (see pkg/pki's package doc comment: ca.BootstrapServer
// hard-errors if TLSConfig.VerifyConnection is already set, and exposes no
// hook to install one) - so PKI-F-02's organization check runs at the
// HTTP-request level instead, via pkg/mtls.RequireOrganization (wrapping
// each listener's handler) and pkg/mtls.WrapRoundTripper (wrapping the
// outbound Storage-Service client's Transport). Both rely on
// net/http.Request.TLS/Response.TLS, which net/http populates from the
// completed handshake regardless of which library built the tls.Config.
//
// One bootstrap token only, per SRS §2.6 ("a single-use bootstrap token,"
// singular, one per service): this server's single identity is
// bootstrapped once (pki.BootstrapTokenEnvVar, via pki.NewServer, see
// buildServerTLSConfig) and its resulting *tls.Config is reused for three
// purposes - both inbound listeners (the same service identity regardless
// of which listener presents it) and the outbound Storage-Service client's
// Transport.TLSClientConfig (buildStorageServiceClient). This is safe
// because github.com/smallstep/certificates/ca.Client.GetServerTLSConfig
// (what pki.NewServer calls internally, confirmed by reading
// ca/tls.go/ca/bootstrap.go/ca/tls_options.go in the vendored module)
// unconditionally sets both GetCertificate and GetClientCertificate on the
// same *tls.Config, wired to the same certificate renewer - so the
// resulting value already presents this server's own certificate whether
// it is dialed as a TLS server or dials out as a TLS client. It also
// carries a populated RootCAs (verified empirically against the real
// Certificate-Authority container, see
// TestBuildServerTLSConfigReusedAsOutboundClient_RealCA in
// main_integration_test.go): TLSOptionCtx.apply, called by
// GetServerTLSConfig internally, unconditionally adds the CA's root
// certificate (extracted from the sign response's own verified chain) to
// tlsConfig.RootCAs before returning - not merely when the "add all
// supported roots" option is applied, so it does not depend on this
// deployment's CA provisioner requiring client authentication for its own
// API. RAM-USB's CA template
// (third-party/certificate-authority/config/organization.x509.tpl) issues
// every certificate with both serverAuth and clientAuth EKU, so there is
// no EKU-based obstacle to reuse either.
//
// See also deployments/compose/certificate-authority.yml's certificate-authority-init
// service: the dev Certificate-Authority container needs a one-time,
// idempotent setup step (a custom x509 template on its bootstrap-token
// provisioner, third-party/certificate-authority/config/
// organization.x509.tpl) before any certificate it issues carries a
// non-empty Subject.Organization at all - without it, PKI-F-02's
// organization check would reject every connection. `docker compose up`
// applies it automatically now; no manual step is required.
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

	"github.com/jackc/pgx/v5/pgxpool"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/login"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/password"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/registration"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/schema"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/server"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// Env var names for values this task introduces. RAM_USB_MASTER_KEY
// (encryption.LoadMasterKey) and RAM_USB_PASSWORD_PEPPER
// (password.LoadPepper) are already established by DV-F-05/DV-F-06 and
// are not redefined here. pki.BootstrapTokenEnvVar
// (RAM_USB_CA_BOOTSTRAP_TOKEN) is already established by CA-F-04 and is
// not redefined here either - it is this server's own single-use
// bootstrap token, used for both inbound listeners (see
// buildServerTLSConfig).
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Security-Switch (DV-F-01).
	envListenAddr = "RAM_USB_DATABASE_VAULT_LISTEN_ADDR"

	// envPublicKeyListenAddr is the address Database-Vault listens on for
	// ST-F-11's public-key lookup, a separate mTLS listener from
	// envListenAddr's register/login one (see internal/server's
	// pubkey_server.go doc comment for why this is a second listener
	// rather than a shared one). It shares this server's one bootstrapped
	// TLS identity with the register/login listener (see
	// buildServerTLSConfig) - only the allowed caller organization,
	// enforced by RequireOrganization at the HTTP-request level, differs
	// per listener.
	envPublicKeyListenAddr = "RAM_USB_DATABASE_VAULT_PUBLIC_KEY_LISTEN_ADDR"

	// envDatabaseURL is the Postgres connection string pgxpool.New
	// parses (DV-F-08).
	envDatabaseURL = "RAM_USB_DATABASE_VAULT_DATABASE_URL"

	// envMigrationsDir locates the directory of SQL migration files
	// (internal/schema.Apply) applied once at startup, before this
	// process starts accepting connections. Optional: defaults to
	// defaultMigrationsDir, the checked-in relative path from this
	// repository's root, so a local/bare-metal run (e.g. `go run
	// ./services/database-vault/cmd/database-vault` from the repo
	// root) works without extra setup. Not part of any earlier
	// requirement's env var list; this session's judgment call, same
	// pattern as every other unestablished env var name in this file.
	envMigrationsDir = "RAM_USB_DATABASE_VAULT_MIGRATIONS_DIR"

	// envStorageServiceURL is Storage-Service's base URL (DV-F-09), e.g.
	// "https://storage-service.internal:8443".
	envStorageServiceURL = "RAM_USB_STORAGE_SERVICE_URL"

	// envMQTTBrokerURL is the MQTT broker's address (DV-F-16), e.g.
	// "tls://mqtt-broker.internal:8883". No separate RAM_USB_MQTT_CLIENT_CERT/
	// RAM_USB_MQTT_CLIENT_KEY/RAM_USB_MQTT_CA env vars exist anymore - this
	// server's MQTT identity and root trust are both derived from
	// serverTLSConfig, the same bootstrapped identity already reused for
	// both inbound listeners and the outbound Storage-Service client (see
	// this file's package doc comment).
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"
)

// organizationStorageService is the Subject.Organization DV-F-09 requires
// of Storage-Service's server certificate. posix.CreatePOSIXUser's doc
// comment already documents this literal string; it is not exported by
// the posix package, so it is repeated here as this session's judgment
// call (same "invented, documented" pattern as every other value in this
// file), rather than adding an unrequested exported constant to a
// package whose own tests are already committed.
const organizationStorageService = "StorageService"

// serviceName is Database-Vault's identifier in every metrics payload it
// publishes and the "<Service-Name>" half of its dedicated MQTT topic
// (DV-F-16), reproduced verbatim from the SRS's literal
// `metrics/Database-Vault` quote. Metrics-Collector (MT-F-02) discards
// any message whose "service" field does not match the MQTT topic it
// arrived on, so this value is deliberately identical to that topic's
// suffix.
const serviceName = "Database-Vault"

// metricsClientID is the MQTT client identifier this server connects
// with (DV-F-16). No SRS/design doc specifies one; a fixed, readable
// value is this session's judgment call.
const metricsClientID = "database-vault"

// metricsPublishInterval is DV-F-16's "every minute, and only."
const metricsPublishInterval = time.Minute

// connectTimeout bounds how long this process waits for the MQTT
// broker's connection handshake at startup.
const connectTimeout = 10 * time.Second

// defaultMigrationsDir is envMigrationsDir's fallback: the migrations
// directory's checked-in location relative to this repository's root.
const defaultMigrationsDir = "services/database-vault/migrations"

func main() {
	if err := run(); err != nil {
		slog.Error("database-vault: fatal startup error", "error", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	masterKey, err := encryption.LoadMasterKey()
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}

	pepper, err := password.LoadPepper()
	if err != nil {
		return fmt.Errorf("load pepper: %w", err)
	}

	listenAddr, err := requireEnv(envListenAddr)
	if err != nil {
		return err
	}

	publicKeyListenAddr, err := requireEnv(envPublicKeyListenAddr)
	if err != nil {
		return err
	}

	// serverTLSConfig is this server's one bootstrapped TLS identity
	// (PKI-F-01, CA-F-04), shared by both inbound listeners below - see
	// buildServerTLSConfig and this file's package doc comment for why one
	// bootstrap exchange, reused, is correct here (as opposed to
	// buildStorageServiceClient's separate exchange for the outbound
	// client identity).
	serverTLSConfig, err := buildServerTLSConfig(ctx)
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	databaseURL, err := requireEnv(envDatabaseURL)
	if err != nil {
		return err
	}

	migrationsDir := getEnvOrDefault(envMigrationsDir, defaultMigrationsDir)
	migration, err := schema.New(databaseURL, migrationsDir)
	if err != nil {
		return fmt.Errorf("build schema migration: %w", err)
	}
	// Up() only, never Down() - Down() is test-cleanup-only (see
	// internal/schema's package doc comment) and must never run against
	// a real database. A failed migration fails this process's startup
	// (RD-04, fail-secure): it never starts serving requests against a
	// schema that might not match what the code expects.
	if err := schema.Apply(migration); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	storageServiceClient, storageServiceURL, err := buildStorageServiceClient(serverTLSConfig)
	if err != nil {
		return fmt.Errorf("build storage-service client: %w", err)
	}

	counters := &httpapi.Counters{}

	handler := &httpapi.Handler{
		Store:            registration.StorageAdapter{DB: storage.PoolBeginner{Pool: pool}},
		POSIXProvisioner: registration.POSIXAdapter{Client: storageServiceClient, BaseURL: storageServiceURL},
		LoginStore:       login.StorageAdapter{DB: storage.PoolQuerier{Pool: pool}},
		MasterKey:        masterKey,
		Pepper:           pepper,
		Metrics:          counters,
	}

	// publicKeyHandler shares the same counters as handler (DV-F-16/
	// DV-F-17's metrics aggregate service-wide, not per-endpoint) but has
	// its own Store — it needs no MasterKey/Pepper/registration/login
	// dependency at all (see pubkey_handler.go's package doc comment).
	publicKeyHandler := &httpapi.PublicKeyHandler{
		Store:   httpapi.PublicKeyStoreAdapter{DB: storage.PoolQuerier{Pool: pool}},
		Metrics: counters,
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

	// publicKeyMux/publicKeyHTTPServer are ST-F-11's separate mux/listener
	// pair, bound to publicKeyListenAddr and sharing serverTLSConfig's one
	// bootstrapped TLS identity, entirely distinct from httpServer's
	// register/login mux/listener only in the organization
	// RequireOrganization requires (organization="StorageService" here,
	// vs organization="SecuritySwitch" above) - see
	// internal/server/pubkey_server.go for why these are two listeners,
	// not one.
	publicKeyMux := http.NewServeMux()
	publicKeyMux.HandleFunc(httpapi.PublicKeyPath, publicKeyHandler.PublicKey)

	publicKeyHTTPServer := &http.Server{
		Addr:              publicKeyListenAddr,
		Handler:           mtls.RequireOrganization(server.AllowedPublicKeyClientOrganization, publicKeyMux),
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
		slog.Info("database-vault: listening", "addr", logging.Sanitize(listenAddr))
		// TLSConfig already carries the bootstrapped certificate (via
		// buildServerTLSConfig's GetCertificate callback, not a static
		// Certificates slice), so ListenAndServeTLS is called with empty
		// file paths per net/http's documented convention for that case.
		serveErr <- httpServer.ListenAndServeTLS("", "")
	}()

	publicKeyServeErr := make(chan error, 1)
	go func() {
		slog.Info("database-vault: public-key listener listening", "addr", logging.Sanitize(publicKeyListenAddr))
		publicKeyServeErr <- publicKeyHTTPServer.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Both listeners are shut down together on the same signal: they
		// are two entry points into one process, not two independently
		// lifecycled services.
		shutdownErr := httpServer.Shutdown(shutdownCtx)
		publicKeyShutdownErr := publicKeyHTTPServer.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			return fmt.Errorf("shutdown register/login listener: %w", shutdownErr)
		}
		if publicKeyShutdownErr != nil {
			return fmt.Errorf("shutdown public-key listener: %w", publicKeyShutdownErr)
		}
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve register/login listener: %w", err)
	case err := <-publicKeyServeErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve public-key listener: %w", err)
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

// getEnvOrDefault reads name from the environment, returning fallback if it
// is unset or empty. Unlike requireEnv, an unset value here is not a
// startup failure - only envMigrationsDir uses this, since it has a
// sensible checked-in-path default (see defaultMigrationsDir), unlike
// every other value in this file, which has no safe default and so must
// come from requireEnv.
func getEnvOrDefault(name, fallback string) string {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return fallback
	}
	return value
}

// buildServerTLSConfig bootstraps this server's one TLS identity from the
// Certificate-Authority (CA-F-04, PKI-F-01), using pki.LoadBootstrapToken's
// single-use token exactly once. The returned *tls.Config is shared by
// both inbound listeners and by buildStorageServiceClient's outbound
// Storage-Service call (see run and this file's package doc comment for
// why reusing it for the outbound call is safe) - it carries no
// organization restriction of its own (that runs at the HTTP-request
// level, via mtls.RequireOrganization/mtls.WrapRoundTripper in run);
// ca.BootstrapServer's default (tls.RequireAndVerifyClientCert) still
// ensures only a certificate this CA itself issued can complete an
// inbound handshake at all.
//
// base is a throwaway *http.Server: pki.NewServer only ever reads/writes
// its TLSConfig field (confirmed by reading
// github.com/smallstep/certificates/ca/bootstrap.go's BootstrapServer),
// so a minimal value discarded immediately after extracting TLSConfig is
// sufficient - the two real *http.Server values run actually serves
// (httpServer, publicKeyHTTPServer) are constructed separately in run.
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

// buildStorageServiceClient builds the outbound *http.Client DV-F-09 uses
// to call Storage-Service (CA-F-04, PKI-F-01), reusing serverTLSConfig -
// this server's one bootstrapped TLS identity (see buildServerTLSConfig
// and this file's package doc comment for why one bootstrap token, reused,
// is correct here rather than a second independent bootstrap exchange) -
// as the outbound Transport.TLSClientConfig, then wraps the resulting
// *http.Client's Transport with mtls.WrapRoundTripper so PKI-F-02's
// organization check (organization=StorageService) runs at the
// HTTP-response level.
//
// pki.ClientTLSConfig clones serverTLSConfig (never mutating the shared
// object itself - see this file's package doc comment on why
// serverTLSConfig is reused across the inbound listeners and this
// outbound client) and forces this handshake's ServerName to
// organizationStorageService instead of the dialed network address
// (envStorageServiceURL's host, which differs between dev/compose and
// production) - see pkg/pki's package doc comment for why this is
// required, not merely defensive.
func buildStorageServiceClient(serverTLSConfig *tls.Config) (*http.Client, string, error) {
	baseURL, err := requireEnv(envStorageServiceURL)
	if err != nil {
		return nil, "", err
	}

	transport := &http.Transport{TLSClientConfig: pki.ClientTLSConfig(serverTLSConfig, organizationStorageService)}
	client := &http.Client{Transport: mtls.WrapRoundTripper(transport, organizationStorageService)}
	return client, baseURL, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// DV-F-16/DV-F-17's periodic publish uses, reusing serverTLSConfig - this
// server's one bootstrapped TLS identity (see buildServerTLSConfig and
// this file's package doc comment) - as the source of this connection's
// client certificate, cloned via pki.ClientTLSConfig with ServerName
// forced to metrics.OrganizationMQTTBroker and layered with PKI-F-02's
// organization check via metrics.TLSConfig. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still serves registration/login traffic without it,
// since DV-F-16/DV-F-17 are about what gets published when metrics are
// published, not a hard dependency of the registration/login control
// flow itself.
func buildMetricsClient(serverTLSConfig *tls.Config) (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("database-vault: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(serverTLSConfig, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout)
	if err != nil {
		return nil, err
	}

	return client, nil
}
