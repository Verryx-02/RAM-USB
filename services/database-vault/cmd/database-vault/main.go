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

	"github.com/jackc/pgx/v5/pgxpool"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/login"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/metrics"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/password"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/registration"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/schema"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/server"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// Env var names for values this task introduces. RAM_USB_MASTER_KEY
// (encryption.LoadMasterKey) and RAM_USB_PASSWORD_PEPPER
// (password.LoadPepper) are already established by DV-F-05/DV-F-06 and
// are not redefined here.
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Security-Switch (DV-F-01).
	envListenAddr = "RAM_USB_DATABASE_VAULT_LISTEN_ADDR"

	// envServerCert/envServerKey locate this server's own TLS certificate
	// and private key, presented to Security-Switch during the mTLS
	// handshake.
	envServerCert = "RAM_USB_DATABASE_VAULT_TLS_CERT"
	envServerKey  = "RAM_USB_DATABASE_VAULT_TLS_KEY"

	// envClientCA locates the CA certificate bundle (PEM) trusted to have
	// issued incoming clients' certificates - used to verify
	// Security-Switch's certificate (DV-F-01) and, on the separate
	// public-key listener below, Storage-Service's certificate (ST-F-11).
	// Reused for both listeners rather than duplicated: this codebase's
	// PKI is a single CA (CA-F-01..CA-F-04) issuing every service's
	// certificate, so the pool trusted to verify one caller's certificate
	// is the same pool trusted to verify any other's - the organization
	// check inside server.NewTLSConfig/NewPublicKeyTLSConfig, not a
	// different trusted-CA set, is what actually distinguishes the two
	// listeners' allowed callers.
	envClientCA = "RAM_USB_DATABASE_VAULT_CLIENT_CA"

	// envPublicKeyListenAddr is the address Database-Vault listens on for
	// ST-F-11's public-key lookup, a separate mTLS listener from
	// envListenAddr's register/login one (see internal/server's
	// pubkey_server.go doc comment for why this is a second listener
	// rather than a shared one). It presents the same server
	// certificate/key as the register/login listener (envServerCert/
	// envServerKey) - both represent the one "DatabaseVault" server
	// identity, only the allowed caller organization differs per listener.
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

	// envStorageServiceClientCert/envStorageServiceClientKey locate the
	// client certificate/key this server presents when calling
	// Storage-Service over mTLS (DV-F-09).
	envStorageServiceClientCert = "RAM_USB_STORAGE_SERVICE_CLIENT_CERT"
	envStorageServiceClientKey  = "RAM_USB_STORAGE_SERVICE_CLIENT_KEY"

	// envStorageServiceCA locates the CA certificate bundle (PEM) trusted
	// to have issued Storage-Service's server certificate.
	envStorageServiceCA = "RAM_USB_STORAGE_SERVICE_CA"

	// envMQTTBrokerURL is the MQTT broker's address (DV-F-16), e.g.
	// "tls://mqtt-broker.internal:8883".
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"

	// envMQTTClientCert/envMQTTClientKey locate the client
	// certificate/key this server presents when connecting to the MQTT
	// broker over mTLS (DV-F-16).
	envMQTTClientCert = "RAM_USB_MQTT_CLIENT_CERT"
	envMQTTClientKey  = "RAM_USB_MQTT_CLIENT_KEY"

	// envMQTTCA locates the CA certificate bundle (PEM) trusted to have
	// issued the MQTT broker's server certificate.
	envMQTTCA = "RAM_USB_MQTT_CA"
)

// organizationStorageService is the Subject.Organization DV-F-09 requires
// of Storage-Service's server certificate. posix.CreatePOSIXUser's doc
// comment already documents this literal string; it is not exported by
// the posix package, so it is repeated here as this session's judgment
// call (same "invented, documented" pattern as every other value in this
// file), rather than adding an unrequested exported constant to a
// package whose own tests are already committed.
const organizationStorageService = "StorageService"

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
		slog.Error("database-vault: fatal startup error", "error", err)
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

	serverTLSConfig, err := buildServerTLSConfig()
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	publicKeyServerTLSConfig, err := buildPublicKeyServerTLSConfig()
	if err != nil {
		return fmt.Errorf("build public-key server tls config: %w", err)
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

	storageServiceClient, storageServiceURL, err := buildStorageServiceClient()
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
		Addr:              listenAddr,
		Handler:           mux,
		TLSConfig:         serverTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// publicKeyMux/publicKeyHTTPServer are ST-F-11's separate mux/listener
	// pair, bound to publicKeyListenAddr and publicKeyServerTLSConfig
	// (organization="StorageService"), entirely distinct from httpServer's
	// register/login mux/listener (organization="SecuritySwitch") - see
	// internal/server/pubkey_server.go for why these are two listeners,
	// not one.
	publicKeyMux := http.NewServeMux()
	publicKeyMux.HandleFunc(httpapi.PublicKeyPath, publicKeyHandler.PublicKey)

	publicKeyHTTPServer := &http.Server{
		Addr:              publicKeyListenAddr,
		Handler:           publicKeyMux,
		TLSConfig:         publicKeyServerTLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

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
		slog.Info("database-vault: listening", "addr", listenAddr)
		// TLSConfig already carries the certificate/key pair (via
		// server.NewTLSConfig), so ListenAndServeTLS is called with empty
		// file paths per net/http's documented convention for that case.
		serveErr <- httpServer.ListenAndServeTLS("", "")
	}()

	publicKeyServeErr := make(chan error, 1)
	go func() {
		slog.Info("database-vault: public-key listener listening", "addr", publicKeyListenAddr)
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

// buildServerTLSConfig assembles DV-F-01's mTLS server configuration from
// this server's own certificate/key and the CA pool trusted to have
// issued Security-Switch's certificate.
func buildServerTLSConfig() (*tls.Config, error) {
	certPath, err := requireEnv(envServerCert)
	if err != nil {
		return nil, err
	}
	keyPath, err := requireEnv(envServerKey)
	if err != nil {
		return nil, err
	}
	caPath, err := requireEnv(envClientCA)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate/key: %w", err)
	}

	clientCAs, err := loadCertPool(caPath)
	if err != nil {
		return nil, err
	}

	return server.NewTLSConfig(cert, clientCAs), nil
}

// buildPublicKeyServerTLSConfig assembles ST-F-11's mTLS server
// configuration for the separate public-key lookup listener: the same
// server certificate/key as buildServerTLSConfig (both represent the one
// "DatabaseVault" server identity) and the same trusted client-CA pool
// (see envClientCA's doc comment for why one CA bundle serves both
// listeners), but paired with server.NewPublicKeyTLSConfig instead of
// server.NewTLSConfig - so this listener requires
// organization="StorageService" instead of organization="SecuritySwitch".
func buildPublicKeyServerTLSConfig() (*tls.Config, error) {
	certPath, err := requireEnv(envServerCert)
	if err != nil {
		return nil, err
	}
	keyPath, err := requireEnv(envServerKey)
	if err != nil {
		return nil, err
	}
	caPath, err := requireEnv(envClientCA)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate/key: %w", err)
	}

	clientCAs, err := loadCertPool(caPath)
	if err != nil {
		return nil, err
	}

	return server.NewPublicKeyTLSConfig(cert, clientCAs), nil
}

// buildStorageServiceClient assembles the *http.Client DV-F-09 uses to
// call Storage-Service over mTLS, verifying organization="StorageService"
// on Storage-Service's certificate.
func buildStorageServiceClient() (*http.Client, string, error) {
	baseURL, err := requireEnv(envStorageServiceURL)
	if err != nil {
		return nil, "", err
	}
	certPath, err := requireEnv(envStorageServiceClientCert)
	if err != nil {
		return nil, "", err
	}
	keyPath, err := requireEnv(envStorageServiceClientKey)
	if err != nil {
		return nil, "", err
	}
	caPath, err := requireEnv(envStorageServiceCA)
	if err != nil {
		return nil, "", err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load storage-service client certificate/key: %w", err)
	}

	rootCAs, err := loadCertPool(caPath)
	if err != nil {
		return nil, "", err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtls.ClientConfig(cert, rootCAs, organizationStorageService),
		},
	}
	return client, baseURL, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// DV-F-16/DV-F-17's periodic publish uses. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still serves registration/login traffic without it,
// since DV-F-16/DV-F-17 are about what gets published when metrics are
// published, not a hard dependency of the registration/login control
// flow itself.
func buildMetricsClient() (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("database-vault: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
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
