// Command security-switch wires every already-implemented Security-Switch
// package into a running mTLS HTTP server: SS-F-01's connection-acceptance
// TLS config (accepting only organization="EntryHub"), outbound mTLS
// clients to Database-Vault (SS-F-04) and Network-Manager (SS-F-05), the
// httpapi handlers (SS-F-02, SS-F-03, SS-F-06, and the request-relay
// control flow they call), and SS-F-07/SS-F-08's periodic metrics publish
// over MQTT.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." This mirrors
// services/database-vault/cmd/database-vault/main.go exactly, adapted to
// Security-Switch's own outbound directions (Database-Vault,
// Network-Manager) in place of Database-Vault's own (Storage-Service).
// Env var names not already established elsewhere follow the same
// RAM_USB_<SERVICE>_* convention that file introduced - this session's
// invented judgment call, documented on each constant below.
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

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/dbvault"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/metrics"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/networkmanager"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/server"
)

// Env var names for values this task introduces.
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Entry-Hub (SS-F-01).
	envListenAddr = "RAM_USB_SECURITY_SWITCH_LISTEN_ADDR"

	// envServerCert/envServerKey locate this server's own TLS certificate
	// and private key, presented to Entry-Hub during the mTLS handshake.
	envServerCert = "RAM_USB_SECURITY_SWITCH_TLS_CERT"
	envServerKey  = "RAM_USB_SECURITY_SWITCH_TLS_KEY"

	// envClientCA locates the CA certificate bundle (PEM) trusted to have
	// issued incoming clients' certificates - used to verify Entry-Hub's
	// certificate (SS-F-01).
	envClientCA = "RAM_USB_SECURITY_SWITCH_CLIENT_CA"

	// envDatabaseVaultURL is Database-Vault's base URL (SS-F-04), e.g.
	// "https://database-vault.internal:8443".
	envDatabaseVaultURL = "RAM_USB_DATABASE_VAULT_URL"

	// envDatabaseVaultClientCert/envDatabaseVaultClientKey locate the
	// client certificate/key this server presents when calling
	// Database-Vault over mTLS (SS-F-04).
	envDatabaseVaultClientCert = "RAM_USB_DATABASE_VAULT_CLIENT_CERT"
	envDatabaseVaultClientKey  = "RAM_USB_DATABASE_VAULT_CLIENT_KEY"

	// envDatabaseVaultCA locates the CA certificate bundle (PEM) trusted
	// to have issued Database-Vault's server certificate.
	envDatabaseVaultCA = "RAM_USB_DATABASE_VAULT_CA"

	// envNetworkManagerURL is Network-Manager's base URL (SS-F-05), e.g.
	// "https://network-manager.internal:8443".
	envNetworkManagerURL = "RAM_USB_NETWORK_MANAGER_URL"

	// envNetworkManagerClientCert/envNetworkManagerClientKey locate the
	// client certificate/key this server presents when calling
	// Network-Manager over mTLS (SS-F-05).
	envNetworkManagerClientCert = "RAM_USB_NETWORK_MANAGER_CLIENT_CERT"
	envNetworkManagerClientKey  = "RAM_USB_NETWORK_MANAGER_CLIENT_KEY"

	// envNetworkManagerCA locates the CA certificate bundle (PEM) trusted
	// to have issued Network-Manager's server certificate.
	envNetworkManagerCA = "RAM_USB_NETWORK_MANAGER_CA"

	// envMQTTBrokerURL is the MQTT broker's address (SS-F-07), e.g.
	// "tls://mqtt-broker.internal:8883". Reuses the exact same env var
	// names Database-Vault's main.go already established
	// (RAM_USB_MQTT_BROKER_URL/RAM_USB_MQTT_CLIENT_CERT/
	// RAM_USB_MQTT_CLIENT_KEY/RAM_USB_MQTT_CA), not a security-switch-
	// specific prefix: each service is its own OS process (its own
	// container/systemd unit with its own environment), so there is no
	// real collision risk from two different processes both reading a
	// same-named env var from their own separate environments - and
	// every metrics publisher in this codebase connects to the one same
	// MQTT broker with the one same required certificate organization
	// (metrics.OrganizationMQTTBroker = "MQTTBroker" in both services'
	// metrics packages), so reusing the identical name is also the more
	// consistent choice, not just the safe one.
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"

	// envMQTTClientCert/envMQTTClientKey locate the client
	// certificate/key this server presents when connecting to the MQTT
	// broker over mTLS (SS-F-07).
	envMQTTClientCert = "RAM_USB_MQTT_CLIENT_CERT"
	envMQTTClientKey  = "RAM_USB_MQTT_CLIENT_KEY"

	// envMQTTCA locates the CA certificate bundle (PEM) trusted to have
	// issued the MQTT broker's server certificate.
	envMQTTCA = "RAM_USB_MQTT_CA"
)

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
		slog.Error("security-switch: fatal startup error", "error", err)
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

	dbVaultClient, dbVaultURL, err := buildDatabaseVaultClient()
	if err != nil {
		return fmt.Errorf("build database-vault client: %w", err)
	}

	networkManagerClient, networkManagerURL, err := buildNetworkManagerClient()
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
			return metrics.PublishOnce(publishCtx, metricsClient, counters.Snapshot())
		})
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("security-switch: listening", "addr", listenAddr)
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

// buildServerTLSConfig assembles SS-F-01's mTLS server configuration from
// this server's own certificate/key and the CA pool trusted to have
// issued Entry-Hub's certificate.
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

// buildDatabaseVaultClient assembles the *http.Client SS-F-04 uses to
// call Database-Vault over mTLS, verifying
// organization=dbvault.OrganizationDatabaseVault on Database-Vault's
// certificate.
func buildDatabaseVaultClient() (*http.Client, string, error) {
	baseURL, err := requireEnv(envDatabaseVaultURL)
	if err != nil {
		return nil, "", err
	}
	certPath, err := requireEnv(envDatabaseVaultClientCert)
	if err != nil {
		return nil, "", err
	}
	keyPath, err := requireEnv(envDatabaseVaultClientKey)
	if err != nil {
		return nil, "", err
	}
	caPath, err := requireEnv(envDatabaseVaultCA)
	if err != nil {
		return nil, "", err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load database-vault client certificate/key: %w", err)
	}

	rootCAs, err := loadCertPool(caPath)
	if err != nil {
		return nil, "", err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtls.ClientConfig(cert, rootCAs, dbvault.OrganizationDatabaseVault),
		},
	}
	return client, baseURL, nil
}

// buildNetworkManagerClient assembles the *http.Client SS-F-05 uses to
// call Network-Manager over mTLS, verifying
// organization=networkmanager.OrganizationNetworkManager on
// Network-Manager's certificate.
func buildNetworkManagerClient() (*http.Client, string, error) {
	baseURL, err := requireEnv(envNetworkManagerURL)
	if err != nil {
		return nil, "", err
	}
	certPath, err := requireEnv(envNetworkManagerClientCert)
	if err != nil {
		return nil, "", err
	}
	keyPath, err := requireEnv(envNetworkManagerClientKey)
	if err != nil {
		return nil, "", err
	}
	caPath, err := requireEnv(envNetworkManagerCA)
	if err != nil {
		return nil, "", err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load network-manager client certificate/key: %w", err)
	}

	rootCAs, err := loadCertPool(caPath)
	if err != nil {
		return nil, "", err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: mtls.ClientConfig(cert, rootCAs, networkmanager.OrganizationNetworkManager),
		},
	}
	return client, baseURL, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client
// SS-F-07/SS-F-08's periodic publish uses. A nil, nil return (no error)
// means metrics publishing is not configured (envMQTTBrokerURL unset) -
// this process still relays registration/login traffic without it,
// since SS-F-07/SS-F-08 are about what gets published when metrics are
// published, not a hard dependency of the request-relay control flow
// itself.
func buildMetricsClient() (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("security-switch: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
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
