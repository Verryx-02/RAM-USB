// Command metrics-collector subscribes to every publishing service's
// dedicated MQTT metrics topic (metrics/#, MT-F-01) and persists each
// accepted payload into TimescaleDB (MT-F-03), discarding (not storing)
// any message whose payload "service" field disagrees with the topic it
// arrived on (MT-F-02, internal/collector.Handler.Handle).
//
// Unlike every other RAM-USB service, this process exposes no HTTP
// listener of its own: nothing calls Metrics-Collector, it only calls out
// (MQTT subscribe, Postgres write) — the same "no inbound listener" shape
// as Network-Manager's Headscale-only outbound gRPC dependency. No
// MT-F-01..04 requirement implies an HTTP surface; Grafana (MT-F-04)
// reads TimescaleDB directly, not through this process.
//
// PKI-F-01/PKI-F-02 (mutual X.509 authentication, organization-field
// check): this process's one connection role — an outbound/subscribe MQTT
// client — now obtains its mTLS identity from the Certificate-Authority
// via pkg/pki's bootstrap-token flow (CA-F-04), the same mechanism every
// OTHER RAM-USB service already uses for its own inbound/outbound roles,
// rather than the static cert/key/CA files this process used before. This
// process has no HTTP listener or outbound HTTP client of its own (see
// above), so it calls pki.NewClient directly — the same "no inbound
// listener to reuse an identity from" shape Entry-Hub's own
// buildSecuritySwitchClient already established (see that file's package
// doc comment) — purely to obtain a *tls.Config with automatic in-process
// renewal; pki.TLSConfig extracts it, pki.ClientTLSConfig clones it with
// ServerName forced to metrics.OrganizationMQTTBroker, and metrics.TLSConfig
// layers PKI-F-02's organization check on top (mtls.WithOrganization).
// Mosquitto still performs a real mTLS handshake (require_certificate
// true, tls_version tlsv1.3 — NET-F-02) and the Organization-derived CN
// identity still gates ACL access (PKI-F-02, enforced by
// third-party/mosquitto/acl.conf's use_identity_as_username) — unchanged
// by this switch, since the CA template
// (third-party/certificate-authority/config/organization.x509.tpl)
// mirrors a minted token's subject into both CommonName and Organization
// regardless of which code path requested the certificate.
// RAM_USB_CA_BOOTSTRAP_TOKEN (pki.BootstrapTokenEnvVar, CA-F-04) is
// therefore required here for the first time, same as every other
// service. Unlike every publish-side service (for which
// RAM_USB_MQTT_BROKER_URL is optional — metrics publishing degrades
// gracefully if unset, since publishing is a side effect of an otherwise-
// independent server), it is REQUIRED here (RD-04, fail-secure): without
// it this process has no reason to run at all.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." Env var names not already
// established by an earlier requirement are this session's judgment call,
// documented on each constant below.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/metrics-collector/internal/collector"
	"github.com/Verryx-02/RAM-USB/services/metrics-collector/internal/schema"
	"github.com/Verryx-02/RAM-USB/services/metrics-collector/internal/store"
)

const (
	// envMQTTBrokerURL is the MQTT broker's address, e.g.
	// "tls://mqtt-broker:8883". Required (see this file's package doc
	// comment for why, unlike every publish-side service).
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"

	// envDatabaseURL is the TimescaleDB/Postgres connection string
	// pgxpool.New parses (MT-F-03).
	envDatabaseURL = "RAM_USB_METRICS_COLLECTOR_DATABASE_URL"

	// envMigrationsDir locates the directory of SQL migration files
	// (internal/schema.Apply) applied once at startup, before this
	// process starts accepting MQTT messages. Optional: defaults to
	// defaultMigrationsDir, the checked-in relative path from this
	// repository's root — same convention as Database-Vault's own
	// envMigrationsDir.
	envMigrationsDir = "RAM_USB_METRICS_COLLECTOR_MIGRATIONS_DIR"
)

// defaultMigrationsDir is envMigrationsDir's fallback: the migrations
// directory's checked-in location relative to this repository's root.
const defaultMigrationsDir = "services/metrics-collector/migrations"

// metricsClientID is the MQTT client identifier this process connects
// with. No SRS/design doc specifies one; a fixed, readable value is this
// session's judgment call, same pattern as every publish-side service's
// own metricsClientID constant.
const metricsClientID = "metrics-collector"

// connectTimeout bounds how long this process waits for the MQTT broker
// connection to complete at startup.
const connectTimeout = 10 * time.Second

// subscribeTopic is MT-F-01's "Metrics-Collector can only read
// metrics/*" — the single wildcard subscription this process ever makes.
const subscribeTopic = "metrics/#"

// subscribeQoS is "at least once" delivery, matching every publisher's
// own publishQoS (pkg/metrics/publish.go) — QoS 0 risks silently missing
// a message this process exists specifically to receive.
const subscribeQoS byte = 1

func main() {
	if err := run(); err != nil {
		slog.Error("metrics-collector: fatal startup error", "error", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	databaseURL, err := requireEnv(envDatabaseURL)
	if err != nil {
		return err
	}

	migrationsDir := getEnvOrDefault(envMigrationsDir, defaultMigrationsDir)
	migration, err := schema.New(databaseURL, migrationsDir)
	if err != nil {
		return fmt.Errorf("build schema migration: %w", err)
	}
	// Up() only, never Down() — Down() is test-cleanup-only (see
	// internal/schema's package doc comment) and must never run against a
	// real database. A failed migration fails this process's startup
	// (RD-04, fail-secure): it never starts consuming MQTT messages
	// against a schema that might not match what this code expects.
	if err := schema.Apply(migration); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	mqttClient, err := buildMQTTClient(ctx)
	if err != nil {
		return fmt.Errorf("build mqtt client: %w", err)
	}
	defer mqttClient.Disconnect(250)

	handler := &collector.Handler{Store: store.Store{DB: store.PoolQuerier{Pool: pool}}}

	token := mqttClient.Subscribe(subscribeTopic, subscribeQoS, handler.OnMessage)
	if !token.WaitTimeout(connectTimeout) {
		return fmt.Errorf("subscribe to %s timed out after %s", subscribeTopic, connectTimeout)
	}
	if err := token.Error(); err != nil {
		return fmt.Errorf("subscribe to %s: %w", subscribeTopic, err)
	}

	slog.Info("metrics-collector: subscribed", "topic", subscribeTopic)

	<-ctx.Done()
	return nil
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

// getEnvOrDefault reads name from the environment, returning fallback if
// it is unset or empty.
func getEnvOrDefault(name, fallback string) string {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return fallback
	}
	return value
}

// buildMQTTClient assembles and connects the mTLS MQTT client this
// process subscribes with, bootstrapping its own mTLS identity directly
// via pki.NewClient (CA-F-04) - this process has no inbound listener or
// other outbound client to reuse an identity from, same "one identity
// role, bootstrapped directly" shape as Entry-Hub's own
// buildSecuritySwitchClient (see this file's package doc comment).
// pki.TLSConfig extracts the resulting *tls.Config, pki.ClientTLSConfig
// clones it with ServerName forced to metrics.OrganizationMQTTBroker, and
// metrics.TLSConfig layers PKI-F-02's organization check on top. Unlike
// every publish-side service's buildMetricsClient (which returns nil, nil
// when metrics publishing is left unconfigured), every value here is
// required — see this file's package doc comment for why.
func buildMQTTClient(ctx context.Context) (mqtt.Client, error) {
	brokerURL, err := requireEnv(envMQTTBrokerURL)
	if err != nil {
		return nil, err
	}

	token, err := pki.LoadBootstrapToken()
	if err != nil {
		return nil, fmt.Errorf("load ca bootstrap token: %w", err)
	}

	client, err := pki.NewClient(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("bootstrap mqtt client identity from certificate-authority: %w", err)
	}

	base, err := pki.TLSConfig(client)
	if err != nil {
		return nil, fmt.Errorf("extract mqtt tls config: %w", err)
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(base, metrics.OrganizationMQTTBroker))

	return metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout)
}
