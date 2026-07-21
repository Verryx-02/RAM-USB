package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/services/metrics-collector/internal/collector"
	"github.com/Verryx-02/RAM-USB/services/metrics-collector/internal/schema"
	"github.com/Verryx-02/RAM-USB/services/metrics-collector/internal/store"
)

// This file verifies MT-F-01 through MT-F-04 end to end against the REAL
// running deployments/docker-compose.dev.yml stack (mqtt-broker,
// metrics-collector-timescaledb, grafana) - not the hand-written fakes
// internal/collector/collector_test.go and internal/store/store_test.go
// already cover. It mirrors this codebase's established real-infra
// integration test pattern exactly: env-var-gated skip (same shape as
// services/security-switch/cmd/security-switch/main_integration_test.go's
// skipUnlessCAConfigured and
// services/network-manager/internal/headscale/policy_integration_test.go's
// NM_TEST_HEADSCALE_ADDR gate), calling this package's own production
// functions/types against real infrastructure rather than reinventing a
// second wiring path, and a doc comment on every test stating the
// specific claim a synthetic/fake-based unit test could not prove.
//
// A non-obvious finding from building this file, worth stating explicitly
// since it shapes every ACL test below: for MQTT 3.1.1 (what
// github.com/eclipse/paho.mqtt.golang and Mosquitto both default to),
// neither a denied PUBLISH nor a denied SUBSCRIBE surfaces as a client-
// visible error at all. Confirmed empirically this session: a PUBLISH to
// a topic the client's ACL grant does not cover returns token.Error() ==
// nil (mosquitto just silently drops it, logging "Denied PUBLISH"
// broker-side only); a SUBSCRIBE to a topic the client has no read grant
// for still gets a normal, successful SUBACK (mosquitto grants the
// subscription unconditionally and instead silently withholds delivery of
// any message that ACL would deny). So "check the returned token/error"
// is not a signal MQTT 3.1.1 + Mosquitto's ACL model actually provides.
// The real, protocol-level, client-observable signal this file uses
// instead is delivery itself: whether a subscriber's MessageHandler
// actually fires within a bounded wait, with a same-shaped permitted
// control case run alongside every denial case to prove the absence of a
// message is the ACL's doing and not a broken test fixture.
const (
	// mqttBrokerURLEnvVar gates every MQTT-broker-touching test below.
	// Same naming shape as store_test.go's databaseURLEnvVar
	// (METRICS_COLLECTOR_TEST_DATABASE_URL) and the PKI_TEST_CA_URL /
	// NM_TEST_HEADSCALE_ADDR convention already established elsewhere.
	mqttBrokerURLEnvVar = "METRICS_COLLECTOR_TEST_MQTT_BROKER_URL"

	// mqttCertsDirEnvVar locates third-party/mosquitto/generate-dev-certs.sh's
	// output directory (one client cert/key pair per identity, plus the
	// dev CA bundle - see that script's own doc comment). Optional:
	// defaults to this repository's checked-in relative path from this
	// test file's own directory, the same "optional env var, checked-in
	// default path" shape as main.go's own envMigrationsDir.
	mqttCertsDirEnvVar = "METRICS_COLLECTOR_TEST_MQTT_CERTS_DIR"

	// defaultMQTTCertsDir is mqttCertsDirEnvVar's fallback, relative to
	// this file's own package directory
	// (services/metrics-collector/cmd/metrics-collector).
	defaultMQTTCertsDir = "../../../../third-party/mosquitto/certs"

	// databaseURLEnvVar gates every TimescaleDB-touching test below. Same
	// value as internal/store/store_test.go's own databaseURLEnvVar
	// (a distinct Go identifier in this distinct package, intentionally
	// the same string - both point at the one real
	// metrics-collector-timescaledb instance).
	databaseURLEnvVar = "METRICS_COLLECTOR_TEST_DATABASE_URL"

	// grafanaURLEnvVar gates the MT-F-04 test below, e.g.
	// "http://localhost:3000".
	grafanaURLEnvVar = "METRICS_COLLECTOR_TEST_GRAFANA_URL"

	// connectTimeoutTest bounds every real-broker connection attempt
	// below.
	connectTimeoutTest = 10 * time.Second

	// deliveryWaitTest bounds how long a delivery-observation test waits
	// for a MessageHandler to fire before concluding "not delivered".
	deliveryWaitTest = 3 * time.Second
)

func skipUnlessMQTTConfigured(t *testing.T) (brokerURL, certsDir string) {
	t.Helper()

	brokerURL = os.Getenv(mqttBrokerURLEnvVar)
	if brokerURL == "" {
		t.Skipf("%s not set; skipping the real-Mosquitto MT-F-01/MT-F-02 test. "+
			"Run `third-party/mosquitto/generate-dev-certs.sh` then "+
			"`docker compose -f deployments/docker-compose.dev.yml up mqtt-broker` "+
			"and set this variable (e.g. tls://localhost:8883) to run it.", mqttBrokerURLEnvVar)
	}

	certsDir = getEnvOrDefault(mqttCertsDirEnvVar, defaultMQTTCertsDir)
	return brokerURL, certsDir
}

func skipUnlessDatabaseConfigured(t *testing.T) string {
	t.Helper()

	databaseURL := os.Getenv(databaseURLEnvVar)
	if databaseURL == "" {
		t.Skipf("%s not set; skipping the real-TimescaleDB MT-F-03 test. "+
			"Run `docker compose -f deployments/docker-compose.dev.yml up metrics-collector-timescaledb` "+
			"and set this variable to run it.", databaseURLEnvVar)
	}
	return databaseURL
}

func skipUnlessGrafanaConfigured(t *testing.T) string {
	t.Helper()

	grafanaURL := os.Getenv(grafanaURLEnvVar)
	if grafanaURL == "" {
		t.Skipf("%s not set; skipping the real-Grafana MT-F-04 test. "+
			"Run `docker compose -f deployments/docker-compose.dev.yml up grafana metrics-collector-timescaledb` "+
			"and set this variable (e.g. http://localhost:3000) to run it.", grafanaURLEnvVar)
	}
	return grafanaURL
}

// testMQTTClient builds and connects a real mTLS MQTT client under
// identity (e.g. "EntryHub", "DatabaseVault", "MetricsCollector" - one of
// third-party/mosquitto/generate-dev-certs.sh's issued identities), via
// this package's own production metrics.NewClient - the same function
// buildMQTTClient (main.go) and every publish-side service's own
// buildMetricsClient call - so this test exercises the real client
// construction path, not a hand-rolled substitute.
func testMQTTClient(t *testing.T, identity, brokerURL, certsDir, clientID string) mqtt.Client {
	t.Helper()

	certPath := filepath.Join(certsDir, identity+".dev-only.crt")
	keyPath := filepath.Join(certsDir, identity+".dev-only.key")
	caPath := filepath.Join(certsDir, "mqtt-dev-ca.dev-only.crt")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("tls.LoadX509KeyPair(%s identity) error = %v — run third-party/mosquitto/generate-dev-certs.sh first", identity, err)
	}
	rootCAs, err := loadCertPool(caPath)
	if err != nil {
		t.Fatalf("loadCertPool(%s) error = %v", caPath, err)
	}

	client, err := metrics.NewClient(brokerURL, cert, rootCAs, clientID, connectTimeoutTest)
	if err != nil {
		t.Fatalf("metrics.NewClient(%s) error = %v", identity, err)
	}
	t.Cleanup(func() { client.Disconnect(250) })

	return client
}

// setUpRealDatabase applies services/metrics-collector/migrations against
// databaseURL (idempotent - migrate.ErrNoChange is fine, see
// internal/schema's own doc comment) and returns a connected pool, rolling
// the schema back via t.Cleanup exactly like
// internal/store/store_test.go's own TestStore_Insert_Postgres.
func setUpRealDatabase(ctx context.Context, t *testing.T, databaseURL string) *pgxpool.Pool {
	t.Helper()

	migrationsDir, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("resolve migrations directory: %v", err)
	}

	m, err := schema.New(databaseURL, migrationsDir)
	if err != nil {
		t.Fatalf("schema.New: %v", err)
	}
	if err := schema.Apply(m); err != nil {
		t.Fatalf("schema.Apply: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			t.Errorf("roll back migrations during cleanup: %v", err)
		}
	})

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	return pool
}

// Requirement: MT-F-01
// Requirement: MT-F-02
// Requirement: MT-F-03
//
// The end-to-end happy path this task's own manual `docker compose up`
// verification exercised by hand: a real EntryHub-identity MQTT client
// calls this project's own metrics.PublishOnce (the exact function every
// publish-side service's main.go uses) against the real Mosquitto broker;
// a real MetricsCollector-identity subscriber, wired through this
// package's own collector.Handler and a real store.Store bound to the
// real TimescaleDB, receives it. Success here is a row actually landing
// in the "metrics" table with the published fields, not merely "no error
// was returned" - the same standard docs/Test_Plan.md §2.3 names for a
// functional system test ("a registration request ... producing a metric
// in TimescaleDB").
func TestMetricsPipeline_RealBroker_RealTimescaleDB_AcceptsMatchingPayload(t *testing.T) {
	brokerURL, certsDir := skipUnlessMQTTConfigured(t)
	databaseURL := skipUnlessDatabaseConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := setUpRealDatabase(ctx, t, databaseURL)

	subscriber := testMQTTClient(t, "MetricsCollector", brokerURL, certsDir, "itest-collector-happy-path")
	handler := &collector.Handler{Store: store.Store{DB: store.PoolQuerier{Pool: pool}}}
	subToken := subscriber.Subscribe("metrics/#", 1, handler.OnMessage)
	if !subToken.WaitTimeout(connectTimeoutTest) || subToken.Error() != nil {
		t.Fatalf("Subscribe(metrics/#) error = %v", subToken.Error())
	}

	publisher := testMQTTClient(t, "EntryHub", brokerURL, certsDir, "itest-entryhub-happy-path")

	// A sentinel RequestCount value distinguishes this test's row from any
	// other "Entry-Hub" row a concurrent/prior test run may have left
	// behind in the same shared real database.
	sentinel := time.Now().UnixNano() % 1_000_000
	counters := metrics.Counters{
		RequestCount:          sentinel,
		ErrorCount:            2,
		AverageResponseTimeMs: 17.25,
		ActiveConnections:     4,
	}

	if err := metrics.PublishOnce(ctx, publisher, "Entry-Hub", counters); err != nil {
		t.Fatalf("metrics.PublishOnce() error = %v, want nil", err)
	}

	var (
		errorCount        int64
		avgResponseTimeMs float64
		activeConnections int64
	)
	deadline := time.Now().Add(deliveryWaitTest + 5*time.Second)
	for {
		row := pool.QueryRow(ctx,
			"SELECT error_count, average_response_time_ms, active_connections FROM metrics WHERE service = $1 AND request_count = $2",
			"Entry-Hub", sentinel)
		err := row.Scan(&errorCount, &avgResponseTimeMs, &activeConnections)
		if err == nil {
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("query inserted row: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("row for service=Entry-Hub request_count=%d never appeared within %s", sentinel, deliveryWaitTest+5*time.Second)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if errorCount != counters.ErrorCount {
		t.Errorf("error_count = %d, want %d", errorCount, counters.ErrorCount)
	}
	if avgResponseTimeMs != counters.AverageResponseTimeMs {
		t.Errorf("average_response_time_ms = %v, want %v", avgResponseTimeMs, counters.AverageResponseTimeMs)
	}
	if activeConnections != counters.ActiveConnections {
		t.Errorf("active_connections = %d, want %d", activeConnections, counters.ActiveConnections)
	}
}

// Requirement: MT-F-01
// Requirement: MT-F-02
//
// EntryHub's ACL grant (third-party/mosquitto/acl.conf) is "topic write
// metrics/Entry-Hub" - nothing else. This proves, by observing actual
// message delivery to a real subscriber (see this file's own top doc
// comment for why token.Error() is not the observable signal here), that
// a publish to a DIFFERENT service's topic is never delivered, while a
// publish to its own topic - the control case, run in the same test -
// is, isolating the negative result as the ACL's doing rather than a
// broken subscriber.
func TestMQTTACL_WriteGrant_OnlyDeliversToOwnTopic(t *testing.T) {
	brokerURL, certsDir := skipUnlessMQTTConfigured(t)

	received := make(chan string, 4)
	subscriber := testMQTTClient(t, "MetricsCollector", brokerURL, certsDir, "itest-collector-write-acl")
	subToken := subscriber.Subscribe("metrics/#", 1, func(_ mqtt.Client, msg mqtt.Message) {
		received <- msg.Topic()
	})
	if !subToken.WaitTimeout(connectTimeoutTest) || subToken.Error() != nil {
		t.Fatalf("Subscribe(metrics/#) error = %v", subToken.Error())
	}

	publisher := testMQTTClient(t, "EntryHub", brokerURL, certsDir, "itest-entryhub-write-acl")

	t.Run("publish to another service's topic is never delivered", func(t *testing.T) {
		marker := fmt.Sprintf(`{"marker":"%d"}`, time.Now().UnixNano())
		token := publisher.Publish("metrics/Database-Vault", 1, false, marker)
		token.WaitTimeout(connectTimeoutTest)
		if token.Error() != nil {
			t.Fatalf("Publish() error = %v, want nil (the client itself does not observe an ACL denial - see this file's top doc comment)", token.Error())
		}

		select {
		case topic := <-received:
			t.Fatalf("subscriber received a message on %q it should never have gotten (EntryHub has no write grant for metrics/Database-Vault)", topic)
		case <-time.After(deliveryWaitTest):
			// Expected: nothing arrives.
		}
	})

	t.Run("publish to its own topic IS delivered (control)", func(t *testing.T) {
		token := publisher.Publish("metrics/Entry-Hub", 1, false, "control-message")
		token.WaitTimeout(connectTimeoutTest)
		if token.Error() != nil {
			t.Fatalf("Publish() error = %v, want nil", token.Error())
		}

		select {
		case topic := <-received:
			if topic != "metrics/Entry-Hub" {
				t.Fatalf("received topic = %q, want metrics/Entry-Hub", topic)
			}
		case <-time.After(deliveryWaitTest):
			t.Fatal("control message on EntryHub's own granted topic was never delivered - subscriber/broker setup itself is broken, not just the ACL case above")
		}
	})
}

// Requirement: MT-F-01
//
// MetricsCollector's ACL grant is "topic read metrics/#"; no other
// identity has any read grant at all. This proves, again via observed
// delivery rather than a client-side error (see this file's own top doc
// comment), that a client with no read grant never receives a message
// even though the SUBSCRIBE call itself succeeds - while a genuinely
// entitled subscriber (MetricsCollector, run in parallel as the control)
// does receive the exact same publish, proving the message really was
// delivered somewhere and the negative result isolates EntryHub's own
// missing grant specifically.
func TestMQTTACL_ReadGrant_OnlyMetricsCollectorReceives(t *testing.T) {
	brokerURL, certsDir := skipUnlessMQTTConfigured(t)

	unauthorizedReceived := make(chan string, 4)
	unauthorizedSubscriber := testMQTTClient(t, "EntryHub", brokerURL, certsDir, "itest-entryhub-read-acl")
	unauthorizedToken := unauthorizedSubscriber.Subscribe("metrics/#", 1, func(_ mqtt.Client, msg mqtt.Message) {
		unauthorizedReceived <- msg.Topic()
	})
	if !unauthorizedToken.WaitTimeout(connectTimeoutTest) || unauthorizedToken.Error() != nil {
		t.Fatalf("Subscribe(metrics/#) error = %v (SUBACK itself is expected to succeed even without a read grant - see this file's top doc comment)", unauthorizedToken.Error())
	}

	authorizedReceived := make(chan string, 4)
	authorizedSubscriber := testMQTTClient(t, "MetricsCollector", brokerURL, certsDir, "itest-collector-read-acl")
	authorizedToken := authorizedSubscriber.Subscribe("metrics/#", 1, func(_ mqtt.Client, msg mqtt.Message) {
		authorizedReceived <- msg.Topic()
	})
	if !authorizedToken.WaitTimeout(connectTimeoutTest) || authorizedToken.Error() != nil {
		t.Fatalf("Subscribe(metrics/#) error = %v", authorizedToken.Error())
	}

	publisher := testMQTTClient(t, "DatabaseVault", brokerURL, certsDir, "itest-databasevault-read-acl")
	token := publisher.Publish("metrics/Database-Vault", 1, false, "read-acl-probe")
	token.WaitTimeout(connectTimeoutTest)
	if token.Error() != nil {
		t.Fatalf("Publish() error = %v, want nil", token.Error())
	}

	select {
	case topic := <-authorizedReceived:
		if topic != "metrics/Database-Vault" {
			t.Fatalf("authorized subscriber received topic = %q, want metrics/Database-Vault", topic)
		}
	case <-time.After(deliveryWaitTest):
		t.Fatal("MetricsCollector (a genuinely entitled subscriber) never received the control publish - message was never actually delivered by the broker, so the negative case below would prove nothing")
	}

	select {
	case topic := <-unauthorizedReceived:
		t.Fatalf("EntryHub (no read grant for metrics/#) received a message on %q; MT-F-01 requires only MetricsCollector can read metrics/*", topic)
	case <-time.After(200 * time.Millisecond):
		// Expected: nothing arrives - already confirmed the message was
		// delivered to the authorized subscriber above, so this short
		// extra wait is just draining any in-flight delivery, not the
		// primary timeout.
	}
}

// Requirement: MT-F-02
//
// The ACL only restricts which TOPIC EntryHub may write to - it has a
// full, legitimate write grant for metrics/Entry-Hub. This proves
// Metrics-Collector's own Handler.Handle (internal/collector/collector.go)
// is what discards a payload whose "service" field disagrees with that
// topic, independently of the ACL: the message here arrives on a topic
// EntryHub is fully entitled to publish on, so if this row ever appeared
// in TimescaleDB, the ACL would have nothing to do with preventing it -
// only this package's own validation logic does.
func TestMetricsPipeline_ServiceTopicMismatch_IsDiscardedNotStored(t *testing.T) {
	brokerURL, certsDir := skipUnlessMQTTConfigured(t)
	databaseURL := skipUnlessDatabaseConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := setUpRealDatabase(ctx, t, databaseURL)

	subscriber := testMQTTClient(t, "MetricsCollector", brokerURL, certsDir, "itest-collector-mismatch")
	handler := &collector.Handler{Store: store.Store{DB: store.PoolQuerier{Pool: pool}}}
	subToken := subscriber.Subscribe("metrics/#", 1, handler.OnMessage)
	if !subToken.WaitTimeout(connectTimeoutTest) || subToken.Error() != nil {
		t.Fatalf("Subscribe(metrics/#) error = %v", subToken.Error())
	}

	publisher := testMQTTClient(t, "EntryHub", brokerURL, certsDir, "itest-entryhub-mismatch")

	sentinel := time.Now().UnixNano() % 1_000_000
	mismatched := metrics.Payload{
		// EntryHub publishes ON ITS OWN, fully-permitted topic
		// (metrics/Entry-Hub - see the Publish call below) but claims a
		// different service inside the payload body.
		Service:               "Database-Vault",
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		RequestCount:          sentinel,
		ErrorCount:            0,
		AverageResponseTimeMs: 1,
		ActiveConnections:     1,
	}
	body, err := json.Marshal(mismatched)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	token := publisher.Publish("metrics/Entry-Hub", 1, false, body)
	token.WaitTimeout(connectTimeoutTest)
	if token.Error() != nil {
		t.Fatalf("Publish() error = %v, want nil", token.Error())
	}

	// Give the subscriber's OnMessage callback time to run (and, if the
	// discard logic were broken, time to insert) before checking for
	// absence - a fixed wait, not a poll-until-found loop, since this
	// test's whole point is proving something does NOT happen.
	time.Sleep(deliveryWaitTest)

	var count int
	row := pool.QueryRow(ctx, "SELECT count(*) FROM metrics WHERE service = $1 AND request_count = $2", "Database-Vault", sentinel)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("query for the mismatched row: %v", err)
	}
	if count != 0 {
		t.Fatalf("found %d row(s) for the mismatched payload (service=Database-Vault, request_count=%d) - Handler.Handle should have discarded it, not stored it", count, sentinel)
	}
}

// Requirement: MT-F-03
//
// Proves the migration's EFFECT persists in the real database - not
// merely that services/metrics-collector/migrations/000001_create_metrics_table.up.sql
// ran once without error (already covered by
// internal/store/store_test.go's own real-Postgres test and by this
// session's earlier manual `psql` verification). Queries TimescaleDB's own
// catalog views directly, the same views an operator would check to
// confirm the policy is really configured: timescaledb_information.
// hypertables (the "metrics" hypertable exists) and timescaledb_information.
// jobs (a policy_retention job with drop_after = 30 days, and a
// policy_compression job with compress_after = 7 days, both scoped to the
// "metrics" hypertable - exact column/job-config shape confirmed live
// this session against timescale/timescaledb:2.23.0-pg18).
func TestTimescaleDBPolicy_HypertableRetentionAndCompressionConfigured(t *testing.T) {
	databaseURL := skipUnlessDatabaseConfigured(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := setUpRealDatabase(ctx, t, databaseURL)

	t.Run("metrics is a hypertable", func(t *testing.T) {
		var hypertableName string
		row := pool.QueryRow(ctx, "SELECT hypertable_name FROM timescaledb_information.hypertables WHERE hypertable_name = 'metrics'")
		if err := row.Scan(&hypertableName); err != nil {
			t.Fatalf("query timescaledb_information.hypertables: %v (metrics is not registered as a hypertable)", err)
		}
	})

	t.Run("30-day retention policy is configured", func(t *testing.T) {
		var dropAfter string
		row := pool.QueryRow(ctx,
			"SELECT config->>'drop_after' FROM timescaledb_information.jobs WHERE proc_name = 'policy_retention' AND hypertable_name = 'metrics'")
		if err := row.Scan(&dropAfter); err != nil {
			t.Fatalf("query timescaledb_information.jobs (retention): %v", err)
		}
		if dropAfter != "30 days" {
			t.Fatalf("retention policy drop_after = %q, want %q", dropAfter, "30 days")
		}
	})

	t.Run("7-day columnstore compression policy is configured", func(t *testing.T) {
		var compressAfter string
		row := pool.QueryRow(ctx,
			"SELECT config->>'compress_after' FROM timescaledb_information.jobs WHERE proc_name = 'policy_compression' AND hypertable_name = 'metrics'")
		if err := row.Scan(&compressAfter); err != nil {
			t.Fatalf("query timescaledb_information.jobs (compression): %v", err)
		}
		if compressAfter != "7 days" {
			t.Fatalf("compression policy compress_after = %q, want %q", compressAfter, "7 days")
		}
	})
}

// Requirement: MT-F-04
//
// Closes the loop past "the dashboard JSON file exists on disk"
// (third-party/grafana/dashboards/metrics-overview.json, present since
// this task's first pass): confirms, against a real running Grafana, that
// the datasource provisioning actually produced a healthy, queryable
// TimescaleDB connection, and that the dashboard the provisioning loaded
// is genuinely retrievable via Grafana's own API - not merely readable as
// a file.
func TestGrafana_DatasourceHealthyAndDashboardLoadable(t *testing.T) {
	grafanaURL := skipUnlessGrafanaConfigured(t)

	client := &http.Client{Timeout: 10 * time.Second}

	t.Run("Grafana itself reports healthy", func(t *testing.T) {
		resp, err := client.Get(grafanaURL + "/api/health") //nolint:noctx // test, client.Timeout already bounds this call
		if err != nil {
			t.Fatalf("GET /api/health: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/health status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("the provisioned TimescaleDB datasource is healthy", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, grafanaURL+"/api/datasources/uid/timescaledb/health", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		// Grafana's default dev-only admin credentials
		// (grafana/grafana:13.1's own default, not overridden by
		// deployments/docker-compose.dev.yml's grafana service) - the same
		// default this session's own manual verification used, confirmed
		// live to authenticate API calls without the UI's forced-password-
		// change flow blocking them.
		req.SetBasicAuth("admin", "admin")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /api/datasources/uid/timescaledb/health: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var body struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode response body: %v", err)
		}
		if resp.StatusCode != http.StatusOK || body.Status != "OK" {
			t.Fatalf("datasource health status = %d/%q, want %d/%q", resp.StatusCode, body.Status, http.StatusOK, "OK")
		}
	})

	t.Run("the metrics-overview dashboard is loadable via the API", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, grafanaURL+"/api/dashboards/uid/ram-usb-metrics-overview", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.SetBasicAuth("admin", "admin")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /api/dashboards/uid/ram-usb-metrics-overview: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var body struct {
			Dashboard struct {
				Panels []struct {
					Title string `json:"title"`
				} `json:"panels"`
			} `json:"dashboard"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode response body: %v", err)
		}
		// MT-F-04's literal three: response time, throughput, active
		// connections.
		if len(body.Dashboard.Panels) != 3 {
			t.Fatalf("dashboard has %d panel(s), want 3 (MT-F-04's response time/throughput/active connections)", len(body.Dashboard.Panels))
		}
	})
}
