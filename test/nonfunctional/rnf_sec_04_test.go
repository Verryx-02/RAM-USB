// Package nonfunctional holds system-level tests for non-functional
// requirements (RNF-*, docs/Test_Plan.md §2.3) measured against the real,
// already-running dev Docker stack (deployments/compose/*.yml) rather than
// a single service's own package - these checks span components no single
// service test file owns.
package nonfunctional

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// skipUnlessContainerRunning skips the test when the docker CLI is
// unavailable or the named container isn't currently running - these
// tests exercise the real dev stack (deployments/compose/*.yml), not a
// synthetic stand-in, so they need it up first (see each test's own doc
// comment for the exact `docker compose -f ... up` command).
func skipUnlessContainerRunning(t *testing.T, container string) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not available: %v", err)
	}

	out, err := exec.CommandContext(t.Context(), "docker", "inspect", "-f", "{{.State.Running}}", container).Output() //nolint:gosec // fixed container name literal per call site, not untrusted input
	if err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Skipf("container %q is not running; start it first (see this test's doc comment)", container)
	}
}

// Requirement: RNF-SEC-04
// Requirement: CA-F-04
//
// The Certificate-Authority's own bootstrap/issuance surface
// (POST /1.0/sign with a single-use out-of-band token, GET /health) is
// deliberately NOT mTLS-gated - a chicken-and-egg problem CA-F-04's own
// design solves with a token, not a pre-existing certificate, since a
// service can't present an mTLS client certificate before it has ever
// been issued one. That is a documented, spec-sanctioned exception, not
// this test's concern.
//
// What RNF-SEC-04 actually obligates for the CA's REAL day-to-day
// inter-service traffic is certificate RENEWAL: every RAM-USB service
// renews its own certificate automatically for the lifetime of its
// process (pki.NewServer/NewClient's doc comment), and step-ca's renewal
// mechanism authenticates the caller BY its current mTLS client
// certificate, not a token. This test proves that against the real
// running Certificate-Authority container
// (deployments/compose/certificate-authority.yml): a POST to /renew with
// NO client certificate presented is rejected.
//
// Run `deployments/scripts/certificate-authority.sh` (or
// `docker compose -f deployments/compose/certificate-authority.yml up`)
// first; this test skips cleanly if the container isn't running.
func TestCertificateAuthority_RealStack_RenewRejectsNoClientCert(t *testing.T) {
	const container = "certificate-authority"
	skipUnlessContainerRunning(t, container)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // this test only cares whether the CA demands a client cert, not about verifying its own server identity
		},
	}

	resp, err := client.Post("https://localhost:9000/renew", "application/json", nil) //nolint:noctx // test, fixed 10s client timeout above already bounds it
	if err != nil {
		// A transport-level failure (e.g. the TLS handshake itself
		// refusing a certificate-less client) is an even stronger form of
		// rejection than an HTTP 4xx - either satisfies "no client cert
		// works only fails closed".
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 400 {
		t.Fatalf("POST /renew with no client certificate: status = %d, want >= 400 (rejected)", resp.StatusCode)
	}
}

// Requirement: RNF-SEC-04
// Requirement: NET-F-02
//
// Mosquitto (third-party/mosquitto/mosquitto.conf: require_certificate
// true, allow_anonymous false, tls_version tlsv1.3) is every metrics
// publisher's (EH-F-10/SS-F-07/DV-F-16/ST-F-12/NM-F-17/CA-F-03) and
// Metrics-Collector's (MT-F-01/MT-F-02) MQTT broker. This test attempts a
// real TLS connection to the real running mqtt-broker container
// (deployments/compose/mqtt-broker.yml) presenting NO client certificate
// and confirms the connection cannot be used - proving mTLS is mandatory,
// not merely available, for this listener too.
//
// mosquitto's OpenSSL-backed TLS 1.3 stack does not always fail the raw
// handshake synchronously for a certificate-less client (confirmed live:
// crypto/tls.Dial can return successfully, deferring the "certificate
// required" rejection to the first attempted read/write) - this test
// therefore treats EITHER a Dial-time failure OR a definitive read/write
// error as proof of rejection, rather than assuming the failure point.
//
// Run `deployments/scripts/mqtt-broker.sh` (or
// `docker compose -f deployments/compose/mqtt-broker.yml up`) first; this
// test skips cleanly if the container isn't running.
func TestMosquitto_RealStack_RejectsNoClientCert(t *testing.T) {
	const container = "mqtt-broker"
	skipUnlessContainerRunning(t, container)

	dialCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // this test only cares whether the broker demands a client cert, not about verifying its own server identity
			MinVersion:         tls.VersionTLS13,
		},
	}
	conn, err := tlsDialer.DialContext(dialCtx, "tcp", "localhost:8883")
	if err != nil {
		// Rejected at the handshake itself - the strongest form of
		// rejection.
		return
	}
	defer func() { _ = conn.Close() }()

	// The handshake completed without a client certificate; mosquitto
	// defers the "certificate required" alert to the first application
	// data exchange - send a minimal MQTT CONNECT-style probe and read
	// the response, expecting a TLS-level rejection.
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("conn.SetDeadline() error = %v, want nil", err)
	}
	if _, err := conn.Write([]byte{0x10, 0x00}); err != nil {
		// Rejected while writing - also proof enough.
		return
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("conn.Read() after connecting with no client certificate error = nil, want a TLS rejection (e.g. \"certificate required\")")
	}
}

// Requirement: RNF-SEC-04
//
// This test documents a REAL, CONFIRMED violation of RNF-SEC-04 found
// during this task, not a false positive to be papered over: Grafana's
// connection to TimescaleDB (third-party/grafana/provisioning/
// datasources - "sslmode: disable", a plaintext password in
// secureJsonData) uses plain Postgres-wire-protocol password
// authentication over the mesh, with NO mTLS and no CA-F-04 bootstrap
// token at all. This is genuinely inter-service traffic (Grafana querying
// Metrics-Collector's embedded TimescaleDB for MT-F-04's dashboards), so
// RNF-SEC-04's "no exceptions" clause DOES apply here, unlike the CA's
// bootstrap surface or Entry-Hub's user-facing login listener (see the
// sibling tests in this file/package for those, both legitimate,
// documented exceptions).
//
// This test connects to the real running Metrics-Collector container's
// embedded TimescaleDB (docs/Known_Issues.md's KI-18: TimescaleDB now
// lives inside that container, not a separate one) using the exact
// plaintext connection string Grafana's own datasource provisioning uses,
// and asserts it is REJECTED. As of this task, it is NOT rejected - the
// query succeeds - so this test is EXPECTED TO FAIL until Grafana's
// connection to TimescaleDB is re-architected to require mTLS (a real
// architectural change, out of scope for a test-writing task - see this
// task's own report for the full explanation). Do not "fix" this test by
// weakening its assertion; the failure is the accurate, current state of
// RNF-SEC-04 on this path.
func TestGrafanaTimescaleDB_RealStack_RNF_SEC_04_PlaintextConnectionShouldBeRejected(t *testing.T) {
	const container = "metrics-collector"
	skipUnlessContainerRunning(t, container)

	// Exactly the connection Grafana's own datasource provisioning
	// (third-party/grafana/provisioning/datasources) uses: plaintext,
	// password-only, no client certificate, no mTLS.
	out, err := exec.CommandContext(t.Context(), "docker", "exec", container, "psql", //nolint:gosec // fixed container/args, not untrusted input
		"postgres://metrics_collector:metrics_collector_dev_only@localhost:5432/metrics_collector?sslmode=disable",
		"-c", "SELECT 1;").CombinedOutput()

	if err == nil {
		t.Fatalf("RNF-SEC-04 VIOLATION (confirmed, not a test bug): a plaintext, no-mTLS, password-only "+
			"connection to Metrics-Collector's TimescaleDB (Grafana's own real connection method, "+
			"third-party/grafana/provisioning/datasources) succeeded:\n%s\n"+
			"RNF-SEC-04 requires mTLS for ALL inter-service communication, with no exceptions. "+
			"This is a genuine, currently-unresolved architectural gap - see this task's report, "+
			"not a flaw in this test.", out)
	}
}
