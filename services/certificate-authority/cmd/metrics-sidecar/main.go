// Command metrics-sidecar implements CA-F-03: Certificate-Authority has no
// requirement of its own code to satisfy beyond this one (CA-F-01/CA-F-02
// are the underlying smallstep/step-ca product's own guarantees - see the
// SRS's own note after CA-F-04). step-ca has no native /metrics endpoint
// (confirmed against its own route table; still-open upstream GitHub issue
// #790) - this process is the workaround: it tails step-ca's own
// structured JSON access log (services/certificate-authority/internal/
// accesslog), derives RequestCount/ErrorCount/AverageResponseTimeMs from
// it (services/certificate-authority/internal/counters), and republishes
// them via pkg/metrics (CA-F-03's own "metrics/Certificate-Authority"
// topic) exactly like every other service.
//
// # Why a separate process, not code inside step-ca itself
//
// step-ca is a third-party binary (github.com/smallstep/certificates),
// not RAM-USB's own code - there is no hook to add a metrics publish loop
// to it directly. This sidecar reads step-ca's own log stream out-of-band
// instead. Since docs/Known_Issues.md's KI-28, this process is no longer a
// separate container: it is s6-supervised alongside step-ca itself, inside
// the SAME "certificate-authority" container/image
// (deployments/docker/certificate-authority/), reading step-ca's tee'd
// access log from a plain local filesystem path
// (envAccessLogPath) rather than a cross-container shared Docker volume.
//
// # RD-01: what this process reads, and what it never lets past its own
// boundary
//
// A step-ca "/sign" access-log line additionally carries "ott" (the
// CA-F-04 bootstrap token, in cleartext), the full issued "certificate",
// "subject", "sans", "issuer", and "provisioner" - accesslog.ParseLine
// decodes ONLY "status"/"duration-ns" from every line (enforced by its
// decode target's own field set, not a runtime filter - see that
// package's own doc comment). This process never logs, persists, or
// forwards a raw log line's content anywhere: internal/counters.Counters
// only ever receives the two already-extracted integers, and this file's
// own error handling for a malformed/non-JSON line (accesslog.ParseLine's
// err return, e.g. step-ca's own plain-text startup banner lines sharing
// this same log stream) logs that the line was skipped, never the line
// itself.
//
// # Identity and mesh membership (KI-28)
//
// This process holds no server role: its own outbound calls are the
// CA-F-04 bootstrap-token exchange (against step-ca's own
// "https://localhost:9000", since it now runs inside the very same
// container - see deployments/docker/certificate-authority/rootfs's own
// mint-metrics-token oneshot for how that token reaches this process) and
// CA-F-03's periodic MQTT publish. It previously joined the mesh via
// pkg/mesh's in-process tsnet, mirroring Entry-Hub's own reasoning for
// staying off a real tailscaled (see services/entry-hub/cmd/entry-hub/
// main.go's package doc comment) - but KI-28 (docs/Known_Issues.md) found
// that reasoning did not actually hold for this process in production:
// Certificate-Authority itself is mesh-only reachable there (no published
// port, no shared Docker network - see
// deployments/proxmox/certificate-authority.md), and pkg/mesh's in-process
// tsnet has no OS-level route to fall back on for this process's own
// non-interceptable CA-bootstrap-token exchange, the same gap KI-27 found
// for Entry-Hub. Consolidating this process into Certificate-Authority's
// own container fixes this at its root rather than working around it:
// this container already runs a real OS-level `tailscaled` sidecar
// (`certificate-authority-mesh`, deployments/compose/
// certificate-authority.yml, sharing this container's network namespace)
// for step-ca's own inbound mesh reachability (NM-F-04) - since a real
// kernel `tailscale0` interface routes every outbound connection any
// process in this shared namespace makes, this process's own MQTT publish
// now goes out over the mesh automatically too, with zero mesh-membership
// code of its own (no pkg/mesh, no separate Tailscale identity/pre-auth
// key). Its own bootstrap-token exchange no longer needs mesh routing at
// all: the CA it bootstraps against is this same container's own step-ca
// process, reachable at https://localhost:9000 without leaving the
// container. This process therefore now calls pki.NewClient (no dialer
// parameter) exactly like Metrics-Collector's own client-role-only
// process (services/metrics-collector/cmd/metrics-collector/main.go),
// and passes a nil mesh.DialFunc to metrics.NewClient/pkg/metrics - see
// that function's own doc comment for why nil means "dial over this
// process's ordinary default route," which here is the shared real
// tailscale0 interface.
//
// It keeps its own separate CA-F-04 bootstrap token (subject
// "CertificateAuthority", matching third-party/mosquitto/acl.conf's
// existing MQTT ACL grant for that subject, not this container's own
// name) - a distinct mTLS identity is still required for MQTT publish,
// even though no separate mesh-join machinery is needed to reach the
// broker anymore.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/env"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/certificate-authority/internal/accesslog"
	"github.com/Verryx-02/RAM-USB/services/certificate-authority/internal/counters"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Env var names, following the same RAM_USB_<SERVICE>_<PURPOSE> convention
// every other mesh-joined service's own main.go uses.
const (
	// envAccessLogPath is the local file this process tails (CA-F-03),
	// written by step-ca's own tee'd command inside this same container
	// (see deployments/compose/certificate-authority.yml's own top
	// comment for how it gets there) - no longer a cross-container shared
	// volume, per KI-28.
	envAccessLogPath = "RAM_USB_CERTIFICATE_AUTHORITY_ACCESS_LOG_PATH"

	// envMQTTBrokerURL is the same shared env var name every other
	// service's own metrics client reads.
	envMQTTBrokerURL = "RAM_USB_MQTT_BROKER_URL"
)

// serviceName is this process's identifier in every metrics payload it
// publishes (CA-F-03), reproduced verbatim from the SRS's literal
// `metrics/Certificate-Authority` quote.
const serviceName = "Certificate-Authority"

// metricsClientID is the MQTT client identifier this process connects
// with - distinct from every other service's own client ID so the broker
// can tell every process's connection apart, and named for this specific
// process (not "certificate-authority" itself, which names the CA
// container, not this sidecar).
const metricsClientID = "certificate-authority-metrics"

// metricsPublishInterval is CA-F-03's "every minute, and only."
const metricsPublishInterval = time.Minute

// connectTimeout bounds how long this process waits for the MQTT broker's
// connection handshake at startup.
const connectTimeout = 10 * time.Second

// logPollInterval bounds how long accesslog.Follow waits between polls of
// envAccessLogPath when no new data is available - CA-F-03 only requires a
// once-a-minute aggregate, so a sub-second polling granularity here is
// already far finer than needed; chosen small enough that a burst of
// requests is reflected well within the same publish interval it occurs
// in, not to minimize latency for its own sake.
const logPollInterval = 500 * time.Millisecond

func main() {
	if err := run(); err != nil {
		slog.Error("certificate-authority-metrics: fatal startup error", "error", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	accessLogPath, err := env.Require(envAccessLogPath)
	if err != nil {
		return err
	}

	mqttTLSBase, err := buildMQTTIdentity(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap mtls identity from certificate-authority: %w", err)
	}

	acc := &counters.Counters{}

	metricsClient, err := buildMetricsClient(mqttTLSBase)
	if err != nil {
		return fmt.Errorf("build metrics client: %w", err)
	}
	defer metricsClient.Disconnect(250)
	go metrics.Run(ctx, metricsPublishInterval, func(publishCtx context.Context) error {
		return metrics.PublishOnce(publishCtx, metricsClient, serviceName, acc.Snapshot())
	})

	// codeql[go/path-injection] accessLogPath comes from env.Require(envAccessLogPath), an operator-supplied
	// deployment setting, not attacker input.
	logFile, err := os.Open(accessLogPath) //nolint:gosec // accessLogPath is an operator-supplied deployment setting, not attacker input
	if err != nil {
		return fmt.Errorf("open access log %s: %w", accessLogPath, err)
	}
	defer func() { _ = logFile.Close() }()

	// Only report on requests from this process's own start onward - see
	// accesslog.Follow's own doc comment.
	if _, err := logFile.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek access log %s: %w", accessLogPath, err)
	}

	followErr := accesslog.Follow(ctx, logFile, logPollInterval, func(line []byte) {
		entry, ok, err := accesslog.ParseLine(line)
		if err != nil {
			// Never log the raw line content (RD-01) - this branch is
			// expected for step-ca's own plain-text startup banner
			// lines, which share this same log stream.
			slog.Debug("certificate-authority-metrics: skipped a non-JSON access-log line")
			return
		}
		if !ok {
			return
		}
		acc.Record(entry.Status, entry.DurationNs)
	})
	if errors.Is(followErr, context.Canceled) {
		return nil
	}
	return followErr
}

// buildMQTTIdentity bootstraps this process's one and only mTLS identity
// (CA-F-04) via the Certificate-Authority and returns its *tls.Config,
// extracted via pki.TLSConfig before the *http.Client itself is discarded
// - this process makes no other outbound HTTP call, so there is no
// ForceServerName/mtls.WrapRoundTripper step to perform the way a service
// with a real HTTP-client role (e.g. Entry-Hub's buildSecurityWitchClient)
// needs. pki.NewClient (no dialer) is correct here per this file's own
// "Identity and mesh membership" package doc comment: the CA it
// bootstraps against is this same container's own step-ca process.
func buildMQTTIdentity(ctx context.Context) (*tls.Config, error) {
	token, err := pki.LoadBootstrapToken()
	if err != nil {
		return nil, fmt.Errorf("load ca bootstrap token: %w", err)
	}

	client, err := pki.NewClient(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("bootstrap mtls identity: %w", err)
	}

	base, err := pki.TLSConfig(client)
	if err != nil {
		return nil, fmt.Errorf("extract mqtt tls config: %w", err)
	}
	return base, nil
}

// buildMetricsClient assembles and connects the mTLS MQTT client CA-F-03's
// periodic publish uses, reusing mqttTLSBase (buildMQTTIdentity's own
// bootstrapped identity) as the source of this connection's client
// certificate. A nil mesh.DialFunc (see metrics.NewClient's own doc
// comment) means this connection goes out over this process's ordinary
// default route - the shared real tailscale0 interface, per this file's
// own "Identity and mesh membership" package doc comment.
//
// An unset envMQTTBrokerURL is a startup error, not a degraded mode
// (RD-04): publishing CA-F-03's metrics is the only thing this process
// exists to do, so a misconfigured broker URL must fail loudly at startup
// instead of leaving a process that tails the log forever and publishes
// nothing. Metrics-Collector reads the same variable the same way
// (services/metrics-collector/cmd/metrics-collector/main.go).
func buildMetricsClient(mqttTLSBase *tls.Config) (mqtt.Client, error) {
	brokerURL, err := env.Require(envMQTTBrokerURL)
	if err != nil {
		return nil, err
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(mqttTLSBase, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}
