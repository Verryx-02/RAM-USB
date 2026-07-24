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
// instead: deployments/compose/certificate-authority.yml's
// certificate-authority-config-init step pre-seeds step-ca's ca.json
// config with "logger": {"format": "json"} before step-ca's own first
// start, and the certificate-authority service's own command: override
// tees step-ca's stderr (where its logger always writes, confirmed live -
// no config option redirects it to a file directly) into a file on a
// shared, read-only-mounted volume this process reads from
// (envAccessLogPath).
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
// # Identity and mesh membership
//
// This process holds no server role and no outbound HTTP-client role
// beyond CA-F-04's own bootstrap exchange (pki.NewClientWithDialer,
// discarding the resulting *http.Client immediately after extracting its
// *tls.Config via pki.TLSConfig - see pki.TLSConfig's own doc comment,
// "e.g. Metrics-Collector's MQTT-only subscribe identity", the same shape
// this process needs) - its one and only outbound connection after
// startup is CA-F-03's own MQTT publish. It therefore joins the mesh via
// pkg/mesh's in-process tsnet, the same reasoning
// services/entry-hub/cmd/entry-hub/main.go's own package doc comment gives
// for Entry-Hub staying on pkg/mesh rather than a real OS tailscaled: no
// server role means no ca.BootstrapServer library limitation to work
// around (see .claude/agent-memory/code-agent.md's "pkg/pki dialer
// routing" entry). Its Headscale pre-auth key is minted with the SAME
// tag:certificate-authority tag services/network-manager/internal/
// headscale/policy.go's certificate-authority-mesh sidecar already uses -
// that tag's existing ACL rule already grants reachability to the MQTT
// broker's mesh identity (TagMQTTBroker), so no policy.go change is
// needed for a second tag:certificate-authority-tagged mesh node.
//
// This container also keeps a ramusb-net attachment (see
// deployments/compose/certificate-authority.yml): pkg/pki's very first
// CA-bootstrap-token exchange has no interceptable dial path (same
// documented library limitation Entry-Hub's own main.go relies on), so it
// always goes out over the container's default network path regardless of
// mesh membership.
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

	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/mesh"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/pki"
	"github.com/Verryx-02/RAM-USB/services/certificate-authority/internal/accesslog"
	"github.com/Verryx-02/RAM-USB/services/certificate-authority/internal/counters"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Env var names, following the same RAM_USB_<SERVICE>_<PURPOSE> convention
// every other mesh-joined service's own main.go uses.
const (
	// envAccessLogPath is the shared, read-only-mounted file this process
	// tails (CA-F-03) - see this file's own package doc comment for how it
	// gets there.
	envAccessLogPath = "RAM_USB_CERTIFICATE_AUTHORITY_ACCESS_LOG_PATH"

	// envMeshDir/envMeshHostname/envMeshAuthKey are this node's own
	// pkg/mesh identity - distinct from certificate-authority-mesh's own
	// sidecar identity (deployments/compose/certificate-authority.yml),
	// which is a separate tailscale/tailscale container sharing
	// Certificate-Authority's OWN network namespace, not this Go process.
	envMeshDir      = "RAM_USB_CERTIFICATE_AUTHORITY_METRICS_MESH_DIR"
	envMeshHostname = "RAM_USB_CERTIFICATE_AUTHORITY_METRICS_MESH_HOSTNAME"
	//nolint:gosec // an env var *name*, not a credential value
	envMeshAuthKey = "RAM_USB_CERTIFICATE_AUTHORITY_METRICS_TAILSCALE_AUTHKEY"

	// envMeshControlURL/envMeshControlCAFile are shared, unmodified,
	// verbatim env var names every mesh-joined service already reads -
	// see services/entry-hub/cmd/entry-hub/main.go's own doc comments for
	// why the same names are reused rather than a per-service variant.
	envMeshControlURL    = "RAM_USB_TAILSCALE_CONTROL_URL"
	envMeshControlCAFile = "RAM_USB_TAILSCALE_CONTROL_CA_FILE"

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

	accessLogPath, err := requireEnv(envAccessLogPath)
	if err != nil {
		return err
	}

	meshNode, err := buildMeshNode(ctx)
	if err != nil {
		return fmt.Errorf("join mesh: %w", err)
	}
	defer func() {
		if closeErr := meshNode.Close(); closeErr != nil {
			slog.Warn("certificate-authority-metrics: mesh node close error", "error", logging.Sanitize(closeErr.Error()))
		}
	}()

	mqttTLSBase, err := buildMQTTIdentity(ctx, meshNode.Dial)
	if err != nil {
		return fmt.Errorf("bootstrap mtls identity from certificate-authority: %w", err)
	}

	acc := &counters.Counters{}

	metricsClient, err := buildMetricsClient(mqttTLSBase, meshNode.Dial)
	if err != nil {
		return fmt.Errorf("build metrics client: %w", err)
	}
	if metricsClient != nil {
		defer metricsClient.Disconnect(250)
		go metrics.Run(ctx, metricsPublishInterval, func(publishCtx context.Context) error {
			return metrics.PublishOnce(publishCtx, metricsClient, serviceName, acc.Snapshot())
		})
	}

	logFile, err := os.Open(accessLogPath)
	if err != nil {
		return fmt.Errorf("open access log %s: %w", accessLogPath, err)
	}
	defer logFile.Close()

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

// requireEnv reads name from the environment, failing closed (RD-04) if it
// is unset or empty.
func requireEnv(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return value, nil
}

// buildMeshNode joins this process to the private Headscale mesh using
// envMeshDir/envMeshHostname/envMeshControlURL/envMeshAuthKey, failing
// closed (RD-04) if any is unset. ctx bounds only the join itself; the
// returned node lives for this process's whole lifetime (closed via a
// deferred call in run).
func buildMeshNode(ctx context.Context) (*mesh.Server, error) {
	dir, err := requireEnv(envMeshDir)
	if err != nil {
		return nil, err
	}
	hostname, err := requireEnv(envMeshHostname)
	if err != nil {
		return nil, err
	}
	controlURL, err := requireEnv(envMeshControlURL)
	if err != nil {
		return nil, err
	}
	authKey, err := requireEnv(envMeshAuthKey)
	if err != nil {
		return nil, err
	}
	// Optional - see envMeshControlCAFile's own doc comment on every
	// other service's main.go for why this is only set in local dev.
	controlCAFile := os.Getenv(envMeshControlCAFile)

	return mesh.Up(ctx, mesh.Config{
		Dir:           dir,
		Hostname:      hostname,
		ControlURL:    controlURL,
		AuthKey:       authKey,
		ControlCAFile: controlCAFile,
	})
}

// buildMQTTIdentity bootstraps this process's one and only mTLS identity
// (CA-F-04) via the Certificate-Authority and returns its *tls.Config,
// extracted via pki.TLSConfig before the *http.Client itself is discarded
// - this process makes no other outbound HTTP call, so there is no
// ForceServerName/mtls.WrapRoundTripper step to perform the way a service
// with a real HTTP-client role (e.g. Entry-Hub's buildSecurityWitchClient)
// needs. dial routes the bootstrapped client's own background certificate
// renewal through the mesh; the one-time bootstrap-token exchange itself
// is not routable regardless (see this file's own package doc comment).
func buildMQTTIdentity(ctx context.Context, dial pki.DialFunc) (*tls.Config, error) {
	token, err := pki.LoadBootstrapToken()
	if err != nil {
		return nil, fmt.Errorf("load ca bootstrap token: %w", err)
	}

	client, err := pki.NewClientWithDialer(ctx, token, dial)
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
// certificate. dial routes the connection itself through the mesh. A nil,
// nil return (no error) means metrics publishing is not configured
// (envMQTTBrokerURL unset).
func buildMetricsClient(mqttTLSBase *tls.Config, dial metrics.DialFunc) (mqtt.Client, error) {
	brokerURL, ok := os.LookupEnv(envMQTTBrokerURL)
	if !ok || brokerURL == "" {
		slog.Warn("certificate-authority-metrics: metrics publishing disabled, " + envMQTTBrokerURL + " is not set")
		return nil, nil
	}

	tlsConfig := metrics.TLSConfig(pki.ClientTLSConfig(mqttTLSBase, metrics.OrganizationMQTTBroker))

	client, err := metrics.NewClient(brokerURL, tlsConfig, metricsClientID, connectTimeout, metrics.WithDial(dial))
	if err != nil {
		return nil, err
	}

	return client, nil
}
