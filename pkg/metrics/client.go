// Package metrics implements the periodic MQTT metrics publish every
// RAM-USB service performs: building an aggregated-only payload
// (BuildPayload/Payload/Counters), an mTLS-verified MQTT client to send it
// (NewClient/TLSConfig), and a once-per-minute scheduling loop
// (Run/PublishOnce). It backs EH-F-10/EH-F-11, SS-F-07/SS-F-08,
// DV-F-16/DV-F-17, ST-F-12/ST-F-13, NM-F-17/NM-F-18, and CA-F-03: every
// one of those requirements is identical modulo which service is
// publishing, so the client construction, TLS verification, payload
// envelope, and publish/schedule logic live here once. A service needing
// this package supplies only its own ServiceName/Topic identity (derived
// via TopicFor) and a Counters source (typically a small per-service
// request/error/response-time accumulator with a Snapshot method) -
// everything else is this package's job.
//
// Metrics-Collector (MT-F-01/MT-F-02, not yet implemented) will import
// this package's Payload type on its subscribe side once built, since the
// wire shape it must parse is the same one BuildPayload produces here.
package metrics

import (
	"crypto/tls"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Option configures optional NewClient behavior - see WithDial. The zero
// value of every Option's underlying config leaves NewClient's default
// (no Option passed) behavior exactly as it was before Option existed, so
// every existing zero-Option call site keeps compiling and behaving
// identically.
type Option func(*clientConfig)

type clientConfig struct {
	dial DialFunc
}

// WithDial routes NewClient's MQTT connection through dial instead of the
// default plain TCP dial, while still completing the TLS handshake using
// tlsConfig (see meshOpenConnectionFn) - e.g. passing pkg/mesh.Server.Dial
// makes this connection go out exclusively over the private mesh (NET-F-02
// requires TLS 1.3, which tlsConfig already enforces independent of the
// dial path) instead of plain ramusb-net Docker DNS. Omitting WithDial
// entirely preserves today's default plain-TCP-then-TLS dial, unchanged.
func WithDial(dial DialFunc) Option {
	return func(c *clientConfig) { c.dial = dial }
}

// NewClient builds and connects a paho MQTT client for publishing/
// subscribing to brokerURL (e.g. "tls://mqtt-broker.internal:8883") over
// mTLS, presenting and verifying certificates per tlsConfig (see TLSConfig -
// the caller builds tlsConfig from its own already-bootstrapped mTLS
// identity, reused for this MQTT connection rather than a second,
// independent certificate). It blocks until the connection completes or
// connectTimeout elapses. opts is optional; pass WithDial to route the
// underlying connection through a custom dialer (e.g. the private mesh)
// instead of the default plain TCP dial.
func NewClient(brokerURL string, tlsConfig *tls.Config, clientID string, connectTimeout time.Duration, opts ...Option) (mqtt.Client, error) {
	var cfg clientConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	options := mqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(clientID).
		SetTLSConfig(tlsConfig).
		SetConnectTimeout(connectTimeout).
		SetAutoReconnect(true)

	if cfg.dial != nil {
		options.SetCustomOpenConnectionFn(meshOpenConnectionFn(cfg.dial, tlsConfig, connectTimeout))
	}

	client := mqtt.NewClient(options)

	token := client.Connect()
	if !token.WaitTimeout(connectTimeout) {
		return nil, fmt.Errorf("metrics: connect to %s timed out after %s", brokerURL, connectTimeout)
	}
	if err := token.Error(); err != nil {
		return nil, fmt.Errorf("metrics: connect to %s: %w", brokerURL, err)
	}

	return client, nil
}
