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

	"github.com/Verryx-02/RAM-USB/pkg/dial"
)

// NewClient builds and connects a paho MQTT client for publishing/
// subscribing to brokerURL (e.g. "tls://mqtt-broker.internal:8883") over
// mTLS, presenting and verifying certificates per tlsConfig (see TLSConfig -
// the caller builds tlsConfig from its own already-bootstrapped mTLS
// identity, reused for this MQTT connection rather than a second,
// independent certificate). It blocks until the connection completes or
// connectTimeout elapses. dialFn is optional (nil routes the connection
// through the default plain TCP dial); pass a mesh-joined service's own
// dialer to route the underlying connection through a custom dialer
// (e.g. the private mesh) instead - NET-F-02 requires TLS 1.3, which
// tlsConfig already enforces independent of the dial path.
func NewClient(brokerURL string, tlsConfig *tls.Config, clientID string, connectTimeout time.Duration, dialFn dial.DialFunc) (mqtt.Client, error) {
	options := mqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(clientID).
		SetTLSConfig(tlsConfig).
		SetConnectTimeout(connectTimeout).
		SetAutoReconnect(true)

	if dialFn != nil {
		options.SetCustomOpenConnectionFn(meshOpenConnectionFn(dialFn, tlsConfig, connectTimeout))
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
