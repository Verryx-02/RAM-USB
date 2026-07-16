package metrics

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// NewClient builds and connects a paho MQTT client for publishing
// Entry-Hub's metrics (EH-F-10) to brokerURL (e.g.
// "tls://mqtt-broker.internal:8883") over mTLS, verifying the broker's
// certificate per TLSConfig. It blocks until the connection completes or
// connectTimeout elapses.
//
// This function is production wiring with no real broker to unit test it
// against in this session, same accepted-gap shape as Database-Vault's
// and Security-Switch's identical NewClient - a thin adapter over an
// already-tested building block (TLSConfig, covered by
// tlsconfig_test.go). Wiring this into a running process is
// cmd/entry-hub/main.go's job.
func NewClient(brokerURL string, clientCert tls.Certificate, rootCAs *x509.CertPool, clientID string, connectTimeout time.Duration) (mqtt.Client, error) {
	options := mqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(clientID).
		SetTLSConfig(TLSConfig(clientCert, rootCAs)).
		SetConnectTimeout(connectTimeout).
		SetAutoReconnect(true)

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
