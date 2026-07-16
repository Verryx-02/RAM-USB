package metrics

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// NewClient builds and connects a paho MQTT client for publishing
// Database-Vault's metrics (DV-F-16) to brokerURL (e.g.
// "tls://mqtt-broker.internal:8883") over mTLS, verifying the broker's
// certificate per TLSConfig. It blocks until the connection completes or
// connectTimeout elapses.
//
// This function is production wiring with no real broker to unit test
// it against in this session (paho's client dials the broker over a
// real TCP/TLS socket; there is no in-process stub broker speaking the
// MQTT wire protocol here) - the same accepted-gap shape as
// storage.PoolBeginner having no direct unit test of its own, since it
// is a thin adapter over an already-tested building block (TLSConfig,
// covered by tlsconfig_test.go). Actually wiring this into a running
// process - loading clientCert/rootCAs, choosing brokerURL/clientID,
// and calling Run with the result - is cmd/database-vault/main.go's
// job, not built yet.
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
