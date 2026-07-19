package metrics

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// NewClient builds and connects a paho MQTT client for publishing
// Network-Manager's metrics (NM-F-17) to brokerURL over mTLS, verifying
// the broker's certificate per TLSConfig. It blocks until the connection
// completes or connectTimeout elapses. No in-process stub broker exists
// to unit test this directly - same accepted-gap shape as Database-
// Vault's identical NewClient.
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
