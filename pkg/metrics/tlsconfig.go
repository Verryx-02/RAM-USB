package metrics

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// OrganizationMQTTBroker is the required Subject.Organization value on
// the MQTT broker's server certificate ("the certificate comes from an
// MQTT-Broker" - EH-F-10, SS-F-07, DV-F-16, ST-F-12, NM-F-17, CA-F-03).
// Every service's metrics client connects to the one same broker, so this
// value is genuinely identical across all of them.
const OrganizationMQTTBroker = "MQTTBroker"

// TLSConfig returns the *tls.Config a metrics-publishing MQTT client uses
// to connect to the broker: present clientCert, trust rootCAs, and accept
// only a broker whose certificate Subject carries OrganizationMQTTBroker
// and is otherwise valid. It reuses pkg/mtls's shared outbound mTLS
// verification logic.
func TLSConfig(clientCert tls.Certificate, rootCAs *x509.CertPool) *tls.Config {
	return mtls.ClientConfig(clientCert, rootCAs, OrganizationMQTTBroker)
}
