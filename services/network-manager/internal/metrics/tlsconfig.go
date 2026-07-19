package metrics

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// OrganizationMQTTBroker is the required Subject.Organization value on
// the MQTT broker's server certificate (NM-F-17: "the certificate comes
// from an MQTT-Broker"). Same PascalCase-no-hyphen mTLS organization
// convention as every other service's metrics package
// ("SecuritySwitch", "StorageService", "EntryHub", "Database-Vault"'s own
// "MQTTBroker").
const OrganizationMQTTBroker = "MQTTBroker"

// TLSConfig returns the *tls.Config a Network-Manager MQTT client uses to
// connect to the broker: present clientCert, trust rootCAs, and accept
// only a broker whose certificate Subject carries OrganizationMQTTBroker
// and is otherwise valid (NM-F-17).
func TLSConfig(clientCert tls.Certificate, rootCAs *x509.CertPool) *tls.Config {
	return mtls.ClientConfig(clientCert, rootCAs, OrganizationMQTTBroker)
}
