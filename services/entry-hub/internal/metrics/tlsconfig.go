package metrics

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// OrganizationMQTTBroker is the required Subject.Organization value on
// the MQTT broker's server certificate (EH-F-10: "the certificate comes
// from an MQTT-Broker"). Deliberately the same literal value as
// services/database-vault/internal/metrics.OrganizationMQTTBroker and
// services/security-switch/internal/metrics.OrganizationMQTTBroker: every
// service's metrics client connects to the one same broker, so the
// required organization is genuinely identical, not a coincidence of
// duplicated code.
const OrganizationMQTTBroker = "MQTTBroker"

// TLSConfig returns the *tls.Config an Entry-Hub MQTT client uses to
// connect to the broker: present clientCert, trust rootCAs, and accept
// only a broker whose certificate Subject carries OrganizationMQTTBroker
// and is otherwise valid (EH-F-10). It reuses pkg/mtls's shared outbound
// mTLS verification logic exactly like Database-Vault's/Security-Switch's
// identical TLSConfig does.
func TLSConfig(clientCert tls.Certificate, rootCAs *x509.CertPool) *tls.Config {
	return mtls.ClientConfig(clientCert, rootCAs, OrganizationMQTTBroker)
}
