package metrics

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// OrganizationMQTTBroker is the required Subject.Organization value on
// the MQTT broker's server certificate (SS-F-07: "the certificate comes
// from an MQTT-Broker"). Unlike Topic (a literal string SS-F-07 quotes
// directly), the SRS states this requirement only in prose ("an
// MQTT-Broker"), the same way SS-F-07 does not give a literal
// `organization="..."` code value the way DV-F-01/SS-F-01 do. This
// string therefore follows this codebase's established
// PascalCase-no-hyphen mTLS organization convention ("SecuritySwitch",
// "StorageService", "EntryHub") rather than reproducing the SRS prose's
// hyphen - a judgment call, not a value pulled directly from the SRS. It
// is deliberately the same literal value as
// services/database-vault/internal/metrics.OrganizationMQTTBroker: both
// services connect to the same single MQTT broker, so the required
// organization is genuinely identical, not a coincidence of duplicated
// code.
const OrganizationMQTTBroker = "MQTTBroker"

// TLSConfig returns the *tls.Config a Security-Switch MQTT client uses to
// connect to the broker: present clientCert, trust rootCAs, and accept
// only a broker whose certificate Subject carries OrganizationMQTTBroker
// and is otherwise valid (SS-F-07). It reuses pkg/mtls's shared outbound
// mTLS verification logic exactly like Database-Vault's identical
// TLSConfig does, rather than reimplementing the organization check.
func TLSConfig(clientCert tls.Certificate, rootCAs *x509.CertPool) *tls.Config {
	return mtls.ClientConfig(clientCert, rootCAs, OrganizationMQTTBroker)
}
