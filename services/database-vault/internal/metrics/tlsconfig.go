package metrics

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// OrganizationMQTTBroker is the required Subject.Organization value on
// the MQTT broker's server certificate (DV-F-16: "the certificate comes
// from an MQTT-Broker"). Unlike Topic (a literal string DV-F-16 quotes
// directly), the SRS states this requirement only in prose ("an
// MQTT-Broker"), the same way DV-F-16 does not give a literal
// `organization="..."` code value the way DV-F-01/SS-F-01 do. This
// string therefore follows this codebase's established
// PascalCase-no-hyphen mTLS organization convention ("SecuritySwitch",
// "StorageService", "EntryHub") rather than reproducing the SRS prose's
// hyphen - a judgment call, not a value pulled directly from the SRS.
const OrganizationMQTTBroker = "MQTTBroker"

// TLSConfig returns the *tls.Config a Database-Vault MQTT client uses to
// connect to the broker: present clientCert, trust rootCAs, and accept
// only a broker whose certificate Subject carries OrganizationMQTTBroker
// and is otherwise valid (DV-F-16). It reuses pkg/mtls's shared outbound
// mTLS verification logic exactly like DV-F-09's Storage-Service client
// does, rather than reimplementing the organization check.
func TLSConfig(clientCert tls.Certificate, rootCAs *x509.CertPool) *tls.Config {
	return mtls.ClientConfig(clientCert, rootCAs, OrganizationMQTTBroker)
}
