package metrics

import (
	"crypto/tls"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// OrganizationMQTTBroker is the required Subject.Organization value on
// the MQTT broker's server certificate ("the certificate comes from an
// MQTT-Broker" - EH-F-10, SS-F-07, DV-F-16, ST-F-12, NM-F-17, CA-F-03).
// Every service's metrics client connects to the one same broker, so this
// value is genuinely identical across all of them.
const OrganizationMQTTBroker = "MQTTBroker"

// TLSConfig returns the *tls.Config a metrics-publishing/subscribing MQTT
// client uses to connect to the broker, from base - the caller's own
// already-bootstrapped mTLS identity's *tls.Config (pkg/pki), with
// ServerName already forced to OrganizationMQTTBroker by the caller
// (pki.ClientTLSConfig(base, OrganizationMQTTBroker), before this function
// runs - see e.g. any service's buildMetricsClient). TLSConfig layers
// PKI-F-02's organization check on top (mtls.WithOrganization), without
// touching base's certificate presentation/renewal mechanism, and without
// this package needing a dependency on pkg/pki itself.
func TLSConfig(base *tls.Config) *tls.Config {
	return mtls.WithOrganization(base, OrganizationMQTTBroker)
}
