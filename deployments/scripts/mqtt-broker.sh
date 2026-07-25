#!/bin/bash
# Shell 4 - MQTT-Broker + its Tailscale mesh sidecar + its own certificate
# issuer/renewer sidecars (KI-16, PKI-F-03). Requires shells 1, 2.
#
# Mosquitto's own mTLS identity (both the broker's server certificate and
# the healthcheck's own client identity) is minted fresh EVERY run, then
# kept current automatically for the lifetime of the stack by
# mqtt-broker-cert-renewer (`step ca renew --daemon`, mTLS-authenticated,
# no token) - unlike the old generate-dev-certs.sh-based design (still
# available for standalone/manual debugging, but no longer wired into this
# script), there is no "re-run this script when a cert expires" step
# anymore. Both RAM_USB_MQTT_BROKER_BOOTSTRAP_TOKEN and
# RAM_USB_MQTT_BROKER_HEALTHCHECK_BOOTSTRAP_TOKEN are CA-F-04 single-use
# bootstrap tokens - minted fresh here, consumed exactly once by
# mqtt-broker-cert-issuer's own one-shot exchange, same pattern as every
# other RAM_USB_CA_BOOTSTRAP_TOKEN-based service.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

docker exec headscale headscale users create mqtt-broker 2>/dev/null || true
MQTT_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="mqtt-broker") | .id')
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_MQTT_BROKER_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$MQTT_ID" --expiration 30m --tags tag:mqtt-broker)

# MQTTBroker: the broker's own server certificate - SANs baked in at mint
# time (mutually exclusive with --token on the exchange step, see
# mqtt-broker-cert-issuer's own doc comment in deployments/compose/
# mqtt-broker.yml).
export RAM_USB_MQTT_BROKER_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token MQTTBroker \
  --san MQTTBroker --san mqtt-broker --san localhost --san 127.0.0.1 \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

# CertificateAuthority: this file's own healthcheck self-publish identity
# (mqtt-broker.yml's own healthcheck), not RAM-USB's Certificate-Authority
# service itself - see acl.conf's own doc comment for why this identity
# string is reused.
export RAM_USB_MQTT_BROKER_HEALTHCHECK_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token CertificateAuthority \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/mqtt-broker.yml up
