#!/bin/bash
# CA-F-03's metrics sidecar. Requires shells 1 (certificate-authority), 2
# (headscale), and 4 (mqtt-broker) already up - a separate compose
# project/script from certificate-authority.sh itself; see
# deployments/compose/certificate-authority-metrics.yml's own top comment
# for why.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

docker exec headscale headscale users create certificate-authority-metrics 2>/dev/null || true
CAM_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="certificate-authority-metrics") | .id')

# Bootstrap subject is "CertificateAuthority" - see
# deployments/compose/certificate-authority-metrics.yml's own comment on
# RAM_USB_CA_BOOTSTRAP_TOKEN for why (third-party/mosquitto/acl.conf's
# pre-existing MQTT ACL grant, confirmed live this session).
export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token CertificateAuthority \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_CERTIFICATE_AUTHORITY_METRICS_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$CAM_ID" --expiration 30m --tags tag:certificate-authority)

docker compose -f deployments/compose/certificate-authority-metrics.yml up --build
