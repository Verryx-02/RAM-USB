#!/bin/bash
# Shell 2 - Headscale (standalone - this session's architectural change,
# see deployments/docker/headscale/Dockerfile's own doc comment). Requires
# shell 1 (Certificate-Authority) only to extract its root certificate as
# a plain file for nginx's own NM-F-12 client-certificate verification -
# Headscale itself has no RAM-USB mTLS identity of its own and is NOT a
# mesh member.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

[ -f third-party/headscale/dev-tls/cert.dev-only.pem ] || {
  echo ">>> generating a dev-only self-signed reverse-proxy certificate (see third-party/headscale/dev-tls/README.txt)"
  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout third-party/headscale/dev-tls/key.dev-only.pem \
    -out third-party/headscale/dev-tls/cert.dev-only.pem \
    -subj "/CN=headscale" \
    -addext "subjectAltName=DNS:headscale,DNS:localhost,IP:127.0.0.1"
}

echo ">>> waiting for Certificate-Authority to be reachable..."
until docker exec certificate-authority step ca health --ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt >/dev/null 2>&1; do
  sleep 1
done

mkdir -p third-party/headscale/ca-root
docker cp certificate-authority:/home/step/certs/root_ca.crt third-party/headscale/ca-root/root_ca.dev-only.crt

docker compose -f deployments/compose/headscale.yml up --build
