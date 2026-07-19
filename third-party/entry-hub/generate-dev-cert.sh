#!/bin/sh
# Generates a dev-only, self-signed TLS certificate/key pair for
# Entry-Hub's public listener (EH-F-01/EH-F-02/EH-F-03), for local
# `docker compose`/manual-container testing only.
#
# Why this exists: in production, Entry-Hub's public listener presents a
# certificate issued by the public Let's Encrypt CA - EH-F-01/EH-F-02/
# EH-F-03's literal requirement, so end users never need to trust or
# reach the internal Certificate-Authority. Let's Encrypt's ACME HTTP-01/
# DNS-01 challenge requires a real, internet-reachable public domain,
# which does not exist in local dev/test - so this script stands in for
# that flow locally, following this project's established "*.dev-only.*"
# naming convention (see
# third-party/certificate-authority/config/password.dev-only.txt).
#
# This certificate is NEVER valid for production use: it is self-signed,
# trusted by nothing but a client explicitly told to trust it (or to
# skip verification), and satisfies only the same two-file-path
# interface (tls.LoadX509KeyPair) that a real Let's Encrypt-issued pair
# would - see services/entry-hub/cmd/entry-hub/main.go's
# buildServerTLSConfig.
#
# Output (git-ignored, regenerated on demand, never committed - unlike
# config/password.dev-only.txt, which is a zero-entropy placeholder
# string safe to commit, this is real key material and is not):
#
#   third-party/entry-hub/config/server.dev-only.crt
#   third-party/entry-hub/config/server.dev-only.key
#
# Usage:
#   third-party/entry-hub/generate-dev-cert.sh
#   docker run \
#       -v "$(pwd)/third-party/entry-hub/config/server.dev-only.crt:/certs/tls.crt:ro" \
#       -v "$(pwd)/third-party/entry-hub/config/server.dev-only.key:/certs/tls.key:ro" \
#       -e RAM_USB_ENTRY_HUB_TLS_CERT=/certs/tls.crt \
#       -e RAM_USB_ENTRY_HUB_TLS_KEY=/certs/tls.key \
#       ...
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/config"
CERT_PATH="$OUT_DIR/server.dev-only.crt"
KEY_PATH="$OUT_DIR/server.dev-only.key"

mkdir -p "$OUT_DIR"

# 10-year validity, RSA 2048: this is a dev-only convenience certificate,
# not a production credential subject to any rotation policy - a long
# validity avoids re-generating it every time a developer touches this
# stack. SAN covers both "localhost" (host-process testing, matching
# this codebase's own pkg/mtls.TestCA.IssueLeaf convention) and
# "entry-hub" (the eventual docker-compose service DNS name).
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
	-keyout "$KEY_PATH" \
	-out "$CERT_PATH" \
	-subj "/CN=localhost" \
	-addext "subjectAltName=DNS:localhost,DNS:entry-hub,IP:127.0.0.1"

chmod 0600 "$KEY_PATH"

echo "wrote dev-only certificate: $CERT_PATH"
echo "wrote dev-only key:         $KEY_PATH"
echo "NEVER use these outside local development/testing."
