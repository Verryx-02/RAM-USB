#!/bin/sh
# Generates a dev-only mTLS certificate set for the mqtt-broker Docker
# Compose service and every one of its clients, for local
# `docker compose`/manual testing only.
#
# Why a purpose-built dev CA, not step-ca (the real Certificate-Authority
# every other RAM-USB mTLS role bootstraps from, PKI-F-01/PKI-F-04): this
# script mirrors an already-established, already-documented judgment call
# - Database-Vault's cmd/database-vault/main.go states plainly that "MQTT
# metrics publishing is deliberately out of [CA-F-04's bootstrap] scope
# ... keeps its existing file-based cert/key/CA convention," and every
# publish-side service's envMQTTClientCert/envMQTTClientKey/envMQTTCA env
# vars already assume a static file pair, not a live pki.NewClient
# bootstrap exchange. This script's only job is to actually produce the
# files those env vars have always pointed at (they didn't exist yet -
# see this task's own scaffolding). A single shared self-signed root
# ("MQTT Dev CA") signs every leaf below, the standard shape for a private
# mTLS deployment - not one independently self-signed cert per identity,
# which would force mosquitto.conf's single cafile to somehow trust N
# unrelated roots at once.
#
# Client identities: one leaf certificate per Subject.Organization value
# any RAM-USB service already uses (see third-party/certificate-authority/
# config/organization.x509.tpl's doc comment for the full list) - each
# leaf's CN is set to that exact identity string, since
# third-party/mosquitto/mosquitto.conf's use_identity_as_username +
# acl.conf's "user <CN>" lines authenticate purely on Subject CN. Plus one
# extra identity, MetricsCollector, which has no HTTP mTLS role elsewhere
# in this project but does have its own MQTT-subscribe identity (MT-F-01).
#
# Output (git-ignored, regenerated on demand, never committed - see
# .gitignore's mosquitto/MQTT entry):
#
#   third-party/mosquitto/certs/mqtt-dev-ca.dev-only.crt
#   third-party/mosquitto/certs/mqtt-dev-ca.dev-only.key
#   third-party/mosquitto/certs/broker.dev-only.{crt,key}
#   third-party/mosquitto/certs/<Identity>.dev-only.{crt,key}   (one pair per identity below)
#
# Usage:
#   third-party/mosquitto/generate-dev-certs.sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/certs"
mkdir -p "$OUT_DIR"

CA_KEY="$OUT_DIR/mqtt-dev-ca.dev-only.key"
CA_CRT="$OUT_DIR/mqtt-dev-ca.dev-only.crt"

# 10-year validity, RSA 2048: same dev-only-convenience rationale as
# third-party/entry-hub/generate-dev-cert.sh - not a production credential
# subject to any rotation policy.
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
	-keyout "$CA_KEY" \
	-out "$CA_CRT" \
	-subj "/CN=RAM-USB MQTT Dev CA"
chmod 0600 "$CA_KEY"

# issue_leaf cn org out_basename san_extra
# Issues one leaf certificate signed by the dev CA above. org sets
# Subject.Organization (PKI-F-02's field, distinct from CN/
# use_identity_as_username's ACL username) - pkg/metrics.TLSConfig
# (pkg/metrics/tlsconfig.go) hard-requires the broker's own certificate to
# carry Organization=OrganizationMQTTBroker ("MQTTBroker") before any
# publish-side or Metrics-Collector client will complete its handshake at
# all (confirmed live this session: connection fails with "peer
# certificate organization [] does not match required organization
# \"MQTTBroker\"" without this). Every client identity below is also
# given its own matching Organization value, for consistency with every
# other RAM-USB certificate's shape (organization.x509.tpl), even though
# Mosquitto itself only ever checks CN, never Organization.
issue_leaf() {
	cn="$1"
	org="$2"
	out_basename="$3"
	san="$4"

	key="$OUT_DIR/$out_basename.dev-only.key"
	crt="$OUT_DIR/$out_basename.dev-only.crt"
	csr="$OUT_DIR/$out_basename.dev-only.csr"

	openssl req -new -newkey rsa:2048 -nodes \
		-keyout "$key" \
		-out "$csr" \
		-subj "/O=$org/CN=$cn"

	openssl x509 -req -in "$csr" -days 3650 \
		-CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
		-out "$crt" \
		-extfile <(printf 'subjectAltName=%s' "$san")

	rm -f "$csr"
	chmod 0600 "$key"
	echo "wrote dev-only certificate: $crt"
}

# The broker's own server identity. SAN covers both the compose service
# name ("mqtt-broker") and "localhost" (host-process testing), same
# convention as third-party/entry-hub/generate-dev-cert.sh. Organization
# MUST be exactly "MQTTBroker" (pkg/metrics.OrganizationMQTTBroker) - see
# issue_leaf's own doc comment above.
issue_leaf "mqtt-broker" "MQTTBroker" "broker" "DNS:mqtt-broker,DNS:localhost,IP:127.0.0.1"

# One client leaf per RAM-USB identity that publishes or reads metrics
# (EH-F-10, SS-F-07, DV-F-16, ST-F-12, NM-F-17, CA-F-03, MT-F-01) - CN
# must equal the ACL username in acl.conf exactly. Client certificates
# authenticate by CN alone (use_identity_as_username); no SAN is
# meaningful here (mosquitto never checks it against a hostname the way a
# server certificate's SAN is checked by a connecting client), but a
# minimal SAN is still set so the certificate itself is well-formed for
# any tool that expects one.
for identity in EntryHub SecuritySwitch DatabaseVault StorageService NetworkManager CertificateAuthority MetricsCollector; do
	issue_leaf "$identity" "$identity" "$identity" "DNS:$identity"
done

rm -f "$OUT_DIR"/*.srl

echo "NEVER use these outside local development/testing."
