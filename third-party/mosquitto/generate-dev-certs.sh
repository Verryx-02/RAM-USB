#!/bin/sh
# Mints a dev-only mTLS certificate set for the mqtt-broker Docker Compose
# service and every one of its clients, from the REAL running
# certificate-authority container - not a separate self-signed root.
#
# Why the real CA, not a purpose-built "MQTT Dev CA" (this script's own
# prior design, replaced here): every other RAM-USB service's inter-
# service mTLS identity already comes from this same CA via pkg/pki's
# bootstrap-token flow (pki.LoadBootstrapToken + pki.NewServer/NewClient) -
# confirmed by reading every one of Entry-Hub's, Security-Switch's,
# Database-Vault's, Network-Manager's, and Storage-Service's own
# cmd/<service>/main.go doc comments. Entry-Hub is the one
# exception-shaped case, and even it only differs for its PUBLIC listener
# (EH-F-01/02/03's Let's-Encrypt-stand-in dev cert,
# third-party/entry-hub/generate-dev-cert.sh) - its OUTBOUND mTLS client
# identity to Security-Switch still comes from this same real CA. A
# separate self-signed MQTT root was the only certificate chain in the
# whole stack not rooted at this CA - this script now closes that gap.
#
# Why NOT pkg/pki's normal bootstrap-token flow (CA-F-04): that flow is
# single-use-token-per-process-startup (RAM_USB_CA_BOOTSTRAP_TOKEN),
# consumed live by a running Go process via pki.NewServer/NewClient - not
# reusable for minting a separate static file pair from an external
# script the way every RAM_USB_MQTT_CLIENT_CERT/RAM_USB_MQTT_CLIENT_KEY
# env var already expects (a file path, loaded via tls.LoadX509KeyPair,
# same as every publish-side service's buildMetricsClient). Instead, this
# script follows the same docker-exec-into-the-CA-container technique
# services/security-switch/cmd/security-switch/main_integration_test.go's
# own generateToken already established for RealCA integration tests:
# mint a token via the "admin" JWK provisioner (the same provisioner
# certificate-authority-init/apply-organization-template.sh already
# configure with organization.x509.tpl), then exchange it for an actual
# certificate/key pair via `step ca certificate`, then `docker cp` the
# result out.
#
# No --ca-url/--root flags are needed on either `step ca token` or
# `step ca certificate` below (unlike this codebase's Go integration
# tests, which run from OUTSIDE the container and must supply both
# explicitly) - confirmed live this session: step's own default config
# inside the certificate-authority container already points at itself,
# the same simplification third-party/certificate-authority/
# apply-organization-template.sh's own `step ca provisioner update`
# call already relies on.
#
# Certificate lifetime: real-CA-issued certificates inherit step-ca's own
# default leaf lifetime (no custom --not-after/TTL is configured anywhere
# in this repository) - confirmed live this session at ~24h, a sharp
# contrast with the old self-signed approach's arbitrary 10-year
# validity. This is an ACCEPTED, EXPECTED characteristic of this dev-only
# script, not a bug to route around: re-run it whenever an mTLS
# connection to mqtt-broker starts failing with a certificate-expired
# error, the same "regenerated on demand, never committed" spirit this
# script's output already followed for other reasons (see .gitignore).
#
# Dependency: the certificate-authority container must already be up AND
# certificate-authority-init must have already completed (so
# organization.x509.tpl is installed on the "admin" provisioner - without
# it, every certificate minted here would carry an empty
# Subject.Organization, exactly the PKI-F-02 gap organization.x509.tpl's
# own doc comment describes). This script is NOT wired as its own
# docker-compose.dev.yml one-shot service (unlike certificate-authority-init
# itself): it needs `docker exec` into an already-running container,
# which requires a docker socket a compose service does not have by
# default - the exact same reason
# third-party/certificate-authority/apply-organization-template.sh (this
# script's own model for the docker-exec-based approach) is a host-side
# manual script and not a compose service either, rather than
# init-organization-template.sh's network-based approach (which HAS no
# docker-exec equivalent for minting a file pair a host-side mosquitto/
# metrics-collector process later reads from disk). Run it manually,
# after bringing up the CA:
#
#   docker compose -f deployments/docker-compose.dev.yml up -d \
#       certificate-authority certificate-authority-init
#   third-party/mosquitto/generate-dev-certs.sh
#
# Output (git-ignored, regenerated on demand, never committed - see
# .gitignore's mosquitto/MQTT entry). File names/paths are UNCHANGED from
# this script's prior self-signed-CA design, despite the content now
# coming from the real CA - every consumer (mosquitto.conf's cafile,
# every service's RAM_USB_MQTT_CA/RAM_USB_MQTT_CLIENT_CERT/
# RAM_USB_MQTT_CLIENT_KEY env vars in deployments/docker-compose.dev.yml)
# already points at these exact paths and needed no change:
#
#   third-party/mosquitto/certs/mqtt-dev-ca.dev-only.crt   (the real CA's root - see below)
#   third-party/mosquitto/certs/broker.dev-only.{crt,key}
#   third-party/mosquitto/certs/<Identity>.dev-only.{crt,key}   (one pair per identity below)
#
# mqtt-dev-ca.dev-only.crt keeps its old name for exactly that path-
# compatibility reason, but is no longer a separate dev-only root: it is
# a verbatim copy of /home/step/certs/root_ca.crt from inside the running
# certificate-authority container - the same root every other RAM-USB
# mTLS trust decision in this stack already chains to.
#
# Usage:
#   third-party/mosquitto/generate-dev-certs.sh [container-name]
# container-name defaults to "deployments-certificate-authority-1" (this
# repository's docker-compose.dev.yml-generated name), same default/
# override-via-positional-argument convention as
# apply-organization-template.sh.
set -eu

CONTAINER="${1:-deployments-certificate-authority-1}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/certs"
mkdir -p "$OUT_DIR"

# mint_and_copy subject out_basename [extra_sans...]
# Mints one real-CA-issued certificate/key pair for subject (both this
# process's own CommonName and, via organization.x509.tpl,
# Subject.Organization - see this file's own doc comment above) and
# copies it out to $OUT_DIR/$out_basename.dev-only.{crt,key}. Any
# additional positional arguments become extra `--san` values on the
# TOKEN mint step - `step ca certificate`'s own --san flag is mutually
# exclusive with --token (a token already carries its authorized SAN
# set), so every SAN this identity's certificate needs must be requested
# up front when minting the token, not at the certificate-exchange step.
mint_and_copy() {
	subject="$1"
	out_basename="$2"
	shift 2

	san_args=""
	for san in "$@"; do
		san_args="$san_args --san $san"
	done

	# shellcheck disable=SC2086 # $san_args is an intentionally word-split,
	# possibly-empty list of "--san VALUE" pairs - there is no array type
	# in POSIX sh, and every value here is a fixed hostname/subject
	# literal from this script's own for-loop below, never external input.
	token="$(docker exec "$CONTAINER" step ca token "$subject" \
		--provisioner admin \
		--password-file /run/secrets/ca-password.dev-only \
		$san_args)"

	docker exec "$CONTAINER" step ca certificate "$subject" \
		"/tmp/mqtt-devcert-$out_basename.crt" "/tmp/mqtt-devcert-$out_basename.key" \
		--token "$token" --force

	docker cp "$CONTAINER:/tmp/mqtt-devcert-$out_basename.crt" "$OUT_DIR/$out_basename.dev-only.crt"
	docker cp "$CONTAINER:/tmp/mqtt-devcert-$out_basename.key" "$OUT_DIR/$out_basename.dev-only.key"
	docker exec "$CONTAINER" rm -f "/tmp/mqtt-devcert-$out_basename.crt" "/tmp/mqtt-devcert-$out_basename.key"

	chmod 0600 "$OUT_DIR/$out_basename.dev-only.key"
	echo "wrote dev-only certificate (real CA, ~24h validity): $OUT_DIR/$out_basename.dev-only.crt"
}

# The broker's own server identity. Subject MUST be exactly "MQTTBroker"
# (pkg/metrics.OrganizationMQTTBroker) - organization.x509.tpl mirrors
# whatever subject a token is minted with into BOTH CommonName and
# Organization, so this is the only token subject that produces the
# Organization value pkg/metrics.TLSConfig hard-requires of the broker's
# certificate (confirmed live this session: every publish-side/
# Metrics-Collector connection fails its handshake otherwise, "peer
# certificate organization [] does not match required organization
# \"MQTTBroker\""). Mosquitto itself never checks this certificate's CN
# against anything (use_identity_as_username/acl.conf's CN-based ACL only
# applies to CLIENT certificates, not the broker's own server identity),
# so "MQTTBroker" as a CommonName is not a naming conflict with anything
# else in this stack.
#
# Extra SANs (mqtt-broker, localhost, 127.0.0.1) are REQUIRED here, unlike
# every client identity below: this is the one certificate in this
# script's output that a Go TLS CLIENT actually dials by network address
# and hostname-verifies (every MQTT-publishing service's
# pkg/metrics.TLSConfig -> pkg/mtls.ClientConfig uses crypto/tls's
# ordinary, unmodified chain+hostname verification - unlike pkg/pki's
# ClientTLSConfig/ForceServerName, which every OTHER RAM-USB service's
# primary mTLS identity uses instead specifically to bypass hostname
# checking in favor of organization-only verification, pkg/mtls.ClientConfig
# was never changed to do the same, and this task's own instructions kept
# it that way - "nothing about the consuming side changes"). Confirmed
# live this session: a broker certificate whose only SAN is "MQTTBroker"
# (the default when no --san is given) fails every client's handshake
# with a generic "certificate verify failed"/"bad certificate" TLS alert,
# for a completely different reason than PKI-F-02's organization check -
# a plain hostname mismatch, invisible in Mosquitto's own broker-side log
# line, only diagnosable by comparing a client-side raw `openssl s_client`
# session (which does not verify hostname unless asked to) against the
# same connection through a client that does (mosquitto_pub, and by the
# same crypto/tls default behavior, every pkg/metrics-based Go client
# here). Client identities below need no such extra SAN: nothing in this
# stack ever dials out to any of them by hostname - Mosquitto verifies a
# client certificate by CA-chain validity and Subject.CN
# (use_identity_as_username/acl.conf) only, never by hostname/SNI.
mint_and_copy "MQTTBroker" "broker" mqtt-broker localhost 127.0.0.1

# One client leaf per RAM-USB identity that publishes or reads metrics
# (EH-F-10, SS-F-07, DV-F-16, ST-F-12, NM-F-17, CA-F-03, MT-F-01) - CN
# must equal the ACL username in acl.conf exactly.
for identity in EntryHub SecuritySwitch DatabaseVault StorageService NetworkManager CertificateAuthority MetricsCollector; do
	mint_and_copy "$identity" "$identity"
done

# The trust root every certificate above (and every OTHER RAM-USB service's
# own mTLS identity, PKI-F-01) chains to - see this file's own doc comment
# for why this keeps the "mqtt-dev-ca.dev-only.crt" name despite no longer
# being a separate dev-only root.
docker cp "$CONTAINER:/home/step/certs/root_ca.crt" "$OUT_DIR/mqtt-dev-ca.dev-only.crt"

echo "wrote real-CA root: $OUT_DIR/mqtt-dev-ca.dev-only.crt"
echo "NEVER use these outside local development/testing."
echo "Real-CA-issued certificates expire in ~24h - re-run this script when an mTLS connection to mqtt-broker starts failing with a certificate-expired error."
