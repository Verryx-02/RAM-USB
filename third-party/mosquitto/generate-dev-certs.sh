#!/bin/sh
# Mints a dev-only mTLS certificate set for the mqtt-broker Docker Compose
# service's own two identities that have no pkg/pki-bootstrapped identity
# to reuse - MQTTBroker (the broker's own server certificate; Mosquitto is
# a C binary, not a Go process, and cannot call pkg/pki) and
# CertificateAuthority (mqtt-broker.yml's own healthcheck self-publish, a
# `mosquitto_pub` shell invocation) - from the REAL running
# certificate-authority container, not a separate self-signed root. Every
# other RAM-USB MQTT client identity (EntryHub, SecuritySwitch,
# DatabaseVault, StorageService, NetworkManager, MetricsCollector) is a Go
# process that now reuses its own already-bootstrapped mTLS identity
# (pkg/pki, CA-F-04) for its MQTT connection too, instead of a second
# static certificate/key pair minted by this script - see the loop below's
# own doc comment.
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
# same as every publish-side service's buildMetricsClient).
#
# Two-step, cross-host-capable issuance (CORRECTED - see below for why the
# prior single-docker-exec design was an architectural bug, not just a
# style choice):
#
#   1. TOKEN MINTING stays `docker exec` into the CA container. Minting a
#      token is legitimately an admin/CA-operator action requiring access
#      to the CA's own admin secret (ca-password.dev-only) - same
#      docker-exec-into-the-CA-container technique
#      services/security-switch/cmd/security-switch/main_integration_test.go's
#      own generateToken already established for RealCA integration
#      tests, and the same operation
#      third-party/certificate-authority/apply-organization-template.sh's
#      `step ca provisioner update` already performs this way. Wherever
#      the CA itself runs, whoever operates it can `docker exec` into it -
#      this step never needs to reach across hosts.
#
#   2. CERTIFICATE EXCHANGE (`step ca certificate ... --token ...`) now
#      runs as a genuine NETWORK call, not `docker exec`. The prior
#      design ran this step via `docker exec` into the SAME
#      certificate-authority container the token was minted from - this
#      only worked because local dev-compose happens to co-locate every
#      container on one Docker host. RNF-ORG-04 (Proxmox VE, KVM/LXC
#      split) means the Mosquitto broker and the Certificate-Authority
#      run on DIFFERENT VMs/hosts in production - `docker exec` has no
#      cross-host equivalent short of exposing the Docker socket over the
#      network, which this project has never done anywhere else and
#      should not start doing here. Every other RAM-USB service's own
#      initial-issuance path (CA-F-04, pkg/pki.NewServer/NewClient) already
#      exchanges its bootstrap token for a certificate purely over the
#      network (`--ca-url`), authenticated by the single-use token itself
#      (bearer-style, over ordinary server-TLS - there is no client
#      certificate yet to present mutually) - this script now matches
#      that same model instead of being the one exception relying on
#      `docker exec` for both steps.
#
#      Mechanically: a disposable `smallstep/step-cli` container (the
#      official standalone CLI image - NOT `smallstep/step-ca`, the full
#      server image already running as the `certificate-authority`
#      service) runs `step ca certificate` with `--ca-url`/`--root`/
#      `--token` all passed as explicit flags, joined to the `ramusb-net`
#      Docker network (the same external network every
#      deployments/compose/*.yml file already joins - the only network
#      convention this project has after MANUAL-DISTRIBUTED-RUN.md became
#      the sole way to run this stack) so it can reach the CA container by
#      its plain `certificate-authority` hostname/DNS name, exactly like
#      any other container on that network would. No persistent
#      `$HOME/.step` config or volume is needed: every value the CLI
#      would otherwise read from a local config file is supplied
#      explicitly on the command line instead, so the container is fully
#      stateless and disposable (`--rm`).
#
#      `--user "$(id -u):$(id -g)"` overrides the image's default non-root
#      `step` account (UID/GID 1000, confirmed live via `docker run --rm
#      smallstep/step-cli:<tag> id`) so the certificate/key files this
#      step writes into the bind-mounted $OUT_DIR land owned by the host
#      user actually running this script, not UID 1000 - otherwise, on a
#      native Linux Docker host (unlike this session's own macOS Docker
#      Desktop, which transparently remaps bind-mount ownership to the
#      invoking host user regardless of the container's UID), this
#      script's own later `chmod 0600` on the private key would fail with
#      "Operation not permitted" for any host user that isn't UID 1000.
#      Confirmed live this session: `step ca certificate` still succeeds
#      running as an arbitrary host UID with no matching /etc/passwd entry
#      inside the container - it never needs to resolve $HOME for this
#      operation, since every value it would otherwise look up there
#      (--ca-url, --root, --token) is supplied explicitly.
#
#      No `$CA_URL`/`--san` flags are needed on the TOKEN mint step
#      (`docker exec`) - confirmed live this session: a token minted with
#      no explicit `--ca-url` still carries an "aud" claim the network
#      exchange step's own explicit `--ca-url https://certificate-authority:9000`
#      satisfies, because DOCKER_STEPCA_INIT_DNS_NAMES already includes
#      "certificate-authority" as one of the CA's own recognized names.
#      This is unlike the RAM_USB_CA_BOOTSTRAP_TOKEN case documented in
#      this project's other compose files, where --ca-url is passed
#      explicitly at mint time too - that difference doesn't matter here
#      because both steps of this script still resolve to the same CA
#      identity/audience either way; explicit is simply not required for
#      correctness in this specific case, confirmed rather than assumed.
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
# own doc comment describes). This script is NOT wired as its own compose
# one-shot service (unlike certificate-authority-init itself): its token-
# minting step needs `docker exec` into an already-running container,
# which requires a docker socket a compose service does not have by
# default - the exact same reason
# third-party/certificate-authority/apply-organization-template.sh (this
# script's own model for the docker-exec-based token-minting step) is a
# host-side manual script and not a compose service either. Run it
# manually, after bringing up the CA (see MANUAL-DISTRIBUTED-RUN.md's own
# ordering - this step belongs right after the Certificate-Authority
# shell, before mqtt-broker or any of the metrics-publishing services):
#
#   docker compose -f deployments/compose/certificate-authority.yml up -d
#   third-party/mosquitto/generate-dev-certs.sh certificate-authority
#
# Output (git-ignored, regenerated on demand, never committed - see
# .gitignore's mosquitto/MQTT entry). File names/paths are UNCHANGED from
# this script's prior self-signed-CA design, despite the content now
# coming from the real CA - mosquitto.conf's cafile and mqtt-broker.yml's
# own healthcheck self-publish (CertificateAuthority) already point at
# these exact paths and needed no change. No RAM_USB_MQTT_CLIENT_CERT/
# RAM_USB_MQTT_CLIENT_KEY/RAM_USB_MQTT_CA env vars exist anymore on the
# publish-side services - see this file's own top doc comment:
#
#   third-party/mosquitto/certs/mqtt-dev-ca.dev-only.crt   (the real CA's root - see below)
#   third-party/mosquitto/certs/broker.dev-only.{crt,key}
#   third-party/mosquitto/certs/CertificateAuthority.dev-only.{crt,key}
#
# mqtt-dev-ca.dev-only.crt keeps its old name for exactly that path-
# compatibility reason, but is no longer a separate dev-only root: it is
# a verbatim copy of /home/step/certs/root_ca.crt from inside the running
# certificate-authority container - the same root every other RAM-USB
# mTLS trust decision in this stack already chains to.
#
# The root fetch itself (`docker cp ...root_ca.crt`) deliberately stays a
# `docker exec`/`docker cp`-based, same-host operation rather than being
# rewritten to a network-based `step ca root --fingerprint ...` fetch:
# unlike per-identity certificate issuance (the operation that actually
# needs to repeat every ~24h, potentially from a different host than the
# CA in production), fetching the root is a coarse, rare operation (once,
# or whenever the CA's root itself changes) and the root is not secret
# material to begin with (it's the public trust anchor every verifier
# already trusts once distributed). `step ca root` would need a
# fingerprint distributed out-of-band anyway to be genuinely
# network-safe (an unauthenticated fetch over plain HTTPS with no
# fingerprint pinning would defeat the point of verifying the root at
# all) - this script has no such fingerprint distribution mechanism today
# and inventing one is out of scope for closing this specific
# `docker exec`-across-hosts gap. If a future task needs this script to
# run from a host that cannot `docker exec`/`docker cp` into the CA
# container at all (not just mint tokens, but fetch the root too), revisit
# this with an explicit fingerprint-distribution story - not needed yet.
#
# Usage:
#   third-party/mosquitto/generate-dev-certs.sh [container-name]
# container-name defaults to "certificate-authority" (the plain,
# stable container_name deployments/compose/certificate-authority.yml
# sets - the only compose convention this project has), same
# default/override-via-positional-argument convention as
# apply-organization-template.sh.
set -eu

CONTAINER="${1:-certificate-authority}"
CA_URL="https://$CONTAINER:9000"
DOCKER_NETWORK="ramusb-net"
STEP_CLI_IMAGE="smallstep/step-cli:0.30.6"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/certs"
mkdir -p "$OUT_DIR"

# The exchange step below needs the root cert already on disk (mounted
# read-only into the disposable step-cli container as --root) - fetch it
# up front, once, rather than at the end of this script as before.
docker cp "$CONTAINER:/home/step/certs/root_ca.crt" "$OUT_DIR/mqtt-dev-ca.dev-only.crt"
echo "wrote real-CA root: $OUT_DIR/mqtt-dev-ca.dev-only.crt"

# mint_and_copy subject out_basename [extra_sans...]
# Mints one real-CA-issued certificate/key pair for subject (both this
# process's own CommonName and, via organization.x509.tpl,
# Subject.Organization - see this file's own doc comment above) and
# writes it directly to $OUT_DIR/$out_basename.dev-only.{crt,key} (the
# network-based exchange step below writes straight into the bind-mounted
# output directory - no docker-cp-out-of-a-temp-path indirection needed
# anymore, unlike the old docker-exec design). Any additional positional
# arguments become extra `--san` values on the TOKEN mint step -
# `step ca certificate`'s own --san flag is mutually exclusive with
# --token (a token already carries its authorized SAN set), so every SAN
# this identity's certificate needs must be requested up front when
# minting the token, not at the certificate-exchange step.
mint_and_copy() {
	subject="$1"
	out_basename="$2"
	shift 2

	san_args=""
	for san in "$@"; do
		san_args="$san_args --san $san"
	done

	# Step 1: mint the token. Stays docker exec - see this file's own doc
	# comment above for why this remains correct even across hosts.
	# shellcheck disable=SC2086 # $san_args is an intentionally word-split,
	# possibly-empty list of "--san VALUE" pairs - there is no array type
	# in POSIX sh, and every value here is a fixed hostname/subject
	# literal from this script's own for-loop below, never external input.
	token="$(docker exec "$CONTAINER" step ca token "$subject" \
		--provisioner admin \
		--password-file /run/secrets/ca-password.dev-only \
		$san_args)"

	# Step 2: exchange the token for a certificate over the network, via
	# a disposable step-cli container on the same Docker network as the
	# CA - see this file's own doc comment above for the full reasoning.
	docker run --rm \
		--network "$DOCKER_NETWORK" \
		--user "$(id -u):$(id -g)" \
		-v "$OUT_DIR:/out" \
		-v "$OUT_DIR/mqtt-dev-ca.dev-only.crt:/root_ca.crt:ro" \
		"$STEP_CLI_IMAGE" \
		step ca certificate "$subject" \
			"/out/$out_basename.dev-only.crt" "/out/$out_basename.dev-only.key" \
			--token "$token" --ca-url "$CA_URL" --root /root_ca.crt --force

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
# Extra SANs (MQTTBroker itself, plus mqtt-broker, localhost, 127.0.0.1)
# are REQUIRED here, unlike every client identity below - and unlike a
# subject minted with NO --san flags at all (every client identity
# below), where step-ca's own default is to use the subject itself as the
# sole SAN: `step ca token`'s explicit --san flags REPLACE that default
# entirely rather than adding to it, so a broker token minted with only
# `--san mqtt-broker --san localhost --san 127.0.0.1` (this script's own
# design before this session's PKI-F-01/pkg/pki MQTT-identity-reuse work)
# omits "MQTTBroker" from its SAN list - confirmed live: every one of the
# 6 Go clients that now reuse their own pki-bootstrapped identity for MQTT
# force their handshake's ServerName to the peer organization
# ("MQTTBroker" - pki.ClientTLSConfig, the same mechanism every OTHER
# RAM-USB outbound mTLS call already uses to bypass network-address-based
# hostname checking in favor of organization-only verification, see
# pkg/pki's package doc comment) rather than dialing by network address -
# so the broker's certificate must carry "MQTTBroker" as a SAN for that
# check to succeed at all, not merely the network names a raw
# `mosquitto_pub`/`openssl s_client` invocation would use. The network
# names are kept anyway, for any non-Go/manual debugging tool that DOES
# hostname-verify by network address instead.
mint_and_copy "MQTTBroker" "broker" MQTTBroker mqtt-broker localhost 127.0.0.1

# CertificateAuthority is the only remaining client identity minted here:
# it backs mqtt-broker.yml's own healthcheck self-publish (a `mosquitto_pub`
# shell invocation, not a Go process - see that compose file), so it has
# no pkg/pki-bootstrapped identity of its own to reuse. Every OTHER RAM-USB
# MQTT client identity (EntryHub, SecuritySwitch, DatabaseVault,
# StorageService, NetworkManager, MetricsCollector - EH-F-10, SS-F-07,
# DV-F-16, ST-F-12, NM-F-17, CA-F-03/MT-F-01) is a Go process that now
# reuses its own already-bootstrapped mTLS identity for its MQTT connection
# too (pki.NewServer/NewClient + pki.ClientTLSConfig + metrics.TLSConfig -
# see each service's own cmd/<service>/main.go), rather than loading a
# second, independent static certificate/key pair minted here - so none of
# them need an entry in this loop anymore. CN must equal the ACL username
# in acl.conf exactly.
mint_and_copy "CertificateAuthority" "CertificateAuthority"

echo "NEVER use these outside local development/testing."
echo "Real-CA-issued certificates expire in ~24h - re-run this script when an mTLS connection to mqtt-broker starts failing with a certificate-expired error."
