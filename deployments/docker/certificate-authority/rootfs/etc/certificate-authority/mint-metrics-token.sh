#!/bin/sh
# mint-metrics-token oneshot (KI-28): mints the certificate-authority-
# metrics longrun's own single-use CA-F-04 bootstrap token, LOCALLY -
# `step ca token` calls step-ca's own admin API at https://localhost:9000,
# never leaving this container, since both processes now live in the same
# one (previously this required a cross-container `docker exec
# certificate-authority step ca token ...`, minted by an operator/script
# BEFORE certificate-authority-metrics's own separate Compose project
# could start - see deployments/scripts/certificate-authority.sh's git
# history for that prior shape). Runs once, after step-ca-ready confirms
# step-ca itself is actually serving (dependencies.d/step-ca-ready) -
# doing this locally, gated on the SAME container's own health, avoids the
# whole-file env-var-interpolation deadlock a plain `${VAR:?}` requirement
# on this container's own compose service would otherwise cause (Compose
# resolves every env var BEFORE any container in the file starts - this
# container cannot mint its own token for itself before it exists).
#
# Subject is "CertificateAuthority" (the SRS service identity
# third-party/mosquitto/acl.conf's own MQTT ACL grant actually authorizes
# - not "certificate-authority-metrics" or any other container-name-
# derived subject; see docs/Known_Issues.md's KI-28 and this container's
# own certificate-authority-metrics longrun's own package doc comment).
#
# The minted token is handed to the certificate-authority-metrics longrun
# via s6-overlay's container-environment directory (the SAME cross-longrun
# runtime-value-handoff pattern Database-Vault's own tailscale-up.sh uses
# to pass its mesh IPv4 address to a later longrun) rather than a Compose-
# level env var, since it is only known at this point in the container's
# own startup, not before the container exists.
set -eu

TOKEN=$(step ca token CertificateAuthority \
	--ca-url https://localhost:9000 \
	--root /home/step/certs/root_ca.crt \
	--provisioner admin \
	--password-file /run/secrets/ca-password.dev-only)

mkdir -p /var/run/s6/container_environment
printf '%s' "${TOKEN}" >/var/run/s6/container_environment/RAM_USB_CA_BOOTSTRAP_TOKEN
