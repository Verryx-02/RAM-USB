#!/bin/sh
# Manual/ad-hoc equivalent of init-organization-template.sh. Plain
# `docker compose -f deployments/docker-compose.dev.yml up` no longer
# requires running this by hand: the certificate-authority-init one-shot
# compose service applies the same template automatically, every bring-up,
# via depends_on: condition: service_healthy on certificate-authority. Use
# this script only for exec'ing into an already-running container outside
# of a full compose up (e.g. to confirm/reapply the template without
# restarting the stack):
#
#   docker compose -f deployments/docker-compose.dev.yml up -d certificate-authority
#   third-party/certificate-authority/apply-organization-template.sh
#
# It installs config/organization.x509.tpl (see that file's own doc
# comment for why this is required for PKI-F-02) on the "admin" JWK
# provisioner via step-ca's remote-management admin API
# (DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT=true). Safe to re-run: "step ca
# provisioner update" replaces the provisioner's template, it does not
# append to it.
#
# The admin login (--admin-subject/--admin-provisioner/
# --admin-password-file) authenticates as the CA's own bootstrapped
# super-admin ("step", the DOCKER_STEPCA_INIT_ADMIN_SUBJECT default),
# using the same dev-only password file
# (config/password.dev-only.txt, mounted at
# /run/secrets/ca-password.dev-only) the container's own
# DOCKER_STEPCA_INIT_PASSWORD_FILE was initialized with - confirmed this
# session that the container's entrypoint script writes that same file's
# content to both the intermediate key's password and the provisioner
# admin password.
set -eu

CONTAINER="${1:-deployments-certificate-authority-1}"

docker exec "$CONTAINER" step ca provisioner update admin \
	--x509-template /run/secrets/organization.x509.tpl \
	--admin-subject step \
	--admin-provisioner admin \
	--admin-password-file /run/secrets/ca-password.dev-only
