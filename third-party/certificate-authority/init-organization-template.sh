#!/bin/sh
# Entrypoint for the certificate-authority-init one-shot compose service
# (deployments/docker-compose.dev.yml). Runs automatically, once, on every
# `docker compose up`, after the certificate-authority service reports
# healthy (depends_on: condition: service_healthy) - no manual step
# required, unlike this directory's apply-organization-template.sh, which
# this script supersedes for the compose workflow.
#
# Installs config/organization.x509.tpl on the "admin" JWK provisioner
# (CA-F-04's bootstrap-token provisioner) over the network
# (https://certificate-authority:9000), not via `docker exec` - this
# container has no docker socket to exec through, unlike
# apply-organization-template.sh's host-side, docker-exec-based approach.
# See organization.x509.tpl's own doc comment for why this template is
# required at all for PKI-F-02.
#
# Idempotent for the same reason apply-organization-template.sh is: "step
# ca provisioner update" replaces the provisioner's template, it does not
# append to it - re-running this against an already-templated CA (e.g. a
# second `docker compose up` without an intervening `down -v`) is a safe
# no-op that leaves the provisioner in the same state.
#
# Trust root: /home/step/certs/root_ca.crt, read from the
# certificate-authority-data named volume (mounted read-only here, owned
# by the certificate-authority service) rather than skipping TLS
# verification - this container must trust the same root the CA
# bootstrapped itself with, exactly like every other real client in this
# codebase (pkg/pki/stepca_test.go's generateTestToken, this package's own
# apply-organization-template.sh mount the equivalent path).
#
# Admin login: the same dev-only super-admin ("step", the
# DOCKER_STEPCA_INIT_ADMIN_SUBJECT default) and password file
# (config/password.dev-only.txt, mounted at
# /run/secrets/ca-password.dev-only) the certificate-authority container
# initialized itself with - see apply-organization-template.sh's doc
# comment for how that was confirmed.
set -eu

step ca provisioner update admin \
	--ca-url https://certificate-authority:9000 \
	--root /home/step/certs/root_ca.crt \
	--x509-template /run/secrets/organization.x509.tpl \
	--admin-subject step \
	--admin-provisioner admin \
	--admin-password-file /run/secrets/ca-password.dev-only
