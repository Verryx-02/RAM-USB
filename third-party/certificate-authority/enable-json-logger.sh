#!/bin/sh
# Entrypoint for the certificate-authority-config-init one-shot compose
# service (deployments/compose/certificate-authority.yml, CA-F-03). Runs
# automatically, once, before the real certificate-authority service ever
# starts step-ca for the first time.
#
# Why this runs BEFORE certificate-authority, not after (unlike this
# directory's init-organization-template.sh, which runs after
# certificate-authority reports healthy): step-ca's own official
# entrypoint.sh only ever generates ca.json once, immediately followed by
# `exec "${@}"` in that SAME invocation - there is no hook to patch
# ca.json between generation and the server actually starting. This
# service instead runs the identical image with the SAME
# DOCKER_STEPCA_INIT_* env vars (so entrypoint.sh's own init_if_possible
# creates ca.json exactly as it otherwise would) but with `command`
# overridden to this script instead of step-ca itself - entrypoint.sh's
# `exec "${@}"` then runs THIS script, which patches ca.json and exits,
# leaving ca.json ready on the shared ramusb-ca-data volume before the
# real certificate-authority service's own entrypoint.sh runs, sees
# ca.json already present, and skips its own init_if_possible.
#
# Confirmed live, this session, end to end from a fresh volume: the real
# certificate-authority service's very first startup already emits JSON
# access-log lines (CA-F-03's own field set: status, duration-ns, etc.)
# with no restart required.
#
# jq is preinstalled in the official smallstep/step-ca image (confirmed
# live this session) - no extra tooling needed.
set -eu

STEPPATH="$(step path)"
CONFIG="${STEPPATH}/config/ca.json"

jq '.logger = {"format": "json"}' "${CONFIG}" > "${CONFIG}.tmp"
mv "${CONFIG}.tmp" "${CONFIG}"
