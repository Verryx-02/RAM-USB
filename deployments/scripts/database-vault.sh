#!/bin/bash
# Shell 5 - Database-Vault, now co-located with its own Postgres in one
# container (DV-F-08) - no separate postgres.sh anymore, no cross-shell
# password handoff (this is the only place the password is generated).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

export RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"

docker exec network-manager headscale users create database-vault 2>/dev/null || true
DV_ID=$(docker exec network-manager headscale users list -o json | jq -r '.[] | select(.name=="database-vault") | .id')

export RAM_USB_MASTER_KEY=$(openssl rand -base64 32)
export RAM_USB_PASSWORD_PEPPER="dev-only-pepper-$(openssl rand -hex 8)"
export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token DatabaseVault \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_TAILSCALE_CONTROL_URL="https://network-manager:8080"
export RAM_USB_DATABASE_VAULT_TAILSCALE_AUTHKEY=$(docker exec network-manager headscale preauthkeys create --user "$DV_ID" --expiration 30m --tags tag:database-vault)

docker compose -f deployments/compose/database-vault.yml up --build
