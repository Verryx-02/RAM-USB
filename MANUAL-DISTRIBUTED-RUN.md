# Manual multi-shell procedure (one shell per container)

> **Last full end-to-end verification**: 2026-07-22. The 12 persistent
> shells (1-12) + the one-shot MQTT certificate step + the end-to-end test
> (Shell 13: registration, real mesh join, login, Postgres persistence
> check, Headscale ACL tag check, TimescaleDB metrics check) were run
> start to finish, from a fully clean stack (no leftover RAM-USB
> container/network/volume). Result: all 5 application services
> (Entry-Hub, Security-Switch, Database-Vault, Storage-Service,
> Network-Manager) published real metrics that reached TimescaleDB,
> confirming live — not just via unit tests — that each one correctly
> reuses its own bootstrapped mTLS identity for the MQTT connection (this
> session's refactor). See "Known issues" at the end of this document for
> things observed during this run that are still to be fixed.

Every RAM-USB service already has its own independent Docker image
(`deployments/docker/<service>/Dockerfile`). This procedure uses a
dedicated Docker Compose file per container in `deployments/compose/` —
one per shell, same split as before — instead of hand-written `docker run`
commands: it eliminates build/env/volume/port boilerplate, and `docker
compose` is a cross-platform binary (macOS, Linux, Windows via
PowerShell), unlike a bash script.

This is now the **only** way the entire RAM-USB stack is started/tested,
both for local development and for integration and system testing
(`docs/Test_Plan.md §4`) — there is no longer a single Compose file that
merges every service into one project: one terminal per service,
exactly as if each service ran on a different machine, deliberately
mirrors the real deployment target (Proxmox VE, separate VM/LXC per
service, RNF-ORG-04) instead of hiding it behind a co-location that only
exists for the convenience of a single Compose file.

Each file in `deployments/compose/` declares **only its own service's
variables**: `docker compose -f deployments/compose/entry-hub.yml up`
neither requires nor knows the tokens of the other 4 services. The shells
communicate over a shared Docker network (`ramusb-net`, created once) and
resolve each other by container name — exactly as they would via real
DNS/routing if the containers were on different machines in different
zones.

> **New category of variables: values that must match across two
> different shells.** Unlike `RAM_USB_MASTER_KEY`,
> `RAM_USB_PASSWORD_PEPPER`, or `RAM_USB_CA_BOOTSTRAP_TOKEN` (each known
> to ONE shell only), the passwords of this stack's two dev-only
> Postgres/TimescaleDB databases (`RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD`,
> shared between shell 1 and shell 6; `RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD`,
> shared between shell 5 and shell 11) must be **exported with the
> identical string in both shells involved**, because they are two
> separate Compose projects that share no state: the database uses it to
> initialize the Postgres account, the application service uses it in its
> own connection string to authenticate against that account. A different
> value in the two shells does not produce a configuration error
> (`docker compose config` still validates, because each file only sees
> its own variable) — it instead produces a Postgres authentication
> failure at runtime (`password authentication failed`) that the
> application service cannot self-diagnose, because it has no way of
> knowing which password was used to initialize the database. Each shell
> involved (1, 5, 6, 11) repeats this warning in its own section below.
> Grafana (shell 12), on the other hand, has its own admin credentials
> (`RAM_USB_GRAFANA_ADMIN_USER`/`RAM_USB_GRAFANA_ADMIN_PASSWORD`) —
> required but not shared with any other shell.

> **Note**: leftover Docker volumes created by `docker-compose.dev.yml`
> may remain from an earlier cleanup
> (`deployments_certificate-authority-data`,
> `deployments_database-vault-postgres-data`,
> `deployments_network-manager-headscale-data`,
> `deployments_metrics-collector-timescaledb-data`,
> `deployments_grafana-data`). This procedure does NOT reuse them — the
> files in `deployments/compose/` create their own volumes
> (`ramusb-*-data`). Remove them yourself with `docker volume rm` if you
> no longer need them.

## Prerequisite (one-time, any shell)

```bash
cd /Users/verryx/Desktop/RAM-USB
docker network create ramusb-net
```

## Startup order

Shells 1-5 (infrastructure: Postgres, Headscale, Certificate-Authority,
MQTT-Broker, Metrics-Collector's TimescaleDB) must be started and ready
**before** any of shells 6-10 (application services) — each of the 5
application services now publishes its own metrics over MQTT (MT-F-01,
EH-F-10/EH-F-11, SS-F-07/SS-F-08, DV-F-16/DV-F-17, ST-F-12/ST-F-13,
NM-F-17/NM-F-18), so it needs `mqtt-broker` already listening. The order
among shells 6-10 is not binding — but they are listed here in dependency
order (leaves first, Entry-Hub last) for clarity. Shell 11
(Metrics-Collector) must be started only after `mqtt-broker` (shell 4)
and `metrics-collector-timescaledb` (shell 5); shell 12 (Grafana) must be
started only after `metrics-collector-timescaledb` (shell 5) — but there
is no mutual ordering constraint among shells 6-12, only toward shells
1-5 that precede them.

As with shells 1-3, shells 4-12 also have **no cross-file Compose
dependencies**: each file in `deployments/compose/` remains its own
Compose project (see this document's introduction), so
`depends_on`/`condition: service_healthy` only works for containers
defined in the SAME file. Ordering across different shells is guaranteed
only by the order in which you, manually, open and start each shell
according to this procedure — exactly as already happens for
Postgres/Headscale/Certificate-Authority.

Every `docker compose ... up` command runs in the **foreground**: the
shell itself shows live logs, no separate `docker logs -f`. Wait to see
the service ready (Postgres: "database system is ready to accept
connections"; Headscale: "listening ... on: 0.0.0.0:8080"; CA: no error
after startup) before moving to the next shell. Ctrl+C stops that
container.

---

## Shell 1 — Postgres (Database-Vault's user data)

**Warning**: `RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD` must also be
exported with the **identical string** in Shell 6 (`database-vault.yml`)
— they are two separate Compose projects, a different value in the two
shells causes Postgres authentication to fail the moment Database-Vault
tries to connect (see the box at the top of this document).

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB
export RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"
docker compose -f deployments/compose/postgres.yml up
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB
$env:RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD = "dev-only-pw-$(Get-Random)"
docker compose -f deployments/compose/postgres.yml up
```

## Shell 2 — Headscale (mesh VPN)

```bash
cd /Users/verryx/Desktop/RAM-USB
docker compose -f deployments/compose/headscale.yml up
```

**Correct readiness signal**: `listening and serving gRPC on:
0.0.0.0:50443` — NOT the HTTP line on port 8080 that appears just before
it (Headscale prints gRPC, then HTTP, then debug/metrics in sequence;
only the gRPC line on 50443 is the port Network-Manager actually uses,
the same one `headscale.yml` exposes).

## Shell 3 — Certificate-Authority (+ applying the organization template)

A single command starts both the CA and the one-shot job that applies
`organization.x509.tpl` to the "admin" provisioner (PKI-F-02) as soon as
the CA is ready — previously this required a second, separate `docker run
--rm`, now it is in the same Compose file.

```bash
cd /Users/verryx/Desktop/RAM-USB
docker compose -f deployments/compose/certificate-authority.yml up
```

**Readiness signals**: `Serving HTTPS on :9000 ...` (the CA is up) +
`certificate-authority-init-1 exited with code 0` (the organization
template was applied successfully). After these two signals, the shell
keeps printing a line every 5 seconds (`GET /health ... status=200`)
**forever** — this is the Docker healthcheck running for the entire
lifetime of the container, not an error or something that "finishes": do
not wait for it to stop. A single isolated `level=warning` line on
`/admin/admins` with `"missing authorization header token"` is also
expected (it is the request attempt before the correct login).

## One-time step — dev-only MQTT certificates (after Shell 3, before Shell 4)

From any already-free shell (no dedicated shell needed: this script exits
on its own, it does not stay in the foreground), once Shell 3 shows the
CA ready (no error after startup):

```bash
cd /Users/verryx/Desktop/RAM-USB
third-party/mosquitto/generate-dev-certs.sh certificate-authority
```

This script now mints **only two static identities**: `MQTTBroker` (the
broker's own server certificate — Mosquitto is a C binary, not a Go
process, and cannot call `pkg/pki`) and `CertificateAuthority` (the
self-publish for `mqtt-broker.yml`'s healthcheck). Every other service
that publishes or reads metrics (Entry-Hub, Security-Switch,
Database-Vault, Storage-Service, Network-Manager, Metrics-Collector) now
reuses its own mTLS identity, already bootstrapped via
`RAM_USB_CA_BOOTSTRAP_TOKEN` (shells 6-11 below), for the MQTT connection
too — no separate certificate/key file for them.

The container name `certificate-authority` is already the script's
default (matching the fixed `container_name:` that
`deployments/compose/certificate-authority.yml` sets, the only Compose
convention this project still uses) — passing it explicitly anyway
remains good explicit practice, not a necessity. The minted certificates
(`third-party/mosquitto/certs/*.dev-only.{crt,key}`, ignored by git) have
a validity of ~24h — repeat this step if an MQTT connection starts
failing with an expired-certificate error (this only concerns
`MQTTBroker`/`CertificateAuthority`: the other 6 services' MQTT identity
renews itself in-process, like their main mTLS identity).

---

From here on (shells 6-10), every application service needs a single-use
CA token (expires in ~15 minutes) minted right before startup — this is
the only value that cannot live in a static YAML file. Each block below
shows **bash/zsh** first, then **PowerShell**: the final `docker compose`
command is identical, only the syntax for capturing the value into an
environment variable changes.

## Shell 4 — MQTT-Broker (Mosquitto)

Requires that the one-time step above has already been run (the dev-only
certificates must already exist in `third-party/mosquitto/certs/`,
otherwise startup fails due to missing volumes).

```bash
cd /Users/verryx/Desktop/RAM-USB
docker compose -f deployments/compose/mqtt-broker.yml up
```

**Readiness**: `mosquitto version 2.1.2 running`. After startup you will
see a sequence repeated every 10 seconds — connection, TLS negotiation,
disconnection, always with user `CertificateAuthority` — this is the
Docker healthcheck (`mosquitto_pub`, a "use once and discard" tool: it
connects, publishes a message, and exits on its own). This is not a
network problem, it is the exact expected behavior of a one-shot command
running in a loop. When the real services connect (shells 6-11), the
difference will be visible: their connection **stays open**, no
"disconnected" right after. See also "Known issues" at the end of this
document for a warning about `acl.conf` permissions visible in this
shell's early logs.

PowerShell: identical command, no bash-specific syntax in this block.

## Shell 5 — TimescaleDB (Metrics-Collector's data)

**Warning**: `RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD` must also be
exported with the **identical string** in Shell 11
(`metrics-collector.yml`) — they are two separate Compose projects, a
different value in the two shells causes Postgres authentication to fail
the moment Metrics-Collector tries to connect (see the box at the top of
this document).

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB
export RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"
docker compose -f deployments/compose/metrics-collector-timescaledb.yml up
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB
$env:RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD = "dev-only-pw-$(Get-Random)"
docker compose -f deployments/compose/metrics-collector-timescaledb.yml up
```

**Readiness**: the **second** occurrence of `database system is ready to
accept connections` (the Postgres image runs an init→shutdown→restart
cycle, the first occurrence is transient). During bootstrap you will also
see a line `ERROR: background worker "TimescaleDB Background Worker
Scheduler for database N" trying to connect to template database,
exiting` — confirmed benign by a TimescaleDB maintainer themselves
(github.com/timescale/timescaledb-docker#170: "has no consequences, but
is alarming for the users"), it is not a real error.

PowerShell: identical command, no bash-specific syntax in this block.

## Shell 6 — Database-Vault

**Warning**: `RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD` below must be
**exactly the same string** exported in Shell 1 (`postgres.yml`) — do not
generate it again here, copy/reuse it from Shell 1. A different value
causes Postgres authentication to fail as soon as Database-Vault tries to
connect (see the box at the top of this document).

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB

# Secrets for this service only: no other container sees them,
# EXCEPT RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD - that one must match
# Shell 1.
export RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD="<the same string exported in Shell 1>"
export RAM_USB_MASTER_KEY=$(openssl rand -base64 32)
export RAM_USB_PASSWORD_PEPPER="dev-only-pepper-$(openssl rand -hex 8)"
export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token DatabaseVault \
  --ca-url https://certificate-authority:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner admin \
  --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/database-vault.yml up --build
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB   # adjust to your path

# Dev-only: random but not cryptographically strong, consistent with this
# project's other "*.dev-only.*" conventions.
$env:RAM_USB_DATABASE_VAULT_POSTGRES_PASSWORD = "<the same string exported in Shell 1>"
$env:RAM_USB_MASTER_KEY = [Convert]::ToBase64String([byte[]](1..32 | ForEach-Object { Get-Random -Maximum 256 }))
$env:RAM_USB_PASSWORD_PEPPER = "dev-only-pepper-$(Get-Random)"
$env:RAM_USB_CA_BOOTSTRAP_TOKEN = docker exec certificate-authority step ca token DatabaseVault `
  --ca-url https://certificate-authority:9000 `
  --root /home/step/certs/root_ca.crt `
  --provisioner admin `
  --password-file /run/secrets/ca-password.dev-only

docker compose -f deployments/compose/database-vault.yml up --build
```

## Shell 7 — Storage-Service

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB
export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token StorageService \
  --ca-url https://certificate-authority:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner admin \
  --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/storage-service.yml up --build
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB
$env:RAM_USB_CA_BOOTSTRAP_TOKEN = docker exec certificate-authority step ca token StorageService `
  --ca-url https://certificate-authority:9000 `
  --root /home/step/certs/root_ca.crt `
  --provisioner admin `
  --password-file /run/secrets/ca-password.dev-only

docker compose -f deployments/compose/storage-service.yml up --build
```

## Shell 8 — Network-Manager

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB
# This API key is also a secret of this service alone.
export RAM_USB_HEADSCALE_API_KEY=$(docker exec network-manager-headscale /ko-app/headscale apikeys create --expiration 24h)
export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token NetworkManager \
  --ca-url https://certificate-authority:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner admin \
  --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/network-manager.yml up --build
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB
$env:RAM_USB_HEADSCALE_API_KEY = docker exec network-manager-headscale /ko-app/headscale apikeys create --expiration 24h
$env:RAM_USB_CA_BOOTSTRAP_TOKEN = docker exec certificate-authority step ca token NetworkManager `
  --ca-url https://certificate-authority:9000 `
  --root /home/step/certs/root_ca.crt `
  --provisioner admin `
  --password-file /run/secrets/ca-password.dev-only

docker compose -f deployments/compose/network-manager.yml up --build
```

## Shell 9 — Security-Switch

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB
export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token SecuritySwitch \
  --ca-url https://certificate-authority:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner admin \
  --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/security-switch.yml up --build
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB
$env:RAM_USB_CA_BOOTSTRAP_TOKEN = docker exec certificate-authority step ca token SecuritySwitch `
  --ca-url https://certificate-authority:9000 `
  --root /home/step/certs/root_ca.crt `
  --provisioner admin `
  --password-file /run/secrets/ca-password.dev-only

docker compose -f deployments/compose/security-switch.yml up --build
```

## Shell 10 — Entry-Hub

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB
# Public dev-only TLS certificate, if it does not already exist.
[ -f third-party/entry-hub/config/server.dev-only.crt ] || third-party/entry-hub/generate-dev-cert.sh

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token EntryHub \
  --ca-url https://certificate-authority:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner admin \
  --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/entry-hub.yml up --build
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB
if (-not (Test-Path third-party\entry-hub\config\server.dev-only.crt)) {
  bash third-party/entry-hub/generate-dev-cert.sh   # requires Git Bash/WSL only for this one-time script
}

$env:RAM_USB_CA_BOOTSTRAP_TOKEN = docker exec certificate-authority step ca token EntryHub `
  --ca-url https://certificate-authority:9000 `
  --root /home/step/certs/root_ca.crt `
  --provisioner admin `
  --password-file /run/secrets/ca-password.dev-only

docker compose -f deployments/compose/entry-hub.yml up --build
```

## Shell 11 — Metrics-Collector

Requires `mqtt-broker` (shell 4) and `metrics-collector-timescaledb`
(shell 5) already ready. Metrics-Collector has no HTTP listener of its
own (no PKI-F-01 role as server), but still bootstraps its own mTLS
identity via `pki.NewClient` (CA-F-04) for the MQTT connection — it
therefore also needs a single-use CA token, minted right before startup,
exactly like shells 6-10.

**Warning**: `RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD` below must be
**exactly the same string** exported in Shell 5
(`metrics-collector-timescaledb.yml`) — do not generate it again here,
copy/reuse it from Shell 5. A different value causes Postgres
authentication to fail as soon as Metrics-Collector tries to connect (see
the box at the top of this document).

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB

export RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD="<the same string exported in Shell 5>"
export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token MetricsCollector \
  --ca-url https://certificate-authority:9000 \
  --root /home/step/certs/root_ca.crt \
  --provisioner admin \
  --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/metrics-collector.yml up --build
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB   # adjust to your path

$env:RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD = "<the same string exported in Shell 5>"
$env:RAM_USB_CA_BOOTSTRAP_TOKEN = docker exec certificate-authority step ca token MetricsCollector `
  --ca-url https://certificate-authority:9000 `
  --root /home/step/certs/root_ca.crt `
  --provisioner admin `
  --password-file /run/secrets/ca-password.dev-only

docker compose -f deployments/compose/metrics-collector.yml up --build
```

## Shell 12 — Grafana

Requires `metrics-collector-timescaledb` (shell 5) already ready.
Dashboards (MT-F-04) provisioned automatically from
`third-party/grafana/provisioning` — no manual UI configuration.
Reachable at http://localhost:3000 with the admin credentials you export
below (`RAM_USB_GRAFANA_ADMIN_USER`/`RAM_USB_GRAFANA_ADMIN_PASSWORD`,
native variables of the `grafana/grafana` image - no image default stays
active). Unlike the Postgres/TimescaleDB passwords above, these do not
need to match anything else: they are only seen by this shell.

bash/zsh:
```bash
cd /Users/verryx/Desktop/RAM-USB
export RAM_USB_GRAFANA_ADMIN_USER="admin"
export RAM_USB_GRAFANA_ADMIN_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"
docker compose -f deployments/compose/grafana.yml up
```

PowerShell:
```powershell
Set-Location C:\path\to\RAM-USB
$env:RAM_USB_GRAFANA_ADMIN_USER = "admin"
$env:RAM_USB_GRAFANA_ADMIN_PASSWORD = "dev-only-pw-$(Get-Random)"
docker compose -f deployments/compose/grafana.yml up
```

**Readiness**: `HTTP Server Listen address=[::]:3000`. Before reaching
that point you will see two `level=error` lines about missing
provisioning directories (`/etc/grafana/provisioning/{plugins,alerting}`)
— non-blocking, Grafana continues and completes startup normally; this
stack does not use those two provisioning categories, so the directories
do not exist. You will also see Grafana download and install a group of
default plugins from the internet (pyroscope, explore-traces,
metrics-drilldown, etc.) not used by MT-F-04 — see "Known issues" at the
end of this document.

---

## Shell 13 — End-to-end test (registration, mesh join, login, verification)

On bash/zsh, unchanged from before. Once shells 1-12 all show logs with
no errors:

```bash
cd /Users/verryx/Desktop/RAM-USB

# --- Registration ---
rm -f /tmp/ramusb_test_key /tmp/ramusb_test_key.pub
ssh-keygen -t ed25519 -N "" -f /tmp/ramusb_test_key -C "test@ramusb" -q
TESTKEY=$(cat /tmp/ramusb_test_key.pub)
TESTEMAIL="test-$(date +%s)@example.com"

REGISTER_RAW=$(curl -sk -w "\n%{http_code}" -X POST https://localhost:8443/api/register \
  -H "Content-Type: application/json" \
  --data-binary @- <<EOF
{"email":"$TESTEMAIL","password":"Sup3rSecretPass123","ssh_public_key":"$TESTKEY"}
EOF
)
REGISTER_STATUS=$(echo "$REGISTER_RAW" | tail -n1)
REGISTER_BODY=$(echo "$REGISTER_RAW" | sed '$d')
echo "$REGISTER_BODY"
echo "HTTP_STATUS:$REGISTER_STATUS"

# Automatic extraction of "pre_auth_key" from the response - no manual
# copy-paste (in an earlier session, the textual placeholder was executed
# literally instead of being substituted, and Headscale correctly
# rejected the string as an "invalid pre auth key").
PREAUTHKEY=$(echo "$REGISTER_BODY" | grep -o '"pre_auth_key":"[^"]*"' | cut -d'"' -f4)
if [ -z "$PREAUTHKEY" ]; then
  echo "ERROR: pre_auth_key not found in the registration response (HTTP $REGISTER_STATUS) - check entry-hub/security-switch logs before continuing." >&2
  return 1 2>/dev/null || exit 1
fi
echo "pre_auth_key extracted successfully."

# --- Real mesh join ---
export TS_AUTHKEY="$PREAUTHKEY"
docker compose -f deployments/compose/tailscale-test.yml up -d --force-recreate

sleep 6
docker logs ramusb-tailscale-test 2>&1 | tail -5

# --- Login (same email used for registration) ---
curl -sk -X POST https://localhost:8443/api/login \
  -H "Content-Type: application/json" \
  --data-binary @- <<EOF -w "\nHTTP_STATUS:%{http_code}\n"
{"email":"$TESTEMAIL","password":"Sup3rSecretPass123"}
EOF
# Expected: {"status":"ok"} / HTTP 200

# --- Check Postgres persistence ---
docker exec database-vault-postgres psql -U database_vault -d database_vault \
  -c "SELECT posix_username, registered_at FROM users ORDER BY registered_at DESC LIMIT 5;"

# --- Check the ACL tag at the network level ---
docker exec network-manager-headscale /ko-app/headscale nodes list

# --- Check that metrics are flowing (MT-F-01..04) ---
# Entry-Hub/Security-Switch publish every minute (EH-F-10/EH-F-11,
# SS-F-07/SS-F-08): wait up to a minute if the table is still empty
# right after the registration/login just performed.
sleep 65
docker exec metrics-collector-timescaledb psql -U metrics_collector -d metrics_collector \
  -c "SELECT service, time, request_count, error_count, average_response_time_ms, active_connections FROM metrics ORDER BY time DESC LIMIT 5;"
```

If this last query returns no rows, check the logs of shell 11
(`metrics-collector`) and shell 4 (`mqtt-broker`) before continuing — a
failed mTLS handshake toward `mqtt-broker` (wrong certificate
organization or SAN, see the comment in the
`third-party/mosquitto/generate-dev-certs.sh` script) is the most common
cause.

On PowerShell, use `curl.exe` explicitly (not the `curl` alias for
`Invoke-WebRequest`, which has incompatible flags) and adapt the
variable-capture syntax as in shells 6-10; `ssh-keygen` is included by
default in Windows 10+ (OpenSSH client).

---

## Known issues (observed during the 2026-07-22 run, not yet fixed)

None of these prevented the end-to-end test from completing
successfully — they are improvements to make, not blockers.

1. **`third-party/mosquitto/acl.conf` has world-readable permissions.**
   Mosquitto warns at startup (shell 4): "Future versions will refuse to
   load this file... use `chmod 0700 /mosquitto/config/acl.conf`."
   The file should be generated/copied with stricter permissions.

2. **The MQTT broker healthcheck (shell 4) reuses the
   `metrics/Certificate-Authority` topic** — the same topic that will one
   day carry the Certificate-Authority's real metrics (CA-F-03, not yet
   implemented). The healthcheck payload (`"healthcheck"`, plain text) is
   not valid JSON, so Metrics-Collector correctly discards it (MT-F-02) —
   but it produces a `WARN` in its log every 10 seconds, forever, and
   mixes an infrastructure probe with a topic that will hold real
   business data. Better: a dedicated topic/ACL for the healthcheck only
   (e.g. `healthcheck/mqtt-broker`), separate from the `metrics/*`
   namespace.

3. **Grafana (shell 12) downloads and installs a group of default plugins
   from the internet on every startup** (grafana-pyroscope-app,
   grafana-exploretraces-app, grafana-metricsdrilldown-app,
   grafana-lokiexplore-app, elasticsearch, zipkin) — none of these are
   needed by MT-F-04 (dashboard on response time/throughput/active
   connections via TimescaleDB). Worth checking whether an environment
   variable exists to disable auto-install of Grafana 13.1's
   pre-installed default plugins, to avoid the internet dependency and
   the extra latency on every restart of this dev-only stack.

---

## Shell 14 (optional) — Full cleanup

```bash
cd /Users/verryx/Desktop/RAM-USB
docker compose -f deployments/compose/grafana.yml down
docker compose -f deployments/compose/metrics-collector.yml down
docker compose -f deployments/compose/entry-hub.yml down
docker compose -f deployments/compose/security-switch.yml down
docker compose -f deployments/compose/network-manager.yml down
docker compose -f deployments/compose/storage-service.yml down
docker compose -f deployments/compose/database-vault.yml down
docker compose -f deployments/compose/metrics-collector-timescaledb.yml down
docker compose -f deployments/compose/mqtt-broker.yml down
docker compose -f deployments/compose/certificate-authority.yml down
docker compose -f deployments/compose/headscale.yml down
docker compose -f deployments/compose/postgres.yml down
docker compose -f deployments/compose/tailscale-test.yml down

docker network rm ramusb-net 2>/dev/null

# Also removes the persisted data (Postgres/CA/Headscale/TimescaleDB/
# Grafana) - only start completely from scratch if you really want to:
# docker volume rm ramusb-postgres-data ramusb-headscale-data ramusb-ca-data \
#   ramusb-metrics-collector-timescaledb-data ramusb-grafana-data
```

PowerShell: same `docker compose ... down` commands, character-for-character
identical (no bash-specific syntax in this block).
