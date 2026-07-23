# Manual multi-shell procedure (one shell per container)

One terminal per service, one script per terminal (`./deployments/scripts/`).
Every script does its own credential minting internally, including the
password shared between a container and its own co-located datastore
(Network-Manager+Headscale, Database-Vault+Postgres are each now ONE
container/ONE script — no more cross-terminal password paste for either of
those two).

**Order**: 1-4 (infra) before 5-7 (services) before 8-10 (public/metrics/
dashboards). Scripts run in the foreground; Ctrl+C stops that service. All
scripts are safe to re-run (network/user-creation steps no-op if already
done). Passwords/master key/pepper are freshly random every run — this is a
testing stack, not a persistence guide, so restarting with old data present
may just lose access to it (that trade-off is deliberate for now).
**This has a sharp edge**: Postgres/TimescaleDB only apply the password env
var the very first time their data volume is initialized — if that volume
already has data (e.g. surviving a Docker restart), re-running a script
that generates a fresh password against an already-initialized volume gets
silently ignored by the database, and the dependent service then fails
with `password authentication failed`/SASL error. This can no longer
happen for Database-Vault's own Postgres (shell 5 generates and consumes
the same value in one script, one Compose file — the cross-shell mismatch
this used to cause is gone by construction) — it can still happen for
Metrics-Collector/TimescaleDB (shells 4/9, still two separate
scripts/Compose projects). Fix: `docker rm -f
metrics-collector-timescaledb` + `docker volume rm ramusb-metrics-collector-timescaledb_ramusb-metrics-collector-timescaledb-data`
first, so the next run is a genuinely fresh init that does respect the new
password.

| Shell | Command                                                                            | Needs                                              |
| ----- | ---------------------------------------------------------------------------------- | --------------------------------------------------- |
| 1     | `./deployments/scripts/network-manager.sh`                                        | — (two-phase startup, see the script's own comment) |
| 2     | `./deployments/scripts/certificate-authority.sh`                                  | shell 1 (its co-located Headscale healthy)          |
| 3     | `./deployments/scripts/mqtt-broker.sh`                                            | shell 1, 2                                          |
| 4     | `./deployments/scripts/metrics-collector-timescaledb.sh`                          | —                                                   |
| 5     | `./deployments/scripts/database-vault.sh`                                         | shell 1, 2                                          |
| 6     | `./deployments/scripts/storage-service.sh`                                        | shell 1, 2                                          |
| 7     | `./deployments/scripts/security-switch.sh`                                        | shell 1, 2                                          |
| 8     | `./deployments/scripts/entry-hub.sh`                                              | shell 2, 3 — not a mesh node                        |
| 9     | `./deployments/scripts/metrics-collector.sh`                                      | shell 3, 4 — **prompts for shell 4's password**     |
| 10    | `./deployments/scripts/grafana.sh`                                                | shell 4                                             |
| 11    | `./deployments/scripts/e2e-test.sh`                                               | shells 1-10 all up                                  |
| 12    | `./deployments/scripts/cleanup.sh` (`--wipe` to also drop volumes/mesh identities)| —                                                   |

Six services join the real Headscale mesh, all via a real OS-level
`tailscaled` client now (Security-Switch, Database-Vault, Network-Manager,
and Storage-Service, Certificate-Authority, MQTT-broker — the latter two as
a Tailscale sidecar container sharing the main container's network
namespace): `pkg/mesh`'s earlier in-process `tsnet` was replaced for the
first three because two libraries they depend on (CA bootstrap/renewal,
MQTT publish) cannot route through an in-process-only netstack — a
confirmed library limitation. Entry-Hub and Metrics-Collector are not mesh
nodes yet — Entry-Hub's own conversion is still pending, and until it
lands, Entry-Hub cannot reach Security-Switch at all (a known, deliberate
transitional gap, not a bug). Network-Manager and Database-Vault are each
now a single container bundling their own third-party backend (Headscale,
Postgres respectively) — see those two Dockerfiles' own package doc
comments for why (NM-F-14, NET-F-01: neither backend should be reachable by
anything but its own owning service).

## Readiness signals

| Shell | Ready when you see                                                                                            |
| ----- | ---------------------------------------------------------------------------------------------------------------- |
| 1     | `>>> waiting for the co-located Headscale to become healthy...` resolves, then (after phase 2) `network-manager: listening addr=<tailscale-ip>:8447`         |
| 2     | `Serving HTTPS on :9000` + `certificate-authority-init-1 exited with code 0` + `magicsock: derp-N connected`      |
| 3     | `mosquitto version 2.1.2 running` + `magicsock: derp-N connected`                                                 |
| 4     | `database system is ready to accept connections`                                                                  |
| 5     | `database-vault: listening addr=<tailscale-ip>:8445`                                                              |
| 6     | `Server listening on <mesh-ip> port 2222` → `storage-service: listening addr=<mesh-ip>:8448`                      |
| 7     | `security-switch: listening addr=<tailscale-ip>:8444`                                                             |
| 10    | `HTTP Server Listen address=[::]:3000` → http://localhost:3000                                                    |

If a shell instead reports `Container ... Running` with no startup lines,
it was already up from before — that's fine, skip waiting for the line.

## Known issues

1. **Stale/duplicate Headscale nodes hijack MagicDNS.** Re-creating a
   service's mesh identity without deleting the old node first leaves it
   `offline` and auto-suffixes the new one (`mqtt-broker-1`, `-2`, ...) —
   a call can then resolve to the stale node and time out with no error at
   all. Check: `docker exec network-manager headscale nodes list` for
   duplicate hostnames. Fix: `headscale nodes delete --identifier
   <stale-id> --force` on each offline duplicate, then re-run the script
   that was resolving wrong.
2. **A crash loop burns a single-use CA token permanently.** If a service
   bootstraps its CA identity fine but fails later at startup and its
   supervisor respawns it, the respawn reuses the same (now consumed)
   token and fails with "lacked necessary authorization." Not a CA/mesh
   bug — just re-run the script (it mints a fresh token every time).
3. **MQTT-broker's own certs are dev-only** (~24h validity, minted via the
   CA's admin password, not CA-F-04's bootstrap-token flow) — not a
   production-ready mechanism. See RISK-04 in the SRS.
4. `third-party/mosquitto/acl.conf` has world-readable permissions;
   Mosquitto warns at startup — should be `chmod 0700`.
5. The MQTT healthcheck (shell 3) reuses `metrics/Certificate-Authority`,
   the topic CA-F-03's real metrics will eventually use — harmless
   (MT-F-02 discards it) but noisy.
6. Grafana downloads a set of unused default plugins from the internet on
   every startup — disabled via `GF_PLUGINS_PREINSTALL_ASYNC: "false"` in
   `deployments/compose/grafana.yml` (this was observed to OOM-kill the
   container on a memory-constrained dev machine before the fix).
7. `authorized-keys-command` (ST-F-11) has no provisioning mechanism yet
   for its own mTLS identity — `sshd` fails secure (RD-04) on any real
   SFTP attempt until this exists. Registration/login/POSIX-user-creation
   all work regardless.
8. **Network-Manager's own dev-only mesh-control-plane TLS cert must carry
   `network-manager` in its SAN**, not the old `network-manager-headscale`
   hostname — regenerate it (see
   `third-party/network-manager/headscale/dev-tls/README.txt` for the
   updated command) before the first run after this session's
   Network-Manager+Headscale container merge, or every other service's
   mesh join fails TLS hostname verification.
9. **Entry-Hub cannot reach Security-Switch right now.** Security-Switch's
   listener (shell 7) binds exclusively to its real Tailscale interface as
   of this session's conversion; Entry-Hub (shell 8) has not yet joined the
   mesh itself and still dials it over plain `ramusb-net`. Registration and
   login will fail at the Security-Switch hop until Entry-Hub's own mesh
   conversion lands — known, deliberate, not a bug to chase.
