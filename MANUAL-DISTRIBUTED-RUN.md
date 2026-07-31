# Manual multi-shell procedure (one shell per container)

One terminal per service, one script per terminal (`./deployments/scripts/`).
Every script does its own credential minting internally, including the
password shared between a container and its own co-located datastore
(Database-Vault+Postgres is now ONE container/ONE script — no more
cross-terminal password paste for it).

**Order**: 1-2 (PKI/mesh coordination infra) before 3-4 (Network-Manager +
messaging infra) before 5-9 (services) before 10-12
(public/metrics/dashboards). Scripts run in the foreground; Ctrl+C
stops that service. All
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
happen for Database-Vault's own Postgres (shell 6 generates and consumes
the same value in one script, one Compose file — the cross-shell mismatch
this used to cause is gone by construction) — the same is now true for
Metrics-Collector/TimescaleDB (shell 5, KI-18: co-located in one
container/one Compose file/one script, the cross-shell mismatch this used
to cause between shells 5 and 10 is gone by construction). Fix if this
still happens (e.g. an old volume from before KI-18 landed): `docker rm -f
metrics-collector` + `docker volume rm
ramusb-metrics-collector_ramusb-metrics-collector-timescaledb-data` first,
so the next run is a genuinely fresh init that does respect the new
password.

| Shell | Command                                                                            | Needs                                              |
| ----- | ---------------------------------------------------------------------------------- | --------------------------------------------------- |
| 1     | `./deployments/scripts/certificate-authority.sh`                                  | — (its own mesh sidecar may need a re-run once shell 2 is up, see Known issues #9; also co-supervises CA-F-03's metrics sidecar, KI-28 - its own publish loop needs shell 2 and shell 4 up too, but is not a startup dependency of this shell) |
| 2     | `./deployments/scripts/headscale.sh`                                              | shell 1 (its root certificate, for NM-F-12's mTLS check) |
| 3     | `./deployments/scripts/network-manager.sh`                                        | shells 1, 2                                         |
| 4     | `./deployments/scripts/mqtt-broker.sh`                                            | shells 1, 2                                         |
| 5     | `./deployments/scripts/metrics-collector.sh`                                      | shells 1, 2, 4 — MT-F-01..03, co-located TimescaleDB (real tailscaled), KI-18 |
| 6     | `./deployments/scripts/database-vault.sh`                                         | shells 1, 2                                         |
| 7     | `./deployments/scripts/storage-service.sh`                                        | shells 1, 2                                         |
| 8     | `./deployments/scripts/security-switch.sh`                                        | shells 1, 2                                         |
| 9     | `./deployments/scripts/entry-hub.sh`                                              | shells 1, 2, 4 — mesh node (real `tailscaled` sidecar `entry-hub-mesh`) |
| 10    | `./deployments/scripts/grafana.sh`                                                | shell 5                                             |
| 11    | `./deployments/scripts/e2e-test.sh`                                               | shells 1-10 all up                                  |
| 12    | `./deployments/scripts/cleanup.sh` (`--wipe` to also drop volumes/mesh identities)| —                                                   |

Headscale is its own standalone deployment this session (deployments/compose/
headscale.yml, deployments/docker/headscale/) — it can never safely be a
member of the mesh it coordinates (headscale.net's own documented
limitation), so it is NOT a mesh node itself and, unlike every other
service, is reached by Network-Manager over the PUBLIC network, not the
mesh (see services/network-manager/cmd/network-manager/main.go's own
package doc comment). Eight services join the real Headscale mesh via a
real OS-level `tailscaled` client (Security-Switch, Database-Vault,
Network-Manager, Storage-Service, Metrics-Collector, Entry-Hub, and
Certificate-Authority, MQTT-broker — the latter three as a Tailscale sidecar
container sharing the main container's network namespace): an earlier
in-process `tsnet` package (`pkg/mesh`, since deleted — see
docs/Known_Issues.md's KI-31) was replaced for Security-Switch/Database-Vault/
Network-Manager/Storage-Service because two libraries they depend on (CA
bootstrap/renewal, MQTT publish) cannot route through an in-process-only
netstack when the service also holds a server role — a confirmed library
limitation (see `.claude/agent-memory/code-agent.md`'s "pkg/pki dialer
routing"). Metrics-Collector joined this group for a different reason
(KI-18, docs/Known_Issues.md): it holds no server role of its own, but its
newly co-located TimescaleDB (MT-F-03) must be reachable by Grafana from a
separate Proxmox guest in production, which needs a genuine kernel network
interface only a real `tailscaled` provides — see
deployments/docker/metrics-collector/Dockerfile's own package doc comment.
Entry-Hub converted last (KI-27, docs/Known_Issues.md), to a real
`tailscaled` sidecar (`entry-hub-mesh`, sharing its network namespace) rather
than an in-container one, since Entry-Hub's own runtime image is distroless
(no shell, no s6-overlay to add a `tailscaled` longrun to) — it holds no
server role at all, but even a pure client's very first CA-bootstrap-token
exchange happens before any application-level dialer can intercept it, so no
role/dialer combination sidesteps the same underlying library limitation —
see `services/entry-hub/cmd/entry-hub/main.go`'s package doc comment, "Mesh
membership", for the full reasoning.
Certificate-Authority's own metrics sidecar (CA-F-03) previously followed
the same real-`tailscaled` reasoning as Entry-Hub, but KI-28 (docs/Known_Issues.md)
found it did not actually hold for this process in production - it is no
longer a separate mesh node at all: since that fix, it is s6-supervised
INSIDE the certificate-authority container itself
(deployments/docker/certificate-authority/), riding that container's own
real `tailscaled` sidecar (`certificate-authority-mesh`) for its own MQTT
publish, with no mesh-membership code of its own — see
`services/certificate-authority/cmd/metrics-sidecar/main.go`'s own package
doc comment for the full reasoning. Headscale itself is the only remaining
non-mesh RAM-USB container, for the reason above. Database-Vault is a single container
bundling its own Postgres — see that Dockerfile's own package doc comment
for why (NET-F-01: Database-Vault's own Postgres should not be reachable by
anything but its own owning service). Metrics-Collector is likewise a
single container bundling its own TimescaleDB (KI-18) — but unlike
Database-Vault's Postgres, TimescaleDB must stay reachable from another
guest (Grafana), so it binds to every local interface rather than loopback
only; see deployments/docker/metrics-collector/rootfs/etc/s6-overlay/
s6-rc.d/timescaledb/run's own comment for the full reasoning. Network-Manager,
by contrast, is no longer co-located with anything — see
deployments/docker/network-manager/Dockerfile's own package doc comment
for why that changed this session.

## Readiness signals

| Shell | Ready when you see                                                                                            |
| ----- | ---------------------------------------------------------------------------------------------------------------- |
| 1     | `Serving HTTPS on :9000` + `certificate-authority-init-1 exited with code 0` + `magicsock: derp-N connected` (the mesh sidecar) - CA-F-03's own co-supervised metrics sidecar has no listener of its own to watch for; it only tails a local log file and dials out (see services/certificate-authority/cmd/metrics-sidecar/main.go) |
| 2     | `listening and serving HTTP on: 127.0.0.1:8081` (Headscale itself) — nginx has no startup log line of its own, `curl -k https://localhost:8080/health` returning `200` confirms it |
| 3     | `network-manager: listening addr=<tailscale-ip>:8447`                                                             |
| 4     | `mosquitto version 2.1.2 running` + `magicsock: derp-N connected`                                                 |
| 5     | `database system is ready to accept connections` (TimescaleDB) → `metrics-collector: subscribed` → `magicsock: derp-N connected` |
| 6     | `database-vault: listening addr=<tailscale-ip>:8445`                                                              |
| 7     | `Server listening on <mesh-ip> port 2222` → `storage-service: listening addr=<mesh-ip>:8448`                      |
| 8     | `security-switch: listening addr=<tailscale-ip>:8444`                                                             |
| 9     | `entry-hub: listening addr=0.0.0.0:8443` → `entry-hub: listening on the mesh for login addr=:8446`                |
| 10    | `HTTP Server Listen address=[::]:3000` → http://localhost:3000                                                    |

If a shell instead reports `Container ... Running` with no startup lines,
it was already up from before — that's fine, skip waiting for the line.

## Known issues

1. **Stale/duplicate Headscale nodes hijack MagicDNS.** Re-creating a
   service's mesh identity without deleting the old node first leaves it
   `offline` and auto-suffixes the new one (`mqtt-broker-1`, `-2`, ...) —
   a call can then resolve to the stale node and time out with no error at
   all. Check: `docker exec headscale headscale nodes list` for
   duplicate hostnames. Fix: `headscale nodes delete --identifier
   <stale-id> --force` on each offline duplicate, then re-run the script
   that was resolving wrong.
2. **A crash loop burns a single-use CA token permanently.** If a service
   bootstraps its CA identity fine but fails later at startup and its
   supervisor respawns it, the respawn reuses the same (now consumed)
   token and fails with "lacked necessary authorization." Not a CA/mesh
   bug — just re-run the script (it mints a fresh token every time).
3. ~~MQTT-broker's own certs are dev-only, no automatic renewal.~~
   Resolved (KI-16, PKI-F-03): `deployments/compose/mqtt-broker.yml`'s
   `mqtt-broker-cert-issuer` (initial CA-F-04 bootstrap-token exchange) and
   `mqtt-broker-cert-renewer` (`step ca renew --daemon`, mTLS-authenticated,
   SIGHUP-reloads Mosquitto via a shared PID namespace) now provision and
   keep current both certificate identities Mosquitto's own container
   needs. Leaf certificates still inherit step-ca's ~24h default lifetime,
   but renewal is now automatic, not a "re-run this script" manual step.
4. `third-party/mosquitto/acl.conf` has world-readable permissions;
   Mosquitto warns at startup — should be `chmod 0700`.
5. The MQTT healthcheck (shell 4) reuses `metrics/Certificate-Authority`,
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
8. **Every mesh-joined service's dev-only mesh-control-plane TLS cert must
   carry `headscale` in its SAN** (this session's architectural change:
   Headscale is its own standalone deployment again, no longer
   `network-manager`) — regenerate it (see
   `third-party/headscale/dev-tls/README.txt` for the updated command,
   `deployments/scripts/headscale.sh` does this automatically if the file
   is missing) before the first run after this session's Headscale/
   Network-Manager split, or every mesh-joined service's own join fails
   TLS hostname verification.
9. **Certificate-Authority's own mesh sidecar may exit before Headscale
   exists.** Shell 1 runs before shell 2 (Headscale) in this procedure,
   but its own Tailscale sidecar (`certificate-authority-mesh`) tries to
   join the mesh immediately — with no Headscale reachable yet, it retries
   for ~30-40s and then exits entirely (a known, accepted quirk of the
   Tailscale sidecar pattern this project uses for non-Go containers, see
   `.claude/agent-memory/code-agent.md`'s "Sidecar mesh pattern" notes).
   Simply re-run `./deployments/scripts/certificate-authority.sh` once
   shell 2 is up; it is safe to re-run.
10. ~~Entry-Hub cannot reach Security-Switch.~~ Resolved: Entry-Hub joins
    the mesh itself (a real `tailscaled` sidecar, `entry-hub-mesh`) and
    dials Security-Switch over it (`RouteThroughDialer`), same as every
    other mesh-joined caller.
11. **Headscale's own coordination endpoint (port 8080) is published
    straight to the Docker host** (`deployments/compose/headscale.yml`'s
    `ports:`), per NM-F-14's wording — a real end-user Tailscale client can
    point its `--login-server`/control URL directly at it. `/api/v1/*` on
    that SAME port additionally requires a valid RAM-USB-internal-CA
    client certificate whose organization is exactly `NetworkManager`
    (NM-F-12) — enforced by the nginx reverse proxy in front of Headscale
    (`deployments/docker/headscale/nginx.conf`), verified live this
    session with `curl --cert`/`openssl s_client` against a real running
    container, with and without a certificate and with the correct/wrong
    organization.
12. **Dev-only limitation, not a bug (KI-05, unchanged by KI-16's fix):**
    `mqtt-broker-cert-renewer`'s own outbound `step ca renew` calls to
    `https://certificate-authority:9000` are routed through
    `network_mode: "service:mqtt-broker"` so they cross the Tailscale mesh
    in production (Certificate-Authority has no other reachable path
    there) - but in THIS dev stack, `mqtt-broker`'s own container is
    *also* still attached to `ramusb-net` (KI-05's own dual-reachability,
    deliberately left unfixed there), and Docker's embedded DNS resolver
    (127.0.0.11) wins over the mesh sidecar's own MagicDNS inside that
    shared network namespace - confirmed live this session (`nslookup
    certificate-authority` inside the renewer resolves to the `ramusb-net`
    IP, not the mesh IP). The mesh path itself was independently verified
    live (a direct TLS dial to Certificate-Authority's mesh IP with the
    correct SNI succeeds; the Headscale ACL policy needed a real fix,
    `services/network-manager/internal/headscale/policy.go`, to allow
    `tag:mqtt-broker` as a source reaching `tag:certificate-authority`) -
    but this dev stack cannot itself prove the RUNNING renewer's own calls
    take that path rather than `ramusb-net`, for the exact same reason
    KI-05 already documents for every other Certificate-Authority
    consumer. Not something to fix within KI-16's own scope.
