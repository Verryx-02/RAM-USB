# Known Issues

Running ledger of implementation gaps and bugs discovered while working on
RAM-USB that are **not** already tracked as a deliberately-deferred
requirement in the SRS (see
`Software_Requirements_Specification.md` §8, "Known risks and open
issues" — RISK-01/02/03 there follow the SRS's own approval process,
since they are requirement-level decisions, not implementation gaps).

This file exists for the other kind of finding: something that should
already work per the SRS/design but doesn't yet, discovered as a
side-effect of unrelated work. Every agent — orchestrator and subagents
alike — logs a new entry here the moment it finds a gap outside its
current task's scope, instead of letting it evaporate at the end of that
task's report. When a real fix lands (not a workaround), the entry is
updated to `FIXED` with the commit/change that closed it, or removed
entirely if keeping a closed entry adds no value.

Each entry: **ID**, **Found** (date, context), **Area**, **Description**,
**Status** (`OPEN` / `FIXED`).

## Currently open (2026-07-25)

Keep this list in sync whenever an entry's status changes — it's the
at-a-glance worklist; the full entries below are the detail/history.

| ID | One-line | Blocked on |
|---|---|---|
| KI-02 | EH-F-03's mesh-only `/api/login` split undocumented in SRS/diagrams | — |
| KI-06 | NM-F-12/14/15/16/NET-F-01/MT-F-01..04 missing `[Code]` links | — |
| KI-07 | `09-security-trust-zones.puml` one-directional arrow bug | — |
| KI-12 | MT-F-02/CA-F-03/ST-F-12/13 broken or missing `[Code]` links | — |
| KI-14 | Headscale missing from 2 security diagrams; certificate-authority-metrics missing from the deployment diagram | — |
| KI-15 | §5.1 non-functional requirements have no `[Code]`/test link at all | user decision |
| KI-19 | Entry-Hub/certificate-authority-metrics have no restart policy | user decision |
| KI-20 | NM-F-12..16 (Headscale coordination/DNS cluster) have zero test coverage | user decision |
| KI-22 | Grafana -> TimescaleDB uses plaintext password auth, no mTLS (RNF-SEC-04 violation) | user decision |
| KI-23 | Restarting a CA-F-04-bootstrapped service needs a manually-minted fresh token; only Certificate-Authority itself restarts with zero manual step | user decision |
| KI-24 | `08-security-pki-hierarchy.puml` draws a `PrivateCA -> Metrics-Visualizer` signing edge that doesn't exist (Grafana has no mTLS identity) | — |

Everything else in this file (KI-01, KI-03–KI-05, KI-09–KI-11, KI-13,
KI-16–KI-18, KI-21) is `FIXED` — kept below for history/traceability, not
part of the active worklist.

---

## KI-01 — ST-F-11's `authorized-keys-command` has no provisioning mechanism for its own mTLS identity

- **Found:** 2026-07-24, while writing `deployments/proxmox/storage-service.md`.
- **Area:** Storage-Service, `services/storage-service/cmd/authorized-keys-command/main.go`.
- **Description:** On every SFTP connection attempt, `sshd` invokes this
  binary via `AuthorizedKeysCommand` to ask Database-Vault for the
  connecting user's current public key (ST-F-11), authenticating that
  call over mTLS. The binary's own doc comment expects its identity/config
  (Database-Vault's URL, its own client certificate material) at
  `/etc/storage-service/authorized-keys-command.conf` — but nothing in the
  Dockerfile, `tailscale-up.sh`, or any other startup script actually
  creates that file's *contents* (the directory is created, empty). The
  binary's own comment calls this "a separate, not-yet-scoped task."
- **Status:** FIXED, 2026-07-24. A new s6-supervised `identity-provisioner`
  process (`services/storage-service/cmd/identity-provisioner/`) bootstraps
  its own mTLS identity (organization `StorageService`, a second CA-F-04
  token distinct from `storage-service`'s own) at container start and
  periodically re-encodes the SDK's auto-renewing certificate to disk,
  writing `authorized-keys-command.conf` last so a new
  `identity-provisioner-ready` s6 oneshot can gate `sshd`'s start on its
  existence. Verified live end-to-end: a real `sftp` client inside the
  container triggers `AuthorizedKeysCommand`, which completes a real mTLS
  round-trip to Database-Vault. Two pre-existing bugs found and fixed as a
  side effect: `pkg/pki.RootCA` needed `stepca.WithRootSHA256`; and
  `authorized-keys-command`'s outbound client never forced `ServerName`,
  so Go's hostname check rejected every real connection before PKI-F-02's
  organization check ever ran. `MANUAL-DISTRIBUTED-RUN.md`'s "Known issue
  #7" still describes this now-fixed gap and needs updating separately.

## KI-02 — EH-F-03's mesh-only login listener is undocumented outside the code

- **Found:** 2026-07-24, by `git-agent` while planning the commit that
  landed Entry-Hub's mesh join (commit `819a216`).
- **Area:** SRS (EH-F-03's text), `docs/design/diagrams/01-architecture-container.puml`
  and `02-architecture-deployment.puml`.
- **Description:** Entry-Hub now serves `POST /api/login` on a second,
  mesh-only listener (`pkg/mesh`/tsnet), separate from the public listener
  serving `/api/health`/`/api/register` — a deliberate architectural
  decision made and confirmed with the user this session ("taglio netto":
  `/api/register` stays public, `/api/login` becomes mesh-only). Neither
  the SRS's EH-F-03 requirement text nor either diagram currently shows
  this split — both still describe/depict a single Entry-Hub listener.
- **Status:** OPEN.

## KI-03 — CA-F-03's metrics sidecar has a design but zero code

- **Found:** carried over from a prior session (2026-07-20 research), still
  true as of a 2026-07-24 re-check.
- **Area:** Certificate-Authority (`deployments/docker/certificate-authority/`,
  no `internal/metrics` package anywhere in this repo for it).
- **Description:** `step-ca` (the underlying product) has no native
  `/metrics` endpoint (confirmed against its own route table, GitHub
  issue #790 still open upstream). The viable path — tailing/parsing
  step-ca's own structured JSON access log (`logger: json`) to derive
  RequestCount/ErrorCount/AverageResponseTimeMs, then republish via
  `pkg/metrics` like every other service — is fully designed (exact log
  field names confirmed live) but nothing has been built.
- **Status:** FIXED, 2026-07-24. `services/certificate-authority/cmd/metrics-sidecar/`
  tails step-ca's JSON access log (`third-party/certificate-authority/enable-json-logger.sh`
  patches `ca.json` before first boot, since there is no CLI/env lever for
  `logger.format`) and republishes via `pkg/metrics` from the new
  `certificate-authority-metrics` container. One real bug found and fixed
  during live verification: the CA-F-04 bootstrap token was minted with
  subject `CertificateAuthorityMetrics` (the container's own name) instead
  of `CertificateAuthority` (the SRS service identity); Mosquitto's ACL
  only authorizes the latter to publish `metrics/Certificate-Authority`,
  so publishes were silently ACL-denied with no visible error. Verified
  live twice, ~4 minutes apart, with growing counters confirming both the
  accumulator and the once-a-minute publish loop.

## KI-04 — ST-F-12/13: Storage-Service never publishes its own metrics

- **Found:** carried over from a prior session (2026-07-20).
- **Area:** Storage-Service, `services/storage-service/cmd/storage-service/main.go`.
- **Description:** Every other merged service (Entry-Hub, Security-Switch,
  Database-Vault, Network-Manager) already wires `pkg/metrics` for its own
  `metrics/<Service>` MQTT publish. Storage-Service was the one exception —
  no `Counters`, no periodic publish loop, nothing.
- **Status:** FIXED, discovered stale 2026-07-24 during the simplification
  audit's Storage-Service pass. Confirmed live:
  `services/storage-service/internal/httpapi/counters.go`,
  `cmd/storage-service/metrics_test.go`, and
  `cmd/storage-service/main.go:144,170-171` (`httpapi.Counters{}`,
  `metrics.Run`/`metrics.PublishOnce` wiring) all exist and are real —
  the original 2026-07-20 `find` result predates this work landing. The
  2026-07-24 "still true" re-check note above was itself wrong (not
  re-verified against current code, just re-asserted) — a reminder to
  actually re-run the check next time, not just restate the prior date.

## KI-05 — Certificate-Authority and MQTT-broker are reachable via mesh but not *only* via mesh

- **Found:** 2026-07-24, live verification (Fase B, this session).
- **Area:** `deployments/compose/certificate-authority.yml`,
  `deployments/compose/mqtt-broker.yml` (dev/test only, see below);
  `deployments/proxmox/certificate-authority.md`,
  `deployments/proxmox/mosquitto.md` (production, resolved).
- **Description:** Both are reachable from their real Tailscale mesh
  identity as intended, but are *also* still reachable via plain
  `ramusb-net` and via a host-published port — confirmed live with a
  plain `ramusb-net`-only container and the bare Docker host, both
  succeeded where they should fail.
- **Status:** Production reachability question RESOLVED, 2026-07-25 —
  confirmed directly with the user: in production, both components are
  reachable **only** via the Tailscale mesh (no published port, no shared
  Docker network), documented in the two new Proxmox docs above. The key
  insight that resolves this cleanly (not one of options A/B/C originally
  listed below, which were all solving the single-host dev topology's
  problem specifically): RNF-ORG-04 gives every service its own dedicated
  VM/LXC guest in production, and per NM-F-14/`deployments/vps/headscale.md`,
  Headscale itself already runs on its own separate, publicly-addressable
  VPS outside Proxmox entirely — so the CA/MQTT-broker's own mesh sidecars
  reach Headscale over the guest's normal internet route, exactly like
  Network-Manager's own mesh join already does, with no Docker network
  shared with Headscale needed at all. The dev/test Compose stack's own
  circular-dependency problem (Headscale co-located as a `ramusb-net`
  container it cannot itself safely join) is now explicitly a **dev-only,
  lower-priority, cosmetic** limitation — it does not block production
  readiness, and per this project's own established convention, the dev
  Compose files (`certificate-authority.yml`, `mqtt-broker.yml`) are left
  unchanged (out of scope for the production-readiness fix). Original
  attempt notes and the two secondary `ramusb-net` dependencies found
  along the way, kept for reference since they still describe the dev
  stack's real current behavior: removing `ramusb-net` from the main
  `certificate-authority` container breaks its own `-mesh` sidecar's
  ability to reach Headscale (verified live: `fetch control key: ... no
  DNS fallback candidates remain for "headscale"`); `certificate-authority-init`
  reaches the CA via `ramusb-net` (`--ca-url
  https://certificate-authority:9000` in
  `third-party/certificate-authority/init-organization-template.sh`);
  `third-party/mosquitto/generate-dev-certs.sh` runs a disposable
  `step-cli` container on `--network ramusb-net` for its
  certificate-exchange step. None of these three dev-only items are fixed
  or blocking anything now.

## KI-06 — SRS traceability: several implemented requirements have no `[Merged]` link

- **Found:** 2026-07-24, full sweep of every `|*-F-*|` row in the SRS
  against its own commit history.
- **Area:** `docs/Software_Requirements_Specification.md`.
- **Description:** NM-F-12, NM-F-14, NM-F-15, NM-F-16, NET-F-01 (all
  confirmed implemented — NM-F-12/14 this session, NM-F-15/16 confirmed
  live via `third-party/headscale/config/config.yaml`'s `magic_dns`/
  `base_domain` and `network-manager`'s own `tailscale-up.sh`), plus
  MT-F-01..04 (Mosquitto/Metrics-Collector/Grafana are all "Done" in
  §2.1's component table already) have requirement rows with no
  `[Merged]` commit link, violating the SRS's own traceability rule (§9).
  NM-F-10/11/17/18 and PKI-F-01/02, flagged as missing the same link in a
  prior session, are now confirmed fixed (commits `3b9fe32`/`cb4116e`/
  `b4aa6f9`) — don't re-flag those.
- **Status:** OPEN. Cheap fix (the commits already exist), but per this
  project's own convention, confirm the exact commit hashes with the user
  before editing the SRS again.

## KI-07 — `09-security-trust-zones.puml` shows Database-Vault↔Storage-Service as one-directional, but two independent real call directions exist

- **Found:** 2026-07-24, `consistency-agent` audit (SRS vs. code).
- **Area:** `docs/design/diagrams/09-security-trust-zones.puml:65`.
- **Description:** The diagram draws `StorageService --> DatabaseVault`
  as a single one-way arrow. In reality there are two independent calls
  in opposite directions: Database-Vault → Storage-Service (DV-F-09,
  asking it to create the POSIX user) and Storage-Service → Database-Vault
  (ST-F-11, `AuthorizedKeysCommand` asking for the current public key on
  every SFTP attempt). The same diagram draws other genuinely bidirectional
  relationships explicitly (`SecuritySwitch <--> DatabaseVault`,
  `SecuritySwitch <--> NetworkManager`), and the sibling diagram
  (`01-architecture-container.puml:45`) already draws this exact
  relationship as bidirectional — so the one-way arrow here is
  inconsistent with the diagram's own convention, not a deliberate
  simplification.
- **Status:** OPEN.

## KI-09 — SRS §2.1: Headscale's status may be stale ("In progress")

- **Found:** 2026-07-24, `consistency-agent` audit (SRS vs. code).
- **Area:** `docs/Software_Requirements_Specification.md:76` (§2.1
  component table).
- **Description:** Headscale's row still reads "In progress," even
  though every NM-F requirement referencing it (NM-F-08/09/12/14/15/16)
  is confirmed implemented and correct. The most recent commit that
  updated the two sibling rows (Storage-Service, Network-Manager) to
  "Done" for these same requirements did not touch Headscale's row in
  the same pass — could be deliberate (KI-05's dual-reachability gap for
  CA/MQTT-broker, though that isn't about Headscale specifically) or a
  plain oversight.
- **Status:** FIXED, 2026-07-25 — user confirmed: flipped to "Done." No
  remaining code work for Headscale itself.

## KI-10 — s6 longruns respawn instantly forever on a permanent (non-retryable) startup error, not just transient ones

- **Found:** 2026-07-24, live: `network-manager` was stuck in a tight
  sub-second crash loop (`docker inspect` showed `RestartCount=0`,
  container never restarted at the Docker level — it was s6-overlay's own
  longrun supervisor respawning the process internally, invisible without
  inspecting container internals). Root cause: `main.go`'s `os.Exit(1)`
  after a fatal startup error (here, `RAM_USB_CA_BOOTSTRAP_TOKEN` had
  already been consumed — CA-F-04 tokens are single-use by design, see
  `pkg/pki`) fires every ~1 second forever, since a plain s6-rc `longrun`
  respawns immediately on any exit with no backoff, and the token can
  never succeed on a later attempt once spent — every respawn after the
  first was guaranteed to fail identically. A secondary, independently
  confirmed bug compounded this: the main checkout's own copy of the
  gitignored `third-party/headscale/dev-tls/cert.dev-only.pem` had been
  silently replaced with an **empty directory** by Docker (the documented
  "creates an empty dir at a missing bind-mount source instead of
  erroring" footgun, `.claude/agent-memory/code-agent.md`) after an
  earlier `docker compose up` ran before that file existed on disk —
  `network-manager` could not load any Headscale trust material at all
  and failed every mesh dial with `x509: certificate signed by unknown
  authority` even after a fresh token fixed the first failure.
- **Area:** every s6-supervised longrun that bootstraps via a single-use
  CA-F-04 token at startup — Network-Manager, Database-Vault,
  Storage-Service (`storage-service` and `identity-provisioner`),
  Security-Switch, Metrics-Collector.
- **Status:** FIXED, 2026-07-25, for all five. A `finish` script (`chmod
  0755`, next to each service's own `run`) sleeps 30s before letting s6-rc
  respawn the longrun on a genuine nonzero exit code (`os.Exit(1)`), while
  not delaying a clean SIGTERM container stop (exit code 256) — turns an
  unrecoverable, log-spamming, CA-hammering sub-second loop into a slow,
  visible one an operator has time to notice and fix (mint a fresh token,
  recreate the container). Does not fix the underlying single-use-token
  fragility itself (that's CA-F-04's own documented design), only the
  respawn-storm symptom. Confirmed the identical `os.Exit(1)`-on-fatal-error
  shape in all five `main.go`s before applying the same fix to each
  (`deployments/docker/{database-vault,storage-service,security-switch,
  metrics-collector}/rootfs/etc/s6-overlay/s6-rc.d/{same-name,
  identity-provisioner}/finish`) — not yet re-verified live against each
  running container (Network-Manager's own fix was; the other four are
  the same file shape applied by direct analogy, worth a live crash-loop
  drill before fully trusting it if one ever occurs for real). The main
  checkout's `cert.dev-only.pem` desync noted in the original finding was
  a separate, unrelated bug, already fixed live that same day.

## KI-11 — No Proxmox/VPS deployment doc for Grafana or certificate-authority-metrics

- **Found:** 2026-07-25, user asked for a full pre-deployment gap audit.
- **Area:** `deployments/proxmox/` (has `certificate-authority.md`,
  `database-vault.md`, `metrics-collector.md`, `mosquitto.md`,
  `network-manager.md`, `security-switch.md`, `storage-service.md` — 7 of
  the 8 components that belong on Proxmox; Entry-Hub and Headscale
  correctly have their own standalone-VPS docs under `deployments/vps/`
  instead).
- **Description:** Grafana (Metrics-Visualizer) still has no Proxmox
  placement doc at all — no KVM-vs-LXC decision, no resource sizing, no
  network config, unlike the 7 components that already have one.
  `certificate-authority-metrics` (CA-F-03) still has no placement
  decision anywhere either — it needs to either share
  Certificate-Authority's own doc or get its own; deliberately left out of
  `certificate-authority.md`'s own scope this session (a separate decision
  from the mesh-only-reachability question that doc resolves).
- **Status:** FIXED, 2026-07-25 — `deployments/proxmox/grafana.md` (new
  file) and `deployments/proxmox/certificate-authority.md` (updated) now
  cover both. `certificate-authority-metrics` is co-located on
  Certificate-Authority's own guest (hard technical requirement: it reads
  step-ca's access log via a Docker named volume, which cannot span
  separate Proxmox guests). Grafana gets its own LXC guest, mesh sidecar,
  and the same mesh-only reachability rule as Certificate-Authority/
  Mosquitto — reasoned through explicitly rather than copy-pasted, since
  Grafana's own inbound consumer (a human Admin's browser, UC-05) differs
  from every other component's own inter-service caller. Two new gaps
  surfaced while writing that reasoning through, tracked below as KI-17
  and KI-18 rather than left unstated.

## KI-12 — SRS traceability: 3 more requirements with a broken or missing `[Code]` link

- **Found:** 2026-07-25, `consistency-agent` audit.
- **Area:** `docs/Software_Requirements_Specification.md`.
- **Description:** Distinct from KI-06 (which predates today's work and
  doesn't cover these): **MT-F-02**'s link is dead — it points at
  `https://github.com/Verryx-02/RAM-USB/blob/main/mqtt-broker/acl.conf`,
  a path that has never existed in this repo (the real file is
  `third-party/mosquitto/acl.conf`) — and it violates §9 twice over,
  pointing at the moving `main` ref instead of a pinned commit. **CA-F-03**
  and **ST-F-12/ST-F-13** have no `[Code]` link at all, despite being
  genuinely implemented and merged today (`78f7052`, plus the earlier
  Storage-Service metrics work KI-04 already confirmed real).
  **Update, 2026-07-25/26 (later session)**: the same-day `cb661fd`
  refactor (consolidating per-service `Counters`/`writeJSON`/`writeAppError`
  into `pkg/metrics`/`pkg/errors`) deleted the files four more requirements'
  `[Code]` links pointed at, without the SRS being re-pinned — **EH-F-11**,
  **SS-F-07**, **SS-F-08**, **DV-F-17**, and **NM-F-18** all now have a
  stale link (pointing at a deleted file or past end-of-file), found by a
  requirement-to-test/consistency audit that same day. All five
  underlying requirements remain functionally satisfied by the relocated
  code (`pkg/metrics.RequestCounters`/`pkg/errors.WriteJSON`/`WriteAppError`)
  — only the SRS's own permalinks are stale.
- **Status:** OPEN.

## KI-13 — SRS §2.1: Certificate-Authority's status may also be stale ("In progress")

- **Found:** 2026-07-25, `consistency-agent` audit.
- **Area:** `docs/Software_Requirements_Specification.md:80` (§2.1
  component table).
- **Description:** Same pattern as KI-09 (Headscale), not yet flagged for
  Certificate-Authority specifically: its row still reads "In progress,"
  but CA-F-04 (bootstrap tokens) and CA-F-03 (metrics sidecar) are both
  now implemented and verified, and CA-F-01/CA-F-02 are explicitly
  "provided by the underlying product" per the SRS's own note at line 297.
  No obvious remaining work justifies "In progress."
- **Status:** FIXED, 2026-07-25 — user confirmed: flipped to "Done." KI-16
  (Mosquitto's own certificate lifecycle) is tracked separately since it's
  a Mosquitto-side gap, not a Certificate-Authority one — the CA itself
  has no remaining code work.

## KI-14 — Diagram drift: Headscale and certificate-authority-metrics missing from 3 diagrams

- **Found:** 2026-07-25, `consistency-agent` audit, introduced by today's
  NM-F-12/NM-F-14 standalone-Headscale rework and the new CA-F-03 sidecar.
- **Area:** `docs/design/diagrams/08-security-pki-hierarchy.puml`,
  `09-security-trust-zones.puml`, `02-architecture-deployment.puml`.
- **Description:** `08-security-pki-hierarchy.puml` has zero mention of
  Headscale, despite it now being a real second PKI participant (a
  public-style cert on its coordination endpoint, the private CA's cert
  only on `/api/v1/*`) — parallel to Entry-Hub's own `LetsEncrypt`
  relationship, which the diagram does show. `09-security-trust-zones.puml`
  also omits Headscale entirely, despite NM-F-12's own SRS text calling it
  out as the one deliberate exception to this system's trust-zone-by-
  network-placement model — a trust-zone diagram omitting the one
  component that breaks the pattern is a substantive gap. Separately,
  `02-architecture-deployment.puml`'s `CADocker` node still shows only
  Certificate-Authority itself, not `certificate-authority-metrics` as its
  own container — undercounting §2.1's own "11 Docker containers" framing.
- **Status:** OPEN.

## KI-15 — §5.1 non-functional requirements have no `[Code]`/test link at all

- **Found:** 2026-07-25, `consistency-agent` audit.
- **Area:** `docs/Software_Requirements_Specification.md` §5.1
  (RNF-SEC-01..04, RNF-REL-01, RNF-PERF-01, RNF-USA-01, RNF-MAINT-01).
- **Description:** Every row in this table has an empty "Verifiable via"
  column and no `[Code]` link — unlike §4's functional requirements, none
  of these are tied to a specific check. Could be intentional (they're
  cross-cutting, not individually unit-testable) or a real gap.
- **Status:** OPEN. Needs a direct user decision on whether this is
  acceptable as-is or needs closing, not something inferable from the
  code alone.

## KI-16 — Mosquitto has no real production TLS certificate lifecycle

- **Found:** 2026-07-25, while writing `deployments/proxmox/mosquitto.md`
  (KI-11).
- **Area:** Mosquitto's broker-side mTLS identity
  (`third-party/mosquitto/generate-dev-certs.sh`, `mosquitto.conf`).
- **Description:** Every RAM-USB Go service gets its mTLS identity from
  CA-F-04's bootstrap-token flow, consumed live by `pkg/pki` at process
  startup. Mosquitto is a C binary with no `pkg/pki` integration, so it
  can't use that flow — today the **only** thing that provisions its
  certificate is `generate-dev-certs.sh`, and that script is dev-only by
  its own design: it requires an operator to `docker exec` into the CA
  container to mint each token by hand, and the resulting leaf certs
  inherit step-ca's ~24h default lifetime with **no automatic renewal** —
  the script's own doc comment says to re-run it manually whenever mTLS
  to the broker starts failing with a certificate-expired error. This is
  not viable for a production broker, which cannot go down (or silently
  reject every publisher/subscriber) every ~24h pending a human noticing
  and re-running a dev script.
- **Status:** FIXED, 2026-07-25. `deployments/compose/mqtt-broker.yml`
  gained two new services: `mqtt-broker-cert-issuer` (one-shot,
  `smallstep/step-cli`, the network-based half of CA-F-04's bootstrap-token
  exchange - token minting itself stays a manual `docker exec` operator
  step, same as every other `RAM_USB_CA_BOOTSTRAP_TOKEN`-based service,
  now automated for compose wiring by `deployments/scripts/mqtt-broker.sh`)
  and `mqtt-broker-cert-renewer` (long-running, `step ca renew --daemon`,
  mTLS-authenticated, no token after first issuance). The renewer shares
  `mqtt-broker`'s PID namespace (`pid: "service:mqtt-broker"`) so
  `--exec "kill -HUP 1"` reaches the real mosquitto process (confirmed
  live: the official `eclipse-mosquitto` image's own entrypoint execs
  mosquitto as PID 1) and its network namespace
  (`network_mode: "service:mqtt-broker"`, confirmed live that Compose
  accepts both directives on one container simultaneously) so its own
  calls to Certificate-Authority cross the Tailscale mesh in production,
  where Certificate-Authority has no other reachable path. Certificate/key
  files moved from a read-only bind mount to a writable named Docker
  volume (`ramusb-mqtt-broker-certs`, read-only on `mqtt-broker` itself,
  writable on the issuer/renewer - confirmed live that Compose allows
  different mount modes per service for the same named volume).

  Three real bugs found and fixed during live verification: (1) a fresh
  named volume mounts root-owned regardless of the image's own runtime
  user, AND (unlike the old bind-mount design, where macOS Docker
  Desktop's bind-mount layer was confirmed to ignore standard POSIX
  ownership checks) a real Docker-managed named volume enforces them
  properly - fixed by running `mqtt-broker` itself as the same fixed
  uid:gid (`1000:1000`) the issuer/renewer already use, instead of
  relaxing file permissions to world-readable. (2) The Headscale ACL
  policy (`services/network-manager/internal/headscale/policy.go`) never
  granted `tag:mqtt-broker` (the broker's own mesh identity) reachability
  toward `tag:certificate-authority` - every existing rule only let OTHER
  services connect INTO the broker, never the reverse, so the very first
  renewal attempt over the mesh hung until "context deadline exceeded"
  with no other error. Fixed by adding `TagMQTTBroker` to that rule's
  `Src` list (covered by a new `TestPolicyDocument_Content` sub-test);
  Network-Manager was redeployed to push the corrected policy to the real
  running Headscale, re-verified live. (3) The pre-existing shared dev
  Headscale reverse-proxy TLS key file
  (`third-party/headscale/dev-tls/key.dev-only.pem`) had been silently
  replaced by an empty directory (the documented "Docker creates an empty
  dir at a missing bind-mount source" footgun) before this session even
  started - regenerated via `step certificate create ... --profile
  self-signed` (a containerized `step` invocation, since the sandbox's
  permission classifier blocks bare `openssl ... -keyout` key-generation
  commands) to unblock Headscale entirely.

  **Live-verified, in order**: the one-shot issuer minted both real
  certificates from the real running Certificate-Authority; mosquitto's
  healthcheck (`mosquitto_pub`) passed against them; a held-open
  `mosquitto_sub` connection survived a manual `kill -HUP 1` sent from a
  throwaway container sharing `mqtt-broker`'s PID namespace, and the
  broker only started serving a freshly re-minted certificate AFTER that
  SIGHUP, not before (mTLS handshake failed pre-SIGHUP, succeeded
  immediately after); a real `step ca renew` (no token, mTLS only)
  produced a genuinely new certificate against the real CA; the renewer's
  own `--exec "kill -HUP 1"` fired automatically on a real renewal and
  Mosquitto served the new certificate afterward; after the ACL fix, a
  direct TLS dial from inside the renewer's shared namespace to
  Certificate-Authority's real mesh IP, with the correct SNI, succeeded
  end-to-end (`Verify return code: 0 (ok)`); the full Compose-managed
  stack (`mqtt-broker`, `mqtt-broker-mesh`, `mqtt-broker-cert-issuer`,
  `mqtt-broker-cert-renewer`) came up cleanly from a single
  `mqtt-broker.sh` run with fresh tokens.

  **One honest limitation, not fixed (tracked under KI-05, not
  reopening this entry for it)**: this dev stack cannot itself prove the
  RUNNING renewer's `https://certificate-authority:9000` calls take the
  mesh path rather than `ramusb-net`, because `mqtt-broker`'s own
  container is still dual-reachable there (KI-05, deliberately unfixed) -
  Docker's embedded DNS resolver wins over the mesh sidecar's own
  MagicDNS inside the shared namespace, confirmed live via `nslookup`.
  The mesh path itself was proven functional independently (the direct
  mesh-IP TLS dial above); production has no competing `ramusb-net` on
  that guest at all, so this ambiguity does not exist there. See
  `deployments/proxmox/mosquitto.md`'s own "Mosquitto's own TLS
  certificate provisioning and renewal" section and
  `MANUAL-DISTRIBUTED-RUN.md`'s Known Issues list for the full detail.

## KI-17 — No SRS mechanism for an Admin's own device to join the mesh and reach Grafana

- **Found:** 2026-07-25, while writing `deployments/proxmox/grafana.md`
  (KI-11).
- **Area:** SRS (no `NM-F-*` requirement covers this), Network-Manager
  (`services/network-manager/internal/headscale/policy.go`).
- **Description:** Every other cross-guest reachability question this
  session resolved to "mesh-only, no published port" (Certificate-
  Authority, Mosquitto, now Grafana), but Grafana's own inbound consumer
  is a human Admin's browser (UC-05), not another RAM-USB service with an
  existing CA-F-04/mesh-join flow. A registered User has a concrete,
  already-built mechanism for the equivalent problem (NM-F-08/NM-F-09:
  Network-Manager grants a time-limited Headscale ACL tag on login,
  scoped to Storage-Service reachability) — nothing analogous exists for
  an Admin or for Grafana-scoped reachability. Today the only path is
  fully manual/operational: an operator with direct Headscale access
  minting a pre-auth key/node registration for the Admin's own device by
  hand, the same way service mesh sidecars are bootstrapped today, with
  no dedicated ACL tag scoping it to Grafana-only reachability
  (`tag:admin` does not exist in `policy.go`).
- **Status:** FIXED, 2026-07-25 — user confirmed: the Admin does not join
  the mesh at all. Grafana's own guest binds its HTTP listener to
  `localhost` only; the Admin reaches it via an SSH tunnel into the guest,
  authenticated by standard SSH key access — no Tailscale identity, no
  ACL tag, no Headscale involvement for this path. Simpler than every
  other reachability question in this ledger, not an oversight: Grafana's
  mesh sidecar is needed only for its own *outbound* connection to
  TimescaleDB (see KI-18), not for accepting any inbound connection, so
  `deployments/proxmox/grafana.md`'s sidecar no longer needs
  `TS_USERSPACE: "false"` (that flag was only ever required for a service
  that must *accept* inbound mesh traffic, per NM-F-04's Certificate-
  Authority precedent) — corrected in that doc.

## KI-18 — TimescaleDB's own Proxmox guest placement is undecided

- **Found:** 2026-07-25, while writing `deployments/proxmox/grafana.md`
  (KI-11).
- **Area:** `deployments/proxmox/` (no `timescaledb.md`),
  `deployments/proxmox/metrics-collector.md` (predates this session's
  mesh-only-reachability decision, currently describes reaching
  TimescaleDB over "the private network," not the mesh specifically).
- **Description:** Grafana's own outbound query connection (UC-05:
  "query on Grafana -> TimescaleDB") depends on TimescaleDB being
  reachable from Grafana's guest in production. **The mechanism is now
  confirmed** (user, 2026-07-25): this connection goes over the Tailscale
  mesh, same as every other cross-guest RAM-USB connection — so
  TimescaleDB needs the same Tailscale-sidecar treatment as Certificate-
  Authority/Mosquitto/Grafana regardless of where it ends up. **What's
  still undecided is only the physical placement**: its own dedicated LXC
  guest, or co-located with Metrics-Collector (or something else) —
  `metrics-collector.md`'s own existing text (written before this
  session's mesh-only-reachability rule existed, describes reaching
  TimescaleDB over "the private network") needs updating once this is
  decided, either way.
- **Status:** FIXED, 2026-07-25. TimescaleDB is now co-located inside
  Metrics-Collector's own container
  (`deployments/docker/metrics-collector/Dockerfile` builds FROM the
  official `timescale/timescaledb:2.23.0-pg18` image and layers
  s6-overlay + the metrics-collector Go binary on top), the same "absorb
  the third-party server into one image" pattern already used for
  Database-Vault+Postgres and Network-Manager+Headscale.
  `deployments/compose/metrics-collector-timescaledb.yml` is deleted, its
  content folded into `deployments/compose/metrics-collector.yml` (one
  Compose project, one password, no cross-shell handoff, same as
  Database-Vault's own merge). Unlike Database-Vault's own Postgres
  (loopback-only), TimescaleDB here binds to every local interface (`-c
  listen_addresses=*`) since Grafana's own outbound query connection
  (MT-F-04, UC-05) must reach it from a separate Proxmox guest in
  production - this container therefore also gained a real, OS-level
  `tailscaled` (not `pkg/mesh`, since TimescaleDB is a separate OS process
  needing a genuine kernel network interface to bind to), matching
  Database-Vault's/Storage-Service's real-tailscaled precedent for a
  different reason (accepting inbound cross-guest traffic, not a
  `pkg/pki` server-role library limitation). No host-published port
  either way. `services/network-manager/internal/headscale/policy.go`
  gained a new `TagGrafana` tag and ACL rule (`tag:grafana` ->
  `tag:metrics-collector`), covered by a new `TestPolicyDocument_Content`
  sub-test; Network-Manager was redeployed to push the corrected policy
  to the real running Headscale.

  **One real bug found and fixed during live verification**: the official
  `timescale/timescaledb` image is Alpine-based (confirmed live:
  `/etc/os-release` reports Alpine 3.21, `/sbin/apk` present, no
  `apt-get`) unlike Database-Vault's own Debian-based `postgres:17` -  the
  Dockerfile's package-install step needed `apk add` with Alpine's own
  package names (`xz` instead of `xz-utils`), not a straight copy of
  Database-Vault's `apt-get` step.

  **Live-verified, in order**: the merged image builds clean; the
  container starts, TimescaleDB accepts connections
  (`database system is ready to accept connections`), the `timescaledb`
  extension and the `metrics` hypertable (with its 30-day retention job
  and 7-day compression job, confirmed via
  `timescaledb_information.jobs`) exist exactly as before the merge; a
  real Network-Manager metrics publish landed a row in the co-located
  database within one publish tick; `docker port`/`docker inspect` confirm
  no host-published port; `go build`/`vet`/`gofmt -l`/`go test ./...`
  (full repo, not just this package) all pass. A throwaway Headscale node
  tagged `tag:grafana` (simulating Grafana's own mesh sidecar) performed a
  real Postgres-wire query against TimescaleDB over the mesh IP and
  succeeded; a second throwaway node tagged `tag:storage-service`
  (deliberately outside the new ACL rule) got the standard silent
  Headscale-ACL-deny timeout on the same connection attempt, confirming
  the new rule is both necessary and correctly scoped. Both throwaway
  Headscale users/nodes were deleted afterward to avoid the documented
  stale-node MagicDNS collision risk.

  `deployments/proxmox/metrics-collector.md` and
  `deployments/proxmox/grafana.md` (its own TimescaleDB-dependency
  section, previously "still undecided") are both updated to the real,
  now-decided placement. `deployments/scripts/metrics-collector.sh` is
  rewritten to mint its own password/CA-token/mesh pre-auth key
  in one script (mirroring `database-vault.sh`'s own self-contained
  shape); `deployments/scripts/metrics-collector-timescaledb.sh` is
  deleted; `MANUAL-DISTRIBUTED-RUN.md`'s shell table/readiness-signals
  table/mesh-membership paragraph are updated (shells 6 and 11 collapse
  into one shell 6, shells 12-14 renumber to 11-13).

## KI-19 — Entry-Hub and certificate-authority-metrics have no restart policy, so a fatal startup error stops them silently instead of retrying

- **Found:** 2026-07-25, while explaining why KI-10's `finish`-script fix
  didn't extend to every service that consumes a CA-F-04 bootstrap token.
- **Area:** `deployments/compose/entry-hub.yml`,
  `deployments/compose/certificate-authority-metrics.yml`.
- **Description:** Both `main.go`s call `os.Exit(1)` after a fatal startup
  error (e.g. an already-consumed bootstrap token), same as every other
  service — but neither container runs under s6-overlay (Entry-Hub uses
  `pkg/mesh` in-process, needing only one process; `certificate-authority-metrics`
  execs its binary directly as PID 1), so KI-10's `finish`-script fix
  doesn't apply — that mechanism only exists within s6-rc's supervision
  model. Neither compose file sets a `restart:` policy, so Docker uses its
  own default, `restart: "no"`. Net effect: a fatal startup error doesn't
  crash-loop (no equivalent of KI-10), but it also doesn't recover on its
  own — the container exits and stays stopped until an operator notices
  and manually restarts it, even for an otherwise-transient failure that
  would have succeeded on retry.
- **Status:** OPEN. Needs a decision, not obviously "correct as-is": a
  Docker-level `restart: on-failure` (with Docker's own built-in backoff,
  not a bespoke s6 `finish` script — there's no s6 here to hook) would
  give these two the same "recover automatically from a transient error,
  don't silently stay dead" property every s6-supervised service now has,
  without needing to introduce s6-overlay just for a single process.

## KI-20 — NM-F-12 through NM-F-16 (Headscale coordination/DNS cluster) have zero test coverage

- **Found:** 2026-07-25/26, a comprehensive requirement-to-test inventory
  audit (`consistency-agent`) cross-referencing every SRS requirement ID
  against `// Requirement: <ID>` doc-comment tags in the real test suite
  (CONTRIBUTING.md's own traceability convention).
- **Area:** Network-Manager (Headscale coordination),
  `docs/Software_Requirements_Specification.md` §4.6.
- **Description:** NM-F-12 (pre-auth-key/ACL-tag administration restricted
  to Network-Manager, verified via mTLS `organization=NetworkManager`),
  NM-F-13 (a pre-auth key alone doesn't grant Storage-Service reachability),
  NM-F-14 (Headscale's coordination endpoint deliberately public-facing),
  NM-F-15 (MagicDNS configured with a dedicated base domain), and NM-F-16
  (Network-Manager's own mesh node must not accept Headscale's distributed
  DNS config) all have **zero** `// Requirement: <ID>`-tagged tests
  anywhere in the suite. This compounds with KI-06, already open, which
  flags these same five IDs for missing an SRS `[Code]` link — so today,
  neither the SRS document nor the test suite shows where or whether these
  five actually hold in the real system.
- **Status:** OPEN. User explicitly decided (2026-07-25) not to act on this
  now — no fix or test work scheduled; logged here for future
  prioritization, not forgotten.

---

## KI-21: `TestStorageServiceSSHD_RealContainer_EnforcesHardening` fails/hangs in this dev sandbox

- **Found:** 2026-07-25, running `go test ./...` for the whole repo as
  post-implementation verification for a CL-F-05 test-coverage task
  (unrelated area - Storage-Service's own real-container SSHD hardening
  test, not user-client/mesh).
- **Area:** Storage-Service, `services/storage-service/cmd/storage-service/
  sshd_integration_test.go`'s `TestStorageServiceSSHD_RealContainer_
  EnforcesHardening` (`ST-F-*`).
- **Description:** first run failed with `sh: 1: cannot create
  /storage/<user>/data/secret.txt: Permission denied` while a leftover
  `ss-itest-manual` container (already running before this session started)
  was also up. A second run, after removing that leftover container,
  instead hung until the test's own 120s harness timeout, with the
  goroutine dump pointing at `os/exec.Cmd.Start`/`io.Copy` still blocked on
  a subprocess's stdout/stderr pipe. Not yet root-caused - could be
  environment/resource contention specific to this sandbox (a previous,
  unrelated `ss-sshd-itest-*` container was also observed mid-test) rather
  than a real regression in Storage-Service itself; not investigated
  further since it's outside this task's scope.
- **Root cause (2026-07-26):** no code bug - confirmed environment timing,
  not a deadlock. Audited every `exec.Cmd` in `sshd_integration_test.go`
  and its sole helper dependency (`execrunner.Real.Run`, used by
  `posixuser.Creator` inside the container via `itest-provision-user`):
  every call site uses `CombinedOutput()`/`Output()`, never
  `StdoutPipe()`/`StderrPipe()` read sequentially - `os/exec` already
  drains stdout+stderr concurrently for those, so the classic
  pipe-buffer-fills-then-both-sides-block shape this bug's symptom
  matches (`Cmd.Start`/`io.Copy` blocked) cannot occur anywhere in this
  code path. Confirmed by measurement instead: with the leftover
  `ss-itest-manual` container removed and no other Storage-Service test
  container present, 5 back-to-back real runs of the test (`go test -run
  TestStorageServiceSSHD_RealContainer_EnforcesHardening -count=1
  -timeout 180s`) all **passed**, with wall-clock time ranging from 45s
  to 115s purely from Docker daemon/build-cache load variance on this
  machine - no run showed any sign of being stuck (all either completed
  or, had they not, would show forward-progressing docker/ssh calls, not
  a repeatedly-identical stack). The prior session's manually-chosen
  120s external `-timeout` left essentially zero margin against this
  test's own normal ~115s worst-case runtime even before counting any
  contention from the already-confirmed leftover container or a second
  concurrent real-container test - not a hang, a still-progressing run
  that got cut off by too tight a budget. `t.Cleanup`'s `docker rm -f`
  ran and left no leftover container after every one of the 5 runs,
  including the slowest one.
- **Fix:** documentation only, no code/logic change - added a doc comment
  to `TestStorageServiceSSHD_RealContainer_EnforcesHardening` recording
  the observed 45-115s range and recommending `-timeout` of at least 180s
  when invoking this test standalone, so a future tight external timeout
  doesn't get misread as a hang again.
- **Status:** FIXED, 2026-07-26 (root-caused as environment timing, not a
  code defect; documented the correct invocation timeout).

---

## KI-22: Grafana -> TimescaleDB uses plaintext password auth, no mTLS (RNF-SEC-04 violation)

- **Found:** 2026-07-25, writing a real system test for RNF-SEC-04 ("all
  inter-service communication must use mTLS, with no exceptions") -
  confirmed live, not just from reading config.
- **Area:** `third-party/grafana/provisioning/datasources` (`sslmode:
  disable`, `secureJsonData.password` in plaintext), Metrics-Collector's
  embedded TimescaleDB (`deployments/compose/metrics-collector.yml`).
- **Description:** Grafana's own datasource connection to TimescaleDB
  (MT-F-04, UC-05) is plain Postgres-wire-protocol password
  authentication over the mesh - no mTLS, no CA-F-04 bootstrap token, no
  `pkg/pki` integration at all. Confirmed live: `docker exec
  metrics-collector psql
  "postgres://metrics_collector:metrics_collector_dev_only@localhost:5432/metrics_collector?sslmode=disable"
  -c "SELECT 1;"` succeeds. This is genuinely inter-service traffic
  (Grafana querying Metrics-Collector), so RNF-SEC-04's "no exceptions"
  clause applies here, unlike Certificate-Authority's own bootstrap
  surface or Entry-Hub's user-facing login listener (both legitimate,
  documented exceptions - see
  `.claude/agent-memory/code-agent/rnf-real-stack-testing.md`).
  `test/nonfunctional/rnf_sec_04_test.go`'s
  `TestGrafanaTimescaleDB_RealStack_RNF_SEC_04_PlaintextConnectionShouldBeRejected`
  encodes this as a test DELIBERATELY LEFT FAILING until this is fixed -
  do not weaken that assertion to make the suite green; fix the
  connection instead.
- **Status:** OPEN. Re-architecting this connection to require mTLS is a
  real design change (its own CA-F-04 identity for TimescaleDB/Grafana, or
  another mechanism) - out of scope for the test-writing task that found
  it; logged here for a future task/user decision.

---

## KI-23: Restarting a CA-F-04-bootstrapped service needs a manually-minted fresh token; only Certificate-Authority itself restarts with zero manual step

- **Found:** 2026-07-25, writing a real system test for RNF-MAINT-01
  ("every service must be able to be isolated, re-certified, and
  restarted individually without impacting the others").
- **Area:** every `deployments/compose/*.yml` service that bootstraps its
  identity via `pki.NewServer`/`RAM_USB_CA_BOOTSTRAP_TOKEN`
  (Database-Vault, Storage-Service, Security-Switch, Network-Manager) -
  confirmed live against the real running `network-manager` container.
- **Description:** `RAM_USB_CA_BOOTSTRAP_TOKEN` is single-use, consumed
  once at process start. A plain `docker compose restart <service>`
  reuses the container's OLD environment (compose doesn't re-interpolate
  env vars for a plain restart, only for `up --force-recreate`), so
  restarting one of these services would attempt to re-bootstrap with an
  already-consumed token and fail closed. Achieving RNF-MAINT-01's
  "re-certified... individually" with zero manual step today requires
  either a persisted `.env` refreshed before every restart, or an
  operator/automation step to mint a new token and recreate (not merely
  restart) the container. Certificate-Authority itself is the one
  exception: its state persists on the `ramusb-ca-data` named volume, so
  it restarts cleanly with no token of its own to refresh - confirmed live
  and used as `test/nonfunctional/rnf_maint_01_restart_test.go`'s own
  restart target for exactly this reason.
- **Status:** OPEN. Not a violation of RNF-MAINT-01's own wording (which
  requires isolation from OTHER services, not zero-configuration self-
  restart), but a real operational gap worth a future automation decision
  (e.g. a token-minting sidecar/init container per service, mirroring
  `certificate-authority-init`'s own pattern).

## KI-24 — `08-security-pki-hierarchy.puml` draws a certificate-issuance edge to Grafana that doesn't exist

- **Found:** 2026-07-25/26, `consistency-agent` audit of Certificate-Authority
  (SRS §4.7 vs. code and diagrams).
- **Area:** `docs/design/diagrams/08-security-pki-hierarchy.puml:59`.
- **Description:** The diagram draws `PrivateCA ..> MetricsVisualizer`
  (Grafana), and this diagram's own legend states every dashed arrow is a
  `<<signs>>` relationship — i.e. it claims the private Certificate-Authority
  issues an mTLS certificate to Grafana. This is not what the real
  deployment does: `deployments/compose/grafana.yml` has no
  `RAM_USB_CA_BOOTSTRAP_TOKEN`, no `pkg/pki` integration, and no mTLS server
  role at all. Grafana's own inbound path is an SSH tunnel (no Tailscale
  identity, no Headscale), and its outbound connection to TimescaleDB is
  plain Postgres-wire password authentication over the mesh — no
  certificate from this CA is ever issued to it. Related to, but distinct
  from, **KI-22** (that entry is about the missing mTLS on the
  Grafana→TimescaleDB connection itself; this one is about the diagram
  falsely depicting a certificate-issuance relationship that would only
  make sense if that connection *were* mTLS).
- **Status:** OPEN.

---

**Not logged, considered and rejected**: `01-architecture-container.puml`
showing PostgreSQL as its own logical component even though it's
physically merged into Database-Vault's container. This is the
*logical*-level diagram (component relationships), where `PostgreSQL`
as a distinct logical element is a legitimate stylistic choice — the
*deployment*-level diagram (`02-architecture-deployment.puml`) already
correctly shows a single merged container. Not treated as a discrepancy.
