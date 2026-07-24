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
- **Status:** OPEN.

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
  `deployments/compose/mqtt-broker.yml`.
- **Description:** Both are reachable from their real Tailscale mesh
  identity as intended, but are *also* still reachable via plain
  `ramusb-net` and via a host-published port — confirmed live with a
  plain `ramusb-net`-only container and the bare Docker host, both
  succeeded where they should fail. Deliberately deferred this session
  ("Fase E": remove the host-published ports/`ramusb-net` membership once
  every consumer is confirmed to route through the mesh instead) — never
  actually done.
- **Status:** OPEN.

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

## KI-08 — `11-operations-metrics-flow.puml`'s note overstates which services actually publish metrics

- **Found:** 2026-07-24, `consistency-agent` audit (SRS vs. code).
- **Area:** `docs/design/diagrams/11-operations-metrics-flow.puml:13-19`.
- **Description:** The diagram's descriptive note lists ST-F-12 and
  CA-F-03 alongside EH-F-10/SS-F-07/DV-F-16/NM-F-17 as services that
  "every service publishes, every minute and only" metrics for — stated
  as settled fact, with no caveat. ST-F-12 and CA-F-03 are not
  implemented at all (see KI-04 and KI-03) — the note should distinguish
  the services that genuinely publish today from the two that don't yet,
  not present all six uniformly.
- **Status:** OPEN. Tightly coupled to KI-03/KI-04 — fixing this note
  properly probably means updating it once those two land, or adding an
  explicit "not yet implemented" caveat to the two in the meantime.

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
- **Status:** OPEN. Needs a direct decision from the user, not something
  inferable from the code alone.

---

**Not logged, considered and rejected**: `01-architecture-container.puml`
showing PostgreSQL as its own logical component even though it's
physically merged into Database-Vault's container. This is the
*logical*-level diagram (component relationships), where `PostgreSQL`
as a distinct logical element is a legitimate stylistic choice — the
*deployment*-level diagram (`02-architecture-deployment.puml`) already
correctly shows a single merged container. Not treated as a discrepancy.
