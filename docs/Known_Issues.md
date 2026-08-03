# Known Issues (cache)

This file is a scratch cache, not the durable record. GitHub Issues
(label [`known-issue`](https://github.com/Verryx-02/RAM-USB/issues?q=is%3Aissue+label%3Aknown-issue),
using `.github/ISSUE_TEMPLATE/known_issue.yml`) is the durable tracker —
distinct from the SRS's own §8 ("Known risks and open issues"), which is
for deliberately-deferred requirement-level decisions requiring the
SRS's own approval process.

**Workflow:** when any agent (orchestrator or subagent) finds an
implementation gap or bug outside its current task's scope, it notes it
below immediately, instead of letting it evaporate at the end of that
task's report. The user then reviews the note, reasons about whether
it's worth tracking, and decides whether to open it as a real GitHub
issue. No agent may create, close, edit, or comment on a GitHub issue
itself (`.claude/settings.json` denies it, same enforcement as the git
non-negotiables) — at most, prepare the exact `gh issue create ...`
command for the user to run themselves. Once a finding is promoted to a
GitHub issue, or the user decides it isn't worth one, remove it from
below — this file should stay close to empty between sessions, not
accumulate history.

**Migrated 2026-07-28:** the 30 entries this file used to hold (KI-01
through KI-31, skipping KI-08) are now GitHub issues under the
`known-issue` label — 13 open, 17 closed as a historical record.

---

## Findings from the full Go code review (2026-08-02)

Full report with plain-language explanations, failure scenarios and fix
sketches: `~/.claude/plans/transient-orbiting-bengio.md`. Three parallel
reviewers read all 193 Go files; every HIGH below was re-verified against
the real code by the orchestrator. Scope excluded the non-Go deployment
layer (Dockerfiles, s6 scripts, sshd_config, ACLs) by the user's choice —
that audit is still owed before the Proxmox deploy.

### Found while fixing the above (2026-08-03), deliberately deferred

| # | Finding | Location |
|---|---|---|
| KI-87 | **Residual grant/sweep race, narrower than KI-36 but not closed.** `Handler.Grant` applies `tag:storage-access` on Headscale and *then* writes the expiry row. A sweep tick landing between those two steps claims and revokes the pre-existing grant; the subsequent `RecordGrant` then persists a row whose tag is no longer on the node. The user holds a persisted grant with no reachability until their next login — the inverse of KI-36, which KI-36's conditional delete does not cover. Closing it needs either a lock held across the Headscale call or a pending row written before it. **User decision 2026-08-03: accepted for now, revisit after the production test.** | `services/network-manager/internal/httpapi/handler.go` (grant path), `services/network-manager/internal/grants/sweep.go` |
| KI-88 | **KI-40's hashed-email migration destroys existing rows.** `grants.Open` drops any table still carrying a plaintext `email` column. `grants` rows regenerate at the next login; `mesh_users` rows **do not** — a user whose row is dropped gets 403 from `Handler.Grant` forever until they re-register through NM-F-08. **User decision 2026-08-03: accepted, no real users yet, test data only.** Must be re-evaluated before any deployment holding real accounts. | `services/network-manager/internal/grants/store.go`, `meshusers.go` |

### Blocking a production test

| # | Finding | Location |
|---|---|---|
| KI-32 | `sftpCommand` interpolates `PrivateKeyPath` unquoted; `os.UserConfigDir()` on darwin contains a space, so restic's shell-style split breaks `ssh -i`. Backup and restore cannot work on macOS at all (CL-F-06, CL-F-07, RNF-ORG-05). Test fixture uses a Linux path, so nothing catches it. | `user-client/internal/restic/restic.go:82` |
| KI-33 | `TagMetricsCollector` missing from NM-F-04's CA reachability rule (`Src`); `TagMQTTBroker`/`TagMetricsCollector`/`TagGrafana` missing from direction two (`Dst`). In mesh-only production Metrics-Collector cannot reach the CA, fails its CA-F-04 bootstrap, and each s6 respawn burns another single-use token. `policy_test.go:123` asserts the incomplete list, certifying the gap. | `services/network-manager/internal/headscale/policy.go:246`, `:253-259` |
| KI-34 | DV-F-10's compensating `DeleteUser` reuses the request context that may itself be why POSIX creation failed, so the rollback fails on a cancelled request. Leaves an orphaned row; `email_hash` is the PK, so every retry hits DV-F-12's 409 forever. No delete/admin endpoint exists anywhere in the system to recover. | `services/database-vault/internal/registration/registration.go:139` |
| KI-35 | `RecordGrant` failure is logged and the handler still returns HTTP 200. The ACL tag is applied at Headscale with no persisted expiry, so NM-F-10's sweep can never find it — an unpersisted grant is unbounded, not merely less durable. Violates NM-F-11's "must". The nil-`Grants` branch is the same fail-open path. | `services/network-manager/internal/httpapi/handler.go:274-278` |
| KI-36 | `SweepOnce` reads the expired set, makes a Headscale round trip, then deletes unconditionally. A login landing in that window gets HTTP 200 while the sweep strips its fresh tag and deletes the new row — no state remains for the system to self-correct. | `services/network-manager/internal/grants/sweep.go:43-63` |

### Security

| # | Finding | Location |
|---|---|---|
| KI-37 | Login is a user-enumeration timing oracle: a lookup miss returns before Argon2id runs, so a nonexistent email answers ~1 ms vs tens of ms for an existing one. Response and log are identical (DV-F-15 honoured); timing is the unhandled third channel. Untested. | `services/database-vault/internal/login/login.go:143-150` |
| KI-38 | `validateSSHPublicKey` discards `ssh.ParseAuthorizedKey`'s `rest`, so a two-line key passes EH-F-04/SS-F-02/DV-F-02, is stored whole, and `authorized-keys-command` prints it verbatim — sshd reads two authorized_keys entries, the second with attacker-chosen options. Bounded by the global sshd restrictions; still an RNF-SEC-02 breach. | `pkg/validation/validation.go:241`, `services/storage-service/cmd/authorized-keys-command/main.go:123` |
| KI-39 | `validateEmail` discards `mail.ParseAddress`'s result, so the display-name form passes and flows downstream unchanged; `HashEmail` only lowercases. `a@b.c` and `X <a@b.c>` become two accounts, two POSIX users, two storage areas — DV-F-12 never fires. | `pkg/validation/validation.go:182` |
| KI-40 | Network-Manager persists user emails as plaintext `TEXT PRIMARY KEY` in SQLite, defeating DV-F-03/DV-F-04's protection of the same data one service over. It only ever uses the email as an opaque key and already hashes it for Headscale. No NM-F-* mandates encryption here — an SRS gap as much as a code one. | `services/network-manager/internal/grants/store.go:73`, `meshusers.go:21` |
| KI-41 | Downstream services' raw response text reaches `slog` without `logging.Sanitize` in 8 places (3 in Security-Switch/Database-Vault, 5 in Network-Manager), against the standing convention applied correctly in 27 others. Storage-Service already defends this and has the test to prove it. | `services/security-switch/internal/networkmanager/client.go:165`, `services/database-vault/internal/posix/client.go:95`, `services/network-manager/internal/httpapi/handler.go:158,246,260`, `internal/grants/sweep.go:50,61` |

### Robustness

| # | Finding | Location |
|---|---|---|
| KI-42 | No `Timeout` on any of the three main-chain outbound clients and no `WriteTimeout` on the servers, while every peripheral call has one. EH-F-09's 503 and SS-F-06's 504 branches are therefore unreachable code; a wedged downstream blocks callers indefinitely. | `services/entry-hub/cmd/entry-hub/main.go`, `services/security-switch/cmd/security-switch/main.go:355,383`, `services/database-vault/cmd/database-vault/main.go:492` |
| KI-43 | CA access-log tail reader holds one `*os.File` and never stats it, so `copytruncate`/rename rotation silently freezes the counters. `Snapshot` never resets, so CA-F-03 keeps publishing the same frozen values — a flat line on the dashboard, not a gap. | `services/certificate-authority/internal/accesslog/tail.go:35-66` |
| KI-44 | `reposecret.Ensure` returns the persisted password without `TrimSpace` (unlike `clientstate.LoadPosixUsername`). A trailing newline added by any editor changes `RESTIC_PASSWORD` and makes every existing snapshot permanently undecryptable (RU-07). | `user-client/internal/reposecret/reposecret.go:53-56` |
| KI-45 | Any DB/transport failure at login collapses into `ErrAuthenticationFailed`, so a Postgres outage presents to every user as bad credentials and to the operator as a wave of failed logins. DV-F-15 requires blending two *credential* cases, not masking an outage. | `services/database-vault/internal/login/login.go:143-150` |
| KI-46 | `decodeJSON` never checks the decoder reached EOF, so trailing JSON after the first object is accepted. `DisallowUnknownFields` only guards inside the first object; Entry-Hub forwards the raw body downstream. | `pkg/validation/validation.go:139-147` |
| KI-47 | Minor, confirmed: `os.MkdirAll` no-ops on an existing chroot dir so its mode is never enforced (`posixuser/creator.go:156`); empty key accepted as success with no explicit guard (`authorized-keys-command/main.go:155`); sweep/metrics goroutines not awaited before `grantStore.Close()` (`network-manager/cmd/.../main.go:318`); migration `*sql.DB` never closed (`database-vault/internal/schema/schema.go:35`); failed MQTT `Connect` leaks an auto-reconnecting client (`pkg/metrics/client.go:56-61`); Security-Switch and Database-Vault register handlers without a method prefix; CA metrics sidecar treats a missing broker URL as a warning rather than `env.Require`; two `Snapshot` implementations read their atomics non-atomically. | various |

### Tests that do not test what they claim

| # | Finding | Location |
|---|---|---|
| KI-48 | RNF-MAINT-01's restart test returns `""` (= no unexpected error) on *any* dial error, including `ECONNREFUSED` and deadline expiry — the exact conditions its own doc comment says would indicate the observed service was impacted. Stop the observed container and the test still reports the requirement verified. Two analogous vacuous passes in `rnf_sec_04_test.go:76,124`. | `test/nonfunctional/rnf_maint_01_restart_test.go:166-172` |
| KI-49 | `ST-F-09_root_login_denied` dials root with `ssh.Password`, which `PasswordAuthentication no` already rejects for every user, so it cannot distinguish whether `PermitRootLogin no` works. | `services/storage-service/cmd/storage-service/sshd_integration_test.go:629-640` |
| KI-50 | Untested error branches: `ErrSecuritySwitchTimeout` (`entry-hub/internal/securityswitch/client_test.go`), `SaveUser`'s marshal-error rollback (`database-vault/internal/storage/storage.go:117-123`), `pkg/metrics/dial.go` has no test file at all. NM-F-12..NM-F-16 confirmed to have zero Go coverage (already tracked as issue #19). | various |

### Simplifications (deletion, not defects)

| # | Finding | Location |
|---|---|---|
| KI-51 | ~380 lines of caller-supplied-dialer machinery with zero production callers since `pkg/mesh` was deleted (KI-27/KI-31): all nine `metrics.NewClient` sites pass `nil`, and `NewClientWithDialer`/`RouteThroughDialer` are referenced only by their own tests. Carries a live trap: `RouteThroughDialer` and `ForceServerName` each overwrite `DialTLSContext`, so the natural call order silently discards the mesh dialer. Deleting it also removes the `//nolint:contextcheck` in metrics-collector. | `pkg/dial/`, `pkg/metrics/dial.go`, `pkg/pki/dialer.go` + tests |
| KI-52 | `^user[0-9a-z]{6}$` reimplemented in 5 places and `validateEmail` in 2 more, against CONTRIBUTING §7's explicit rule that validation rules live in `pkg/validation` and each layer *calls* them. The in-code justification ("`validateEmail` is unexported") describes a missing export, not a reason to fork. Fix: export `ValidateEmail`/`ValidatePosixUsername`. | `storage-service/internal/{httpapi:56,posixuser:25,pubkeylookup:45}`, `cmd/authorized-keys-command/main.go:88`, `network-manager/internal/httpapi/handler.go:319-327` |
| KI-53 | `securityswitch.forward`, `httpclient.Post` and `posix/client.go` are three copies of the same marshal→POST→classify→read shape; `httpclient` belongs in `pkg/` per CONTRIBUTING §7. `metrics.RequestCounters.Track` exists to kill the 4-line counter boilerplate and only Database-Vault adopted it. `metricsPublishInterval` is redeclared in 6 mains for a value the SRS fixes at one minute. `pkg/mtls/testcert.go` is not `_test.go`, so CA-minting code links into all 8 production binaries. | various |
| KI-54 | Tooling gaps: no CI at all (no `.github/workflows/`) despite CONTRIBUTING §7's mandated 9-step pre-commit pipeline; `golangci-lint` and `govulncheck` are not installed locally; `tailscale.com` is still a direct `go.mod` dependency with no importer (`go mod tidy` removes 188 lines); the Makefile has no `verify` target. | `go.mod`, `Makefile`, repo root |
