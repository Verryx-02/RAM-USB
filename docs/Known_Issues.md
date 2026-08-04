# Known Issues (cache)

This file is a scratch cache, not the durable record. GitHub Issues
(label [`known-issue`](https://github.com/Verryx-02/RAM-USB/issues?q=is%3Aissue+label%3Aknown-issue),
using `.github/ISSUE_TEMPLATE/known_issue.yml`) is the durable tracker —
distinct from the SRS's own section 8 ("Known risks and open issues"), which is
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
`known-issue` label.

**Migrated 2026-08-03:** KI-32 through KI-89 — the findings from the full
Go code review, the deployment-layer audit, and the merge and verification
work that followed — are now GitHub issues under the same label. Of those,
KI-32..KI-44, KI-47, KI-49, KI-56..KI-60, KI-66..KI-71, KI-78, KI-81..KI-83
were fixed and merged the same day; the rest remain open. Two are recorded
as accepted rather than fixed, by explicit decision: KI-87 (a residual
grant/sweep race) and KI-88 (the hashed-email migration dropping existing
rows, acceptable while there are no real users).

---

(no pending findings)
