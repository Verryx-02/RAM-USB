This document defines how requirements become tests, tests become code, and code becomes a traceable commit history. It merges the implementation guide, the testing strategy, and the commit conventions used throughout this project.

All requirement IDs referenced below (`EH-F-*`, `RU-*`, etc.) come from [`docs/SRS.md`](https://github.com/Verryx-02/RAM-USB/blob/main/docs/SRS.md), which remains the single source of truth for what the system must do.  
This document only covers _how_ that gets built and verified.

---

## 1. Development methodology

RAM-USB follows a V-model: every level of specification has a corresponding level of testing, and a test is written before the implementation it verifies. Test levels, technique per level, integration strategy, and entry/exit criteria are in [`docs/Test_Plan.md`](docs/Test_Plan.md).

Two rules shape the git workflow directly:

- No new feature is started until the current one is thoroughly tested.
- If a test cannot be written for a requirement, the requirement is not clear enough: it gets reworded in the SRS before implementation starts.

---

## 2. Git workflow

### 2.1 Branching

Each feature is implemented and tested on its own branch:

```
feature/<area>-<feature>
```

Example: `feature/entryhub-registration`

A branch is only merged once its feature is complete and thoroughly tested.

### 2.2 Commit structure

Every commit, on a feature branch or a merge commit, follows this exact structure:

```
git commit -m "<type>(<area>): <description> (<requirement IDs>)"
```

- **`<type>`**: one of the commit types below.
- **`<area>`**: one of the commit areas below.
- **`<description>`**: written per the description rules below.
- **`(<requirement IDs>)`**: the SRS requirement ID(s) covered by this commit.

When a feature is complete and tested, it is merged into `main`.  
**The merge commit must include every requirement covered by the branch**. A feature-branch commit may cite a requirement it's building toward (e.g. a shared library a requirement depends on, before every caller exists yet); the merge commit only cites a requirement once it's fully complete.

---

## 3. Commit types

|**Type**|**Meaning**|
|---|---|
|`feat`|New functionality|
|`fix`|Bug fix|
|`refactor`|Refactoring with no functional change|
|`perf`|Performance improvement|
|`test`|Adding/modifying a test|
|`chore`|Maintenance|
|`docs`|Documentation|

---

## 4. Commit areas

| Area                    |
| ----------------------- |
| `user-client`           |
| `entryhub`              |
| `security-switch`       |
| `database-vault`        |
| `storage-service`       |
| `network-manager`       |
| `mqtt-broker`           |
| `metrics-collector`     |
| `metrics-visualizer`    |
| `certificate-authority` |
| project                 |

---

## 5. Description rules

The description must always answer this question:

> "What changes in the system, in a verifiable way?"

It must **not** describe:

- what you did at a personal level ("I fixed...", "I worked on...")
- how it was done in implementation detail
- the requirement itself (that belongs in the ID list, not the prose)

**Structure:** `verb + what was done + (optional technical detail)`

Example:

```
feat(entryhub): add request validation for register endpoint
```

---

## 6. Diagrams

PlantUML source lives flat in `docs/design/diagrams/`, named `NN-category-name.puml`. The numeric prefix is the intended reading order, not a folder grouping — a plain `ls` already sorts the diagrams the way they're meant to be read.

`_style.puml` holds the shared skinparam theme. Every diagram includes it with `!include _style.puml`; it is not itself a diagram and is skipped by the render step.

To regenerate the rendered SVGs after editing a `.puml` file, from the project root run:

```
make diagrams
```

This runs PlantUML in Docker (no local Java or Graphviz needed) and rewrites `docs/design/diagrams/rendered/NN-category-name.svg` to match its source. Commit the `.puml` and its regenerated `.svg` together.

To add a new diagram: create `NN-category-name.puml` directly in `docs/design/diagrams/`, following the existing reading order, starting with `!include _style.puml`, then run `make diagrams` and commit both files together.

---

## 7. Code style

Tooling and package layout are baseline. Error handling and logging are structural decisions, each with a specific reason behind it.

**Formatting and linting:** every file passes `gofmt`/`goimports` and `go vet`. `golangci-lint` runs with `errcheck`, `govet`, `staticcheck`, `unused`, `gosimple`, `ineffassign`, `gosec`, plus (added 2026-07-20) `bodyclose`, `sqlclosecheck`, `rowserrcheck`, `contextcheck`, `noctx`, `errorlint`, `sloglint`, `revive`, `gocritic`. `gosec` specifically: this project's non-functional requirements are security-first, and the linter enforces that in code; the 2026-07-20 additions extend that same rationale to resource-leak and error-handling correctness (unclosed HTTP bodies/SQL rows, missing context propagation, error-wrapping mistakes) rather than being general-purpose style linters.

**Verification pipeline** (run before every commit, per this project's own practice): `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...`, `golangci-lint run ./...`, plus (added 2026-07-20, catch classes of bug the above cannot): `go test -race ./...` (data races - already caught one real bug in a test's hand-written fake), `govulncheck ./...` (known vulnerabilities in the dependency graph, code-path-aware), `gitleaks detect` (committed secrets - already caught one dev-only key committed by mistake), `trivy fs .` (dependency vulnerabilities, Dockerfile misconfiguration, secrets - overlaps with the two above by design, as a second independent scanner).

**Package layout:**

- `cmd/<service>/main.go`: wiring, config loading, dependency construction, server start.
- `internal/<service>/`: everything private to that service.
- `pkg/{mtls,errors,logging,validation}`: code genuinely shared across services. Input validation belongs here: every layer re-validates independently at request time (`RNF-SEC-03`), but the rules for what counts as valid live in one place, called by each service's own boundary, not reimplemented per service.

**Error handling:** errors reaching an HTTP boundary use a structured error type in `pkg/errors`. The type carries a fixed, safe public message per HTTP status code and the full internal error, both set inside the constructor. Why: `EH-F-09`, `SS-F-06`, `DV-F-20`, and `ST-F-*` require a sanitized response to the client and a detailed one in the log; a status-code-bound constructor guarantees the public message is always the safe one.

**Logging:** structured logging via `log/slog` (stdlib). Any field that could hold a login credential (email, password) is typed as a dedicated redacting type in `pkg/logging`, implementing `slog.LogValuer`, printing as `REDACTED` wherever it gets logged. Why: `DV-F-03` and `RD-01` require credentials stay out of logs, and a type-level guarantee holds regardless of who writes a new log line.

**Testing:** one test file per implementation file. Table-driven tests over the stdlib `testing` package. The bottom-up driver/stub strategy (`docs/Test_Plan.md` §3) uses hand-written fakes implementing the relevant interface: a fake's behavior is a few lines of Go, readable start to finish. Every test function carries a `// Requirement: <ID>` doc comment directly above it.