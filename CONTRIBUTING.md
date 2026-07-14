This document defines how requirements become tests, tests become code, and code becomes a traceable commit history. It merges the implementation guide, the testing strategy, and the commit conventions used throughout this project.

All requirement IDs referenced below (`EH-F-*`, `RU-*`, etc.) come from [`docs/SRS.md`](https://github.com/Verryx-02/RAM-USB/blob/main/docs/SRS.md), which remains the single source of truth for what the system must do.  
This document only covers _how_ that gets built and verified.

---

## 1. Development methodology

### 1.1 Pre-testing (TDD)

Before implementing anything, a test is written that describes the expected behavior for a specific requirement.

- If a test cannot be written for a requirement, the requirement is not clear enough and it must be clarified or reworded in the SRS before implementation starts.
- Each `*-F-*` ID should have a corresponding test conceived before its implementation.

### 1.2 Implementation and testing (V-model)

Implementation follows the V-model: every level of specification has a corresponding level of testing, executed in parallel with implementation.

| **Specification level**                                    | **Corresponding testing level**            |
| ---------------------------------------------------------- | ------------------------------------------ |
| System requirement for a single component (e.g. `EH-F-04`) | Component test (unit test)                 |
| Use case spanning multiple components (`UC-01`..`UC-05`)   | Integration test                           |
| Non-functional requirement (`RNF-*`)                       | System test                                |
| User requirement (`RU-*`)                                  | Acceptance checklist against the use cases |

Rules that apply throughout:

- No new feature is started until the current one is thoroughly tested.
- Every relevant change triggers a re-run of the affected test suite (regression testing).

### 1.3 Integration strategy: bottom-up, driver and stub

```
DRIVER (simulates the caller) -> COMPONENT UNDER TEST -> STUB (simulates the callee)
```

Integration starts from the innermost component (Database-Vault) and works outward.

### 1.4 System tests

Once the full chain is integrated:

- **Functional**: complete end-to-end scenarios (e.g. registration from client HTTP request down to the Database-Vault row and the resulting TimescaleDB metric).
- **Non-functional**: p50/p95/p99 response times, verification that no internal service is reachable from outside the mesh, isolation checks (a component going down should not take down others where isolation is required).

### 1.5 Exit criteria

A test level is considered complete for a given component/feature when:

- Decision coverage is reached on validation functions.
- No known failing test on the already-integrated chain.

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
**The merge commit must include every requirement covered by the branch**.

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