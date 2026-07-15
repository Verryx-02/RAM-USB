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