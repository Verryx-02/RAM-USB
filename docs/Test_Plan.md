# RAM-USB — Software Test Plan

This document defines how RAM-USB gets tested: which test level applies to which level of specification, what technique each level uses, when a level counts as done, and what tooling supports it. It follows the structure of IEEE 829 / ISO/IEC/IEEE 29119, the standard references for test documentation under a V-model process, sized for a single-developer thesis project: one developer, one reviewer, the thesis supervisor.

Requirements come from [`docs/Software_Requirements_Specification.md`](Software_Requirements_Specification.md), the single source of truth for what the system must do. This document only covers *how* those requirements get verified. Build and commit process is in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

---

## 1. Scope

**In scope:** every `*-F-*`, `RNF-*`, `RD-*` requirement and every `UC-*` use case in the SRS.

**Out of scope:** anything the SRS itself marks out of scope (§1.2): credential revocation, backup tamper-protection, GDPR compliance. No test gets written for a requirement that doesn't exist.

---

## 2. Test levels

Four levels, each tied to a granularity of specification, not to a project phase. They run continuously as features get built, not as a single end-of-project pass.

| Specification level | Test level | Technique |
|---|---|---|
| Single-component requirement (`EH-F-04`, `DV-F-01`...) | Unit / component test | Table-driven Go tests, stdlib `testing` |
| Use case (`UC-01`..`UC-05`) | Integration test | Bottom-up, driver/stub |
| Non-functional requirement (`RNF-*`) | System test | Full stack, measured against a numeric threshold |
| User requirement (`RU-*`) | Acceptance checklist | Manual walkthrough of the use case it maps to |

**Why four levels:** tying each level to one specification granularity means a failure at the unit level points precisely at one requirement, one component, one function.

### 2.1 Unit / component tests

- **What they cover:** one `*-F-*` requirement, one component, no network, no other service.
- **Technique:** table-driven tests over the stdlib `testing` package. Each test case is one row: input, expected output, expected error.
- **Traceability:** a `// Requirement: <ID>` doc comment directly above every test function.
- **Worked example:** `DV-F-15` ("same 401 for nonexistent email and wrong password") is a two-row table: one row with a valid email and a wrong password, one row with a nonexistent email. Both rows assert the identical status code and the identical response body.

### 2.2 Integration tests

- **What they cover:** a full use case (`UC-01`..`UC-05`), crossing multiple components.
- **Technique:** bottom-up, driver/stub. See §3.
- **Traceability:** one integration test suite per use case, named after the `UC-*` ID.

### 2.3 System tests

- **What they cover:** a non-functional requirement (`RNF-*`), measured against the full running stack.

**Functional system tests:** complete scenarios end to end. Example: a registration request entering at Entry-Hub, landing as a row in Database-Vault, and producing a metric in TimescaleDB.

**Non-functional system tests:** measured thresholds, not pass/fail booleans.

- **Latency (`RNF-PERF-01`):** p50/p95/p99 response time per endpoint. Worked example: if `p50 = 20ms` and `p99 = 300ms`, 99% of requests return within 300ms. The remaining 1% is what gets investigated, not the median.
- **Isolation (`RNF-REL-01`):** killing one component's container must not take down another where isolation is required. Verified by stopping a container and checking the others keep responding.
- **Network exposure (`NET-F-01`):** no internal service is reachable from outside the mesh. Verified by attempting a direct connection from outside the Headscale network and expecting a timeout or refusal, not a response.

### 2.4 Acceptance checklist

- **What it covers:** one `RU-*` user requirement.
- **Technique:** manual walkthrough of the use case(s) that requirement traces to (SRS §9), checked off once observed to behave as specified.
- **Why manual:** an `RU-*` requirement describes a user-perceived outcome ("I want the guarantee that..."). The system tests in §2.3 already exercise the mechanics; the acceptance checklist is the final sign-off that ties those results back to the original user-facing promise.

---

## 3. Integration strategy: bottom-up, driver and stub

```
DRIVER (simulates the caller) -> COMPONENT UNDER TEST -> STUB (simulates the callee)
```

Integration starts from the innermost component and works outward:

**Database-Vault -> Storage-Service -> Security-Switch -> Network-Manager -> Entry-Hub**

**Why bottom-up:** Database-Vault has the fewest outbound dependencies (only Storage-Service) and the highest concentration of SRS requirements (`DV-F-01` through `DV-F-20`). Building it first, stubbing everything above it, means the component with the most to get right is also the one that gets tested the most before anything else depends on it.

Driver and stub are hand-written fakes implementing the relevant Go interface (`CONTRIBUTING.md` §7).

---

## 4. Test environment and tools

- **Unit tests:** `go test ./...`. No external dependency, no Docker.
- **Integration and system tests:** run against the Docker Compose stack (`deployments/docker-compose.dev.yml`), with real mTLS certificates issued by the local Certificate-Authority container.
- **Linting:** `golangci-lint` (`CONTRIBUTING.md` §7.1) runs before any test suite. Only lint-clean files proceed to testing.
- **Coverage:** `go test -cover`, tracked per package. See §5 for the exit criterion this protects.

---

## 5. Entry and exit criteria

**Entry criteria, before implementation of a requirement starts:**

- A test exists for that requirement, and it fails, before any implementation code is written.
- If a test cannot be written for a requirement, implementation does not start. The requirement goes back to the SRS for clarification first.

**Exit criteria, before a requirement or component counts as done:**

- Decision coverage reached on validation functions: every branch of every `if`/`switch` deciding accept or reject has a test case that hits it.
- No known failing test on the already-integrated chain.
- Regression: every relevant change re-runs the affected test suite, not just the new test.

---

## 6. Traceability

Every test traces to exactly one requirement ID, via the doc comment convention in `CONTRIBUTING.md` §7.5. This is what makes traceability (`CONTRIBUTING.md` §2, SRS §9) checkable in both directions:

- **Requirement to test:** grep the test suite for the ID.
- **Test to requirement:** read the doc comment above the failing test.

---

## 7. Known gaps

- **RISK-01 / RISK-02 (SRS §8):** no test exists for backup tamper-protection (out of scope) or master-key rotation (no rotation procedure exists yet to test).
- **Load and stress testing:** planned for a later iteration. The p50/p95/p99 thresholds in §2.3 are measured under normal load, matching this thesis's case-study scope.
