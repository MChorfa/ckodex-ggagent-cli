# CKODEX Architectural Signature & System Design

**System:** `ckodex-ggagent-cli`  
**Architecture:** Pure Hexagonal / CKODEX Four-Layer Architecture / Clean Condamian Convention  

---

## 🏛️ Hexagonal Four-Layer Architecture

```text
┌────────────────────────────────────────────────────────────┐
│                    Explicit Transport                      │
│ (A2A JSON-RPC 2.0, SSE Streaming, ARD Service, MCP Bridge) │
│                       crates/ggagent-transport             │
└─────────────────────────────┬──────────────────────────────┘
                              │ depends inward
┌─────────────────────────────▼──────────────────────────────┐
│                    Shared Validation                       │
│ (Agent Card, ARD Documents, Confused Deputy & EffectGuards)│
│                      crates/ggagent-validation             │
└─────────────────────────────┬──────────────────────────────┘
                              │ depends inward
┌─────────────────────────────▼──────────────────────────────┐
│                   Pure Semantic Kernel                     │
│ (Vector State, 77 Subagent Strategies, A2A/ARD Core, FSM)  │
│                       crates/ggagent-kernel                │
│             [ZERO I/O, ZERO NETWORK, ZERO DB]              │
└─────────────────────────────┬──────────────────────────────┘
                              │ emits facts
┌─────────────────────────────▼──────────────────────────────┐
│                      Evidence Fabric                       │
│ (Digests, DSSE Attestations, Lineage, Receipts, FlightRec) │
│                      crates/ggagent-evidence               │
└────────────────────────────────────────────────────────────┘
```

---

## 📦 Modular Crate Decomposition

1. **`crates/ggagent-kernel`**: Pure domain semantics, entities, value objects, state vectors $S(e,t)$, full catalog of the 77 subagent strategies, A2A task state machine, ARD data models, and capability leases. Zero external I/O dependencies.
2. **`crates/ggagent-validation`**: Shared validation rules, Agent Card linter, ARD document validator, Confused Deputy check, Loopjacking use-time effect guard verification, and hard anti-invariant dominance checkers.
3. **`crates/ggagent-evidence`**: Content-addressed SHA-256 digests, Ed25519 signed execution receipts, in-toto v1.0 attestations in DSSE envelopes, state mutation lineage ledger, and tamper-evident flight recorder.
4. **`crates/ggagent-transport`**: A2A JSON-RPC 2.0 protocol handler, Server-Sent Events (SSE) streaming engine, ARD `/.well-known/ard.json` publisher/server, MCP client/server bridge, cross-harness dispatch adapters, and native async HTTP server.
5. **`crates/ggagent-cli`**: Clap CLI binary (`ggagent`) exposing `create`, `playground`, `eval`, `ard`, `a2a`, `subagents`, `harness`, `doctor`, `explain`, and `verify`.

---

## 🛡️ Sandboxing & Virtualization Boundary Contracts (Chapters 24–30)

Grounded in the formal virtualization and agent sandboxing contracts:

### 1. 4-Dimensional Coordinated State Machines (Chapter 24)
Collapsing execution, authority, candidate, and reclamation into a single lifecycle enum causes state-coupling bugs. `ggagent` coordinates 4 orthogonal dimensions:
- **`ExecutionLifecycle`**: `REQUESTED` ➔ `ADMITTED` ➔ `PROVISIONING` ➔ `READY` ➔ `RUNNING` ➔ `STOPPING` ➔ `STOPPED` ➔ `DENIED` ➔ `FAILED`
- **`AuthorityLifecycle`**: `PENDING` ➔ `ACTIVE` ➔ `SUSPENDED` ➔ `REVOKED` ➔ `EXPIRED` ➔ `CLOSED`
- **`CandidateLifecycle`**: `ABSENT` ➔ `STAGED` ➔ `SEALED` ➔ `UNDER_REVIEW` ➔ `ACCEPTED` ➔ `REJECTED` ➔ `QUARANTINED`
- **`ReclamationLifecycle`**: `ALLOCATED` ➔ `CLEANUP_PENDING` ➔ `RECLAIMED` ➔ `CLEANUP_FAILED`

**Cross-State Invariants:**
- `Execution::Running` strictly requires `Authority::Active`. Loss of authority immediately forces execution to `Stopping`.
- `Reclamation::CleanupPending` prohibits new execution admissions and candidate staging.
- `Candidate::Accepted` strictly requires prior `UnderReview` and `Authority::Active`.

### 2. Monotonic Generation Fencing & Atomic Effect Broker (Chapters 25 & 26)
In distributed or partitioned agent execution, network partitions can cause split-brain executions where an older worker emerges late to commit side effects.
- Every lease carries monotonic `generation: u64` and `fencing_token: fence-{generation}-{lease_id}`.
- When authority is migrated or recovered, the broker advances `generation N ➔ N + 1`.
- Any worker attempting to execute an effect with `received_generation < current_generation` is strictly **FENCED** (`EffectDisposition::Fenced`).
- Idempotency keys prevent duplicate side-effect execution upon replay.
- Use-Time Material Binding (`AtomicEffectGuard`) eliminates parameter tampering and Loopjacking (arXiv:2609.21081).

### 3. Safe Workspace Staging & Symlink Traversal Defeat (Chapters 21, 28, 29)
Untrusted agent workloads produce candidates (patches, modified files) within mutable workspaces:
- Paths are strictly validated relative to the workspace root, rejecting absolute paths and `..` directory traversal.
- Symlinks pointing outside the workspace boundary are caught and rejected as `ContainmentEscapeViolation`.
- Staged candidate files are sealed into immutable byte buffers with SHA-256 digests (`SealedCandidate`), defeating TOCTOU (check-to-use) workspace mutation races.

### 4. Four Formal Failure Modes (Chapter 30)
Rather than generic error codes, failure is categorized into four distinct modes:
1. `ContainmentEscape`: Boundary violation attempts (symlink escape, unauthorized path traversal, illegal syscall/network access).
2. `AuthorizedHarm`: Operation had valid authority, but caused destructive or un-reconcilable side effects.
3. `VerificationFailure`: Candidate artifact or test assertion failed objective verification criteria.
4. `GovernanceFailure`: Split-brain, stale generation fence, missing authority delegation, expired lease, or confused deputy approval.

### 5. Three-Loop Architecture & Message Primitives (Chapter 2)
Responsibility separation across execution loops:
- **`InnerLoop`**: Bounded worker iteration (receives admitted task, inspects context, calls tools, proposes candidates). Prohibited from granting itself authority or expanding budget.
- **`OuterLoop`**: Independent verification (runs tests, linters, and invariant audits). Prohibited from publishing side effects or mutating production state.
- **`GovernanceLoop`**: Authoritative coordinator (controls admission, capability leases, budget, promotion, revocation).

Categorical Message Primitives:
- `CommandRequest`: Requests an operation.
- `EventReport`: Reports an occurrence.
- `EvidenceClaim`: Submits a verifiable proposition with artifact digest.
- `GovernanceDecision`: Authorizes an admission or promotion (`Admit`, `Deny`, `Promote`, `Revoke`, `Quarantine`).
- `ExecutionReceipt`: Cryptographically records outcome.

### 6. Multi-Dimensional Execution Budgeting & Monotonic Attenuation (Chapters 2, 14, 22)
Tasks track four explicit resource dimensions: `max_steps`, `max_mutating_effects`, `max_tokens`, and `max_duration_ms`.
- Monotonic attenuation: Subagent budgets MUST NOT exceed the remaining parent budget.
- Exhaustion on any dimension automatically blocks new mutating effects.

### 7. Partitioned Handoff Protocol & Zero-Credential Inheritance (Chapters 3 & 26)
Task migration across nodes or partitions is governed by `HandoffManifest`:
- Carries contract version, `source_generation`, `target_generation`, checkpoint digest, 7D vector state, 4D coordinated state, and remaining budget.
- `HandoffValidator` verifies checkpoint cryptographic digest and enforces strict budget non-inflation.
- Zero standing secrets are transferred; target nodes must re-bind ephemeral credentials.

### 8. Forensic Evidence Bundles (Chapters 18 & 30)
Tamper-evident post-mortem bundle (`ForensicBundle`) uniting vector state, coordinated state, hash-chained flight recorder events across 4 truth channels, signed execution receipts, and failure classification under a top-level root SHA-256 manifest.

---

## 🔄 Canonical Day-2 Control Loop

```text
OBSERVE ──► DETECT ──► DIAGNOSE ──► DEGRADE ──► CONTAIN ──► RECOVER ──► VERIFY ──► RECONCILE
```

Every production-significant subsystem exposes deep diagnostics (`doctor`, `explain`, `inspect`, `verify`) rather than relying on raw log dumps.
