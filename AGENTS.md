# AGENTS.md — Agent Governance & Operating Rules

**Status:** Binding  
**Scope:** All autonomous agents, subagents, and human operators interacting with `ckodex-ggagent-cli` (`ggagent`).  
**Default Autonomy:** GAL 1 (Governed Autonomy Level 1)  

---

## 1. Prime Invariants

1. **Pure Domain Kernel Purity:**
   The `crates/ggagent-kernel` crate MUST remain 100% free of I/O, network crates, databases, and asynchronous runtimes. Domain invariants depend strictly inward.
2. **Authority Precedes Capability:**
   No capability lease may be granted without an identifiable root authority path (`Root Fabric -> Tenant -> Workspace -> Resource`).
3. **Receipt After Execution:**
   Every authority-bearing side effect MUST produce an `ExecutionReceipt` with an Ed25519 signature and SHA-256 digests.
4. **Vector State Truth:**
   Do not collapse governed reality into boolean status. Use the typed product $S(e,t) = \langle P, V, A, C, E, L, \tau \rangle$. A single `AntiRelation` violation dominates aggregate scoring.
5. **A2A Role Separation (Confused Deputy Defense):**
   Peer agent turns (`A2ARole::RemoteAgent`) MUST NEVER be mapped to `A2ARole::HumanUser` or permitted to approve mutating actions (CVE-2026-18236 / ADK Issue #6461).
6. **Use-Time Material Binding (Loopjacking Defense):**
   Sensitive actions MUST be bound to their exact arguments using `AtomicEffectGuard` verification (arXiv:2609.21081).
7. **Zero-Warning Quality Gate:**
   No commit or PR may be merged with failing tests, formatting errors, or Clippy warnings (`-D warnings`).
8. **Generation Fencing (Split-Brain Defense):**
   Every capability lease carries a monotonic `generation: u64` and `fencing_token`. Authority handoffs and partition recovery MUST advance generation $N \to N+1$. In-flight effects from stale generations MUST be strictly fenced by the `AtomicEffectBroker`.
9. **4-Dimensional Coordinated States:**
   Do not collapse execution, authority, candidate, and reclamation lifecycles into a single enum. Cross-lifecycle invariants: `Execution::Running` strictly requires `Authority::Active`; revocation immediately drops running execution to `Stopping`; reclamation blocks new admissions.
10. **Immutable Candidate Sealing & Symlink Traversal Defeat:**
   Workspace candidate files MUST be path-validated to defeat symlink escapes out of the sandbox, and sealed into immutable snapshots with SHA-256 digests prior to review, defeating TOCTOU check-to-use races.
11. **Three-Loop Separation of Responsibility:**
   Inner loop workers MUST NOT grant themselves authority or expand budgets. Outer loop verifiers MUST NOT commit mutating side effects or publish artifacts.
12. **Monotonic Budget Attenuation:**
   Child subagents and delegated handoffs MUST NOT receive a resource budget exceeding the remaining parent budget. Budget inflation is an immediate hard invariant violation.
13. **Zero Standing Secrets in Sandboxes:**
   Static API keys, private keys, and long-lived tokens MUST NOT exist inside execution sandboxes. Payloads, flight recorders, and receipts must be actively scrubbed by `SecretGuard`.

---

## 2. Dispatching Subagents (The 77 Canonical Strategies)

When dispatching tasks to subagents or cross-family peers, consult [`SUBAGENTS-77-CATALOG.md`](docs/SUBAGENTS-77-CATALOG.md).
Follow the role-to-tier mappings:
- **Tier S (Mechanical):** Mechanical indexing, file search, and formatting. Receives closed specs.
- **Tier B (Builder):** Feature implementation and unit testing. Receives decided specifications.
- **Tier R (Reasoner):** High-level trade-offs, formal invariants, and ambiguous bugs. Receives raw constraints, not pre-cooked plans.
- **Tier Peer (Cross-Family):** Blind-first planning (Gemini + Codex) without shared internal plans.

---

## 3. Local Verification Commands

Before declaring any task complete:
```bash
make fmt       # Verify rustfmt
make clippy    # Verify -D warnings
make test      # Run all workspace tests
make doctor    # Verify Day-2 runtime health
```
