# The 77 Canonical Subagent Strategies (SAS-001 through SAS-077)

**Status:** Normative & Governed  
**Specification:** CKODEX Subagent Strategy Taxonomy v2.0  
**Implementation:** `ggagent-kernel::strategies::StrategyRegistry`  

---

## 🏛️ Strategy Taxonomy & The Seven Core Archetypes

The 77 Subagent Strategies are cataloged across seven fundamental engineering archetypes:

```text
┌────────────────────────────────────────────────────────────────────────┐
│               THE 77 SUBAGENT STRATEGY ARCHETYPES                      │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Triage & Decomposition          (SAS-001 - SAS-011)                 │
│ 2. Context Isolation & Compression (SAS-012 - SAS-022)                 │
│ 3. Model Routing & Optimization    (SAS-023 - SAS-033)                 │
│ 4. Authority Leases & Fencing      (SAS-034 - SAS-044)                 │
│ 5. Concurrency, Workflows & Graphs (SAS-045 - SAS-055)                 │
│ 6. Verification, Attestation & Receipts (SAS-056 - SAS-066)            │
│ 7. Day-2 Operability & Resilience  (SAS-067 - SAS-077)                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Archetype 1: Triage & Decomposition (SAS-001 to SAS-011)

| Code | Name | Applicable Tiers | Description & Intent |
|---|---|---|---|
| **SAS-001** | Blind-First Planner | R, Peer | Dispatches problem statement to cross-family peer without sharing internal plan to eliminate groupthink. |
| **SAS-002** | Closed-Spec Downlink | S, B | Translates intent into closed specifications with zero open questions before mechanical dispatch. |
| **SAS-003** | Hierarchical Decomposition | R, Conductor | Decomposes compound intents into a tree of bounded units of work with measurable acceptance criteria. |
| **SAS-004** | Domain-Bounded Sharding | B | Partitions tasks strictly along architectural bounded contexts to prevent cross-domain contamination. |
| **SAS-005** | Risk-Proportional Sizing | Conductor | Classifies work into Core, Governed, or Assured levels based on blast radius, irreversibility, and authority. |
| **SAS-006** | Epistemic Routing | R | Routes queries based on whether information is durable knowledge, empirical measurement, or heuristic inference. |
| **SAS-007** | Task Slicing by Layer | B | Separates kernel, validation, transport, and evidence edits into distinct subagent tickets. |
| **SAS-008** | Spec Arbiter | Conductor, Peer | Arbitrates conflicting plan proposals across peer agents using formal dominance rules. |
| **SAS-009** | Intent Envelope Triage | Conductor | Wraps raw user or system prompts into structured IntentEnvelopes with actor, authority, constraints, and effects. |
| **SAS-010** | Conformal Dispatcher | R | Calibrates subagent task assignments using split conformal risk prediction sets ($\alpha \le 0.05$). |
| **SAS-011** | Dependency Barrier | Conductor | Fences subagent execution order so dependents never execute before dependencies emit verified evidence. |

---

## Archetype 2: Context Isolation & Compression (SAS-012 to SAS-022)

| Code | Name | Applicable Tiers | Description & Intent |
|---|---|---|---|
| **SAS-012** | Spoke-Window Isolation | S, B | Executes deep exploration inside isolated worker windows, returning concise summaries to shield conductor. |
| **SAS-013** | Context-Rot Shield | Conductor | Monitors token utilization and attention drift; triggers subagent handoff before threshold degradation. |
| **SAS-014** | Byte-for-Byte State Handoff | Conductor, B | Transfers execution state between agent generations via deterministic JSON serialization without amnesia. |
| **SAS-015** | Delta-Only Folding | B | Transmits only state diffs and mutated tokens rather than full snapshots between parent and subagents. |
| **SAS-016** | AST-Scoped Injection | S, B | Provides subagents only the precise symbol AST definitions and immediate callers, omitting whole files. |
| **SAS-017** | Summary Condenser | S | Compresses multi-turn subagent execution logs into structured YAML evidence tables. |
| **SAS-018** | Sibling Context Fence | Conductor | Prevents concurrent subagents from reading each other's in-progress uncommitted context. |
| **SAS-019** | History Compaction | Conductor | Folds conversational turns into formal vector states, discarding intermediate chat chatter. |
| **SAS-020** | Epistemic Class Segregation | R | Stores durable facts, retrieved docs, and temporary model thoughts in segregated context channels. |
| **SAS-021** | Memory-Context Decoupler | B | Decouples durable knowledge base updates from working scratchpad memory. |
| **SAS-022** | Pinned Context Slices | S, B | Pins exact file:line spans into subagent prompts, forbidding speculative whole-repo greps. |

---

## Archetype 3: Model Routing & Multi-Tier Optimization (SAS-023 to SAS-033)

| Code | Name | Applicable Tiers | Description & Intent |
|---|---|---|---|
| **SAS-023** | Fast-Tier Indexer | S | Routes mechanical indexing, file discovery, and symbol lookup to lightweight high-throughput models. |
| **SAS-024** | Mid-Tier Builder | B | Routes decided specifications and implementation tickets to balanced general reasoning models. |
| **SAS-025** | Deep-Tier Reasoner | R | Routes cross-cutting architectural trade-offs and ambiguous bugs to deep reasoning models. |
| **SAS-026** | Conformal Risk Router | Conductor | Dynamically escalates model tier when task uncertainty score exceeds calibration threshold. |
| **SAS-027** | Cross-Family Blind Pair | Peer | Executes peer planning across different model families (e.g. Gemini + Codex) independently. |
| **SAS-028** | Cost-Constrained Selector | Conductor | Calculates required capability heuristic $\propto \text{Uncertainty} \times \text{BlastRadius} \times \text{Cost}$. |
| **SAS-029** | Token Budget Allocator | Conductor | Apportions fixed token budgets to subagents with hard pre-emptive cancellation on overrun. |
| **SAS-030** | Model Escalation Ladder | Conductor | Promotes subagent task through Fast $\to$ Mid $\to$ Deep tiers upon verified mechanical failure. |
| **SAS-031** | Failure-Tier Promoter | Conductor | Automatically promotes subagent tier by one level on second consecutive mechanical failure. |
| **SAS-032** | Split-Role Dispatcher | B, R | Dispatches generator role to creative tier and checker/verifier role to strict deterministic tier. |
| **SAS-033** | Fallback Graceful Degrader | Conductor | Falls back to local offline model or heuristics if remote inference provider degrades or times out. |

---

## Archetype 4: Authority Leases & Fencing (SAS-034 to SAS-044)

| Code | Name | Applicable Tiers | Description & Intent |
|---|---|---|---|
| **SAS-034** | Least-Authority Sandboxing | S, B, R | Equips subagents strictly with minimal tools and filesystem paths necessary for their task. |
| **SAS-035** | CapabilityLease Attenuation | Conductor | Attenuates parent authority when delegating; child leases cannot exceed parent permissions. |
| **SAS-036** | Read-Only Fencing | S, R | Strikes all mutating tools (file write, git commit, shell exec) from research and auditor subagents. |
| **SAS-037** | AtomicEffectGuard Binding | Conductor, B | Binds approval to SHA-256(action \|\| target \|\| params) at use time, defeating Loopjacking. |
| **SAS-038** | Confused Deputy Barrier | Conductor | Rejects approval turns originating from peer agents masquerading as human users (CVE-2026-18236). |
| **SAS-039** | Egress-Restricted Sandbox | B | Restricts subagent network egress strictly to designated ARD and A2A endpoints. |
| **SAS-040** | Time-Bounded Execution Lease | Conductor | Attaches cryptographic expiration timestamps to subagent leases; expires automatically. |
| **SAS-041** | Parent-Child Authority Propagation | Conductor | Carries complete lineage of parent authority tokens in child execution envelope. |
| **SAS-042** | Credential Non-Inheritance | B | Subagents do not inherit ambient credentials, cloud tokens, or SSH keys from host environment. |
| **SAS-043** | Quarantine Enclave | Conductor | Immediately isolates subagent upon detecting invariant violation, preserving state for forensics. |
| **SAS-044** | Revocation Interceptor | Conductor, B | Checks real-time revocation list before executing any authority-bearing tool invocation. |

---

## Archetype 5: Concurrency, Workflows & Graphs (SAS-045 to SAS-055)

| Code | Name | Applicable Tiers | Description & Intent |
|---|---|---|---|
| **SAS-045** | Directed Acyclic Graph Engine | Conductor | Models multi-subagent workflows as typed DAG nodes with explicit conditional routing edges. |
| **SAS-046** | Cycle & Loop Guard | Conductor | Bounds maximum cycles and detects recurring state loops in subagent execution graphs. |
| **SAS-047** | Parallel Fan-Out / Fan-In | Conductor | Fans out independent tasks to multiple subagents; fans in via typed aggregator. |
| **SAS-048** | ErrGroup Concurrency | Conductor | Runs concurrent subagents under unified cancellation context; first failure cancels siblings. |
| **SAS-049** | Worktree Branch Worker | B | Spawns subagents in isolated git worktrees so filesystem changes do not collide. |
| **SAS-050** | Shared Workcell Workspace | B | Coordinates access to shared workspace via strict file-locking leases and transaction boundaries. |
| **SAS-051** | Non-Blocking Event Stream | Conductor, B | Emits subagent progress and telemetry via SSE channels without blocking worker execution loop. |
| **SAS-052** | Backpressure Limiter | Conductor | Throttles subagent spawning when worker pool queue depth exceeds saturation threshold. |
| **SAS-053** | Rate-Budgeted Worker Pool | Conductor | Enforces token-per-minute and request-per-minute rate ceilings across all running subagents. |
| **SAS-054** | Topological Dependency Sched | Conductor | Calculates topological sort of subagent task graph and schedules ready nodes in parallel batches. |
| **SAS-055** | Continuation Token Bind | Conductor | Cryptographically binds multi-turn continuation tokens to exact task and session identifiers. |

---

## Archetype 6: Verification, Attestation & Receipts (SAS-056 to SAS-066)

| Code | Name | Applicable Tiers | Description & Intent |
|---|---|---|---|
| **SAS-056** | Mechanical Over Model Arbiter | Conductor | Prioritizes compiler, linter, and test results over model claims; code compiles or it didn't happen. |
| **SAS-057** | Property-Based Falsifier | B, R | Runs randomized proptests across subagent output to falsify invariant claims before acceptance. |
| **SAS-058** | Anti-State Dominator | Conductor | Enforces that a single structural contradiction (AntiRelation) overrides any number of passing checks. |
| **SAS-059** | Cross-Family Two-Model Agreement | Peer | Requires concordant verdicts from two separate model families when mechanical verification is unavailable. |
| **SAS-060** | TOCTOU Source Commitment | Conductor, B | Hashes source tree before and after subagent run to prevent race mutations. |
| **SAS-061** | Mutation Lineage Ledger | Conductor | Records state changes as $M = \langle S_0, Trigger, Authority, Transformation, S_1, Evidence, Time \rangle$. |
| **SAS-062** | DSSE Envelope Attestor | Conductor | Signs subagent execution receipts with Ed25519 DSSE envelopes for non-repudiation. |
| **SAS-063** | In-Toto Statement Producer | Conductor | Generates in-toto v1.0 supply chain attestations linking subagent inputs to output artifacts. |
| **SAS-064** | Conformance Vector Transition | Conductor | Evaluates transition contract $\delta(P_e, S_0, X, C) \to \langle d, O, S_1, E, R \rangle$. |
| **SAS-065** | Derogation Ledger | Conductor | Binds accepted risk to failing requirement without rewriting FAIL to PASS. |
| **SAS-066** | Flight Recorder Proof | Conductor | Maintains tamper-evident execution trace of digests, authority tokens, and decisions. |

---

## Archetype 7: Day-2 Operability & Resilience (SAS-067 to SAS-077)

| Code | Name | Applicable Tiers | Description & Intent |
|---|---|---|---|
| **SAS-067** | Canonical Control Loop Reconciler | Conductor | Runs OBSERVE $\to$ DETECT $\to$ DIAGNOSE $\to$ DEGRADE $\to$ CONTAIN $\to$ RECOVER $\to$ VERIFY $\to$ RECONCILE. |
| **SAS-068** | Degraded Mode Contract | Conductor | Switches agent to explicit read-only or local-only mode upon upstream network or auth failure. |
| **SAS-069** | Jittered Backoff Retrier | B | Executes bounded retries with full jitter and exponential backoff under strict retry budget. |
| **SAS-070** | Safe-Hold Freeze | Conductor | Freezes all mutating side effects upon unexpected anomaly, awaiting human instruction. |
| **SAS-071** | Anti-Entropic State Repair | Conductor | Proactively repairs drifted vector states and reconciles ghost files across workcells. |
| **SAS-072** | Time-Machine Rollback | Conductor | Rolls back agent state to last verified checkpoint upon unrecoverable subagent failure. |
| **SAS-073** | Checkpoint Resume | Conductor | Resumes multi-hour workflows from durable disk checkpoints rather than restarting from zero. |
| **SAS-074** | Drift Detector | Conductor | Continuously compares observed state with authoritative baseline profile to flag decoherence. |
| **SAS-075** | Deep Diagnostic Doctor | Conductor | Exposes doctor/inspect/explain/trace/verify suite answering What, Where, Why, Under Whose Authority. |
| **SAS-076** | Live Telemetry Prober | Conductor | Probes agent latency, memory footprint, token rate, and connection health in real time. |
| **SAS-077** | Sovereign Air-Gap Resolver | Conductor, B | Enforces offline dependency resolution, local model fallbacks, and air-gapped evidence packaging. |
