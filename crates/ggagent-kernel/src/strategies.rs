use serde::{Deserialize, Serialize};

/// The 7 Core Subagent Strategy Archetypes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StrategyArchetype {
    TriageAndDecomposition,
    ContextIsolationAndCompression,
    ModelRoutingAndOptimization,
    AuthorityLeasesAndFencing,
    ConcurrencyWorkflowsAndGraphs,
    VerificationAttestationAndReceipts,
    Day2OperabilityAndResilience,
}

/// A formal, discrete Subagent Strategy specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubagentStrategy {
    pub id: u32,
    pub code: String,
    pub name: String,
    pub archetype: StrategyArchetype,
    pub description: String,
    pub intent: String,
    pub invariants: Vec<String>,
    pub required_evidence: Vec<String>,
    pub applicable_tiers: Vec<String>,
}

/// The Canonical 77 Subagent Strategy Registry
pub struct StrategyRegistry;

impl StrategyRegistry {
    /// Return all 77 strategies
    #[allow(clippy::vec_init_then_push)]
    pub fn all() -> Vec<SubagentStrategy> {
        let mut list = Vec::with_capacity(77);

        // --- Archetype 1: Triage & Decomposition (1-11) ---
        list.push(SubagentStrategy {
            id: 1,
            code: "SAS-001".into(),
            name: "Blind-First Planner".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Dispatches problem statement to cross-family peer without sharing internal plan to produce independent formulation".into(),
            intent: "Eliminate planning groupthink and confirmation bias".into(),
            invariants: vec!["Never send plan to reasoner; send problem only".into()],
            required_evidence: vec!["independent_plan_diff".into()],
            applicable_tiers: vec!["R".into(), "Peer".into()],
        });
        list.push(SubagentStrategy {
            id: 2,
            code: "SAS-002".into(),
            name: "Closed-Spec Downlink".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Translates high-level intent into closed specifications with zero open questions before mechanical dispatch".into(),
            intent: "Constrain mechanical workers to deterministic execution".into(),
            invariants: vec!["Zero open ambiguity in downward dispatch brief".into()],
            required_evidence: vec!["closed_spec_validation".into()],
            applicable_tiers: vec!["S".into(), "B".into()],
        });
        list.push(SubagentStrategy {
            id: 3,
            code: "SAS-003".into(),
            name: "Hierarchical Decomposition".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Decomposes complex compound intents into a tree of bounded units of work with explicit acceptance criteria".into(),
            intent: "Structure complex objectives into verifiable atomic tasks".into(),
            invariants: vec!["Leaf tasks must have measurable acceptance criteria".into()],
            required_evidence: vec!["task_tree_receipt".into()],
            applicable_tiers: vec!["R".into(), "Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 4,
            code: "SAS-004".into(),
            name: "Domain-Bounded Sharding".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Partitions tasks strictly along architectural bounded contexts to prevent cross-domain contamination".into(),
            intent: "Preserve clean hexagonal boundaries during multi-agent edits".into(),
            invariants: vec!["Worker scope cannot cross foreign domain boundaries".into()],
            required_evidence: vec!["boundary_conformance_check".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 5,
            code: "SAS-005".into(),
            name: "Risk-Proportional Sizing".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Assigns governance level (Core, Governed, Assured) based on blast radius, irreversibility, and authority".into(),
            intent: "Keep governance complexity strictly proportional to consequence".into(),
            invariants: vec!["High consequence tasks must enforce Assured machinery".into()],
            required_evidence: vec!["risk_classification_record".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 6,
            code: "SAS-006".into(),
            name: "Epistemic Routing".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Routes queries based on whether information is durable knowledge, empirical measurement, or heuristic inference".into(),
            intent: "Prevent epistemic class collapse during agent delegation".into(),
            invariants: vec!["Inference never promoted to empirical fact without measurement".into()],
            required_evidence: vec!["epistemic_classification".into()],
            applicable_tiers: vec!["R".into()],
        });
        list.push(SubagentStrategy {
            id: 7,
            code: "SAS-007".into(),
            name: "Task Slicing by Layer".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Separates kernel, validation, transport, and evidence edits into distinct subagent tickets".into(),
            intent: "Enforce CKODEX four-layer architectural separation".into(),
            invariants: vec!["Transport worker cannot modify kernel crates".into()],
            required_evidence: vec!["layer_commit_diff".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 8,
            code: "SAS-008".into(),
            name: "Spec Arbiter".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Arbitrates conflicting plan proposals across peer agents using formal dominance rules".into(),
            intent: "Resolve architectural divergences objectively".into(),
            invariants: vec!["Mechanical arbiter beats model agreement".into()],
            required_evidence: vec!["arbitration_verdict".into()],
            applicable_tiers: vec!["Conductor".into(), "Peer".into()],
        });
        list.push(SubagentStrategy {
            id: 9,
            code: "SAS-009".into(),
            name: "Intent Envelope Triage".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Wraps raw user or system prompts into structured IntentEnvelopes with actor, authority, constraints, and effects".into(),
            intent: "Ground execution in formal intent rather than raw RPC/prompt strings".into(),
            invariants: vec!["Unenveloped prompts cannot acquire execution leases".into()],
            required_evidence: vec!["intent_envelope_digest".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 10,
            code: "SAS-010".into(),
            name: "Conformal Dispatcher".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description:
                "Calibrates subagent task assignments using split conformal risk prediction sets"
                    .into(),
            intent: "Guarantee bounded error rates for probabilistic routing decisions".into(),
            invariants: vec!["Routing risk bound alpha <= 0.05".into()],
            required_evidence: vec!["conformal_prediction_set".into()],
            applicable_tiers: vec!["R".into()],
        });
        list.push(SubagentStrategy {
            id: 11,
            code: "SAS-011".into(),
            name: "Dependency Barrier".into(),
            archetype: StrategyArchetype::TriageAndDecomposition,
            description: "Fences subagent execution order so dependents never execute before dependencies emit verified evidence".into(),
            intent: "Enforce strict topological ordering on side-effect DAGs".into(),
            invariants: vec!["Upstream evidence required before downstream lease grant".into()],
            required_evidence: vec!["barrier_release_proof".into()],
            applicable_tiers: vec!["Conductor".into()],
        });

        // --- Archetype 2: Context Isolation & Compression (12-22) ---
        list.push(SubagentStrategy {
            id: 12,
            code: "SAS-012".into(),
            name: "Spoke-Window Isolation".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Executes deep exploration or tool churning inside isolated subagent context windows, returning concise summaries".into(),
            intent: "Shield the main conductor context window from context rot".into(),
            invariants: vec!["Spoke internal history discarded after summary handoff".into()],
            required_evidence: vec!["compressed_handoff_payload".into()],
            applicable_tiers: vec!["S".into(), "B".into()],
        });
        list.push(SubagentStrategy {
            id: 13,
            code: "SAS-013".into(),
            name: "Context-Rot Shield".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Monitors token utilization and attention drift; triggers subagent handoff before threshold degradation".into(),
            intent: "Prevent hallucination induced by saturated attention windows".into(),
            invariants: vec!["Trigger compaction at 70% context threshold".into()],
            required_evidence: vec!["context_metrics_telemetry".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 14,
            code: "SAS-014".into(),
            name: "Byte-for-Byte State Handoff".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Transfers execution state between agent generations via deterministic JSON serialization without memory loss".into(),
            intent: "Preserve exact working memory across process/agent boundaries".into(),
            invariants: vec!["Zero non-deterministic mutations during serialization".into()],
            required_evidence: vec!["state_handoff_digest".into()],
            applicable_tiers: vec!["Conductor".into(), "B".into()],
        });
        list.push(SubagentStrategy {
            id: 15,
            code: "SAS-015".into(),
            name: "Delta-Only Folding".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Transmits only state diffs and mutated tokens rather than full snapshots between parent and subagents".into(),
            intent: "Maximize token transmission efficiency by over 75%".into(),
            invariants: vec!["Base state hash + delta hash equals target state hash".into()],
            required_evidence: vec!["delta_folding_receipt".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 16,
            code: "SAS-016".into(),
            name: "AST-Scoped Injection".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Provides subagents only the precise symbol AST definitions and immediate callers, omitting whole files".into(),
            intent: "Minimize token noise and eliminate irrelevance distraction".into(),
            invariants: vec!["Injected snippet must include symbol declaration and callers".into()],
            required_evidence: vec!["ast_slice_reference".into()],
            applicable_tiers: vec!["S".into(), "B".into()],
        });
        list.push(SubagentStrategy {
            id: 17,
            code: "SAS-017".into(),
            name: "Summary Condenser".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description:
                "Compresses multi-turn subagent execution logs into structured YAML evidence tables"
                    .into(),
            intent: "Retain high-density machine-verifiable findings without prompt bloat".into(),
            invariants: vec!["Summary must retain exact file:line citations".into()],
            required_evidence: vec!["condensed_evidence_table".into()],
            applicable_tiers: vec!["S".into()],
        });
        list.push(SubagentStrategy {
            id: 18,
            code: "SAS-018".into(),
            name: "Sibling Context Fence".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Prevents concurrent subagents from reading each other's in-progress uncommitted context".into(),
            intent: "Eliminate race conditions and hallucinations in parallel subagents".into(),
            invariants: vec!["Workers communicate only via verified evidence ledger".into()],
            required_evidence: vec!["isolation_fence_audit".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 19,
            code: "SAS-019".into(),
            name: "History Compaction".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Folds conversational turns into formal vector states, discarding intermediate chat chatter".into(),
            intent: "Retain state invariants while pruning conversation trajectory".into(),
            invariants: vec!["FSM state preserved after chat compaction".into()],
            required_evidence: vec!["compacted_vector_state".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 20,
            code: "SAS-020".into(),
            name: "Epistemic Class Segregation".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Stores durable facts, retrieved docs, and temporary model thoughts in segregated context channels".into(),
            intent: "Prevent LLM from confusing transient output with ground truth".into(),
            invariants: vec!["Transient thoughts never contaminate durable memory".into()],
            required_evidence: vec!["segregated_memory_index".into()],
            applicable_tiers: vec!["R".into()],
        });
        list.push(SubagentStrategy {
            id: 21,
            code: "SAS-021".into(),
            name: "Memory-Context Decoupler".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Decouples durable knowledge base updates from working scratchpad memory"
                .into(),
            intent: "Enforce explicit authority gates on permanent knowledge storage".into(),
            invariants: vec!["Working scratchpad writes cannot commit to long-term memory".into()],
            required_evidence: vec!["memory_admission_receipt".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 22,
            code: "SAS-022".into(),
            name: "Pinned Context Slices".into(),
            archetype: StrategyArchetype::ContextIsolationAndCompression,
            description: "Pins exact file:line spans into subagent prompts, forbidding speculative whole-repo greps".into(),
            intent: "Bound search radius and enforce targeted code edits".into(),
            invariants: vec!["Subagent prompt must cite exact pinned file:line span".into()],
            required_evidence: vec!["pinned_slice_manifest".into()],
            applicable_tiers: vec!["S".into(), "B".into()],
        });

        // --- Archetype 3: Model Routing & Multi-Tier Optimization (23-33) ---
        list.push(SubagentStrategy {
            id: 23,
            code: "SAS-023".into(),
            name: "Fast-Tier Indexer".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Routes mechanical indexing, file discovery, and symbol lookup to lightweight high-throughput models".into(),
            intent: "Conserve reasoning budget for non-mechanical architectural tasks".into(),
            invariants: vec!["Fast-tier tasks must have deterministic verification".into()],
            required_evidence: vec!["indexing_symbol_table".into()],
            applicable_tiers: vec!["S".into()],
        });
        list.push(SubagentStrategy {
            id: 24,
            code: "SAS-024".into(),
            name: "Mid-Tier Builder".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Routes decided specifications and implementation tickets to balanced general reasoning models".into(),
            intent: "Deliver clean, idiomatic code against unambiguous contracts".into(),
            invariants: vec!["Builder receives closed spec, never open constraints".into()],
            required_evidence: vec!["builder_test_pass_receipt".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 25,
            code: "SAS-025".into(),
            name: "Deep-Tier Reasoner".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Routes cross-cutting architectural trade-offs, formal invariants, and ambiguous bugs to deep reasoning models".into(),
            intent: "Maximize reasoning depth where blast radius is high".into(),
            invariants: vec!["Reasoner receives raw constraints, not pre-cooked plans".into()],
            required_evidence: vec!["formal_tradeoff_analysis".into()],
            applicable_tiers: vec!["R".into()],
        });
        list.push(SubagentStrategy {
            id: 26,
            code: "SAS-026".into(),
            name: "Conformal Risk Router".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Dynamically escalates model tier when task uncertainty score exceeds calibration threshold".into(),
            intent: "Ensure minimal cost while guaranteeing bounded error tolerance".into(),
            invariants: vec!["Escalate tier immediately if risk threshold exceeded".into()],
            required_evidence: vec!["calibration_escalation_log".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 27,
            code: "SAS-027".into(),
            name: "Cross-Family Blind Pair".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Executes peer planning across different model families (e.g. Gemini + Codex) independently".into(),
            intent: "Falsify proprietary blind spots through cross-family consensus".into(),
            invariants: vec!["Peer models must originate from distinct model families".into()],
            required_evidence: vec!["cross_family_consensus_diff".into()],
            applicable_tiers: vec!["Peer".into()],
        });
        list.push(SubagentStrategy {
            id: 28,
            code: "SAS-028".into(),
            name: "Cost-Constrained Selector".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Calculates required capability heuristic ~ Uncertainty x BlastRadius x Irreversibility x VerificationCost".into(),
            intent: "Select smallest reliable model for the bounded subagent task".into(),
            invariants: vec!["Model selection must satisfy heuristic bound".into()],
            required_evidence: vec!["cost_heuristic_calculation".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 29,
            code: "SAS-029".into(),
            name: "Token Budget Allocator".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Apportions fixed token budgets to subagents with hard pre-emptive cancellation on overrun".into(),
            intent: "Prevent runaway loops and token-drain catastrophes".into(),
            invariants: vec!["Task terminated immediately when budget exhausted".into()],
            required_evidence: vec!["token_usage_receipt".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 30,
            code: "SAS-030".into(),
            name: "Model Escalation Ladder".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Promotes subagent task through Fast -> Mid -> Deep tiers upon verified mechanical failure".into(),
            intent: "Attempt low-cost resolution first, escalating only on failure".into(),
            invariants: vec!["Escalation requires recorded mechanical failure trace".into()],
            required_evidence: vec!["escalation_ladder_record".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 31,
            code: "SAS-031".into(),
            name: "Failure-Tier Promoter".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Automatically promotes subagent tier by one level on second consecutive mechanical failure".into(),
            intent: "Break stubborn implementation blocks with increased reasoning capacity".into(),
            invariants: vec!["Never retry twice at the same model tier without plan change".into()],
            required_evidence: vec!["tier_promotion_trace".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 32,
            code: "SAS-032".into(),
            name: "Split-Role Dispatcher".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Dispatches generator role to creative tier and checker/verifier role to strict deterministic tier".into(),
            intent: "Separate generative hypotheses from adversarial verification".into(),
            invariants: vec!["Checker model must be independent of generator model".into()],
            required_evidence: vec!["adversarial_verification_verdict".into()],
            applicable_tiers: vec!["B".into(), "R".into()],
        });
        list.push(SubagentStrategy {
            id: 33,
            code: "SAS-033".into(),
            name: "Fallback Graceful Degrader".into(),
            archetype: StrategyArchetype::ModelRoutingAndOptimization,
            description: "Falls back to local offline model or heuristics if remote inference provider degrades or times out".into(),
            intent: "Maintain system operability during network partitions or quota limits".into(),
            invariants: vec!["Residual capability contract must be explicitly declared".into()],
            required_evidence: vec!["fallback_transition_receipt".into()],
            applicable_tiers: vec!["Conductor".into()],
        });

        // --- Archetype 4: Authority, Leases & Fencing (34-44) ---
        list.push(SubagentStrategy {
            id: 34,
            code: "SAS-034".into(),
            name: "Least-Authority Sandboxing".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Equips subagents strictly with the minimal tools and filesystem paths necessary for their task".into(),
            intent: "Contain rogue subagent tool calls and prevent unintended mutations".into(),
            invariants: vec!["Tools outside authorized manifest are strictly uncallable".into()],
            required_evidence: vec!["sandbox_manifest_digest".into()],
            applicable_tiers: vec!["S".into(), "B".into(), "R".into()],
        });
        list.push(SubagentStrategy {
            id: 35,
            code: "SAS-035".into(),
            name: "CapabilityLease Attenuation".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Attenuates parent authority when delegating to subagents; child leases cannot exceed parent permissions".into(),
            intent: "Enforce strict monotonic attenuation across delegation chains".into(),
            invariants: vec!["ChildLease <= ParentLease in all permissions and bounds".into()],
            required_evidence: vec!["attenuation_proof".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 36,
            code: "SAS-036".into(),
            name: "Read-Only Fencing".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Strikes all mutating tools (file write, git commit, shell exec) from research and auditor subagents".into(),
            intent: "Guarantee that audit and research tasks are physically incapable of mutation".into(),
            invariants: vec!["Zero mutating tools in auditor capability lease".into()],
            required_evidence: vec!["read_only_lease_verification".into()],
            applicable_tiers: vec!["S".into(), "R".into()],
        });
        list.push(SubagentStrategy {
            id: 37,
            code: "SAS-037".into(),
            name: "AtomicEffectGuard Binding".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Binds approval to SHA-256(action || target || params) at use time, defeating Loopjacking (arXiv:2609.21081)".into(),
            intent: "Prevent attackers from swapping operations between approval and execution".into(),
            invariants: vec!["H(action_now || target_now || params_now) == grant.effect_digest".into()],
            required_evidence: vec!["effect_guard_hash_match".into()],
            applicable_tiers: vec!["Conductor".into(), "B".into()],
        });
        list.push(SubagentStrategy {
            id: 38,
            code: "SAS-038".into(),
            name: "Confused Deputy Barrier".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Rejects approval turns originating from peer agents masquerading as human users (CVE-2026-18236 / ADK #6461)".into(),
            intent: "Enforce explicit distinction between A2ARoleHumanUser and A2ARoleRemoteAgent".into(),
            invariants: vec!["Peer agents cannot grant human approval for mutating side effects".into()],
            required_evidence: vec!["principal_role_verification".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 39,
            code: "SAS-039".into(),
            name: "Egress-Restricted Sandbox".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description:
                "Restricts subagent network egress strictly to designated ARD and A2A endpoints"
                    .into(),
            intent: "Prevent data exfiltration and untrusted dependency poisoning".into(),
            invariants: vec!["Egress outside whitelisted CIDR blocks is dropped".into()],
            required_evidence: vec!["egress_firewall_log".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 40,
            code: "SAS-040".into(),
            name: "Time-Bounded Execution Lease".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Attaches cryptographic expiration timestamps to subagent leases; expires automatically".into(),
            intent: "Prevent lingering standing privilege from stale or abandoned subagents".into(),
            invariants: vec!["Lease invalid when current_time > valid_until".into()],
            required_evidence: vec!["timestamp_expiration_audit".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 41,
            code: "SAS-041".into(),
            name: "Parent-Child Authority Propagation".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description:
                "Carries complete lineage of parent authority tokens in child execution envelope"
                    .into(),
            intent: "Enable end-to-end provenance tracing of delegated actions".into(),
            invariants: vec![
                "Root authority identifier preserved across all delegation hops".into(),
            ],
            required_evidence: vec!["delegation_chain_signature".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 42,
            code: "SAS-042".into(),
            name: "Credential Non-Inheritance".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Subagents do not inherit ambient credentials, cloud tokens, or SSH keys from the host environment".into(),
            intent: "Possession of credentials != authorization".into(),
            invariants: vec!["Ambient environment variables scrubbed before subagent spawn".into()],
            required_evidence: vec!["sanitized_environment_record".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 43,
            code: "SAS-043".into(),
            name: "Quarantine Enclave".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Immediately isolates subagent upon detecting invariant violation, preserving state for forensic analysis".into(),
            intent: "Contain damage while preserving forensic evidence".into(),
            invariants: vec!["Quarantined subagent egress and mutation frozen immediately".into()],
            required_evidence: vec!["quarantine_snapshot_receipt".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 44,
            code: "SAS-044".into(),
            name: "Revocation Interceptor".into(),
            archetype: StrategyArchetype::AuthorityLeasesAndFencing,
            description: "Checks real-time revocation list before executing any authority-bearing tool invocation".into(),
            intent: "Cancel in-flight subagents instantly when user revokes intent".into(),
            invariants: vec!["Revoked lease blocks subsequent tool execution".into()],
            required_evidence: vec!["revocation_check_receipt".into()],
            applicable_tiers: vec!["Conductor".into(), "B".into()],
        });

        // --- Archetype 5: Concurrency, Workflows & Graphs (45-55) ---
        list.push(SubagentStrategy {
            id: 45,
            code: "SAS-045".into(),
            name: "Directed Acyclic Graph Engine".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Models multi-subagent workflows as typed DAG nodes with explicit conditional routing edges".into(),
            intent: "Replace brittle prompt loops with deterministic graph orchestration".into(),
            invariants: vec!["Workflow graph must be statically valid with typed inputs/outputs".into()],
            required_evidence: vec!["dag_topology_manifest".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 46,
            code: "SAS-046".into(),
            name: "Cycle & Loop Guard".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Bounds maximum cycles and detects recurring state loops in subagent execution graphs".into(),
            intent: "Prevent infinite retry loops and runaway compute consumption".into(),
            invariants: vec!["Max cycle limit <= 3; abort to human on loop repetition".into()],
            required_evidence: vec!["loop_counter_record".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 47,
            code: "SAS-047".into(),
            name: "Parallel Fan-Out / Fan-In".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Fans out independent search or verification tasks to multiple subagents; fans in via typed aggregator".into(),
            intent: "Speed up high-volume independent tasks with bounded concurrency".into(),
            invariants: vec!["All fan-out branches must report or reach timeout before fan-in".into()],
            required_evidence: vec!["fan_in_aggregation_verdict".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 48,
            code: "SAS-048".into(),
            name: "ErrGroup Concurrency".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Runs concurrent subagent tasks under unified cancellation context; first failure cancels siblings".into(),
            intent: "Fail fast and prevent wasted computation on doomed tasks".into(),
            invariants: vec!["Sibling tasks receive cancellation signal immediately upon error".into()],
            required_evidence: vec!["errgroup_completion_status".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 49,
            code: "SAS-049".into(),
            name: "Worktree Branch Worker".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Spawns subagents in isolated git worktrees so filesystem changes do not collide during parallel builds".into(),
            intent: "Enable concurrent code authoring without workspace corruption".into(),
            invariants: vec!["Each worker operates in dedicated isolated worktree path".into()],
            required_evidence: vec!["worktree_diff_receipt".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 50,
            code: "SAS-050".into(),
            name: "Shared Workcell Workspace".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Coordinates access to shared workspace via strict file-locking leases and transaction boundaries".into(),
            intent: "Prevent concurrent file corruption in single-repository workflows".into(),
            invariants: vec!["Only one worker holds write lease for target file at a time".into()],
            required_evidence: vec!["file_lock_lease_receipt".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 51,
            code: "SAS-051".into(),
            name: "Non-Blocking Event Stream".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Emits subagent progress and telemetry via SSE channels without blocking worker execution loop".into(),
            intent: "Provide real-time deep observability without performance overhead".into(),
            invariants: vec!["Telemetry drop on buffer saturation cannot stall worker".into()],
            required_evidence: vec!["event_stream_heartbeat".into()],
            applicable_tiers: vec!["Conductor".into(), "B".into()],
        });
        list.push(SubagentStrategy {
            id: 52,
            code: "SAS-052".into(),
            name: "Backpressure Limiter".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Throttles subagent spawning when worker pool queue depth exceeds saturation threshold".into(),
            intent: "Defend against thread exhaustion and memory starvation".into(),
            invariants: vec!["Worker pool size bounded by CPU cores * multiplier".into()],
            required_evidence: vec!["queue_depth_metric".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 53,
            code: "SAS-053".into(),
            name: "Rate-Budgeted Worker Pool".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Enforces token-per-minute and request-per-minute rate ceilings across all running subagents".into(),
            intent: "Eliminate 429 RateLimitExceeded interruptions".into(),
            invariants: vec!["Subagent dispatch paused before upstream rate limit exceeded".into()],
            required_evidence: vec!["rate_governor_audit".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 54,
            code: "SAS-054".into(),
            name: "Topological Dependency Sched".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Calculates topological sort of subagent task graph and schedules ready nodes in parallel batches".into(),
            intent: "Maximize parallel execution while respecting causal dependencies".into(),
            invariants: vec!["No node executes before all incoming dependencies resolve".into()],
            required_evidence: vec!["topological_schedule_plan".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 55,
            code: "SAS-055".into(),
            name: "Continuation Token Bind".into(),
            archetype: StrategyArchetype::ConcurrencyWorkflowsAndGraphs,
            description: "Cryptographically binds multi-turn continuation tokens to the exact task and session identifiers".into(),
            intent: "Prevent cross-task token injection attacks".into(),
            invariants: vec!["Continuation token valid only for matching task_id and state_hash".into()],
            required_evidence: vec!["token_signature_verification".into()],
            applicable_tiers: vec!["Conductor".into()],
        });

        // --- Archetype 6: Verification, Attestation & Receipts (56-66) ---
        list.push(SubagentStrategy {
            id: 56,
            code: "SAS-056".into(),
            name: "Mechanical Over Model Arbiter".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Prioritizes compiler, linter, and test results over model claims; code compiles or it didn't happen".into(),
            intent: "Eliminate hallucinated claims of completion".into(),
            invariants: vec!["Mechanical verifier always beats model agreement".into()],
            required_evidence: vec!["compiler_exit_code_zero".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 57,
            code: "SAS-057".into(),
            name: "Property-Based Falsifier".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Runs randomized proptests across subagent output to falsify invariant claims before acceptance".into(),
            intent: "Expose edge-case defects that unit tests miss".into(),
            invariants: vec!["State machine invariants must hold across 1,000 randomized cases".into()],
            required_evidence: vec!["proptest_falsification_report".into()],
            applicable_tiers: vec!["B".into(), "R".into()],
        });
        list.push(SubagentStrategy {
            id: 58,
            code: "SAS-058".into(),
            name: "Anti-State Dominator".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Enforces that a single structural contradiction (AntiRelation) overrides any number of passing checks".into(),
            intent: "Never average away a critical safety violation".into(),
            invariants: vec!["Anti invariant presence results in NON-CONFORMANT status".into()],
            required_evidence: vec!["anti_relation_dominance_proof".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 59,
            code: "SAS-059".into(),
            name: "Cross-Family Two-Model Agreement".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Requires concordant verdicts from two separate model families when mechanical verification is unavailable".into(),
            intent: "Provide bounded assurance for semantic/natural-language assertions".into(),
            invariants: vec!["Agreement treated as scanned, never as validated".into()],
            required_evidence: vec!["dual_model_consensus_signatures".into()],
            applicable_tiers: vec!["Peer".into()],
        });
        list.push(SubagentStrategy {
            id: 60,
            code: "SAS-060".into(),
            name: "TOCTOU Source Commitment".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Hashes source tree before and after subagent run to prevent Time-of-Check-to-Time-of-Use race mutations".into(),
            intent: "Detect and reject unrecorded file modifications".into(),
            invariants: vec!["Pre-execution tree hash + recorded diff equals post-execution tree hash".into()],
            required_evidence: vec!["source_tree_merkle_digest".into()],
            applicable_tiers: vec!["Conductor".into(), "B".into()],
        });
        list.push(SubagentStrategy {
            id: 61,
            code: "SAS-061".into(),
            name: "Mutation Lineage Ledger".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Records state changes as M = <S0, Trigger, Authority, Transformation, S1, Evidence, Time> in append-only log".into(),
            intent: "Enable forensic time-machine reconstruction and reversibility".into(),
            invariants: vec!["State history is append-only and cannot be overwritten".into()],
            required_evidence: vec!["mutation_ledger_receipt".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 62,
            code: "SAS-062".into(),
            name: "DSSE Envelope Attestor".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description:
                "Signs subagent execution receipts with Ed25519 DSSE envelopes for non-repudiation"
                    .into(),
            intent: "Provide tamper-evident cryptographic proof of subagent execution".into(),
            invariants: vec!["Receipt signature must verify against subagent public key".into()],
            required_evidence: vec!["dsse_signed_envelope".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 63,
            code: "SAS-063".into(),
            name: "In-Toto Statement Producer".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Generates in-toto v1.0 software supply chain attestations linking subagent inputs to output artifacts".into(),
            intent: "Satisfy SLSA Build L3 provenance requirements".into(),
            invariants: vec!["Attestation must cite exact input digests and output digests".into()],
            required_evidence: vec!["in_toto_statement_json".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 64,
            code: "SAS-064".into(),
            name: "Conformance Vector Transition".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Evaluates transition contract delta(Pe, S0, X, C) -> <d, O, S1, E, R> against expected resulting state".into(),
            intent: "Verify formal state transition contracts".into(),
            invariants: vec!["Resulting state S1 must strictly match required disposition d".into()],
            required_evidence: vec!["conformance_vector_receipt".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 65,
            code: "SAS-065".into(),
            name: "Derogation Ledger".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description:
                "Binds accepted risk to failing requirement without rewriting FAIL to PASS".into(),
            intent: "Preserve objective truth while documenting authorized risk acceptance".into(),
            invariants: vec!["Derogation does not erase historical failure vector".into()],
            required_evidence: vec!["signed_derogation_certificate".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 66,
            code: "SAS-066".into(),
            name: "Flight Recorder Proof".into(),
            archetype: StrategyArchetype::VerificationAttestationAndReceipts,
            description: "Maintains tamper-evident execution trace of digests, authority tokens, and decisions".into(),
            intent: "Enable post-incident forensic replay without leaking raw private thoughts".into(),
            invariants: vec!["Flight recorder events signed and chronologically chained".into()],
            required_evidence: vec!["flight_recorder_block_hash".into()],
            applicable_tiers: vec!["Conductor".into()],
        });

        // --- Archetype 7: Day-2 Operability & Resilience (67-77) ---
        list.push(SubagentStrategy {
            id: 67,
            code: "SAS-067".into(),
            name: "Canonical Control Loop Reconciler".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Runs OBSERVE -> DETECT -> DIAGNOSE -> DEGRADE -> CONTAIN -> RECOVER -> VERIFY -> RECONCILE loop".into(),
            intent: "Drive subagent system state continuously toward desired baseline".into(),
            invariants: vec!["Reconciliation must be idempotent, bounded, and observable".into()],
            required_evidence: vec!["reconciliation_loop_telemetry".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 68,
            code: "SAS-068".into(),
            name: "Degraded Mode Contract".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Switches agent to explicit read-only or local-only mode upon upstream network or auth failure".into(),
            intent: "Maintain availability without silently violating security or integrity".into(),
            invariants: vec!["Degraded mode contract declares prohibited capabilities explicitly".into()],
            required_evidence: vec!["degraded_mode_contract_manifest".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 69,
            code: "SAS-069".into(),
            name: "Jittered Backoff Retrier".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Executes bounded retries with full jitter and exponential backoff under strict retry budget".into(),
            intent: "Avoid thundering herd collapse against remote model endpoints".into(),
            invariants: vec!["Max retries = 2; budget bounded by time and count".into()],
            required_evidence: vec!["retry_budget_audit".into()],
            applicable_tiers: vec!["B".into()],
        });
        list.push(SubagentStrategy {
            id: 70,
            code: "SAS-070".into(),
            name: "Safe-Hold Freeze".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Freezes all mutating side effects upon unexpected anomaly, awaiting human instruction".into(),
            intent: "Halt automated degradation before cascade occurs".into(),
            invariants: vec!["Zero side effects permitted while in SafeHold mode".into()],
            required_evidence: vec!["safe_hold_activation_receipt".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 71,
            code: "SAS-071".into(),
            name: "Anti-Entropic State Repair".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Proactively repairs drifted vector states and reconciles ghost files across workcells".into(),
            intent: "Eliminate state drift and decoherence over long-running sessions".into(),
            invariants: vec!["Drift repair action strictly bounded to delta convergence".into()],
            required_evidence: vec!["state_convergence_proof".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 72,
            code: "SAS-072".into(),
            name: "Time-Machine Rollback".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Rolls back agent state to last verified checkpoint upon unrecoverable subagent failure".into(),
            intent: "Guarantee transactional recovery of workspace and state".into(),
            invariants: vec!["Rollback target must possess verified attestation receipt".into()],
            required_evidence: vec!["rollback_completion_receipt".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 73,
            code: "SAS-073".into(),
            name: "Checkpoint Resume".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Resumes multi-hour workflows from durable disk checkpoints rather than restarting from zero".into(),
            intent: "Provide crash tolerance and seamless task resumption".into(),
            invariants: vec!["Checkpoint includes state vector, flight recorder, and worktree sha".into()],
            required_evidence: vec!["checkpoint_integrity_check".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 74,
            code: "SAS-074".into(),
            name: "Drift Detector".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Continuously compares observed state with authoritative baseline profile to flag decoherence".into(),
            intent: "Spot unauthorized or unexpected environmental shifts".into(),
            invariants: vec!["Flag decoherence when observed hash != baseline hash".into()],
            required_evidence: vec!["drift_detection_report".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 75,
            code: "SAS-075".into(),
            name: "Deep Diagnostic Doctor".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Exposes doctor/inspect/explain/trace/verify suite answering What, Where, Why, Under Whose Authority".into(),
            intent: "Provide operators deep causal observability instead of raw log dumps".into(),
            invariants: vec!["Doctor checks must run without modifying target system".into()],
            required_evidence: vec!["doctor_health_report".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 76,
            code: "SAS-076".into(),
            name: "Live Telemetry Prober".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Probes agent latency, memory footprint, token rate, and connection health in real time".into(),
            intent: "Detect resource leaks and performance degradation before failure".into(),
            invariants: vec!["Prober overhead < 1% of total agent CPU consumption".into()],
            required_evidence: vec!["telemetry_probe_sample".into()],
            applicable_tiers: vec!["Conductor".into()],
        });
        list.push(SubagentStrategy {
            id: 77,
            code: "SAS-077".into(),
            name: "Sovereign Air-Gap Resolver".into(),
            archetype: StrategyArchetype::Day2OperabilityAndResilience,
            description: "Enforces offline dependency resolution, local model fallbacks, and air-gapped evidence packaging".into(),
            intent: "Guarantee agent execution capability in disconnected/sovereign environments".into(),
            invariants: vec!["Zero unproxied internet calls permitted in air-gap mode".into()],
            required_evidence: vec!["airgap_conformance_certificate".into()],
            applicable_tiers: vec!["Conductor".into(), "B".into()],
        });

        list
    }

    /// Find strategy by numeric ID (1-77)
    pub fn get_by_id(id: u32) -> Option<SubagentStrategy> {
        Self::all().into_iter().find(|s| s.id == id)
    }

    /// Find strategy by code (e.g. "SAS-001")
    pub fn get_by_code(code: &str) -> Option<SubagentStrategy> {
        Self::all()
            .into_iter()
            .find(|s| s.code.eq_ignore_ascii_case(code))
    }

    /// Filter by archetype
    pub fn get_by_archetype(archetype: StrategyArchetype) -> Vec<SubagentStrategy> {
        Self::all()
            .into_iter()
            .filter(|s| s.archetype == archetype)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_77_strategies_present_and_unique() {
        let all = StrategyRegistry::all();
        assert_eq!(all.len(), 77, "Must contain exactly 77 subagent strategies");

        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_codes = std::collections::HashSet::new();

        for s in all {
            assert!(s.id >= 1 && s.id <= 77);
            assert!(seen_ids.insert(s.id), "Duplicate ID: {}", s.id);
            assert!(
                seen_codes.insert(s.code.clone()),
                "Duplicate Code: {}",
                s.code
            );
            assert!(!s.name.is_empty());
            assert!(!s.description.is_empty());
            assert!(!s.invariants.is_empty());
            assert!(!s.required_evidence.is_empty());
        }
    }
}
