# ADR 0004: Formal Taxonomy of the 77 Canonical Subagent Strategies

**Status:** Accepted  
**Deciders:** CKODEX Architecture & AI Operations Team  
**Date:** 2026-10-22  

---

## Context
Multi-agent systems suffer from common failure modes: "context rot" (token saturation and attention drift), planning groupthink, unchecked retry loops, and unverified completion claims. Ad-hoc prompts fail to maintain invariants across multi-tier agent workflows.

## Decision
1. Establish a formal taxonomy of **77 Canonical Subagent Strategies** organized into 7 core archetypes:
   - Archetype 1: Triage & Decomposition (SAS-001 to SAS-011)
   - Archetype 2: Context Isolation & Compression (SAS-012 to SAS-022)
   - Archetype 3: Model Routing & Optimization (SAS-023 to SAS-033)
   - Archetype 4: Authority Leases & Fencing (SAS-034 to SAS-044)
   - Archetype 5: Concurrency, Workflows & Graphs (SAS-045 to SAS-055)
   - Archetype 6: Verification, Attestation & Receipts (SAS-056 to SAS-066)
   - Archetype 7: Day-2 Operability & Resilience (SAS-067 to SAS-077)
2. Implement the Strategy Registry in `ggagent-kernel::strategies::StrategyRegistry` with explicit typed contracts, invariant requirements, and evidence obligations.
3. Expose strategy exploration and execution directly in the CLI (`ggagent subagents list|inspect|run`).

## Consequences
- **Positive:** Every delegation is a typed brief with measurable acceptance criteria.
- **Positive:** Eliminates context rot through spoke-window isolation (SAS-012) and context-rot shielding (SAS-013).
