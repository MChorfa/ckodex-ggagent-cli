# ADR 0005: AtomicEffectGuard & Loopjacking Defense

**Status:** Accepted  
**Deciders:** CKODEX Security Engineering Team  
**Date:** 2026-10-22  

---

## Context
In agent workflows with Human-in-the-Loop (HITL) approval gates, authorization is often bound only to a `taskId` or `callId`. As identified in research (Loopjacking, arXiv:2609.21081), prompt injection or an intermediate compromised subagent can swap the approved operation before execution occurs under the same task identifier.

## Decision
1. Implement `AtomicEffectGuard` in `ggagent-kernel::lease`:
   $$\text{EffectDigest} = \text{SHA-256}(\text{action} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{target} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{canonical\_json\_params})$$
2. When human approval is granted, the approved effect digest is immutably sealed in the task.
3. At use-time immediately before execution, `SecurityGuards::verify_effect_guard` recomputes the digest over the actual arguments. If a single byte differs, execution is aborted with `ValidationError::LoopjackingViolation`.

## Consequences
- **Positive:** Complete cryptographic protection against operation-swapping and continuation hijacking.
- **Positive:** Works transparently across local tool execution and remote A2A calls.
