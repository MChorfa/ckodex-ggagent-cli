# Security Architecture & Assurance Profile

**Status:** High Assurance  
**Assurance Level:** ASSURED  
**Standard:** NIST SP 800-53 / SLSA Build Level 3 / CKODEX Constitution  

---

## 1. Confused Deputy Defense (CVE-2026-18236 / ADK Issue #6461)

### Problem Description
In standard multi-agent communication networks, turns relayed from remote peer agents are frequently mapped to `role: "user"`. Downstream tools and execution runtime interpret any message with `role: "user"` as human operator authority, enabling an untrusted remote peer agent to approve destructive operations (e.g. `rm -rf /`, `kubectl delete namespace production`, `git push --force`).

### Architecture Defense
`ggagent` enforces strict algebraic role segregation in the pure domain model:
```rust
pub enum A2ARole {
    HumanUser,    // Verified human principal
    RemoteAgent,  // Remote peer agent turn (STRICTLY PROHIBITED from approving mutating tasks)
    Tool,         // Tool execution output
    System,       // System messages
}
```

Any attempt by a `RemoteAgent` to supply a `confirmed_call_id` triggers an immediate `ValidationError::ConfusedDeputyViolation` and transitions the task into `TASK_STATE_FAILED`.

---

## 2. Loopjacking Defense (arXiv:2609.21081)

### Problem Description
When human approval is requested, naive systems bind authorization solely to a transient `taskId` or `callId`. An attacker or compromised intermediate model can alter the payload between human approval and execution (e.g., swapping a safe `cat /etc/hosts` for an unapproved `cat /etc/shadow`).

### Architecture Defense: AtomicEffectGuard
`ggagent` implements use-time cryptographic material binding via `AtomicEffectGuard`:

$$\text{Digest} = \text{SHA-256}(\text{action} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{target} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{canonical\_json\_params})$$

Before the execution lease is consumed, the runtime computes the material digest of the operation about to execute. If it does not match the granted `effect_digest`, execution is rejected with `ValidationError::LoopjackingViolation`.

---

## 3. Vector State Anti-Invariant Dominance

`ggagent` uses 7-dimensional vector states:

$$S(e,t) = \langle P, V, A, C, E, L, \tau \rangle$$

A single mandatory structural contradiction (`AntiRelation::Attacks`, `AntiRelation::Invalidates`, `AntiRelation::Contradicts`) immediately dominates all positive scores, forcing the state into `NON-CONFORMANT` and halting execution into `SafeHold` or `Quarantine`.

---

## 4. Cryptographic Evidence & DSSE Attestation

All consequential executions emit:
1. `ExecutionReceipt`: Carries task ID, actor ID, authority ID, input digest, output digest, effect digest, duration, exit code, and Ed25519 signature.
2. `DsseEnvelope`: Wraps in-toto v1.0 software supply chain attestations (`https://in-toto.io/Statement/v1`) with predicate type `https://ckodex.io/attestation/execution-receipt/v1`.
3. `FlightRecorder`: Append-only, privacy-scrubbed, hash-chained ledger verifying chronological execution integrity.
