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

---

## 5. Generation Fencing & Split-Brain Execution Defense (Chapters 24–26)

### Problem Description
In distributed or sandboxed execution, network partitions, failovers, and agent handoffs can result in split-brain execution where an older, delayed worker emerges to commit unauthorized or stale side effects.

### Architecture Defense: AtomicEffectBroker
Every `CapabilityLease` embeds a monotonic `generation: u64` and cryptographic `fencing_token`.
When authority migrates, the broker increments `generation N ➔ N + 1`. The `AtomicEffectBroker` rejects any mutation attempt where `received_generation < current_generation` with `EffectDisposition::Fenced`. Idempotency keys prevent duplicate side-effect execution across network retries.

---

## 6. Workspace Staging Containment & TOCTOU Defeat (Chapters 21, 28, 29)

### Problem Description
Sandboxed workloads produce deliverables within a mutable directory. Attackers may attempt directory traversal via `../`, external symlinks (`workspace/link -> /etc/shadow`), or modify files concurrently while an out-of-band verifier is evaluating them (check-to-use TOCTOU race).

### Architecture Defense: WorkspaceStagingGuard
`WorkspaceStagingGuard` canonicalizes candidate paths against the workspace root, detects external symlink escapes, and captures immutable in-memory snapshots (`SealedCandidate`) with SHA-256 digests. Subsequent mutations to workspace files have zero effect on the verified artifact.

---

## 7. Four Formal Failure Modes (Chapter 30)

Failure is explicitly taxonomized into four non-interchangeable failure modes:
1. `ContainmentEscape`: Boundary escape attempts (symlink traversal, path escalation, syscall violations).
2. `AuthorizedHarm`: Permitted by credentials/lease, but produced destructive side effects.
3. `VerificationFailure`: Candidate artifact or test assertion failed objective verification criteria.
4. `GovernanceFailure`: Stale generation fencing, lease expiration, or confused deputy approval.

---

## 8. Partitioned Handoff Protocol & Budget Fencing (Chapters 3 & 26)

### Problem Description
Task migration across execution environments, failovers, or network partitions may lead to credential leaking, stale node takeovers, or budget inflation (e.g. an agent resetting its step count upon migration).

### Architecture Defense: HandoffValidator
Handoffs require a cryptographic `HandoffManifest` linking `source_generation` to `target_generation` with a SHA-256 checkpoint digest over the state vector. `HandoffValidator` strictly enforces generation monotonicity and budget non-inflation (remaining budget $\le$ maximum permitted budget).

---

## 9. Ephemeral Secret Scrubbing & Exfiltration Defense (Chapter 15)

### Problem Description
Static API keys or tokens embedded in tool calls, traces, or receipts present a persistent data leakage vector.

### Architecture Defense: SecretGuard
`SecretGuard` intercepts payloads and receipts, actively detecting and rejecting raw private keys or cloud credential tokens, and scrubbing sensitive authorization patterns (`[REDACTED_SECRET]`) prior to flight recording and receipt issuance.

---

## 10. Tamper-Evident Forensic Post-Mortem Bundles (Chapters 18 & 30)

Forensic investigations require non-repudiable state reconstruction. `ForensicBundle` captures:
- 7D Vector State snapshot $S(e,t)$
- 4D Coordinated Lifecycle state
- Cryptographic hash-chained flight recorder events across all 4 truth channels
- Signed Ed25519 execution receipts
- Objective failure classification
- Top-level Root Manifest SHA-256 digest verifiable offline.
