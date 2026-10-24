# ADR 0006: In-Cluster Kubernetes Agentic Platform Assurance & Non-Bypassable Containment

**Status:** Accepted  
**Date:** 2026-10-24  
**Audience:** All Codex and Antigravity Agents, System Architects, Verifiers  
**Governance Level:** GAL 1 (Binding)

---

## 1. Context & Problem Statement

Packaging `ckodex-ggagent-cli` into distroless containers and rendering Kubernetes manifests (`Deployment`, `Service`, `NetworkPolicy`, `Sidecar`) demonstrated structural deployment syntax, but **failed to prove runtime enforcement of authority, non-bypassable containment, or independent verification**.

Specific critical architectural flaws were identified during formal architecture review:
1. **Self-Asserted Caller Identity:** HTTP JSON-RPC payloads allowed callers to self-declare their authority (`"role": "HumanUser"`, `"root_fabric": "..."`), making authorization purely client-claimed.
2. **Sidecar as False Containment:** Kubernetes Pod containers share network namespaces (`localhost`) and IPC. A sidecar cannot serve as an untrusted code containment boundary.
3. **Additive NetworkPolicy Limitations:** Standard Kubernetes `NetworkPolicy` allow-rules do not guarantee default-deny egress against cloud IMDS (`169.254.169.254/32`) in the presence of permissive cluster defaults or host-network workloads.
4. **A2A Protocol Divergence:** Custom RPC methods (`a2a.task.submit`) were mislabeled as standard Google A2A 1.0 instead of implementing standardized `SendMessage` / `SendStreamingMessage` interfaces.
5. **Self-Attestation Anti-Pattern:** Allowing an executing worker to sign its own acceptance receipts violates the Three-Loop Architecture and circularizes evidence.

---

## 2. Decision: The Governed In-Cluster Architecture

We formally separate **Mediation**, **Authority**, **Execution**, and **Verification** into discrete, non-bypassable fabrics:

```
Intent -> [Authority Fabric: SPIFFE / K8s TokenReview]
       -> [Orchestration Fabric: CapabilityLease & Monotonic Generation]
       -> [Execution Fabric: CRI Sandbox (gVisor / Kata) + Landlock LSM]
       -> [Network Fabric: Cilium eBPF Egress-Deny Policy]
       -> [Effect Broker: AtomicEffectGuard Use-Time Binding]
       -> [Evidence Fabric: Independent OuterLoop Verifier DSSE Receipt]
```

### 2.1 Identity & Authority Fabric
- **No Self-Declared Roles:** Identity is derived exclusively from **SPIFFE/SPIRE Workload SVIDs** or **Kubernetes Projected ServiceAccount Tokens** verified via `TokenReview`.
- **Capability Leases:** Operations require an unforgeable, ephemeral `CapabilityLease` issued by the Governance Loop, bound to monotonic generation $N$, permitted resource scopes, and maximum budget.

### 2.2 Execution & Sandboxing Fabric
- **Sidecar Demotion:** The sidecar pattern is formally demoted to an **ambient mediator and telemetry proxy**. It is prohibited from being marketed as a sandbox boundary.
- **Untrusted Code Execution:** Any untrusted tool, code generation, or shell execution MUST be isolated using **RuntimeClass: gVisor (`runsc`)** or **Kata Containers (MicroVMs)**.
- **Kernel-Level Filesystem Jailing:** Containers enforce **Landlock LSM**, binding write authority strictly to `/tmp` (memory-backed) and `/workspace`.

### 2.3 Network Egress Fabric (eBPF Fencing)
- Cluster-wide IMDS (`169.254.169.254/32` and IPv6 `fd00:ec2::254/128`) protection is enforced via **`CiliumClusterwideNetworkPolicy`** with explicit `egressDeny`, taking kernel-level precedence over any additive allow rules.

### 2.4 Use-Time Effect Broker & AtomicEffectGuard
- Mutating side effects require a cryptographically signed confirmation token from a verified human or governance principal:
  $$\text{Token} = \text{Sign}_{K_{\text{auth}}}\Big(H\big(\text{task\_id} \,\|\, \text{action} \,\|\, H(\text{canonical\_args}) \,\|\, \text{nonce} \,\|\, \text{generation}\big)\Big)$$
- If arguments change between approval and execution, the hash decoheres and the action is blocked.

### 2.5 Independent Evidence Fabric
- In accordance with the **Three-Loop Separation of Responsibility**, the **Inner Loop (worker)** cannot evaluate its own output or sign acceptance receipts.
- An independent **Outer Loop Verifier Pod** reviews sealed candidates in an isolated environment, runs regression suites, and publishes signed Ed25519 DSSE attestations.

---

## 3. Concrete Acceptance Gates (G0 through G7)

Promotion to production requires automated verification against the following executable gates:

| Gate | Title | Verification Criteria |
| :--- | :--- | :--- |
| **G0** | **Build Integrity** | Cosign image signature verification + SLSA Level 3 reproducible in-toto attestation. |
| **G1** | **K8s PSA Admission** | Pod Security Standards `restricted` admission + Gatekeeper validation. |
| **G2** | **Identity & Authority** | Rejection of unauthenticated or role-spoofed requests (HTTP 401/403). |
| **G3** | **Sandbox Containment** | Verified failure of `connect(169.254.169.254:80)` via Cilium eBPF socket drop. |
| **G4** | **Action Integrity** | Rejection of replayed, altered, or expired tokens via `AtomicEffectGuard`. |
| **G5** | **Protocol Interoperability** | 100% pass on official Google A2A 1.0 JSON-RPC conformance test suite. |
| **G6** | **Evidence Independence** | Outer loop isolation; worker cannot sign `GovernanceDisposition::Promote`. |
| **G7** | **Recovery & Resilience** | Generation fencing ($N \to N+1$) defeats dual-worker partition split-brain. |
