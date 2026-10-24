# In-Cluster Kubernetes Governed Agentic Platform

This directory provides the production-grade, zero-trust Kubernetes manifests for deploying `ckodex-ggagent-cli` (`ggagent`) as an in-cluster governed autonomous agent platform in compliance with **ADR 0006** and the **CKODEX Constitution**.

---

## 1. Architectural Fabrics in Kubernetes

Rather than treating Kubernetes manifests as self-certifying security boundaries, `ggagent` strictly separates **Mediation**, **Authority**, **Sandboxing**, and **Independent Verification** into discrete fabrics:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  KUBERNETES CLUSTER                                    │
│                                                                                        │
│  [Identity & Authority Fabric]                                                         │
│  - Projected ServiceAccount Tokens (Audience-bound, 1h expiry) / SPIFFE SVIDs           │
│  - CapabilityLease with Monotonic Generation N & Budget Attenuation                   │
│  - Self-asserted caller identity/roles strictly rejected (CVE-2026-18236)              │
│                                                                                        │
│  [Ingress & Mediation: ggagent Gateway Service]                                        │
│  Namespace: agent-system | Service: ggagent.agent-system.svc.cluster.local:8080       │
│  - Google A2A 1.0 JSON-RPC (SendMessage, SendStreamingMessage, GetTask)                │
│  - ARD Catalog (/.well-known/ard.json) & Agent Card (/.well-known/agent-card.json)      │
│  - Flight Recorder & DSSE Evidence Ingestion                                          │
│                                                                                        │
│  [Untrusted Code Sandboxing: CRI Isolation]                                            │
│  - RuntimeClass: gVisor (runsc) / Kata Containers (MicroVMs)                           │
│  - Landlock LSM & Read-only rootfs; ephemeral memory-backed /tmp                       │
│  - Staged candidates sealed into immutable SHA-256 snapshots (defeats TOCTOU)         │
│                                                                                        │
│  [Network Egress Fabric: Kernel eBPF Enforcement]                                      │
│  - CiliumClusterwideNetworkPolicy explicit egressDeny to cloud IMDS                    │
│    (169.254.169.254/32 and IPv6 fd00:ec2::254/128) - overrides additive allow-rules   │
│                                                                                        │
│  [Use-Time Authorization: AtomicEffectBroker]                                          │
│  - AtomicEffectGuard: binds (task_id, action, sha256(canonical_args), generation)     │
│  - Generation fencing (N -> N+1) defeats dual-worker partition split-brain             │
│                                                                                        │
│  [Evidence Fabric: Independent Outer-Loop Verifier]                                    │
│  - Three-Loop Architecture: Executing worker CANNOT sign its own acceptance receipts   │
│  - Isolated Verifier Job mounts candidates read-only, tests invariants, and signs      │
│    Ed25519 DSSE attestation receipts                                                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. In-Cluster Operational Topologies

### Topology 1: Centralized Governed Gateway (`deployment.yaml` & `service.yaml`)
Deploys `ggagent` as a resilient 2-replica `Deployment` fronted by a `ClusterIP` Service:
- **Service DNS:** `http://ggagent.agent-system.svc.cluster.local:8080`
- **Agent Card:** `GET /.well-known/agent-card.json`
- **ARD Discovery:** `GET /.well-known/ard.json`
- **A2A Execution:** `POST /api/v1/a2a` (standard Google A2A 1.0 JSON-RPC)
- **Streaming Events:** `GET /api/v1/a2a/events` (SSE streaming)

### Topology 2: Ambient Mediator Sidecar (`sidecar-pattern.yaml`)
Co-locates `ggagent` inside the same Pod as an AI runtime (Python, Node.js, Go) as an **ambient mediator and telemetry proxy**.
> **Important:** In accordance with ADR 0006, the sidecar is an ambient adapter and mediator, NOT a security containment boundary for untrusted code execution.

### Topology 3: Sandboxed Worker Container (`sandboxed-worker-gvisor.yaml`)
For executing untrusted tools, shell commands, or generated code. Employs hardware-isolated CRI sandboxing (`runtimeClassName: gvisor` / `runsc`), memory-backed workspace mounts, and projected audience-bound tokens.

### Topology 4: Independent Outer-Loop Verifier (`independent-verifier-job.yaml`)
Enforces the **Three-Loop Separation of Responsibility**:
- Worker (Inner Loop) produces sealed candidates.
- Verifier (Outer Loop) runs in an isolated Job, validates split-conformal risk bounds, and produces the final cryptographic `ExecutionReceipt` signed with Ed25519.

---

## 3. Strict Security & Governance Controls

| Invariant / Defense | Implementation in Kubernetes |
| :--- | :--- |
| **Non-Root & Distroless** | Runs as unprivileged `UID:GID 65534:65534` (`distroless/cc-debian12:nonroot`). |
| **Immutable Filesystem** | `readOnlyRootFilesystem: true`. Temporary writes restricted to memory-backed `emptyDir`. |
| **Capability Dropping** | `capabilities: drop: ["ALL"]` and `allowPrivilegeEscalation: false`. |
| **Least-Authority RBAC** | ServiceAccount `ggagent-sa` has 0 cluster-admin, 0 secret read, 0 pod delete permissions. |
| **IMDS Exfiltration Defeat** | `CiliumClusterwideNetworkPolicy` with explicit eBPF socket-level `egressDeny`. |
| **Confused Deputy Defense** | Self-asserted caller roles rejected. `human_user` requires verified cryptographic proof tokens. |
| **Loopjacking Defense** | `AtomicEffectGuard` binds exact arguments at use time. |
| **Generation Fencing** | `AtomicEffectBroker` rejects stale generation requests during partition failover ($N \to N+1$). |
| **Day-2 Health Probes** | `livenessProbe` and `readinessProbe` bind to `/healthz` and in-pod `ggagent doctor`. |

---

## 4. Verification & Deployment Quickstart

### Step 1: Run Pre-Flight KinD Admission & RBAC Verification
Before deploying to production, execute the automated verification script against your cluster:
```bash
make kind-verify
# Or directly: ./scripts/kind-admission-verify.sh
```
This tests:
1. Pod Security Admission `restricted` namespace enforcement.
2. Server-side dry-run admission of all CRDs, policies, deployments, and jobs.
3. Least-authority RBAC audit (asserting 0 cluster-admin, 0 secret read, 0 pod delete).

### Step 2: Deploy with Kustomize
```bash
# Preview rendered resources
kubectl kustomize deploy/kubernetes

# Apply all resources to cluster
kubectl apply -k deploy/kubernetes
```

### Step 3: Run In-Cluster Day-2 Diagnostics
```bash
# Execute deep doctor diagnostics inside the running pod (20/20 subsystems)
kubectl exec -n agent-system deploy/ggagent-gateway -c ggagent -- /usr/local/bin/ggagent doctor
```

### Step 4: Interact with the Agent from Within the Cluster

From any workload or client Pod in the cluster:

#### 1. Discover Agent Card (A2A 1.0)
```bash
curl -s http://ggagent.agent-system.svc.cluster.local:8080/.well-known/agent-card.json
```

#### 2. Discover Resources (ARD 1.0)
```bash
curl -s http://ggagent.agent-system.svc.cluster.local:8080/.well-known/ard.json
```

#### 3. Send Task via Standard Google A2A 1.0 JSON-RPC
Pass the projected in-pod ServiceAccount token in the `Authorization` header:
```bash
TOKEN=$(cat /var/run/secrets/tokens/agent-token 2>/dev/null || cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -s -X POST http://ggagent.agent-system.svc.cluster.local:8080/api/v1/a2a \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "SendMessage",
    "params": {
      "message": {
        "message_id": "msg-001",
        "sender_id": "worker-client",
        "parts": [
          { "text": "Execute security audit of namespace workloads" }
        ],
        "timestamp": "2026-10-24T18:00:00Z"
      }
    },
    "id": 1
  }'
```

#### 4. Run Governed 8-Step Lifecycle Verification (M2)
```bash
# Run the full end-to-end governed lifecycle verification in-pod:
kubectl exec -n agent-system deploy/ggagent-gateway -c ggagent -- /usr/local/bin/ggagent agent lifecycle -F table
```
