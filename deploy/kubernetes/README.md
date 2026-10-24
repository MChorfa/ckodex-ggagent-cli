# In-Cluster Kubernetes Deployment & Governed Agentic Platform

This directory provides the production-grade, zero-trust Kubernetes manifests for deploying `ckodex-ggagent-cli` (`ggagent`) as an in-cluster autonomous agent platform.

---

## 1. Architectural Roles in Kubernetes

When running in Kubernetes, `ggagent` provides the governed execution kernel and communication substrate for autonomous AI agents across three distinct operational topologies:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             KUBERNETES CLUSTER                                   │
│                                                                                  │
│  [Pattern 1: Centralized A2A & ARD Gateway]                                     │
│  Namespace: agent-system                                                        │
│  Service: ggagent.agent-system.svc.cluster.local:8080                            │
│  ┌─────────────────────────┐         ┌──────────────────────────────────────┐   │
│  │ ggagent Gateway Pod     │ <─────> │ Client Pods / Microservices          │   │
│  │ - A2A JSON-RPC 2.0      │         │ - Discovery: /.well-known/agent.json │   │
│  │ - ARD Catalog           │         │ - Delegation via A2A protocol        │   │
│  │ - Flight Recorder       │         └──────────────────────────────────────┘   │
│  └─────────────────────────┘                                                     │
│                                                                                  │
│  [Pattern 2: Governed Sidecar Proxy]                                            │
│  Namespace: app-workloads                                                       │
│  ┌────────────────────────────────────────────────────────┐                      │
│  │ Application Pod                                        │                      │
│  │  ┌───────────────────────┐   localhost:8080   ┌────────┴───────────────────┐  │
│  │  │ LLM Runner / Worker   │ ─────────────────> │ ggagent Sidecar Container  │  │
│  │  │ (Python/Node/Go/Lang) │                    │ - AtomicEffectGuard        │  │
│  │  └───────────────────────┘                    │ - Confused Deputy Defense  │  │
│  │                                               │ - IMDS Egress Block        │  │
│  │                                               │ - Ed25519 DSSE Attestation │  │
│  └───────────────────────────────────────────────┴────────────────────────────┘  │
│                                                                                  │
│  [Pattern 3: Ephemeral 4-Agent Mesh Workflow Job]                                │
│  Namespace: agent-system                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │ Kubernetes Job: ggagent agent mesh run                                   │    │
│  │ Gemini (Planner) -> Codex (Patcher) -> Claude (Reviewer) -> Cohere (Auditor)   │
│  │ Monotonic Budget Attenuation & Generation Fencing [N -> N+1]              │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. In-Cluster Operational Patterns

### Pattern 1: Centralized Gateway Service (`deploy/kubernetes/`)
Deploys `ggagent` as a resilient, 2-replica `Deployment` fronted by a `ClusterIP` Service.
- **Service DNS:** `http://ggagent.agent-system.svc.cluster.local:8080`
- **Agent Discovery:** `GET http://ggagent.agent-system.svc.cluster.local:8080/.well-known/agent-card.json`
- **Resource Discovery:** `GET http://ggagent.agent-system.svc.cluster.local:8080/.well-known/ard.json`
- **A2A Execution:** `POST http://ggagent.agent-system.svc.cluster.local:8080/api/v1/a2a`
- **Streaming Events:** `GET http://ggagent.agent-system.svc.cluster.local:8080/api/v1/a2a/events`

### Pattern 2: Governed Sidecar Proxy (`sidecar-pattern.yaml`)
Co-locates `ggagent` inside the same Pod as an AI execution container (e.g. LangChain, AutoGen, CrewAI, or raw worker script).
- Intercepts mutating tool calls before they hit cluster APIs, databases, or cloud endpoints.
- Verifies use-time material binding (`AtomicEffectGuard`) to defeat loopjacking attacks.
- Enforces strict egress boundaries (blocks AWS/GCP/Azure IMDS `169.254.169.254/32` to prevent credential theft).

### Pattern 3: Ephemeral Workflow Job (`mesh-job-pattern.yaml`)
Runs a single-shot, audit-gated multi-model mesh task as a Kubernetes `Job` or `CronJob`.
- Automatically terminates after generation of signed Ed25519 DSSE receipts and CycloneDX 1.7 AI-BOMs.

---

## 3. Strict Security & Governance Controls

| Invariant / Defense | Implementation in Kubernetes |
| :--- | :--- |
| **Non-Root & Distroless** | Runs as unprivileged `UID:GID 65534:65534` (`distroless/cc-debian12:nonroot`). |
| **Immutable Filesystem** | `readOnlyRootFilesystem: true`. Temporary writes restricted to memory-backed `emptyDir`. |
| **Capability Dropping** | `capabilities: drop: ["ALL"]` and `allowPrivilegeEscalation: false`. |
| **Least-Authority RBAC** | ServiceAccount `ggagent-sa` has NO cluster-admin standing. Scoped exclusively to namespace events and leases. |
| **IMDS Exfiltration Defeat** | `NetworkPolicy` explicitly fences `169.254.169.254/32` (AWS/GCP/Azure metadata service). |
| **Confused Deputy Defense** | A2A role validation strictly rejects remote peer agents masquerading as human approvers (CVE-2026-18236). |
| **Day-2 Health Probes** | `livenessProbe` and `readinessProbe` bind to `/healthz` and in-pod `ggagent doctor`. |

---

## 4. Quickstart: Installing into Kubernetes

### Prerequisites
- Kubernetes v1.28+ cluster
- `kubectl` configured with cluster access

### Step 1: Deploy with Kustomize
```bash
# Preview rendered resources
kubectl kustomize deploy/kubernetes

# Apply all resources
kubectl apply -k deploy/kubernetes
```

### Step 2: Verify Rollout
```bash
# Verify pods are running in agent-system namespace
kubectl get pods -n agent-system -l app.kubernetes.io/name=ggagent

# Verify Service endpoints
kubectl get svc -n agent-system ggagent
```

### Step 3: Run In-Cluster Day-2 Diagnostics
```bash
# Execute deep doctor diagnostics inside the running pod (20/20 subsystems)
kubectl exec -n agent-system deploy/ggagent-gateway -c ggagent -- /usr/local/bin/ggagent doctor
```

### Step 4: Interact with the Agent from Within the Cluster
From any Pod in the cluster:
```bash
# 1. Discover Agent Card
curl -s http://ggagent.agent-system.svc.cluster.local:8080/.well-known/agent-card.json

# 2. Discover Cataloged Resources (ARD)
curl -s http://ggagent.agent-system.svc.cluster.local:8080/.well-known/ard.json

# 3. Submit an A2A Task via JSON-RPC
curl -s -X POST http://ggagent.agent-system.svc.cluster.local:8080/api/v1/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "a2a.submit_task",
    "params": {
      "task_id": "k8s-task-001",
      "instruction": "Audit namespace workloads for security compliance",
      "authority": {
        "root_fabric": "thales-trt-canada",
        "tenant": "cluster-default",
        "namespace": "agent-system",
        "role": "InClusterWorker"
      }
    },
    "id": 1
  }'
```
