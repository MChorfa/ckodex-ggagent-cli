# ckodex-ggagent-cli (`ggagent`)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/architecture-Clean%20Condamian-success.svg)](ARCHITECTURE.md)
[![A2A Protocol](https://img.shields.io/badge/protocol-Google%20A2A%20v1.0-brightgreen.svg)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
[![ARD Discovery](https://img.shields.io/badge/discovery-ARD%20v1.0-blueviolet.svg)](https://agenticresourcediscovery.org/)
[![Subagents](https://img.shields.io/badge/strategies-77%20Canonical%20Subagents-orange.svg)](SUBAGENTS-77-CATALOG.md)

**Cleanroom High-Assurance Re-implementation of Google Agents CLI & A2A Runtime.**

Synthesizes the **CKODEX Four-Layer Hexagonal Architecture**, **Clean Condamian Convention**, **Google Agent-to-Agent (A2A) Protocol**, **Agentic Resource Discovery (ARD)**, and the **77 Canonical Subagent Strategies** into an ultra-fast, zero-dependency, static Rust CLI and runtime engine.

---

## ⚡ Key Capabilities

- **Pure Semantic Kernel (`ggagent-kernel`)**: Pure domain model, zero I/O, vector state $S(e,t) = \langle P, V, A, C, E, L, \tau \rangle$, transition contracts, and the complete 77 Subagent Strategies catalog.
- **Google A2A Protocol Standard**: Native support for Agent Cards (`/.well-known/agent-card.json`), A2A JSON-RPC 2.0, SSE streaming events, and the formal task lifecycle state machine.
- **Confused Deputy Defense (CVE-2026-18236 / ADK Issue #6461)**: Explicit typed peer roles (`A2ARole::HumanUser` vs `A2ARole::RemoteAgent`). Untrusted peer turns are structurally barred from approving mutating side effects.
- **Loopjacking Defense (arXiv:2609.21081)**: `AtomicEffectGuard` enforces cryptographic use-time material binding: $H(\text{action} \mathbin{\Vert} \text{target} \mathbin{\Vert} \text{params}) \equiv \text{grant.effect\_digest}$.
- **Agentic Resource Discovery (ARD)**: Full compliance with [agenticresourcediscovery.org](https://agenticresourcediscovery.org/) (`/.well-known/ard.json`), enabling decentralized discovery of tools, MCP servers, and skills.
- **Agnostic Cross-Harness Interoperability**: Adapters and dispatchers for Google Antigravity (Gemini), Claude Code, OpenAI Codex, OpenCode, and SAM Agent Mesh.
- **Interactive Playground**: Web & TTY playground with live state vector visualizer, SSE streaming logs, and subagent dispatcher.
- **Cryptographic Evidence Fabric (`ggagent-evidence`)**: Content-addressed SHA-256 digests, Ed25519 DSSE signed receipts, in-toto v1.0 attestations, and append-only tamper-evident flight recorders.

---

## 🚀 Quick Start

### Build & Test
```bash
# Build the workspace
make build

# Run unit tests and property checks
make test

# Verify zero-warning quality gate
make clippy

# Run Day-2 health check
make doctor
```

### Launch Interactive Playground & A2A/ARD Endpoints
```bash
./bin/ggagent playground --port 8080
```
Open [http://127.0.0.1:8080/playground](http://127.0.0.1:8080/playground) in your browser:
- **A2A Agent Card:** `GET http://127.0.0.1:8080/.well-known/agent-card.json`
- **ARD Document:** `GET http://127.0.0.1:8080/.well-known/ard.json`
- **A2A JSON-RPC 2.0:** `POST http://127.0.0.1:8080/api/v1/a2a`
- **A2A SSE Stream:** `GET http://127.0.0.1:8080/api/v1/a2a/events`

---

## 📖 CLI Commands Overview

```text
Commands:
  create      Scaffold a new high-assurance Google ADK / A2A agent project
  playground  Launch the interactive Web & Terminal Playground with live A2A/ARD endpoints
  eval        Evaluate agent conformance vectors and conformal risk calibration
  ard         Agentic Resource Discovery (ARD) protocol operations
  a2a         Google Agent-to-Agent (A2A) protocol operations
  subagents   Explore and execute the 77 Canonical Subagent Strategies
  harness     Cross-Harness interoperability bridge (Antigravity, Claude Code, Codex, OpenCode, SAM Mesh)
  forensic    Export or inspect tamper-evident post-mortem forensic evidence bundles
  doctor      Deep Day-2 diagnostic suite (Doctor verifying 18 core systems)
  explain     Explain causal decision trace and authority path for a task
  verify      Verify cryptographic execution receipt or DSSE envelope
```

### 1. Explore the 77 Subagent Strategies
```bash
# List all 77 strategies
./bin/ggagent subagents list

# Filter by archetype
./bin/ggagent subagents list --archetype ContextIsolationAndCompression

# Deep inspect strategy SAS-038 (Confused Deputy Barrier)
./bin/ggagent subagents inspect SAS-038

# Test execute strategy SAS-037 (AtomicEffectGuard Binding)
./bin/ggagent subagents run SAS-037
```

### 2. Scaffold a New Agent Project
```bash
./bin/ggagent create my-adk-agent --template adk-go
```

### 3. Cross-Harness Dispatch Bridge
```bash
# List harness profiles
./bin/ggagent harness list

# Verify adapter conformance across all 6 harnesses
./bin/ggagent harness verify

# Format cross-family dispatch
./bin/ggagent harness dispatch claude "Review state transition conformance"
./bin/ggagent harness dispatch codex "Audit AtomicEffectGuard use-time binding"
```

### 4. Forensic Evidence Bundles
```bash
# Export post-mortem forensic bundle
./bin/ggagent forensic export --task task-101 --output /tmp/bundle.json

# Inspect and verify root manifest SHA-256 digest
./bin/ggagent forensic inspect /tmp/bundle.json
```

### 5. Evaluate Conformance Vectors
```bash
./bin/ggagent eval run --conformal-alpha 0.05
```

---

## 🏛️ Architecture & Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Hexagonal 4-layer architecture, Clean Condamian invariants
- [SUBAGENTS-77-CATALOG.md](SUBAGENTS-77-CATALOG.md) - The complete catalog of the 77 canonical subagent strategies
- [A2A-ARD-SPEC.md](A2A-ARD-SPEC.md) - Google A2A protocol & ARD standard integration specifications
- [SECURITY.md](SECURITY.md) - Security architecture, Confused Deputy & Loopjacking defenses
- [IMPLEMENTATION-DOSSIER.md](IMPLEMENTATION-DOSSIER.md) - Verification evidence and quality gates
- [proto/a2a/v1/a2a.proto](proto/a2a/v1/a2a.proto) - Protobuf v3 contract for A2A services

---

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
