# CKODEX Architectural Signature & System Design

**System:** `ckodex-ggagent-cli`  
**Architecture:** Pure Hexagonal / CKODEX Four-Layer Architecture / Clean Condamian Convention  

---

## 🏛️ Hexagonal Four-Layer Architecture

```text
┌────────────────────────────────────────────────────────────┐
│                    Explicit Transport                      │
│ (A2A JSON-RPC 2.0, SSE Streaming, ARD Service, MCP Bridge) │
│                       crates/ggagent-transport             │
└─────────────────────────────┬──────────────────────────────┘
                              │ depends inward
┌─────────────────────────────▼──────────────────────────────┐
│                    Shared Validation                       │
│ (Agent Card, ARD Documents, Confused Deputy & EffectGuards)│
│                      crates/ggagent-validation             │
└─────────────────────────────┬──────────────────────────────┘
                              │ depends inward
┌─────────────────────────────▼──────────────────────────────┐
│                   Pure Semantic Kernel                     │
│ (Vector State, 77 Subagent Strategies, A2A/ARD Core, FSM)  │
│                       crates/ggagent-kernel                │
│             [ZERO I/O, ZERO NETWORK, ZERO DB]              │
└─────────────────────────────┬──────────────────────────────┘
                              │ emits facts
┌─────────────────────────────▼──────────────────────────────┐
│                      Evidence Fabric                       │
│ (Digests, DSSE Attestations, Lineage, Receipts, FlightRec) │
│                      crates/ggagent-evidence               │
└────────────────────────────────────────────────────────────┘
```

---

## 📦 Modular Crate Decomposition

1. **`crates/ggagent-kernel`**: Pure domain semantics, entities, value objects, state vectors $S(e,t)$, full catalog of the 77 subagent strategies, A2A task state machine, ARD data models, and capability leases. Zero external I/O dependencies.
2. **`crates/ggagent-validation`**: Shared validation rules, Agent Card linter, ARD document validator, Confused Deputy check, Loopjacking use-time effect guard verification, and hard anti-invariant dominance checkers.
3. **`crates/ggagent-evidence`**: Content-addressed SHA-256 digests, Ed25519 signed execution receipts, in-toto v1.0 attestations in DSSE envelopes, state mutation lineage ledger, and tamper-evident flight recorder.
4. **`crates/ggagent-transport`**: A2A JSON-RPC 2.0 protocol handler, Server-Sent Events (SSE) streaming engine, ARD `/.well-known/ard.json` publisher/server, MCP client/server bridge, cross-harness dispatch adapters, and native async HTTP server.
5. **`crates/ggagent-cli`**: Clap CLI binary (`ggagent`) exposing `create`, `playground`, `eval`, `ard`, `a2a`, `subagents`, `harness`, `doctor`, `explain`, and `verify`.

---

## 🔄 Canonical Day-2 Control Loop

```text
OBSERVE ──► DETECT ──► DIAGNOSE ──► DEGRADE ──► CONTAIN ──► RECOVER ──► VERIFY ──► RECONCILE
```

Every production-significant subsystem exposes deep diagnostics (`doctor`, `explain`, `inspect`, `verify`) rather than relying on raw log dumps.
