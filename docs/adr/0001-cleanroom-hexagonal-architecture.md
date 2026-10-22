# ADR 0001: Cleanroom Hexagonal Four-Layer Architecture

**Status:** Accepted  
**Deciders:** CKODEX Architecture Team  
**Date:** 2026-10-22  

---

## Context
Traditional CLI tools often couple business logic, network requests, terminal printing, and storage into single files. This creates fragile dependencies, prevents automated verification, and allows unauthenticated actions to occur without audit trails.

## Decision
We adopt the CKODEX Hexagonal Four-Layer Architecture and Clean Condamian Convention:
1. `ggagent-kernel`: Pure domain model. Zero network, zero disk, zero async runtime.
2. `ggagent-validation`: Shared boundary validation, linting, and authorization guards.
3. `ggagent-evidence`: Cryptographic digests, DSSE envelopes, execution receipts, and flight recorders.
4. `ggagent-transport`: Protocol adapters (A2A JSON-RPC 2.0, SSE, ARD, MCP, cross-harness CLI dispatch).
5. `ggagent-cli`: Bounded presentation and CLI application entry point.

## Consequences
- **Positive:** Domain logic is 100% testable in sub-millisecond unit tests without mocking servers.
- **Positive:** Clear dependency direction (Adapters $\to$ Validation $\to$ Kernel; Kernel $\to$ Evidence).
- **Trade-off:** Requires explicit type conversions between transport payloads and pure domain entities.
