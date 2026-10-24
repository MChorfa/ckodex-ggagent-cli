# ckodex-ggagent-cli

Static CLI and local runtime for the Google Agent-to-Agent (A2A) protocol, Agentic Resource Discovery (ARD), and sandboxed multi-agent execution.

## System overview

`ggagent` implements a pure domain kernel for agent execution, isolated from I/O and network libraries. The codebase separates domain semantics from transport, validation, and cryptographic evidence.

- **Domain kernel (`ggagent-kernel`):** Pure state machine, typed state vectors $S(e,t)$, capability lease tracking, and the 77 subagent strategies catalog. Contains zero I/O, network, or database dependencies.
- **Shared validation (`ggagent-validation`):** Input validation, Agent Card and ARD document linters, Confused Deputy defense, and use-time effect guards.
- **Evidence fabric (`ggagent-evidence`):** Content-addressed SHA-256 digests, Ed25519 DSSE envelopes, in-toto v1.0 statements, and append-only flight recorders.
- **Transport (`ggagent-transport`):** A2A JSON-RPC 2.0 protocol handler, Server-Sent Events (SSE) streaming engine, ARD document publisher, and cross-harness dispatch adapters.
- **CLI (`ggagent-cli`):** Single binary exposing project scaffolding, evaluation, verification, and Day-2 diagnostics.

## Quick start

### Prerequisites

- Rust 1.80 or newer
- Make

### Build and test

```bash
make build
make test
make clippy
make doctor
```

`make doctor` runs 18 automated diagnostic checks across the local kernel, network substrate, and cryptographic engine.

### Run local runtime and playground

```bash
./bin/ggagent playground --port 8080
```

The runtime exposes:
- Interactive ledger: `http://127.0.0.1:8080/playground`
- A2A Agent Card: `GET http://127.0.0.1:8080/.well-known/agent-card.json`
- ARD Resource Catalog: `GET http://127.0.0.1:8080/.well-known/ard.json`
- A2A JSON-RPC 2.0: `POST http://127.0.0.1:8080/api/v1/a2a`
- A2A SSE Stream: `GET http://127.0.0.1:8080/api/v1/a2a/events`

## Command reference

```text
Usage: ggagent <COMMAND>

Commands:
  create       Scaffold a new Google ADK / A2A agent project
  playground   Launch the local runtime and interactive web interface
  dashboard    High-density Day-2 architecture & runtime dashboard
  status       Quick status check of all 20 runtime subsystems (alias for doctor)
  doctor       Run Day-2 diagnostic suite across 20 operational systems
  eval         Evaluate agent conformance vectors and conformal risk calibration
  ard          Agentic Resource Discovery (ARD) operations
  a2a          Google Agent-to-Agent (A2A) protocol operations
  subagents    List, inspect, and execute the 77 canonical subagent strategies
  harness      Cross-harness interoperability bridge (Gemini, Claude, Codex, OpenCode, SAM)
  sbom         High-assurance SBOM engine (sbom-tools) & ISO/IEC 5962:2021 SPDX bridge
  aibom        CycloneDX 1.7 (ECMA-424) AI-BOM generation and cryptographic verification
  forensic     Export or inspect tamper-evident post-mortem evidence bundles
  explain      Output causal decision trace and authority path for a task
  verify       Verify cryptographic execution receipt or DSSE envelope
  completions  Generate shell autocompletions (bash, zsh, fish, powershell, elvish)
```

### Inspect subagent strategies

```bash
# List all 77 strategies
./bin/ggagent subagents list

# Filter by archetype
./bin/ggagent subagents list --archetype ContextIsolationAndCompression

# Inspect specific strategy contract
./bin/ggagent subagents inspect SAS-037

# Execute bounded strategy trial
./bin/ggagent subagents run SAS-037
```

### Cross-harness interoperability

Verify adapter interfaces across supported harnesses:

```bash
./bin/ggagent harness verify
```

Supported targets:
1. `AntigravityGemini` (`gemini -p ...`)
2. `ClaudeCode` (`claude -p ...`)
3. `CodexOpenAi` (`codex exec ...`)
4. `OpenCode` (`opencode run ...`)
5. `SamMesh` (`a2a call ...`)
6. `GoogleAgentsCli` (`agents-cli eval ...`)

Format a task brief for dispatch to another tool:

```bash
./bin/ggagent harness dispatch claude "Review state transition conformance"
```

## Security controls

### Confused deputy defense (CVE-2026-18236)

Multi-agent turn relays distinguish human operators from peer agents using typed roles (`A2ARole::HumanUser` vs `A2ARole::RemoteAgent`). Messages originating from peer agents cannot approve mutating tasks or supply confirmation tokens.

### Loopjacking defense (AtomicEffectGuard)

Actions require use-time cryptographic material binding. Before side effects execute, the runtime verifies:

$$\text{SHA-256}(\text{action} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{target} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{canonical\_json\_params}) \equiv \text{lease.effect\_digest}$$

Verification completes in under 31 microseconds in release builds.

### Split-brain generation fencing

Capability leases carry a monotonic generation counter and fencing token. When authority migrates or resumes from a checkpoint, the generation increments ($N \to N+1$). In-flight requests from older generations are fenced.

### TOCTOU workspace staging

Candidate files generated by workers are validated against directory traversal and symlink escapes, then sealed into immutable memory snapshots with SHA-256 digests before outer-loop evaluation.

### Network egress governance

Workloads default to denied network access. Connections to cloud instance metadata (`169.254.169.254`, `metadata.google.internal`) and private intranets (RFC 1918) are blocked.

## Laboratory contracts

The test suite validates 13 formal execution contracts in `crates/ggagent-cli/tests/conformance_test.rs`:

| Contract | Target Invariant | Primary Mechanism |
| :--- | :--- | :--- |
| Lab 1 | Loopjacking defense | `AtomicEffectGuard` material digest verification |
| Lab 2 | Generation fencing under partition | `AtomicEffectBroker` monotonic generation advancement |
| Lab 3 | Candidate staging & TOCTOU defeat | `WorkspaceStagingGuard` + `SealedCandidate` immutable buffers |
| Lab 4 | 4D coordinated states | Orthogonal state tracking (Execution, Authority, Candidate, Reclamation) |
| Lab 5 | Three-loop responsibility | Inner, Outer, and Governance loop separation of authority |
| Lab 6 | Multi-dimensional budget accounting | Monotonic budget attenuation across child tasks |
| Lab 7 | Partitioned handoff protocol | `HandoffManifest` checkpoint digests and non-inflation checks |
| Lab 8 | Secret scrubbing | `SecretGuard` static pattern detection and redaction |
| Lab 9 | Forensic bundle integrity | `ForensicBundle` root manifest SHA-256 verification |
| Lab 10 | Network egress governance | `NetworkEgressGuard` blocking IMDSv2 and RFC 1918 ranges |
| Lab 11 | Sandbox isolation profiles | Landlock filesystem bounds and seccomp syscall filters |
| Lab 12 | Deterministic checkpoint & replay | `ReplayEngine` idempotency caching and side-effect fencing |
| Lab 13 | Cross-harness interoperability | Conformance verified across all 6 ecosystem adapters |

## Specification and standards references

- [Underlying Tensions, Risks & Papercut Ledger](docs/UNDERLYING-TENSIONS-AND-RISKS.md)
- [Google Agent-to-Agent (A2A) Protocol](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [Agentic Resource Discovery (ARD)](https://agenticresourcediscovery.org/)
- [in-toto Attestation Framework v1.0](https://in-toto.io)
- [Protobuf Service Definitions](proto/a2a/v1/a2a.proto)
- [Architecture Details](ARCHITECTURE.md)
- [Security Model](SECURITY.md)
- [77 Subagent Strategies Catalog](SUBAGENTS-77-CATALOG.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
