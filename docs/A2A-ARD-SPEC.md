# Google Agent-to-Agent (A2A) & Agentic Resource Discovery (ARD) Specification

**Status:** Normative & Implemented  
**Standards:**
- [Google Agent-to-Agent (A2A) Protocol (Linux Foundation Standard)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [Agentic Resource Discovery (ARD) Protocol (agenticresourcediscovery.org)](https://agenticresourcediscovery.org/)

---

## 1. Google Agent-to-Agent (A2A) Protocol Specification

The **A2A Protocol** establishes standard peer-to-peer and client-to-agent communication across frameworks.

### 1.1 The Agent Card (`/.well-known/agent-card.json`)

Every A2A server advertises its identity, capabilities, endpoints, and authentication mechanism at `/.well-known/agent-card.json`:

```json
{
  "$schema": "https://a2aprotocol.org/schemas/v1/agent-card.json",
  "name": "ckodex-ggagent",
  "version": "2.0.0",
  "description": "Canonical Google ADK & A2A Interoperability Agent with 77 Subagent Strategies",
  "endpoints": {
    "rpc": "http://127.0.0.1:8080/api/v1/a2a",
    "events": "http://127.0.0.1:8080/api/v1/a2a/events"
  },
  "capabilities": [
    {
      "id": "conformance_evaluation",
      "description": "Evaluates state transition contracts delta(Pe, S0, X, C)",
      "parameters": {}
    },
    {
      "id": "subagent_orchestration",
      "description": "Executes multi-tier subagents across the 77 canonical strategies",
      "parameters": {}
    }
  ],
  "authentication": {
    "type": "mtls_or_bearer",
    "token_endpoint": null
  },
  "metadata": {}
}
```

### 1.2 Task Lifecycle Finite State Machine (FSM)

```text
               ┌───────────────────────┐
               │ TASK_STATE_SUBMITTED  │
               └───────────┬───────────┘
                           │ validate
                           ▼
               ┌───────────────────────┐
               │  TASK_STATE_WORKING   │
               └───────┬───────────┬───┘
                       │           │
    needs confirmation │           │ complete
                       ▼           ▼
  ┌─────────────────────────┐  ┌───────────────────────┐
  │ TASK_STATE_AUTH_REQUIRED│  │ TASK_STATE_COMPLETED  │
  └────────────┬────────────┘  └───────────────────────┘
               │ human approves
               ▼
  ┌─────────────────────────┐
  │ TASK_STATE_AUTH_RECEIVED│
  └────────────┬────────────┘
               │ execute
               ▼
  ┌─────────────────────────┐
  │ TASK_STATE_COMPLETED /  │
  │   TASK_STATE_FAILED     │
  └─────────────────────────┘
```

### 1.3 Confused Deputy Defense (CVE-2026-18236 / ADK Issue #6461)

In multi-agent architectures, inbound turns from remote peer agents are frequently mapped as `role: "user"`. Naive downstream frameworks mistake this for human authorization and execute mutating commands (`kubectl delete`, `rm -rf`).

**Implementation:**
`ggagent` enforces strict algebraic role separation:
- `A2ARole::HumanUser`: Verified human principal with cryptographic standing.
- `A2ARole::RemoteAgent`: Remote peer turn. **PROHIBITED** from granting authorization for mutating tasks.
- `A2ARole::Tool`: Tool execution output.

---

## 2. Agentic Resource Discovery (ARD) Specification

The **ARD Protocol** ([agenticresourcediscovery.org](https://agenticresourcediscovery.org/)) enables decentralized, vendor-neutral capability discovery analogous to `robots.txt` for search engines.

### 2.1 The ARD Document (`/.well-known/ard.json`)

```json
{
  "$schema": "https://agenticresourcediscovery.org/schemas/v1/ard.json",
  "publisher": "CKODEX Architecture Team",
  "domain": "127.0.0.1:8080",
  "version": "1.0.0",
  "generated_at": "2026-10-22T20:55:00Z",
  "resources": [
    {
      "id": "ggagent-a2a-service",
      "name": "CKODEX A2A Agent Service",
      "resource_type": "agent",
      "version": "2.0.0",
      "description": "High-assurance A2A protocol agent runtime with Confused Deputy defense",
      "endpoints": [
        {
          "name": "rpc",
          "protocol": "a2a_rpc",
          "uri": "http://127.0.0.1:8080/api/v1/a2a"
        },
        {
          "name": "events",
          "protocol": "a2a_rpc",
          "uri": "http://127.0.0.1:8080/api/v1/a2a/events"
        }
      ],
      "capabilities": [
        {
          "id": "evaluate_conformance",
          "name": "Evaluate Conformance",
          "description": "Runs conformance vector evaluation with hard anti-invariants",
          "tags": ["governance", "conformance"]
        }
      ],
      "required_authorities": ["ckodex:authority:root"]
    }
  ]
}
```

### 2.2 Strict Discovery vs. Execution Separation

ARD strictly handles **discovery**, not execution:
1. Agent queries `GET /.well-known/ard.json`
2. Agent evaluates schema and required authority
3. Agent connects directly to the declared protocol (A2A JSON-RPC, MCP, OpenAPI) with bounded CapabilityLease.

---

## 3. Cross-Harness Interoperability

`ggagent` provides out-of-the-box bridge support for all major coding agent harnesses:

| Harness | Configuration Root | Discovery | Execution Bridge |
|---|---|---|---|
| **Google Antigravity / Gemini** | `~/.gemini` | A2A + ARD + MCP | `gemini -p "<intent>"` |
| **Anthropic Claude Code** | `~/.claude` | `CLAUDE.md` + MCP | `claude -p "<intent>"` |
| **OpenAI Codex** | `~/.codex` | Responses API + MCP | `codex exec "<intent>"` |
| **OpenCode** | `~/.opencode` | OpenCode Manifest | `opencode run "<intent>"` |
| **SAM Agent Mesh** | `~/.sam` | A2A Mesh + ARD | `sam-node call <agent> <tool>` |
| **Google Agents CLI** | `~/.agents` | ADK v2 + A2A | `agents-cli eval run` |
