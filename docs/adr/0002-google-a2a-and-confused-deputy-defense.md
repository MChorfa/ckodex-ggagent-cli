# ADR 0002: Google Agent-to-Agent (A2A) Protocol & Confused Deputy Defense

**Status:** Accepted  
**Deciders:** CKODEX Security & Architecture Team  
**Date:** 2026-10-22  

---

## Context
Google Agent-to-Agent (A2A) protocol is the open Linux Foundation standard for cross-agent communication. However, multi-agent frameworks often map incoming messages as `role: "user"`. In Google ADK Issue #6461 (CVE-2026-18236), a malicious remote peer agent can trick a local execution agent into executing destructive commands by masquerading as the user.

## Decision
1. Implement the standard A2A protocol:
   - Agent Card advertised at `/.well-known/agent-card.json`
   - JSON-RPC 2.0 endpoints for task lifecycle management
   - Server-Sent Events (SSE) for real-time progress streaming
2. Enforce strict typed role separation:
   - `A2ARole::HumanUser`
   - `A2ARole::RemoteAgent`
   - `A2ARole::Tool`
   - `A2ARole::System`
3. Any message that attempts to confirm a task call (`confirmed_call_id`) MUST originate from `A2ARole::HumanUser`. Non-human attempts are rejected with `ValidationError::ConfusedDeputyViolation` and transition the task to `TASK_STATE_FAILED`.

## Consequences
- **Positive:** Immune to cross-agent authorization impersonation (CVE-2026-18236).
- **Positive:** Compliant with official Linux Foundation / Google A2A standards.
