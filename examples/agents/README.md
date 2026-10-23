# Exemplar Agents & Multi-Model Use Cases

This directory contains production-ready agent definitions, Google A2A Agent Cards, ARD manifests, and task templates demonstrating specialized model capabilities under the CKODEX Constitution.

| Agent Identifier | Primary Model / Harness | Primary Specialization | Key Subagent Strategies |
| :--- | :--- | :--- | :--- |
| [`gemini-topology-planner`](gemini-topology-planner/) | Google Gemini 1.5/2.0 Pro (ADK v2) | Whole-repository AST cartography & uninfluenced blind-first planning | `SAS-001` (Blind-First Planner), `SAS-019` (Topology Cartographer) |
| [`cohere-grounded-auditor`](cohere-grounded-auditor/) | Cohere Command R+ & Rerank v3.5 | Citation-grounded compliance audits with exact byte-span evidence | `SAS-054` (Evidence Grounding), `SAS-022` (Document Gatekeeper) |
| [`codex-security-patcher`](codex-security-patcher/) | OpenAI Codex / Responses API | Deterministic security patching with use-time material effect binding | `SAS-037` (AtomicEffectGuard), `SAS-042` (Dynamic Red-Team) |
| [`claude-kernel-refactor`](claude-kernel-refactor/) | Anthropic Claude 3.7 / 3.5 Sonnet | Pure domain kernel refactoring, negative constraint enforcement & unslop | `SAS-061` (Quality Gate Invariant), `SAS-012` (Spoke-Window Isolation) |

---

## 1. Google Gemini: Repository Topology & Blind-First Planner
- **Strength:** Millions of tokens of context for comprehensive codebase ingestion without truncation.
- **Problem Solved:** Prevents anchor bias in multi-agent workflows. Formulates independent implementation plans before evaluating peer proposals.
- **Verification:** Produces inward-pointing DAGs where infrastructure depends strictly on domain abstractions.

## 2. Cohere: Citation-Grounded Compliance & Policy Auditor
- **Strength:** Native citation extraction (`start`, `end`, `text`) and cross-encoder reranking.
- **Problem Solved:** Eliminates hallucinated compliance claims. Every architectural assertion must link directly to an authoritative standard (NIST SP 800-53, CKODEX Constitution).
- **Verification:** Emits `AntiRelation::Contradicts` if a claim is unsupported by cited documents.

## 3. OpenAI Codex: Bound Security Patcher & Fenced Actuator
- **Strength:** High-precision deterministic code synthesis with strict JSON schema and tool-call contracts.
- **Problem Solved:** Prevents Loopjacking (arXiv:2609.21081). Binds every patch to an `AtomicEffectGuard` material hash verified in &lt;31 microseconds.
- **Verification:** Patches are sealed into immutable memory snapshots (`SealedCandidate`) before outer-loop review, defeating TOCTOU races.

## 4. Anthropic Claude: Clean Kernel Refactorer & Anti-Slop Gate
- **Strength:** High adherence to negative constraints and formal architectural guidelines.
- **Problem Solved:** Prevents architectural degradation. Strips I/O and async runtimes from domain kernel crates, ensuring zero Clippy warnings (`-D warnings`).
- **Verification:** Enforces Clean Condamian kernel purity and purges promotional fluff.

---

## CLI Execution

```bash
# List available exemplar agents
./bin/ggagent agent list

# Inspect an agent's A2A card and capabilities
./bin/ggagent agent inspect cohere-grounded-auditor

# Run an agent task through the local validation runtime
./bin/ggagent agent run cohere-grounded-auditor
```
