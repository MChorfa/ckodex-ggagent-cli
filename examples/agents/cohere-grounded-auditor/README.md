# Cohere Grounded Auditor (`cohere-grounded-auditor`)

Verification agent utilizing Cohere Command R+ and Rerank v3.5 for citation-grounded compliance audits and regulatory evidence generation.

## Use case

Standard LLM evaluators hallucinate compliance claims: they claim a security control is satisfied without citing where or how. 

`cohere-grounded-auditor` harnesses Cohere Command R+'s native citation generation. For every asserted fact, it extracts precise character spans and computes SHA-256 digests over the source text. It integrates directly with the CKODEX 7D Vector State: if an asserted claim contradicts an audited document, it marks `AntiRelation::Contradicts`, preventing unauthorized promotion.

## Supported capabilities

- `audit_evidence_grounding`: Verifies propositions against source files with exact character spans (Strategy `SAS-054`).
- `rerank_policy_invariants`: Neural cross-encoder retrieval over regulatory specifications (NIST SP 800-53, SLSA Level 3).
