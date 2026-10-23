# Codex Security Patcher (`codex-security-patcher`)

Remediation agent utilizing OpenAI Codex for targeted vulnerability patching, use-time material effect binding, and deterministic test generation.

## Use case

Unchecked autonomous code generation introduces loopjacking: an operator approves an intended action, but the executed payload is swapped or mutated during generation.

`codex-security-patcher` binds every patch proposal to an `AtomicEffectGuard` hash. Before the patch is applied, the execution broker checks that the SHA-256 material digest matches the exact approved lease. Patches are sealed into immutable byte buffers, defeating TOCTOU workspace race conditions.

## Supported capabilities

- `synthesize_hardened_patch`: Generates clean, minimal diffs strictly bound by cryptographic parameter digests (Strategy `SAS-037`).
- `generate_conformance_vectors`: Produces boundary unit tests covering anti-invariants and edge cases.
