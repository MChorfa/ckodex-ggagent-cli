# Contributing to ckodex-ggagent-cli

We welcome contributions to `ckodex-ggagent-cli`. To maintain high structural assurance, all contributions must adhere to the engineering guidelines outlined below.

---

## Code Quality Standards

1. **Clean Condamian Convention**:
   - Keep `crates/ggagent-kernel` pure (zero I/O).
   - Decompose crates by responsibility rather than creating monolithic modules.
   - Files exceeding 500 lines should be evaluated for refactoring candidates.

2. **Zero-Warning Gate**:
   - All code must compile with `cargo clippy --workspace --all-targets -- -D warnings`.
   - Code must be formatted with `cargo fmt`.
   - All unit and property tests must pass (`cargo test --workspace`).

3. **Cryptographic & Governance Invariants**:
   - Ensure all A2A turns defend against Confused Deputy attacks by checking `A2ARole`.
   - Ensure mutating actions verify `AtomicEffectGuard` digests at execution time.
   - Vector state transitions must increment the epoch $\tau$.

---

## Pull Request Checklist

- [ ] `make fmt` passes without diffs.
- [ ] `make clippy` passes with zero warnings.
- [ ] `make test` runs and passes all unit tests.
- [ ] `./bin/ggagent doctor` reports all systems nominal.
- [ ] Any new subagent strategy or A2A capability is documented in `docs/SUBAGENTS-77-CATALOG.md` or `docs/A2A-ARD-SPEC.md`.
