# sbom-tools 0.4 migration assessment

Status: preparation only; no migration validated. Reviewed 2026-10-31 against ggagent
`5bbd0c8bdd840d3bcea13b1cea2ce48c27b4ecd1` and upstream
`4ab62eeac43c49e2f4e57bf1d932899abe3e247d`.
Latest GitHub release inspected: v0.3.0. The upstream main manifest still identifies
itself as 0.3.0; it is not the published 0.4 release.

## Existing support discrepancy and decision

The workspace declares Rust 1.80; the v0.3.0 upstream tag declares Rust 1.88.
The current direct dependency therefore already conflicts with the workspace MSRV.
No support promise or manifest is silently changed here. Until maintainers decide
whether to raise the published MSRV or isolate/replace this dependency, do not
claim the full workspace supports 1.80. A feature-gated integration alone does not
preserve the existing default feature set on 1.80. Prove any chosen approach using
both Rust 1.80 and the approved new minimum across intended build configurations.
Other transitive dependencies could require newer Rust too.

## Scope and compatibility

- `SbomAnalyzer` directly returns upstream normalized, diff, scoring and compliance
  types. `ggagent-validation` publicly re-exports several upstream types. That makes
  source and serialized representation changes visible to downstream users.
- Inspection found direct field reads and checker/scorer calls; this is not a compiler
  check. No actual 0.4-specific ggagent compilation failure has been established.
  Upstream's non-exhaustive types break external struct literals and exhaustive enum
  matches, including potential downstream consumers; inspect all consumers and test.
- ggagent's own JSON output is produced from Rust values and is not automatically the
  upstream CLI v2 envelope. Its generated SARIF uses positional RULE-nnn identifiers,
  not upstream stable rule identifiers. Do not claim upstream SARIF migration fixes it.
- The upstream CLI exit code, v2 envelope, OSCAL and sbomqs changes apply to consumers
  of those upstream interfaces, not automatically to ggagent's Rust calls. Assess any
  external scripts separately.
- `SbomToolBridge` invokes Microsoft's separate `sbom-tool` or its native fallback.
  Do not apply sbom-tools CLI flags or exit-code rules to that bridge.

## Upgrade gate

1. Preserve the current production dependency requirement (`0.3.0`, Cargo-compatible
   0.3.x range) until a published 0.4 release is available and validated. Note this is
   not an exact 0.3.0 pin and there is no committed workspace Cargo.lock at the reviewed
   revision. Decide on an exact pin and lockfile policy separately.
2. In an isolated checkout test a SHA-pinned upstream candidate using a temporary Cargo
   patch and suitable Rust toolchain. Record its commit, lockfile, compiler and command
   output; do not mistake current main's package version for published v0.4.
3. Run `cargo test -p ggagent-validation --test sbom_migration_contract`, full workspace
   tests, formatting, clippy and doctor; additionally compile public downstream examples.
   The new tests exercise wrapper consistency with the selected upstream library; they
   do not by themselves establish independent verdict correctness or 0.4 compatibility.
4. Compare both versions on fixed CycloneDX JSON/XML and SPDX fixtures, fixed evaluation
   date where available, and record verdict, applicability, errors, warnings, rule IDs,
   score and normalized component identities. Add independently justified golden cases
   for empty inventory, placeholders, service/package distinction and evidence refs.
   Classify changes using upstream's migration guide; investigate unexplained deltas.
5. Validate the final published release and its actual MSRV, public APIs, serialized
   output, applicable schemas and downstream contracts before changing the requirement.
   Approve the MSRV decision explicitly, update CI and support documentation, and rerun
   all required checks. Keep Microsoft bridge tests separate.

## Verification in this change

Source and tagged manifests were inspected through GitHub. No Rust compiler, Cargo or
checkout was available in the execution environment; no Rust build, test, formatter,
clippy, doctor or 0.4 compilation comparison was run. The added tests are unverified.
No production dependency, MSRV declaration or bridge behavior has been changed.

Upstream reference: https://github.com/sbom-tool/sbom-tools/blob/4ab62eeac43c49e2f4e57bf1d932899abe3e247d/docs/MIGRATING-0.4.md
