# Claude Kernel Refactorer (`claude-kernel-refactor`)

Architectural refactoring agent utilizing Anthropic Claude Code to enforce Clean Condamian purity, strict compiler checks, and anti-slop guidelines.

## Use case

As codebases evolve, developers inadvertently import I/O crates, async runtimes, or database drivers into the core domain layer, creating tight coupling and making unit testing brittle.

`claude-kernel-refactor` performs deep refactoring under strict negative constraints. It isolates domain semantics from transport adapters, preserves zero-warning compiler gates (`cargo clippy -- -D warnings`), and ensures clean hexagonal boundaries.

## Supported capabilities

- `refactor_domain_kernel`: Extracts I/O and transport dependencies out of domain logic (Strategy `SAS-061`).
- `audit_slop_and_tells`: Audits technical documentation and code comments to remove AI fluff and marketing jargon.
