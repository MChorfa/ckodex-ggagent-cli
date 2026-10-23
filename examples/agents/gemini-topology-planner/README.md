# Gemini Topology Planner (`gemini-topology-planner`)

Planning agent designed for repository cartography, AST ingestion, and uninfluenced strategy formulation.

## Use case

Multi-agent software engineering fails when agents suffer from anchor bias: reviewing agent A's plan biases agent B into replicating the same subtle architectural blindspots. 

`gemini-topology-planner` leverages Google Gemini's large context window (1M+ tokens) to ingest complete codebase ASTs and formulate **Blind-First Plans** (Strategy `SAS-001`). It maps static dependency DAGs and cross-crate interfaces into pure domain transitions before exposing its plan to peer reviewers.

## Supported capabilities

- `map_repository_topology`: Ingests AST boundaries and produces inward dependency graphs.
- `plan_blind_first`: Generates independent decomposition plans satisfying the 7D state vector $S(e,t)$.
