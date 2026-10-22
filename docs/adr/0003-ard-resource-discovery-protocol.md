# ADR 0003: Agentic Resource Discovery (ARD) Protocol Implementation

**Status:** Accepted  
**Deciders:** CKODEX Architecture Team  
**Date:** 2026-10-22  

---

## Context
AI agents need to discover tools, MCP servers, and specialized micro-agents across enterprise networks without manual point-to-point hardcoding. The Agentic Resource Discovery (ARD) standard ([agenticresourcediscovery.org](https://agenticresourcediscovery.org/)) provides an open, vendor-neutral specification analogous to `robots.txt`.

## Decision
1. Implement ARD v1.0 standard document published at `/.well-known/ard.json`.
2. Strictly maintain the boundary: **Discovery $\neq$ Execution**.
   - ARD handles capability discovery, schemas, required authorities, and transport URIs.
   - Once discovered, execution shifts to the resource's declared protocol (A2A JSON-RPC, MCP, OpenAPI) with bounded `CapabilityLease`.
3. Provide validation tools (`ggagent ard lint`) to ensure third-party ARD catalogs comply with the standard schema.

## Consequences
- **Positive:** Interoperable with cross-industry agent discovery catalogs.
- **Positive:** Eliminates hardcoded tool endpoints.
