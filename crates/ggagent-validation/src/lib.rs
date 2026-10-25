//! # ggagent-validation
//!
//! Shared Validation Engine for `ckodex-ggagent-cli`.
//!
//! Validates:
//! - A2A Agent Cards and communication turns
//! - Agentic Resource Discovery (ARD) documents
//! - Confused Deputy defense (CVE-2026-18236 / ADK #6461)
//! - Loopjacking defense (arXiv:2609.21081)
//! - Capability Leases and hard Anti-Invariants

pub mod agent_card;
pub mod ard_validator;
pub mod context_guard;
pub mod effect_broker;
pub mod egress_proxy;
pub mod error;
pub mod guards;
pub mod handoff_validator;
pub mod isolation_guard;
pub mod mesh_orchestrator;
pub mod network_guard;
pub mod replay_engine;
pub mod sbom_analyzer;
pub mod sbom_tool_bridge;
pub mod secret_guard;
pub mod spdx_validator;
pub mod workspace_staging;

pub use agent_card::AgentCardValidator;
pub use ard_validator::ArdValidator;
pub use context_guard::ContextGuard;
pub use effect_broker::{AtomicEffectBroker, EffectRequest};
pub use egress_proxy::{EgressProxyDecision, EgressProxyEngine, EgressProxyRequest};
pub use error::ValidationError;
pub use guards::SecurityGuards;
pub use handoff_validator::HandoffValidator;
pub use isolation_guard::IsolationGuard;
pub use mesh_orchestrator::{MeshExecutionReport, MeshOrchestrator, StageResult};
pub use network_guard::NetworkEgressGuard;
pub use replay_engine::{ReplayEngine, ResumedTaskState};
pub use sbom_analyzer::SbomAnalyzer;
pub use sbom_tool_bridge::{SbomExecutionResult, SbomToolBridge};
pub use sbom_tools::diff::DiffResult;
pub use sbom_tools::quality::{ComplianceLevel, ComplianceResult, QualityReport, ScoringProfile};
pub use secret_guard::SecretGuard;
pub use spdx_validator::SpdxValidator;
pub use workspace_staging::{SealedCandidate, WorkspaceStagingGuard};
