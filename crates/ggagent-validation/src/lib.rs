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
pub mod effect_broker;
pub mod error;
pub mod guards;
pub mod handoff_validator;
pub mod network_guard;
pub mod replay_engine;
pub mod secret_guard;
pub mod workspace_staging;

pub use agent_card::AgentCardValidator;
pub use ard_validator::ArdValidator;
pub use effect_broker::{AtomicEffectBroker, EffectRequest};
pub use error::ValidationError;
pub use guards::SecurityGuards;
pub use handoff_validator::HandoffValidator;
pub use network_guard::NetworkEgressGuard;
pub use replay_engine::{ReplayEngine, ResumedTaskState};
pub use secret_guard::SecretGuard;
pub use workspace_staging::{SealedCandidate, WorkspaceStagingGuard};
