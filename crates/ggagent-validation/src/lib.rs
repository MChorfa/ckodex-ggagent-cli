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
pub mod error;
pub mod guards;

pub use agent_card::AgentCardValidator;
pub use ard_validator::ArdValidator;
pub use error::ValidationError;
pub use guards::SecurityGuards;
