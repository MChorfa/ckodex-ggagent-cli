//! # ggagent-kernel
//!
//! Pure Domain Semantic Kernel for `ckodex-ggagent-cli`.
//!
//! Strictly conforms to the Clean Condamian Convention:
//! - ZERO I/O (no network, no database, no async runtime dependencies)
//! - Pure domain invariants, vector state products, and state transition contracts
//! - Complete catalog of the 77 Subagent Strategies (SAS-001 through SAS-077)
//! - Google A2A (Agent-to-Agent) domain lifecycle and Confused Deputy defenses
//! - Agentic Resource Discovery (ARD) protocol specifications
//! - Capability Leases, Execution Leases, and Atomic Effect Guards (anti-Loopjacking)
//! - Conformance vectors: delta(Pe, S0, X, C) -> <d, O, S1, E, R>

pub mod a2a;
pub mod aibom;
pub mod ard;
pub mod budget;
pub mod checkpoint;
pub mod conformance;
pub mod coordinated_states;
pub mod error;
pub mod handoff;
pub mod lease;
pub mod loops;
pub mod network;
pub mod sandbox_profile;
pub mod strategies;
pub mod vector_state;

// Re-exports
pub use a2a::{A2AEvent, A2AMessage, A2APart, A2ARole, A2ATask, A2ATaskState, AgentCard};
pub use aibom::{AiBomDocument, BomComponent, BomMetadata, ComponentType, ModelCardInfo};
pub use ard::{ArdCapability, ArdDocument, ArdEndpoint, ArdProtocol, ArdResource, ArdResourceType};
pub use budget::ExecutionBudget;
pub use checkpoint::TaskCheckpoint;
pub use conformance::{
    ConformalRiskCertificate, ConformanceDisposition, ConformanceEvaluationResult,
    ConformanceStimulus, ConformanceVector,
};
pub use coordinated_states::{
    AuthorityLifecycle, CandidateLifecycle, CoordinatedTaskState, ExecutionLifecycle,
    FailureClassification, ReclamationLifecycle,
};
pub use error::KernelError;
pub use handoff::{HandoffManifest, HandoffParams};
pub use lease::{AtomicEffectGuard, CapabilityLease, EffectDisposition};
pub use loops::{
    CommandRequest, EventReport, EvidenceClaim, GovernanceDecision, GovernanceDisposition,
    LoopCoordinator, LoopRole,
};
pub use network::{EgressMode, NetworkEgressPolicy};
pub use sandbox_profile::{ProfileTier, SandboxProfile};
pub use strategies::{StrategyArchetype, StrategyRegistry, SubagentStrategy};
pub use vector_state::{
    AntiRelation, Coherence, EvidenceStatus, LifecycleState, Presence, RuntimeMode, Valence,
    VectorState,
};
