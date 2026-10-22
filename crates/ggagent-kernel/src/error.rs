use crate::coordinated_states::FailureClassification;
use thiserror::Error;

/// Pure domain kernel errors (zero I/O dependencies).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KernelError {
    #[error("Invalid state transition: from {from} to {to} reason: {reason}")]
    InvalidStateTransition {
        from: String,
        to: String,
        reason: String,
    },

    #[error("Anti-invariant violation: {invariant} contradicts state {context}")]
    AntiInvariantViolation { invariant: String, context: String },

    #[error("Decoherence detected: admitted digest {admitted} != runtime digest {runtime}")]
    DecoherenceDetected { admitted: String, runtime: String },

    #[error("Confused deputy detected: approval turn originated from role {role:?} instead of human user")]
    ConfusedDeputyDetected { role: String },

    #[error("Loopjacking detected: material effect digest mismatch (expected {expected}, computed {actual})")]
    LoopjackingMismatch { expected: String, actual: String },

    #[error("Capability lease expired or revoked: lease_id={lease_id}")]
    LeaseExpiredOrRevoked { lease_id: String },

    #[error("Invalid strategy identifier: {0}")]
    InvalidStrategyId(u32),

    #[error("Invalid A2A task state transition from {from:?} to {to:?}")]
    InvalidA2ATransition { from: String, to: String },

    #[error("Missing mandatory authority for capability: {0}")]
    MissingAuthority(String),

    #[error(
        "Stale generation fencing violation: current={current}, received={received}, token={token}"
    )]
    StaleGeneration {
        current: u64,
        received: u64,
        token: String,
    },

    #[error("Coordinated state invariant violation: {0}")]
    CoordinatedStateViolation(String),

    #[error("Classified failure [{class:?}]: {detail}")]
    ClassifiedFailure {
        class: FailureClassification,
        detail: String,
    },

    #[error(
        "Execution budget exhausted on dimension '{dimension}': limit={limit}, consumed={consumed}"
    )]
    BudgetExhausted {
        dimension: String,
        limit: u64,
        consumed: u64,
    },

    #[error("Budget attenuation exceeded on dimension '{dimension}': requested={requested}, remaining_parent={remaining_parent}")]
    BudgetAttenuationExceeded {
        dimension: String,
        requested: u64,
        remaining_parent: u64,
    },

    #[error("Invalid partitioned handoff: {reason}")]
    InvalidHandoff { reason: String },
}
