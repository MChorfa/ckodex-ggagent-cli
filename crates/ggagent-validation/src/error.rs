use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("Agent card validation failed: {0}")]
    InvalidAgentCard(String),

    #[error("ARD document validation failed: {0}")]
    InvalidArdDocument(String),

    #[error("Confused deputy violation: inbound message from non-human role {role} attempted to confirm call {call_id}")]
    ConfusedDeputyViolation { role: String, call_id: String },

    #[error("Loopjacking violation: effect digest mismatch for action {action} (expected {expected}, actual {actual})")]
    LoopjackingViolation {
        action: String,
        expected: String,
        actual: String,
    },

    #[error("Mandatory anti-invariant violation: {0}")]
    AntiInvariantViolation(String),

    #[error("Capability lease violation: operation {operation} not permitted by lease {lease_id}")]
    LeaseViolation { lease_id: String, operation: String },

    #[error("Schema validation failed: {field}: {reason}")]
    SchemaMismatch { field: String, reason: String },

    #[error("Containment escape violation: {0}")]
    ContainmentEscapeViolation(String),

    #[error(
        "Stale generation fencing violation: current={current}, received={received}, token={token}"
    )]
    StaleGenerationViolation {
        current: u64,
        received: u64,
        token: String,
    },

    #[error("Effect execution denied: {0}")]
    EffectExecutionDenied(String),

    #[error("Invalid partitioned handoff: {0}")]
    InvalidHandoffViolation(String),

    #[error("Execution budget exhaustion: {0}")]
    BudgetExhaustionViolation(String),

    #[error("Secret leakage detected in execution payload: {0}")]
    SecretLeakageViolation(String),

    #[error("Network egress governance violation: {0}")]
    EgressViolation(String),

    #[error("Deterministic replay violation: {0}")]
    ReplayViolation(String),

    #[error("SPDX 2.2 SBOM validation failed: {0}")]
    InvalidSpdxDocument(String),

    #[error("SPDX tool execution error: {0}")]
    SbomToolExecutionError(String),

    #[error("SBOM semantic analysis failed: {0}")]
    SbomAnalysisError(String),

    #[error("Isolation contract violation: {0}")]
    IsolationViolation(String),

    #[error("Context fault violation: {0}")]
    ContextFaultViolation(String),

    #[error("Effect indeterminate (IN_DOUBT): {reason}, last_stage={last_stage}")]
    InDoubtViolation { reason: String, last_stage: String },

    #[error("Egress proxy policy violation: {0}")]
    EgressProxyViolation(String),
}
