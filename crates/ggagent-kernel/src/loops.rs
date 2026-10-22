//! # Three-Loop Architecture & Message Primitives (Chapter 2)
//!
//! Formalizes the separation of responsibilities across the three governing loops:
//! 1. `InnerLoop`: Bounded execution worker (plans, invokes allowed tools, proposes candidate).
//! 2. `OuterLoop`: Independent verifier (checks candidate artifacts against objective tests/linters).
//! 3. `GovernanceLoop`: Authoritative orchestrator (controls admission, leases, budget, promotion, revocation).
//!
//! Categorical Message vs Transition Primitives:
//! - `CommandRequest`: Requests an operation
//! - `EventReport`: Reports an occurrence
//! - `EvidenceClaim`: Submits a verifiable fact/digest
//! - `GovernanceDecision`: Authorizes an admission or state transition
//! - `ExecutionReceipt`: Cryptographically records outcome

use crate::budget::ExecutionBudget;
use crate::coordinated_states::{CandidateLifecycle, CoordinatedTaskState, ExecutionLifecycle};
use crate::error::KernelError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The Three Operational Loops
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoopRole {
    /// Bounded execution: inspect context, execute allowed tools, propose candidate
    InnerLoop,
    /// Independent evaluation: test suite execution, invariant checks, linting
    OuterLoop,
    /// Authoritative governance: admission, budget, capability leases, promotion
    GovernanceLoop,
}

/// Message Primitive: Command Request (requests an action)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRequest {
    pub command_id: String,
    pub task_id: String,
    pub issuer_role: LoopRole,
    pub action: String,
    pub parameters: serde_json::Value,
    pub requested_at: DateTime<Utc>,
}

/// Message Primitive: Event Report (reports an observed occurrence)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventReport {
    pub event_id: String,
    pub task_id: String,
    pub source_loop: LoopRole,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

/// Message Primitive: Evidence Claim (supports a proposition with cryptographic digest)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceClaim {
    pub claim_id: String,
    pub task_id: String,
    pub assertion: String,
    pub artifact_digest: String,
    pub verifier_signature: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Message Primitive: Governance Decision (authorizes admission or promotion)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDecision {
    pub decision_id: String,
    pub task_id: String,
    pub decision_maker: String,
    pub policy_version: String,
    pub target_generation: u64,
    pub candidate_digest: String,
    pub disposition: GovernanceDisposition,
    pub assigned_budget: ExecutionBudget,
    pub decided_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceDisposition {
    Admit,
    Deny,
    Promote,
    Quarantine,
    Revoke,
}

/// Loop Coordinator & Enforcer
pub struct LoopCoordinator;

impl LoopCoordinator {
    /// Validate that a proposed action conforms to loop responsibility boundaries
    pub fn validate_loop_action(
        issuer: LoopRole,
        action: &str,
        task: &CoordinatedTaskState,
    ) -> Result<(), KernelError> {
        match issuer {
            LoopRole::InnerLoop => {
                // Invariant 1: Inner loop cannot grant authority or promote candidates
                if action == "promote" || action == "expand_lease" || action == "expand_budget" {
                    return Err(KernelError::MissingAuthority(format!(
                        "InnerLoop worker cannot execute governance action '{}'",
                        action
                    )));
                }
                // Invariant 2: Inner loop cannot execute if task is not in Running state
                if task.execution != ExecutionLifecycle::Running {
                    return Err(KernelError::CoordinatedStateViolation(format!(
                        "InnerLoop cannot execute in state {:?}",
                        task.execution
                    )));
                }
            }
            LoopRole::OuterLoop => {
                // Invariant 3: Outer verifier cannot mutate production or publish
                if action == "publish" || action == "commit_mutation" {
                    return Err(KernelError::MissingAuthority(format!(
                        "OuterLoop verifier cannot execute mutating action '{}'",
                        action
                    )));
                }
                // Invariant 4: Outer verifier can only review when candidate is Sealed or UnderReview
                if task.candidate != CandidateLifecycle::Sealed
                    && task.candidate != CandidateLifecycle::UnderReview
                {
                    return Err(KernelError::CoordinatedStateViolation(format!(
                        "OuterLoop cannot evaluate candidate in state {:?}",
                        task.candidate
                    )));
                }
            }
            LoopRole::GovernanceLoop => {
                // Governance loop is authoritative across all decisions
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinated_states::AuthorityLifecycle;

    #[test]
    fn test_inner_loop_cannot_expand_authority() {
        let task = CoordinatedTaskState::new("task-loop-1");
        let res = LoopCoordinator::validate_loop_action(LoopRole::InnerLoop, "expand_lease", &task);
        assert!(matches!(res, Err(KernelError::MissingAuthority(_))));
    }

    #[test]
    fn test_outer_loop_cannot_publish_side_effects() {
        let mut task = CoordinatedTaskState::new("task-loop-2");
        task.transition_authority(AuthorityLifecycle::Active)
            .unwrap();
        task.stage_candidate("sha256-111").unwrap();
        task.seal_candidate().unwrap();

        let res = LoopCoordinator::validate_loop_action(LoopRole::OuterLoop, "publish", &task);
        assert!(matches!(res, Err(KernelError::MissingAuthority(_))));
    }
}
