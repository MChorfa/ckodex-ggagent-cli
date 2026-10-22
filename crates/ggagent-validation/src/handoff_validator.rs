//! # Partitioned Handoff Validator (Chapters 3 & 26)
//!
//! Validates state handoff manifests across node migrations, failovers, or sandbox boundaries:
//! - Checkpoint digest cryptographic verification
//! - Monotonic generation advancement
//! - Strict budget non-inflation invariant
//! - Coordinated state consistency

use crate::error::ValidationError;
use ggagent_kernel::budget::ExecutionBudget;
use ggagent_kernel::handoff::HandoffManifest;

pub struct HandoffValidator;

impl HandoffValidator {
    /// Validates an incoming handoff manifest against current authoritative node state
    pub fn validate_handoff(
        manifest: &HandoffManifest,
        current_node_generation: u64,
        max_permitted_budget: &ExecutionBudget,
    ) -> Result<(), ValidationError> {
        // 1. Checkpoint Digest Cryptographic Verification
        if !manifest.verify_digest() {
            return Err(ValidationError::InvalidHandoffViolation(format!(
                "Checkpoint digest mismatch for task {}: computed digest does not match manifest {}",
                manifest.task_id, manifest.checkpoint_digest
            )));
        }

        // 2. Monotonic Generation Advancement: target generation must strictly exceed current generation
        if manifest.target_generation <= current_node_generation {
            return Err(ValidationError::InvalidHandoffViolation(format!(
                "Handoff target generation ({}) is not strictly greater than current node generation ({})",
                manifest.target_generation, current_node_generation
            )));
        }

        // 3. Monotonic Generation Advancement: target > source
        if manifest.target_generation <= manifest.source_generation {
            return Err(ValidationError::InvalidHandoffViolation(format!(
                "Target generation ({}) must exceed source generation ({})",
                manifest.target_generation, manifest.source_generation
            )));
        }

        // 4. Strict Budget Non-Inflation Invariant (Chapter 26)
        // The remaining budget in the handoff cannot exceed the maximum permitted budget
        if manifest.remaining_budget.remaining_steps() > max_permitted_budget.remaining_steps() {
            return Err(ValidationError::BudgetExhaustionViolation(format!(
                "Budget inflation detected: handoff steps ({}) exceed maximum permitted ({})",
                manifest.remaining_budget.remaining_steps(),
                max_permitted_budget.remaining_steps()
            )));
        }

        if manifest.remaining_budget.remaining_effects() > max_permitted_budget.remaining_effects()
        {
            return Err(ValidationError::BudgetExhaustionViolation(format!(
                "Budget inflation detected: handoff mutating effects ({}) exceed maximum permitted ({})",
                manifest.remaining_budget.remaining_effects(),
                max_permitted_budget.remaining_effects()
            )));
        }

        // 5. Coordinated State Consistency
        if manifest.coordinated_state.candidate
            == ggagent_kernel::coordinated_states::CandidateLifecycle::Sealed
            && manifest.coordinated_state.candidate_digest.is_none()
        {
            return Err(ValidationError::InvalidHandoffViolation(
                "Coordinated state is SEALED but missing candidate_digest".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ggagent_kernel::coordinated_states::CoordinatedTaskState;
    use ggagent_kernel::handoff::HandoffParams;
    use ggagent_kernel::vector_state::VectorState;

    #[test]
    fn test_valid_handoff_validation() {
        let vstate = VectorState::new("task-val-1");
        let cstate = CoordinatedTaskState::new("task-val-1");
        let budget = ExecutionBudget::new(10, 5, 1000, 5000);
        let max_budget = ExecutionBudget::new(20, 10, 2000, 10000);

        let manifest = HandoffManifest::new(HandoffParams {
            task_id: "task-val-1".into(),
            source_node_id: "node-1".into(),
            target_node_id: "node-2".into(),
            source_generation: 1,
            target_generation: 2,
            vector_state: vstate,
            coordinated_state: cstate,
            remaining_budget: budget,
        })
        .unwrap();

        assert!(HandoffValidator::validate_handoff(&manifest, 1, &max_budget).is_ok());
    }

    #[test]
    fn test_stale_generation_handoff_rejected() {
        let vstate = VectorState::new("task-val-2");
        let cstate = CoordinatedTaskState::new("task-val-2");
        let budget = ExecutionBudget::new(10, 5, 1000, 5000);
        let max_budget = ExecutionBudget::new(20, 10, 2000, 10000);

        let manifest = HandoffManifest::new(HandoffParams {
            task_id: "task-val-2".into(),
            source_node_id: "node-1".into(),
            target_node_id: "node-2".into(),
            source_generation: 1,
            target_generation: 2,
            vector_state: vstate,
            coordinated_state: cstate,
            remaining_budget: budget,
        })
        .unwrap();

        // If current node generation is already at 3, target generation 2 is stale!
        let err = HandoffValidator::validate_handoff(&manifest, 3, &max_budget);
        assert!(matches!(
            err,
            Err(ValidationError::InvalidHandoffViolation(_))
        ));
    }
}
