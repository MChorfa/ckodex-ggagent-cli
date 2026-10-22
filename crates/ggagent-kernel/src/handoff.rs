//! # Partitioned Handoff Protocol (Chapters 3 & 26)
//!
//! Enforces zero-credential-inheritance, explicit state migration across nodes,
//! sandboxes, or network partition boundaries.
//!
//! Transfers explicit task state, cryptographic checkpoint digest, monotonic generation advancement,
//! remaining budget, and pending effect digests.

use crate::budget::ExecutionBudget;
use crate::coordinated_states::CoordinatedTaskState;
use crate::error::KernelError;
use crate::vector_state::VectorState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Structured Partitioned Handoff Manifest (Chapter 26)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffManifest {
    pub contract_version: String,
    pub task_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub source_generation: u64,
    pub target_generation: u64,
    pub checkpoint_digest: String,
    pub vector_state: VectorState,
    pub coordinated_state: CoordinatedTaskState,
    pub remaining_budget: ExecutionBudget,
    pub pending_effect_digests: Vec<String>,
    pub evidence_receipt_ids: Vec<String>,
    pub issued_at: DateTime<Utc>,
}

/// Parameters for creating a partitioned handoff manifest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffParams {
    pub task_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub source_generation: u64,
    pub target_generation: u64,
    pub vector_state: VectorState,
    pub coordinated_state: CoordinatedTaskState,
    pub remaining_budget: ExecutionBudget,
}

impl HandoffManifest {
    pub fn compute_checkpoint_digest(
        task_id: &str,
        source_gen: u64,
        target_gen: u64,
        vector_state: &VectorState,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(task_id.as_bytes());
        hasher.update(b":");
        hasher.update(source_gen.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(target_gen.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(vector_state.to_canonical_string().as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn new(params: HandoffParams) -> Result<Self, KernelError> {
        // Invariant 1: Target generation must strictly advance
        if params.target_generation <= params.source_generation {
            return Err(KernelError::InvalidHandoff {
                reason: format!(
                    "Target generation ({}) must be strictly greater than source generation ({})",
                    params.target_generation, params.source_generation
                ),
            });
        }

        let digest = Self::compute_checkpoint_digest(
            &params.task_id,
            params.source_generation,
            params.target_generation,
            &params.vector_state,
        );

        Ok(Self {
            contract_version: "ckodex.handoff/v1.0".into(),
            task_id: params.task_id,
            source_node_id: params.source_node_id,
            target_node_id: params.target_node_id,
            source_generation: params.source_generation,
            target_generation: params.target_generation,
            checkpoint_digest: digest,
            vector_state: params.vector_state,
            coordinated_state: params.coordinated_state,
            remaining_budget: params.remaining_budget,
            pending_effect_digests: Vec::new(),
            evidence_receipt_ids: Vec::new(),
            issued_at: Utc::now(),
        })
    }

    /// Verify checkpoint digest integrity
    pub fn verify_digest(&self) -> bool {
        let expected = Self::compute_checkpoint_digest(
            &self.task_id,
            self.source_generation,
            self.target_generation,
            &self.vector_state,
        );
        self.checkpoint_digest == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handoff_manifest_integrity_and_generation_advancement() {
        let vstate = VectorState::new("task-h1");
        let cstate = CoordinatedTaskState::new("task-h1");
        let budget = ExecutionBudget::new(10, 5, 1000, 5000);

        // Target generation 2 > source 1 succeeds
        let manifest = HandoffManifest::new(HandoffParams {
            task_id: "task-h1".into(),
            source_node_id: "node-alpha".into(),
            target_node_id: "node-beta".into(),
            source_generation: 1,
            target_generation: 2,
            vector_state: vstate,
            coordinated_state: cstate,
            remaining_budget: budget,
        })
        .expect("valid handoff");

        assert!(manifest.verify_digest());
        assert_eq!(manifest.source_generation, 1);
        assert_eq!(manifest.target_generation, 2);

        // Stale or equal generation fails
        let vstate2 = VectorState::new("task-h2");
        let cstate2 = CoordinatedTaskState::new("task-h2");
        let budget2 = ExecutionBudget::new(10, 5, 1000, 5000);
        let err = HandoffManifest::new(HandoffParams {
            task_id: "task-h2".into(),
            source_node_id: "node-alpha".into(),
            target_node_id: "node-beta".into(),
            source_generation: 2,
            target_generation: 2,
            vector_state: vstate2,
            coordinated_state: cstate2,
            remaining_budget: budget2,
        });
        assert!(matches!(err, Err(KernelError::InvalidHandoff { .. })));
    }
}
