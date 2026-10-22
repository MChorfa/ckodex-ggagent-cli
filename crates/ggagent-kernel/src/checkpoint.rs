//! # Deterministic Checkpoint & Restore (Chapter 16)
//!
//! Provides point-in-time cryptographic checkpoints for durable agent workflows:
//! - Complete 7D vector state and 4D coordinated state snapshot
//! - Monotonic generation and epoch preservation
//! - Remaining budget state
//! - Cryptographically content-addressed checkpoint digest
//! - Safe replay without duplicating committed side effects

use crate::budget::ExecutionBudget;
use crate::coordinated_states::CoordinatedTaskState;
use crate::vector_state::VectorState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCheckpoint {
    pub checkpoint_id: String,
    pub task_id: String,
    pub generation: u64,
    pub epoch: u64,
    pub vector_state: VectorState,
    pub coordinated_state: CoordinatedTaskState,
    pub budget: ExecutionBudget,
    pub committed_effect_digests: Vec<String>,
    pub checkpoint_digest: String,
    pub created_at: DateTime<Utc>,
}

impl TaskCheckpoint {
    pub fn compute_digest(
        task_id: &str,
        generation: u64,
        epoch: u64,
        vstate: &VectorState,
        cstate: &CoordinatedTaskState,
        effects: &[String],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(task_id.as_bytes());
        hasher.update(b":");
        hasher.update(generation.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(epoch.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(vstate.to_canonical_string().as_bytes());
        hasher.update(b":");
        hasher.update(cstate.fencing_token.as_bytes());
        hasher.update(b":");
        for eff in effects {
            hasher.update(eff.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    pub fn create(
        task_id: impl Into<String>,
        generation: u64,
        epoch: u64,
        vector_state: VectorState,
        coordinated_state: CoordinatedTaskState,
        budget: ExecutionBudget,
        committed_effects: Vec<String>,
    ) -> Self {
        let tid = task_id.into();
        let checkpoint_id = format!("ckpt-{}", Uuid::new_v4());
        let digest = Self::compute_digest(
            &tid,
            generation,
            epoch,
            &vector_state,
            &coordinated_state,
            &committed_effects,
        );

        Self {
            checkpoint_id,
            task_id: tid,
            generation,
            epoch,
            vector_state,
            coordinated_state,
            budget,
            committed_effect_digests: committed_effects,
            checkpoint_digest: digest,
            created_at: Utc::now(),
        }
    }

    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_digest(
            &self.task_id,
            self.generation,
            self.epoch,
            &self.vector_state,
            &self.coordinated_state,
            &self.committed_effect_digests,
        );
        self.checkpoint_digest == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_creation_and_integrity() {
        let vstate = VectorState::new("task-ckpt-1");
        let cstate = CoordinatedTaskState::new("task-ckpt-1");
        let budget = ExecutionBudget::new(10, 5, 1000, 5000);
        let effects = vec!["sha256:effect1".into(), "sha256:effect2".into()];

        let ckpt = TaskCheckpoint::create("task-ckpt-1", 1, 3, vstate, cstate, budget, effects);

        assert!(ckpt.verify_integrity());

        let mut tampered = ckpt.clone();
        tampered.checkpoint_digest = "tampered".into();
        assert!(!tampered.verify_integrity());
    }
}
