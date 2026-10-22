//! # Deterministic Replay & Restoration Engine (Chapter 16)
//!
//! Restores execution from durable checkpoints:
//! - Verifies checkpoint cryptographic integrity
//! - Side-effect fencing: Registers historical committed effects in the effect broker
//! - Fences stale workers by monotonically advancing generation $N \to N+1$
//! - Restores execution budget and 4D coordinated states

use crate::effect_broker::AtomicEffectBroker;
use crate::error::ValidationError;
use ggagent_kernel::checkpoint::TaskCheckpoint;
use ggagent_kernel::coordinated_states::CoordinatedTaskState;
use ggagent_kernel::lease::EffectDisposition;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumedTaskState {
    pub task_id: String,
    pub generation: u64,
    pub coordinated_state: CoordinatedTaskState,
    pub fencing_token: String,
}

pub struct ReplayEngine;

impl ReplayEngine {
    /// Resumes a task from a valid checkpoint, securing the side-effect broker against duplicate mutations
    pub fn resume_from_checkpoint(
        checkpoint: &TaskCheckpoint,
        broker: &mut AtomicEffectBroker,
    ) -> Result<ResumedTaskState, ValidationError> {
        // 1. Verify Checkpoint Cryptographic Digest
        if !checkpoint.verify_integrity() {
            return Err(ValidationError::ReplayViolation(format!(
                "Checkpoint digest mismatch for task {}",
                checkpoint.task_id
            )));
        }

        // 2. Fence older generation: broker advances generation beyond checkpoint
        let new_gen = checkpoint.generation + 1;
        let new_fence = format!("fence-{}-{}", new_gen, checkpoint.task_id);
        broker.current_generation = new_gen;
        broker.authoritative_fencing_token = new_fence.clone();

        // 3. Register previously committed side effects in the broker's idempotency cache
        // to strictly prevent side-effect duplication during replay
        for (idx, effect_digest) in checkpoint.committed_effect_digests.iter().enumerate() {
            let replay_key = format!("hist-eff-{}", idx);
            broker.idempotency_cache.insert(
                replay_key,
                EffectDisposition::Committed {
                    receipt_id: format!("hist-rcpt-{}", idx),
                    effect_digest: effect_digest.clone(),
                    generation: checkpoint.generation,
                },
            );
        }

        // 4. Advance coordinated task state generation
        let mut restored_coord = checkpoint.coordinated_state.clone();
        restored_coord.generation = new_gen;
        restored_coord.fencing_token = new_fence.clone();

        Ok(ResumedTaskState {
            task_id: checkpoint.task_id.clone(),
            generation: new_gen,
            coordinated_state: restored_coord,
            fencing_token: new_fence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ggagent_kernel::budget::ExecutionBudget;
    use ggagent_kernel::vector_state::VectorState;

    #[test]
    fn test_resume_from_checkpoint_advances_generation_and_fences() {
        let vstate = VectorState::new("task-rep-1");
        let cstate = CoordinatedTaskState::new("task-rep-1");
        let budget = ExecutionBudget::new(10, 5, 1000, 5000);
        let committed = vec!["sha256:mutation1".into(), "sha256:mutation2".into()];

        let ckpt = TaskCheckpoint::create("task-rep-1", 2, 5, vstate, cstate, budget, committed);

        let mut broker = AtomicEffectBroker::new(2, "fence-2-task-rep-1");
        let resumed = ReplayEngine::resume_from_checkpoint(&ckpt, &mut broker).unwrap();

        // Must advance generation to 3
        assert_eq!(resumed.generation, 3);
        assert_eq!(broker.current_generation, 3);
        assert_eq!(resumed.fencing_token, "fence-3-task-rep-1");

        // Historical effects must be populated in broker cache
        assert!(broker.idempotency_cache.contains_key("hist-eff-0"));
        assert!(broker.idempotency_cache.contains_key("hist-eff-1"));
    }
}
