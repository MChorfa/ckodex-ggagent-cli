//! # Coordinated Multidimensional State Machines (Chapter 24)
//!
//! Replaces collapsed boolean and single-lifecycle representations with four orthogonal,
//! formally coordinated state machines:
//! 1. `ExecutionLifecycle`: Runtime substrate process execution
//! 2. `AuthorityLifecycle`: Scoped capability lease standing
//! 3. `CandidateLifecycle`: Immutable candidate artifact progression
//! 4. `ReclamationLifecycle`: Workspace and sandbox resource cleanup
//!
//! Also defines the Four Formal Failure Modes (Chapter 30):
//! - `ContainmentEscape`
//! - `AuthorizedHarm`
//! - `VerificationFailure`
//! - `GovernanceFailure`

use crate::error::KernelError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 1. Execution Lifecycle: Tracks process/runtime substrate lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionLifecycle {
    #[default]
    Requested,
    Admitted,
    Provisioning,
    Ready,
    Running,
    Stopping,
    Stopped,
    Denied,
    Failed,
}

/// 2. Authority Lifecycle: Tracks validity and standing of the capability lease
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityLifecycle {
    #[default]
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
    Closed,
}

/// 3. Candidate Lifecycle: Tracks candidate artifacts (patches, files, models)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateLifecycle {
    #[default]
    Absent,
    Staged,
    Sealed,
    UnderReview,
    Accepted,
    Rejected,
    Quarantined,
}

/// 4. Reclamation Lifecycle: Tracks resource cleanup and sandbox sanitization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReclamationLifecycle {
    #[default]
    Allocated,
    CleanupPending,
    Reclaimed,
    CleanupFailed,
}

/// The Four Formal Failure Modes (Chapter 30: Quality and Interview Defense)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureClassification {
    /// Attempt or occurrence of breaking out of isolation boundary
    ContainmentEscape,
    /// Operation was syntactically authorized, but produced destructive side effects
    AuthorizedHarm,
    /// Candidate artifact or execution result failed objective verification
    VerificationFailure,
    /// Failure in authority, lease, admission, or fencing coordination
    GovernanceFailure,
}

/// Coordinated Multidimensional Task State (Chapter 24)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatedTaskState {
    pub task_id: String,
    pub generation: u64,
    pub fencing_token: String,
    pub execution: ExecutionLifecycle,
    pub authority: AuthorityLifecycle,
    pub candidate: CandidateLifecycle,
    pub reclamation: ReclamationLifecycle,
    pub candidate_digest: Option<String>,
    pub failure_classification: Option<FailureClassification>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CoordinatedTaskState {
    pub fn new(task_id: impl Into<String>) -> Self {
        let id = task_id.into();
        let now = Utc::now();
        let fence = format!("fence-0-{}", &id);
        Self {
            task_id: id,
            generation: 0,
            fencing_token: fence,
            execution: ExecutionLifecycle::Requested,
            authority: AuthorityLifecycle::Pending,
            candidate: CandidateLifecycle::Absent,
            reclamation: ReclamationLifecycle::Allocated,
            candidate_digest: None,
            failure_classification: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Advance execution generation (fencing partition handoff)
    pub fn advance_generation(&mut self) -> u64 {
        self.generation += 1;
        self.fencing_token = format!("fence-{}-{}", self.generation, self.task_id);
        self.updated_at = Utc::now();
        self.generation
    }

    /// Transition Execution Lifecycle with cross-machine invariant checks
    pub fn transition_execution(&mut self, next: ExecutionLifecycle) -> Result<(), KernelError> {
        // Invariant 1: Running strictly requires Authority to be Active
        if next == ExecutionLifecycle::Running && self.authority != AuthorityLifecycle::Active {
            return Err(KernelError::CoordinatedStateViolation(format!(
                "Cannot transition Execution to RUNNING: Authority lifecycle is {:?} (must be ACTIVE)",
                self.authority
            )));
        }

        // Invariant 2: Active execution cannot proceed if Reclamation is underway
        if (matches!(
            next,
            ExecutionLifecycle::Requested
                | ExecutionLifecycle::Admitted
                | ExecutionLifecycle::Provisioning
                | ExecutionLifecycle::Ready
                | ExecutionLifecycle::Running
        )) && self.reclamation != ReclamationLifecycle::Allocated
        {
            return Err(KernelError::CoordinatedStateViolation(format!(
                "Cannot execute in state {:?}: Reclamation lifecycle is {:?}",
                next, self.reclamation
            )));
        }

        self.execution = next;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Transition Authority Lifecycle with automatic Execution coordination
    pub fn transition_authority(&mut self, next: AuthorityLifecycle) -> Result<(), KernelError> {
        self.authority = next;
        self.updated_at = Utc::now();

        // Cross-machine cascade: if authority is lost while running, execution must halt
        if matches!(
            next,
            AuthorityLifecycle::Suspended
                | AuthorityLifecycle::Revoked
                | AuthorityLifecycle::Expired
                | AuthorityLifecycle::Closed
        ) && self.execution == ExecutionLifecycle::Running
        {
            self.execution = ExecutionLifecycle::Stopping;
        }

        Ok(())
    }

    /// Stage a candidate artifact
    pub fn stage_candidate(&mut self, digest: impl Into<String>) -> Result<(), KernelError> {
        if self.reclamation != ReclamationLifecycle::Allocated {
            return Err(KernelError::CoordinatedStateViolation(format!(
                "Cannot stage candidate: Reclamation is {:?}",
                self.reclamation
            )));
        }

        if matches!(
            self.candidate,
            CandidateLifecycle::Sealed | CandidateLifecycle::UnderReview
        ) {
            return Err(KernelError::CoordinatedStateViolation(
                "Cannot stage new candidate while previous candidate is Sealed or UnderReview without explicit rejection".into(),
            ));
        }

        self.candidate = CandidateLifecycle::Staged;
        self.candidate_digest = Some(digest.into());
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Seal candidate: makes artifact immutable and locks digest
    pub fn seal_candidate(&mut self) -> Result<(), KernelError> {
        if self.candidate != CandidateLifecycle::Staged {
            return Err(KernelError::CoordinatedStateViolation(format!(
                "Cannot seal candidate: Candidate lifecycle is {:?} (must be STAGED)",
                self.candidate
            )));
        }
        if self.candidate_digest.is_none() {
            return Err(KernelError::CoordinatedStateViolation(
                "Cannot seal candidate: Missing candidate digest".into(),
            ));
        }

        self.candidate = CandidateLifecycle::Sealed;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Submit sealed candidate for independent review
    pub fn submit_candidate_for_review(&mut self) -> Result<(), KernelError> {
        if self.candidate != CandidateLifecycle::Sealed {
            return Err(KernelError::CoordinatedStateViolation(format!(
                "Cannot submit candidate for review: Candidate is {:?} (must be SEALED)",
                self.candidate
            )));
        }

        self.candidate = CandidateLifecycle::UnderReview;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Accept candidate artifact: requires UnderReview and Active Authority
    pub fn accept_candidate(&mut self) -> Result<(), KernelError> {
        if self.candidate != CandidateLifecycle::UnderReview {
            return Err(KernelError::CoordinatedStateViolation(format!(
                "Cannot accept candidate: Candidate is {:?} (must be UNDER_REVIEW)",
                self.candidate
            )));
        }
        if self.authority != AuthorityLifecycle::Active {
            return Err(KernelError::CoordinatedStateViolation(format!(
                "Cannot accept candidate: Authority is {:?} (must be ACTIVE)",
                self.authority
            )));
        }

        self.candidate = CandidateLifecycle::Accepted;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Reject candidate
    pub fn reject_candidate(&mut self, reason: impl Into<String>) -> Result<(), KernelError> {
        let _ = reason.into();
        self.candidate = CandidateLifecycle::Rejected;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Quarantine candidate
    pub fn quarantine_candidate(&mut self, reason: impl Into<String>) -> Result<(), KernelError> {
        let _ = reason.into();
        self.candidate = CandidateLifecycle::Quarantined;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Classify failure with formal failure mode taxonomy
    pub fn mark_failure(&mut self, class: FailureClassification, detail: impl Into<String>) {
        let _ = detail.into();
        self.failure_classification = Some(class);
        self.execution = ExecutionLifecycle::Failed;
        self.updated_at = Utc::now();
    }

    /// Start sandbox cleanup / reclamation
    pub fn start_reclamation(&mut self) -> Result<(), KernelError> {
        if self.execution == ExecutionLifecycle::Running {
            self.execution = ExecutionLifecycle::Stopping;
        }
        self.reclamation = ReclamationLifecycle::CleanupPending;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Mark reclamation successfully completed
    pub fn complete_reclamation(&mut self) -> Result<(), KernelError> {
        if self.execution == ExecutionLifecycle::Running {
            return Err(KernelError::CoordinatedStateViolation(
                "Cannot complete reclamation while execution is still RUNNING".into(),
            ));
        }
        self.reclamation = ReclamationLifecycle::Reclaimed;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_running_requires_active_authority() {
        let mut state = CoordinatedTaskState::new("task-42");

        // Attempting to run when authority is Pending must fail
        assert_eq!(state.authority, AuthorityLifecycle::Pending);
        let res = state.transition_execution(ExecutionLifecycle::Running);
        assert!(res.is_err());

        // Activate authority
        state
            .transition_authority(AuthorityLifecycle::Active)
            .unwrap();
        assert!(state
            .transition_execution(ExecutionLifecycle::Running)
            .is_ok());

        // Revoking authority forces running execution to Stopping
        state
            .transition_authority(AuthorityLifecycle::Revoked)
            .unwrap();
        assert_eq!(state.execution, ExecutionLifecycle::Stopping);
    }

    #[test]
    fn test_candidate_progression_invariants() {
        let mut state = CoordinatedTaskState::new("task-100");
        state
            .transition_authority(AuthorityLifecycle::Active)
            .unwrap();

        // 1. Stage
        state.stage_candidate("sha256-abcdef").unwrap();
        assert_eq!(state.candidate, CandidateLifecycle::Staged);

        // Cannot submit directly from staged without sealing
        assert!(state.submit_candidate_for_review().is_err());

        // 2. Seal
        state.seal_candidate().unwrap();
        assert_eq!(state.candidate, CandidateLifecycle::Sealed);

        // 3. Submit for review
        state.submit_candidate_for_review().unwrap();
        assert_eq!(state.candidate, CandidateLifecycle::UnderReview);

        // 4. Accept
        state.accept_candidate().unwrap();
        assert_eq!(state.candidate, CandidateLifecycle::Accepted);
    }

    #[test]
    fn test_reclamation_blocks_execution() {
        let mut state = CoordinatedTaskState::new("task-200");
        state.start_reclamation().unwrap();
        assert_eq!(state.reclamation, ReclamationLifecycle::CleanupPending);

        // Execution cannot be admitted once reclamation started
        let res = state.transition_execution(ExecutionLifecycle::Admitted);
        assert!(res.is_err());
    }
}
