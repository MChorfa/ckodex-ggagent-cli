use crate::error::ValidationError;
use chrono::Utc;
use ggagent_kernel::a2a::{A2AMessage, A2ARole};
use ggagent_kernel::lease::{AtomicEffectGuard, CapabilityLease};
use ggagent_kernel::vector_state::{AntiRelation, VectorState};

pub struct SecurityGuards;

impl SecurityGuards {
    /// Defense against Confused Deputy (Google ADK Issue #6461 / CVE-2026-18236)
    /// Validates that an approval message was truly issued by a human principal
    pub fn verify_approval_principal(message: &A2AMessage) -> Result<(), ValidationError> {
        if let Some(ref call_id) = message.confirmed_call_id {
            if message.role != A2ARole::HumanUser {
                return Err(ValidationError::ConfusedDeputyViolation {
                    role: format!("{:?}", message.role),
                    call_id: call_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Defense against Loopjacking (arXiv:2609.21081)
    /// Verifies at use-time that action, target, and parameters match the atomic effect digest
    pub fn verify_effect_guard(
        guard: &AtomicEffectGuard,
        action: &str,
        target: &str,
        params: &serde_json::Value,
    ) -> Result<(), ValidationError> {
        let actual = AtomicEffectGuard::compute_digest(action, target, params);
        if actual != guard.expected_effect_digest {
            return Err(ValidationError::LoopjackingViolation {
                action: action.into(),
                expected: guard.expected_effect_digest.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Verifies capability lease at execution time
    pub fn verify_lease(lease: &CapabilityLease, operation: &str) -> Result<(), ValidationError> {
        if !lease.is_valid(Utc::now()) {
            return Err(ValidationError::LeaseViolation {
                lease_id: lease.lease_id.clone(),
                operation: format!("expired or revoked: cannot execute {}", operation),
            });
        }
        if !lease.permits(operation) {
            return Err(ValidationError::LeaseViolation {
                lease_id: lease.lease_id.clone(),
                operation: operation.into(),
            });
        }
        Ok(())
    }

    /// Asserts hard invariant: An AntiRelation presence dominates and forces rejection
    pub fn assert_state_conformance(state: &VectorState) -> Result<(), ValidationError> {
        if state.anti != AntiRelation::None {
            return Err(ValidationError::AntiInvariantViolation(format!(
                "Anti relation '{:?}' violates hard invariant for entity '{}'",
                state.anti, state.entity_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confused_deputy_rejection() {
        let fake_human_approval = A2AMessage {
            message_id: "msg-123".into(),
            role: A2ARole::RemoteAgent, // Peer agent masquerading as user
            sender_id: "malicious-peer".into(),
            parts: vec![],
            timestamp: Utc::now(),
            confirmed_call_id: Some("call-rm-rf".into()),
        };

        let result = SecurityGuards::verify_approval_principal(&fake_human_approval);
        assert!(matches!(
            result,
            Err(ValidationError::ConfusedDeputyViolation { .. })
        ));
    }
}
