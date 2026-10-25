//! # Context Guard (Section 2.2, INVARITH v0.2.0)
//!
//! Enforces:
//! 1. Authority precedes ContextRoot: ContextRoot MUST be bound to a valid CapabilityLease
//!    and cannot precede the lease's validity window.
//! 2. ContextFault detection: Distinguishes Missing, Unavailable, Stale, IntegrityFailure,
//!    and PolicyDenied. Rejects silent fallback to lower-trust sources or synthetic data.

use crate::error::ValidationError;
use ggagent_kernel::governed_execution::{ContextFault, ContextRoot};
use ggagent_kernel::lease::CapabilityLease;

pub struct ContextGuard;

impl ContextGuard {
    /// Verify that ContextRoot was legitimately authorized by the referenced CapabilityLease.
    pub fn verify_context_precedence(
        context_root: &ContextRoot,
        lease: &CapabilityLease,
    ) -> Result<(), ValidationError> {
        context_root
            .verify_authority_precedence(lease)
            .map_err(|e| ValidationError::ContextFaultViolation(e.to_string()))
    }

    /// Check if a context read results in a ContextFault.
    /// If a fault is present, fail-closed: do not invent summaries or fall back silently.
    pub fn assert_no_context_fault(fault: Option<&ContextFault>) -> Result<(), ValidationError> {
        if let Some(f) = fault {
            let detail = match f {
                ContextFault::Missing { resource } => format!("Missing resource: {}", resource),
                ContextFault::Unavailable { resource, .. } => {
                    format!("Resource temporarily unavailable: {}", resource)
                }
                ContextFault::Stale {
                    current_epoch,
                    requested_epoch,
                } => format!(
                    "Stale context epoch: current={}, requested={}",
                    current_epoch, requested_epoch
                ),
                ContextFault::IntegrityFailure {
                    expected_digest,
                    actual_digest,
                } => format!(
                    "Integrity digest failure: expected={}, actual={}",
                    expected_digest, actual_digest
                ),
                ContextFault::PolicyDenied { reason } => format!("Policy denied: {}", reason),
            };
            return Err(ValidationError::ContextFaultViolation(detail));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_context_precedence_and_fault_defense() {
        let lease = CapabilityLease::new(
            "lease-ctx-001",
            "principal-data",
            "db/embeddings",
            vec!["read".into()],
            Utc::now() + Duration::hours(1),
        );

        let root = ContextRoot::new(
            "ctx-root-1",
            "lease-ctx-001",
            "sha256:dec",
            "sha256:obs",
            "SECRET",
        );

        assert!(ContextGuard::verify_context_precedence(&root, &lease).is_ok());

        // Fault detection: stale epoch is rejected
        let fault = ContextFault::Stale {
            current_epoch: 5,
            requested_epoch: 3,
        };
        assert!(ContextGuard::assert_no_context_fault(Some(&fault)).is_err());

        // Integrity failure is rejected
        let int_fault = ContextFault::IntegrityFailure {
            expected_digest: "sha256:aaa".into(),
            actual_digest: "sha256:bbb".into(),
        };
        assert!(ContextGuard::assert_no_context_fault(Some(&int_fault)).is_err());
    }
}
