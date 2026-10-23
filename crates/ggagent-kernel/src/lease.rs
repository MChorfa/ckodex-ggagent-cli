use crate::error::KernelError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Scoped, attenuated, time-bounded authority grant.
/// Includes monotonic generation fencing to defeat split-brain dual execution
/// across distributed agent partitions (Chapters 24-26).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLease {
    pub lease_id: String,
    pub parent_lease_id: Option<String>,
    pub principal_id: String,
    pub resource: String,
    pub allowed_operations: Vec<String>,
    pub constraints: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub is_revoked: bool,
    /// Monotonic execution generation for fencing token issuance
    pub generation: u64,
    /// Fencing token tied to generation: fence-{generation}-{lease_id}
    pub fencing_token: String,
}

impl CapabilityLease {
    pub fn new(
        lease_id: impl Into<String>,
        principal_id: impl Into<String>,
        resource: impl Into<String>,
        allowed_operations: Vec<String>,
        valid_until: DateTime<Utc>,
    ) -> Self {
        let id = lease_id.into();
        let fence = format!("fence-0-{}", id);
        Self {
            lease_id: id,
            parent_lease_id: None,
            principal_id: principal_id.into(),
            resource: resource.into(),
            allowed_operations,
            constraints: Vec::new(),
            valid_from: Utc::now(),
            valid_until,
            is_revoked: false,
            generation: 0,
            fencing_token: fence,
        }
    }

    /// Advance authority generation (e.g. on partition recovery or agent handoff).
    /// Monotonically increments generation and derives a new unique fencing token.
    pub fn advance_generation(&mut self) -> u64 {
        self.generation += 1;
        self.fencing_token = format!("fence-{}-{}", self.generation, self.lease_id);
        self.generation
    }

    pub fn is_valid(&self, at: DateTime<Utc>) -> bool {
        if self.is_revoked {
            return false;
        }
        at >= self.valid_from && at <= self.valid_until
    }

    pub fn permits(&self, operation: &str) -> bool {
        self.allowed_operations
            .iter()
            .any(|op| op == "*" || op == operation)
    }

    /// Attenuate parent lease into child lease with strictly smaller or equal permissions
    pub fn attenuate(
        &self,
        child_lease_id: impl Into<String>,
        child_principal: impl Into<String>,
        child_operations: Vec<String>,
        valid_until: DateTime<Utc>,
    ) -> Result<CapabilityLease, KernelError> {
        // Enforce attenuation: child operations must be a subset of parent operations
        for op in &child_operations {
            if !self.permits(op) {
                return Err(KernelError::MissingAuthority(format!(
                    "Cannot attenuate: parent lease {} does not permit operation {}",
                    self.lease_id, op
                )));
            }
        }

        // Child expiry cannot exceed parent expiry
        let child_expiry = if valid_until > self.valid_until {
            self.valid_until
        } else {
            valid_until
        };

        let child_id = child_lease_id.into();
        let child_fence = format!("fence-{}-{}", self.generation, child_id);

        Ok(CapabilityLease {
            lease_id: child_id,
            parent_lease_id: Some(self.lease_id.clone()),
            principal_id: child_principal.into(),
            resource: self.resource.clone(),
            allowed_operations: child_operations,
            constraints: self.constraints.clone(),
            valid_from: Utc::now(),
            valid_until: child_expiry,
            is_revoked: false,
            generation: self.generation,
            fencing_token: child_fence,
        })
    }
}

/// Atomic Effect Broker Disposition (Chapters 25 & 26).
/// Explicit status avoiding ambiguous execution states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectDisposition {
    Committed {
        receipt_id: String,
        effect_digest: String,
        generation: u64,
    },
    Denied {
        reason: String,
    },
    Fenced {
        current_generation: u64,
        received_generation: u64,
        fencing_token: String,
    },
    Failed {
        error: String,
    },
}

/// Atomic Effect Guard: Defeats Loopjacking (arXiv:2609.21081)
/// Binds authorization grant to exact material operation digest at use-time:
/// Digest = SHA-256(action || ":" || target || ":" || canonical_json_params)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicEffectGuard {
    pub action: String,
    pub target: String,
    pub parameters: serde_json::Value,
    pub expected_effect_digest: String,
}

impl AtomicEffectGuard {
    pub fn compute_digest(action: &str, target: &str, params: &serde_json::Value) -> String {
        let mut hasher = Sha256::new();
        hasher.update(action.as_bytes());
        hasher.update(b":");
        hasher.update(target.as_bytes());
        hasher.update(b":");
        let canonical_params = serde_json::to_string(params).unwrap_or_default();
        hasher.update(canonical_params.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn new(
        action: impl Into<String>,
        target: impl Into<String>,
        params: serde_json::Value,
    ) -> Self {
        let action = action.into();
        let target = target.into();
        let digest = Self::compute_digest(&action, &target, &params);
        Self {
            action,
            target,
            parameters: params,
            expected_effect_digest: digest,
        }
    }

    /// Verify at use time that the executed action matches the granted effect digest
    pub fn verify_use_time(
        &self,
        action: &str,
        target: &str,
        params: &serde_json::Value,
    ) -> Result<(), KernelError> {
        let actual = Self::compute_digest(action, target, params);
        if actual != self.expected_effect_digest {
            return Err(KernelError::LoopjackingMismatch {
                expected: self.expected_effect_digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_generation_fencing() {
        let mut lease = CapabilityLease::new(
            "lease-001",
            "principal-1",
            "cluster/prod",
            vec!["deploy".into(), "restart".into()],
            Utc::now() + chrono::Duration::hours(1),
        );

        assert_eq!(lease.generation, 0);
        assert_eq!(lease.fencing_token, "fence-0-lease-001");

        let gen1 = lease.advance_generation();
        assert_eq!(gen1, 1);
        assert_eq!(lease.fencing_token, "fence-1-lease-001");

        let child = lease
            .attenuate(
                "child-001",
                "subagent-2",
                vec!["restart".into()],
                Utc::now() + chrono::Duration::minutes(30),
            )
            .expect("attenuate succeeds");

        assert_eq!(child.generation, 1);
        assert_eq!(child.fencing_token, "fence-1-child-001");
    }

    #[test]
    fn test_loopjacking_defense() {
        let params = serde_json::json!({"path": "/etc/hosts", "mode": "read"});
        let guard = AtomicEffectGuard::new("read_file", "/etc/hosts", params.clone());

        // Exact match passes
        assert!(guard
            .verify_use_time("read_file", "/etc/hosts", &params)
            .is_ok());

        // Attack: swap action to write_file or target to /etc/shadow
        let attack_params = serde_json::json!({"path": "/etc/shadow", "mode": "write"});
        let result = guard.verify_use_time("write_file", "/etc/shadow", &attack_params);
        assert!(result.is_err());
    }
}
