use crate::error::KernelError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Scoped, attenuated, time-bounded authority grant.
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
}

impl CapabilityLease {
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

        Ok(CapabilityLease {
            lease_id: child_lease_id.into(),
            parent_lease_id: Some(self.lease_id.clone()),
            principal_id: child_principal.into(),
            resource: self.resource.clone(),
            allowed_operations: child_operations,
            constraints: self.constraints.clone(),
            valid_from: Utc::now(),
            valid_until: child_expiry,
            is_revoked: false,
        })
    }
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
