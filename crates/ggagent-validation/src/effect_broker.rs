//! # Atomic Effect Broker (Chapters 25 & 26)
//!
//! Enforces:
//! 1. Monotonic generation fencing: Defeats split-brain execution across partitions.
//! 2. Exact use-time material binding: Defeats Loopjacking (arXiv:2609.21081).
//! 3. Idempotent effect dispatch: Prevents duplicate execution of side effects.
//! 4. Explicit disposition: `Committed`, `Denied`, `Fenced`, `Failed`.

use crate::error::ValidationError;
use crate::guards::SecurityGuards;
use ggagent_kernel::lease::{AtomicEffectGuard, CapabilityLease, EffectDisposition};
use std::collections::BTreeMap;
use tracing::warn;

/// Request payload for effect execution at the broker
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectRequest<'a> {
    pub lease: &'a CapabilityLease,
    pub guard: &'a AtomicEffectGuard,
    pub received_generation: u64,
    pub idempotency_key: &'a str,
    pub action: &'a str,
    pub target: &'a str,
    pub params: &'a serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct AtomicEffectBroker {
    /// Authoritative current execution generation
    pub current_generation: u64,
    /// Authoritative active fencing token
    pub authoritative_fencing_token: String,
    /// Idempotency cache: idempotency_key -> EffectDisposition
    pub idempotency_cache: BTreeMap<String, EffectDisposition>,
}

impl AtomicEffectBroker {
    pub fn new(initial_generation: u64, fencing_token: impl Into<String>) -> Self {
        Self {
            current_generation: initial_generation,
            authoritative_fencing_token: fencing_token.into(),
            idempotency_cache: BTreeMap::new(),
        }
    }

    /// Advance authoritative generation (e.g. partition migration, failover, handoff)
    pub fn advance_generation(&mut self, new_token: impl Into<String>) -> u64 {
        self.current_generation += 1;
        self.authoritative_fencing_token = new_token.into();
        self.current_generation
    }

    /// Execute or evaluate an effect request
    pub fn execute_effect(
        &mut self,
        req: &EffectRequest<'_>,
    ) -> Result<EffectDisposition, ValidationError> {
        // 1. Idempotency Check: if already executed in this broker session, return cached outcome
        if let Some(cached) = self.idempotency_cache.get(req.idempotency_key) {
            return Ok(cached.clone());
        }

        // 2. Generation Fencing Check (Chapters 24-26):
        // If the worker is running on a stale generation, strictly fence the effect.
        if req.received_generation < self.current_generation {
            warn!(
                current = self.current_generation,
                received = req.received_generation,
                token = %req.lease.fencing_token,
                "Partitioned split-brain attempt: fencing stale worker effect"
            );
            let fenced = EffectDisposition::Fenced {
                current_generation: self.current_generation,
                received_generation: req.received_generation,
                fencing_token: req.lease.fencing_token.clone(),
            };
            self.idempotency_cache
                .insert(req.idempotency_key.to_string(), fenced.clone());
            return Ok(fenced);
        }

        // 3. Lease Validation (Authority Precedes Capability)
        if let Err(e) = SecurityGuards::verify_lease(req.lease, req.action) {
            let denied = EffectDisposition::Denied {
                reason: format!("Lease verification failed: {}", e),
            };
            self.idempotency_cache
                .insert(req.idempotency_key.to_string(), denied.clone());
            return Ok(denied);
        }

        // 4. Use-Time Material Binding (Anti-Loopjacking Check)
        if let Err(e) =
            SecurityGuards::verify_effect_guard(req.guard, req.action, req.target, req.params)
        {
            let denied = EffectDisposition::Denied {
                reason: format!("Anti-loopjacking check failed: {}", e),
            };
            self.idempotency_cache
                .insert(req.idempotency_key.to_string(), denied.clone());
            return Ok(denied);
        }

        // 5. Commit Effect
        let receipt_id = format!("rcpt-{}-{}", self.current_generation, req.idempotency_key);
        let effect_digest = AtomicEffectGuard::compute_digest(req.action, req.target, req.params);
        let committed = EffectDisposition::Committed {
            receipt_id,
            effect_digest,
            generation: self.current_generation,
        };

        self.idempotency_cache
            .insert(req.idempotency_key.to_string(), committed.clone());
        Ok(committed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_generation_fencing_defeats_split_brain() {
        let mut broker = AtomicEffectBroker::new(1, "fence-1-task-root");

        let mut lease_worker1 = CapabilityLease::new(
            "lease-1",
            "worker-1",
            "db/cluster",
            vec!["write".into()],
            Utc::now() + Duration::hours(1),
        );
        lease_worker1.generation = 1;

        let params = serde_json::json!({"query": "DROP TABLE test;"});
        let guard = AtomicEffectGuard::new("write", "db/cluster", params.clone());

        // First worker succeeds on generation 1
        let req1 = EffectRequest {
            lease: &lease_worker1,
            guard: &guard,
            received_generation: 1,
            idempotency_key: "idem-101",
            action: "write",
            target: "db/cluster",
            params: &params,
        };
        let disp1 = broker.execute_effect(&req1).unwrap();
        assert!(matches!(disp1, EffectDisposition::Committed { .. }));

        // Partition event: broker advances to generation 2 (e.g. worker-2 took over)
        broker.advance_generation("fence-2-task-root");

        // Old worker-1 emerges from network partition with delayed message (generation 1)
        let req_stale = EffectRequest {
            lease: &lease_worker1,
            guard: &guard,
            received_generation: 1,
            idempotency_key: "idem-102",
            action: "write",
            target: "db/cluster",
            params: &params,
        };
        let disp_stale = broker.execute_effect(&req_stale).unwrap();

        // Must be strictly FENCED
        match disp_stale {
            EffectDisposition::Fenced {
                current_generation,
                received_generation,
                ..
            } => {
                assert_eq!(current_generation, 2);
                assert_eq!(received_generation, 1);
            }
            _ => panic!("Expected Fenced disposition for stale generation"),
        }
    }

    #[test]
    fn test_idempotent_effect_replay() {
        let mut broker = AtomicEffectBroker::new(0, "fence-0-test");
        let lease = CapabilityLease::new(
            "lease-0",
            "worker-0",
            "res",
            vec!["exec".into()],
            Utc::now() + Duration::hours(1),
        );
        let params = serde_json::json!({"run": true});
        let guard = AtomicEffectGuard::new("exec", "res", params.clone());

        let req = EffectRequest {
            lease: &lease,
            guard: &guard,
            received_generation: 0,
            idempotency_key: "key-dup",
            action: "exec",
            target: "res",
            params: &params,
        };
        let res1 = broker.execute_effect(&req).unwrap();
        let res2 = broker.execute_effect(&req).unwrap();

        assert_eq!(res1, res2);
    }
}
