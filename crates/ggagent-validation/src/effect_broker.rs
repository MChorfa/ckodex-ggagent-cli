//! # Atomic Effect Broker (Chapters 25 & 26 & INVARITH v0.2.0)
//!
//! Enforces:
//! 1. Monotonic generation fencing: Defeats split-brain execution across partitions.
//! 2. Exact use-time material binding: Defeats Loopjacking (arXiv:2609.21081).
//! 3. 7-Stage Effect Safety Transactional FSM:
//!    PROPOSED -> AUTHORIZED -> PREPARED -> CLAIMED -> APPLYING -> RECONCILED -> COMMITTED
//! 4. Explicit IN_DOUBT state handling (GFX-S09): On timeout/crash/network partition,
//!    mark IN_DOUBT, observe and reconcile before any retry! NO BLIND RETRIES.
//! 5. Explicit disposition: `Prepared`, `Committed`, `InDoubt`, `Denied`, `Fenced`, `Failed`.

use crate::error::ValidationError;
use crate::guards::SecurityGuards;
use chrono::Utc;
use ggagent_kernel::governed_execution::EffectStage;
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
    /// Transactional effect safety journal: idempotency_key -> EffectStage
    pub effect_journal: BTreeMap<String, EffectStage>,
}

impl AtomicEffectBroker {
    pub fn new(initial_generation: u64, fencing_token: impl Into<String>) -> Self {
        Self {
            current_generation: initial_generation,
            authoritative_fencing_token: fencing_token.into(),
            idempotency_cache: BTreeMap::new(),
            effect_journal: BTreeMap::new(),
        }
    }

    /// Advance authoritative generation (e.g. partition migration, failover, handoff)
    pub fn advance_generation(&mut self, new_token: impl Into<String>) -> u64 {
        self.current_generation += 1;
        self.authoritative_fencing_token = new_token.into();
        self.current_generation
    }

    /// Step 3 of 7-Stage FSM: Durably prepare intent & exact preconditions before side-effects (GFX-S08).
    pub fn prepare_effect(
        &mut self,
        req: &EffectRequest<'_>,
    ) -> Result<EffectDisposition, ValidationError> {
        // Idempotency check: if already evaluated, return cached disposition
        if let Some(cached) = self.idempotency_cache.get(req.idempotency_key) {
            return Ok(cached.clone());
        }

        // Generation Fencing Check (GFX-S22)
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
            self.effect_journal.insert(
                req.idempotency_key.to_string(),
                EffectStage::Fenced {
                    current_generation: self.current_generation,
                    received_generation: req.received_generation,
                    fenced_at: Utc::now(),
                },
            );
            return Ok(fenced);
        }

        // Lease Validation (Authority Precedes Capability - GFX-S01)
        if let Err(e) = SecurityGuards::verify_lease(req.lease, req.action) {
            let denied = EffectDisposition::Denied {
                reason: format!("Lease verification failed: {}", e),
            };
            self.idempotency_cache
                .insert(req.idempotency_key.to_string(), denied.clone());
            self.effect_journal.insert(
                req.idempotency_key.to_string(),
                EffectStage::Denied {
                    reason: format!("Lease verification failed: {}", e),
                    denied_at: Utc::now(),
                },
            );
            return Ok(denied);
        }

        // Use-Time Material Binding (Anti-Loopjacking Check - GFX-S04)
        if let Err(e) =
            SecurityGuards::verify_effect_guard(req.guard, req.action, req.target, req.params)
        {
            let denied = EffectDisposition::Denied {
                reason: format!("Anti-loopjacking check failed: {}", e),
            };
            self.idempotency_cache
                .insert(req.idempotency_key.to_string(), denied.clone());
            self.effect_journal.insert(
                req.idempotency_key.to_string(),
                EffectStage::Denied {
                    reason: format!("Anti-loopjacking check failed: {}", e),
                    denied_at: Utc::now(),
                },
            );
            return Ok(denied);
        }

        // Record PREPARED in journal
        let effect_digest = AtomicEffectGuard::compute_digest(req.action, req.target, req.params);
        let prepared_id = format!("prep-{}-{}", self.current_generation, req.idempotency_key);
        let fencing_token = req.lease.fencing_token.clone();

        self.effect_journal.insert(
            req.idempotency_key.to_string(),
            EffectStage::Prepared {
                request_digest: effect_digest,
                fencing_token: fencing_token.clone(),
                prepared_at: Utc::now(),
            },
        );

        let prepared_disp = EffectDisposition::Prepared {
            prepared_id,
            fencing_token,
        };
        self.idempotency_cache
            .insert(req.idempotency_key.to_string(), prepared_disp.clone());
        Ok(prepared_disp)
    }

    /// Step 4 of 7-Stage FSM: Broker exclusively claims the prepared effect with compare-and-swap (GFX-S08).
    pub fn claim_effect(
        &mut self,
        idempotency_key: &str,
        broker_identity: &str,
    ) -> Result<String, ValidationError> {
        let current_stage = self.effect_journal.get(idempotency_key).ok_or_else(|| {
            ValidationError::EffectExecutionDenied(format!(
                "Cannot claim effect: key '{}' has not been prepared",
                idempotency_key
            ))
        })?;

        match current_stage {
            EffectStage::Prepared { fencing_token, .. } => {
                let token = fencing_token.clone();
                self.effect_journal.insert(
                    idempotency_key.to_string(),
                    EffectStage::Claimed {
                        fencing_token: token.clone(),
                        claimed_by: broker_identity.to_string(),
                        claimed_at: Utc::now(),
                    },
                );
                Ok(token)
            }
            other => Err(ValidationError::EffectExecutionDenied(format!(
                "Cannot claim effect: current stage is {:?}, expected PREPARED",
                other
            ))),
        }
    }

    /// Step 5 of 7-Stage FSM: Mark operation as APPLYING under broker capability.
    pub fn record_applying(
        &mut self,
        idempotency_key: &str,
        remote_request_id: &str,
    ) -> Result<(), ValidationError> {
        let current_stage = self.effect_journal.get(idempotency_key).ok_or_else(|| {
            ValidationError::EffectExecutionDenied(format!(
                "Cannot record applying: key '{}' not found",
                idempotency_key
            ))
        })?;

        if !matches!(current_stage, EffectStage::Claimed { .. }) {
            return Err(ValidationError::EffectExecutionDenied(format!(
                "Cannot apply effect: current stage is {:?}, expected CLAIMED",
                current_stage
            )));
        }

        self.effect_journal.insert(
            idempotency_key.to_string(),
            EffectStage::Applying {
                remote_request_id: remote_request_id.to_string(),
                started_at: Utc::now(),
            },
        );
        Ok(())
    }

    /// Steps 6 & 7: Reconcile or transition to IN_DOUBT (GFX-S09).
    /// If external execution is ambiguous or timed out, marks IN_DOUBT and blocks duplicate side effects.
    pub fn reconcile_or_doubt(
        &mut self,
        idempotency_key: &str,
        outcome: Result<String, String>,
    ) -> Result<EffectDisposition, ValidationError> {
        match outcome {
            Ok(observed_digest) => {
                // Record Reconciled then Committed
                self.effect_journal.insert(
                    idempotency_key.to_string(),
                    EffectStage::Reconciled {
                        observed_digest: observed_digest.clone(),
                        reconciled_at: Utc::now(),
                    },
                );

                let receipt_id = format!("rcpt-{}-{}", self.current_generation, idempotency_key);
                let committed = EffectDisposition::Committed {
                    receipt_id,
                    effect_digest: observed_digest,
                    generation: self.current_generation,
                };

                self.effect_journal.insert(
                    idempotency_key.to_string(),
                    EffectStage::Committed {
                        receipt_id: format!("rcpt-{}-{}", self.current_generation, idempotency_key),
                        effect_digest: match &committed {
                            EffectDisposition::Committed { effect_digest, .. } => {
                                effect_digest.clone()
                            }
                            _ => String::new(),
                        },
                        generation: self.current_generation,
                        committed_at: Utc::now(),
                    },
                );

                self.idempotency_cache
                    .insert(idempotency_key.to_string(), committed.clone());
                Ok(committed)
            }
            Err(reason) => {
                // Ambiguous outcome (timeout, disconnect, partition) -> IN_DOUBT
                warn!(
                    key = idempotency_key,
                    error = %reason,
                    "Ambiguous effect outcome detected: entering IN_DOUBT (no blind retry)"
                );
                let in_doubt = EffectDisposition::InDoubt {
                    reason: reason.clone(),
                    last_stage: "APPLYING".into(),
                    requires_reconciliation: true,
                };

                self.effect_journal.insert(
                    idempotency_key.to_string(),
                    EffectStage::InDoubt {
                        reason,
                        last_stage: "APPLYING".into(),
                        requires_reconciliation: true,
                        detected_at: Utc::now(),
                    },
                );

                self.idempotency_cache
                    .insert(idempotency_key.to_string(), in_doubt.clone());
                Ok(in_doubt)
            }
        }
    }

    /// Complete synchronous effect execution with full 7-stage transactional safety.
    pub fn execute_effect(
        &mut self,
        req: &EffectRequest<'_>,
    ) -> Result<EffectDisposition, ValidationError> {
        // 1. Idempotency Check
        if let Some(cached) = self.idempotency_cache.get(req.idempotency_key) {
            // InDoubt rejects blind retry
            if matches!(cached, EffectDisposition::InDoubt { .. }) {
                return Ok(cached.clone());
            }
            if !matches!(cached, EffectDisposition::Prepared { .. }) {
                return Ok(cached.clone());
            }
        }

        // 2. Prepare Effect (validates lease, generation fencing, and effect guard)
        let prep_disp = self.prepare_effect(req)?;
        if !matches!(prep_disp, EffectDisposition::Prepared { .. }) {
            return Ok(prep_disp);
        }

        // 3. Broker Claim
        self.claim_effect(req.idempotency_key, "atomic-effect-broker-local")?;

        // 4. Record Applying
        let remote_id = format!("remote-call-{}", req.idempotency_key);
        self.record_applying(req.idempotency_key, &remote_id)?;

        // 5. Reconcile & Commit
        let effect_digest = AtomicEffectGuard::compute_digest(req.action, req.target, req.params);
        self.reconcile_or_doubt(req.idempotency_key, Ok(effect_digest))
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

        // Partition event: broker advances to generation 2
        broker.advance_generation("fence-2-task-root");

        // Old worker-1 emerges with delayed message (generation 1)
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
    fn test_7_stage_fsm_and_in_doubt_handling() {
        let mut broker = AtomicEffectBroker::new(0, "fence-0-test");
        let lease = CapabilityLease::new(
            "lease-test",
            "worker-test",
            "k8s/deployments",
            vec!["patch".into()],
            Utc::now() + Duration::hours(1),
        );
        let params = serde_json::json!({"image": "app:v2"});
        let guard = AtomicEffectGuard::new("patch", "k8s/deployments", params.clone());

        let req = EffectRequest {
            lease: &lease,
            guard: &guard,
            received_generation: 0,
            idempotency_key: "idem-timeout-1",
            action: "patch",
            target: "k8s/deployments",
            params: &params,
        };

        // Step 1: Prepare
        let prep = broker.prepare_effect(&req).unwrap();
        assert!(matches!(prep, EffectDisposition::Prepared { .. }));

        // Step 2: Claim
        broker
            .claim_effect("idem-timeout-1", "broker-worker")
            .unwrap();

        // Step 3: Applying
        broker
            .record_applying("idem-timeout-1", "req-remote-001")
            .unwrap();

        // Step 4: Simulate network timeout / ambiguous partition -> IN_DOUBT
        let doubt = broker
            .reconcile_or_doubt("idem-timeout-1", Err("Connection reset by peer".into()))
            .unwrap();

        assert!(matches!(
            doubt,
            EffectDisposition::InDoubt {
                requires_reconciliation: true,
                ..
            }
        ));

        // Subsequent retry with the same key is strictly held in IN_DOUBT (no blind retry!)
        let retry_disp = broker.execute_effect(&req).unwrap();
        assert!(matches!(retry_disp, EffectDisposition::InDoubt { .. }));
    }
}
