//! # Forensic Evidence Bundle & Forensics Engine (Chapters 18 & 30)
//!
//! Generates and verifies complete, tamper-evident post-mortem forensic bundles:
//! - Complete 7D Vector State snapshot $S(e,t)$
//! - Complete 4D Coordinated State snapshot
//! - Cryptographic hash-chained flight recorder events across all 4 truth channels
//! - Cryptographically signed execution receipts
//! - Immutable sealed candidate digests
//! - Formal Failure Mode classification (ContainmentEscape, AuthorizedHarm, VerificationFailure, GovernanceFailure)
//! - Top-level Root Manifest Digest

use crate::digest::DigestEngine;
use crate::flight_recorder::{FlightRecorder, FlightRecorderEvent};
use crate::receipt::ExecutionReceipt;
use chrono::{DateTime, Utc};
use ggagent_kernel::coordinated_states::{CoordinatedTaskState, FailureClassification};
use ggagent_kernel::vector_state::VectorState;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Tamper-evident Forensic Evidence Bundle
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicBundle {
    pub bundle_id: String,
    pub task_id: String,
    pub vector_state: VectorState,
    pub coordinated_state: CoordinatedTaskState,
    pub flight_recorder_hash: String,
    pub flight_events: Vec<FlightRecorderEvent>,
    pub receipts: Vec<ExecutionReceipt>,
    pub candidate_digests: Vec<String>,
    pub failure_classification: Option<FailureClassification>,
    pub root_manifest_digest: String,
    pub exported_at: DateTime<Utc>,
}

impl ForensicBundle {
    pub fn compute_root_digest(
        task_id: &str,
        vstate: &VectorState,
        cstate: &CoordinatedTaskState,
        flight_hash: &str,
        receipts: &[ExecutionReceipt],
        candidates: &[String],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(task_id.as_bytes());
        hasher.update(b":");
        hasher.update(vstate.to_canonical_string().as_bytes());
        hasher.update(b":");
        hasher.update(cstate.generation.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(flight_hash.as_bytes());
        hasher.update(b":");
        for r in receipts {
            hasher.update(r.receipt_id.as_bytes());
            hasher.update(r.signature.as_bytes());
        }
        for c in candidates {
            hasher.update(c.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    pub fn create(
        task_id: impl Into<String>,
        vector_state: VectorState,
        coordinated_state: CoordinatedTaskState,
        flight_recorder: &FlightRecorder,
        receipts: Vec<ExecutionReceipt>,
        candidate_digests: Vec<String>,
        failure_classification: Option<FailureClassification>,
    ) -> Self {
        let tid = task_id.into();
        let bundle_id = format!("bundle-{}", Uuid::new_v4());
        let root_digest = Self::compute_root_digest(
            &tid,
            &vector_state,
            &coordinated_state,
            &flight_recorder.current_hash,
            &receipts,
            &candidate_digests,
        );

        Self {
            bundle_id,
            task_id: tid,
            vector_state,
            coordinated_state,
            flight_recorder_hash: flight_recorder.current_hash.clone(),
            flight_events: flight_recorder.events.clone(),
            receipts,
            candidate_digests,
            failure_classification,
            root_manifest_digest: root_digest,
            exported_at: Utc::now(),
        }
    }

    /// Verifies the bundle's integrity:
    /// 1. Recomputes and verifies the root manifest digest
    /// 2. Verifies the flight recorder hash-chain integrity
    /// 3. Verifies each execution receipt's cryptographic signature
    pub fn verify_integrity(&self) -> bool {
        // 1. Root manifest digest check
        let expected_root = Self::compute_root_digest(
            &self.task_id,
            &self.vector_state,
            &self.coordinated_state,
            &self.flight_recorder_hash,
            &self.receipts,
            &self.candidate_digests,
        );
        if self.root_manifest_digest != expected_root {
            return false;
        }

        // 2. Flight recorder hash-chain check
        let mut prev_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        for event in &self.flight_events {
            if event.prev_hash != prev_hash {
                return false;
            }
            let raw_block = format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                prev_hash,
                event.sequence,
                event.channel,
                event.actor_id,
                event.authority_id,
                event.operation,
                event.fact_digest,
                event.policy_version
            );
            let computed = DigestEngine::sha256_str(&raw_block);
            if computed != event.block_hash {
                return false;
            }
            prev_hash = &event.block_hash;
        }

        // 3. Receipt verification
        for r in &self.receipts {
            if !r.verify_signature() {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ExecutionReceiptParams;

    #[test]
    fn test_forensic_bundle_generation_and_integrity_verification() {
        let vstate = VectorState::new("task-f1");
        let cstate = CoordinatedTaskState::new("task-f1");

        let mut fr = FlightRecorder::new("session-1");
        fr.record_event(
            "Execution",
            "actor-1",
            "auth:root",
            "compile",
            "sha256:1111",
            "v1.0",
        );
        fr.record_event(
            "Evidence",
            "verifier",
            "auth:root",
            "test_pass",
            "sha256:2222",
            "v1.0",
        );

        let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
            task_id: "task-f1".into(),
            actor_id: "actor-1".into(),
            authority_id: "auth:root".into(),
            capability_id: "build".into(),
            action: "compile".into(),
            input_digest: "sha256:aaaa".into(),
            output_digest: "sha256:bbbb".into(),
            effect_digest: "sha256:cccc".into(),
            duration_ms: 120,
            exit_code: 0,
        });

        let bundle = ForensicBundle::create(
            "task-f1",
            vstate,
            cstate,
            &fr,
            vec![receipt],
            vec!["sha256:patch_hash".into()],
            Some(FailureClassification::VerificationFailure),
        );

        assert!(bundle.verify_integrity());

        // Tampering with root manifest should fail verification
        let mut tampered = bundle.clone();
        tampered.root_manifest_digest = "tampered_digest".into();
        assert!(!tampered.verify_integrity());
    }
}
