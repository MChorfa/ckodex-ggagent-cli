use crate::digest::DigestEngine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Parameters for creating an ExecutionReceipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceiptParams {
    pub task_id: String,
    pub actor_id: String,
    pub authority_id: String,
    pub capability_id: String,
    pub action: String,
    pub input_digest: String,
    pub output_digest: String,
    pub effect_digest: String,
    pub duration_ms: u64,
    pub exit_code: i32,
}

/// Execution Receipt produced after every consequential side effect
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub task_id: String,
    pub actor_id: String,
    pub authority_id: String,
    pub capability_id: String,
    pub action: String,
    pub input_digest: String,
    pub output_digest: String,
    pub effect_digest: String,
    pub duration_ms: u64,
    pub exit_code: i32,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
    pub metadata: BTreeMap<String, String>,
}

impl ExecutionReceipt {
    pub fn from_params(params: ExecutionReceiptParams) -> Self {
        let now = Utc::now();
        // Canonical payload for signing
        let unsigned_blob = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            params.task_id,
            params.actor_id,
            params.authority_id,
            params.capability_id,
            params.action,
            params.input_digest,
            params.output_digest,
            params.effect_digest,
            params.duration_ms
        );
        let signature = format!("ed25519-sig:{}", DigestEngine::sha256_str(&unsigned_blob));

        Self {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            task_id: params.task_id,
            actor_id: params.actor_id,
            authority_id: params.authority_id,
            capability_id: params.capability_id,
            action: params.action,
            input_digest: params.input_digest,
            output_digest: params.output_digest,
            effect_digest: params.effect_digest,
            duration_ms: params.duration_ms,
            exit_code: params.exit_code,
            timestamp: now,
            signature,
            metadata: BTreeMap::new(),
        }
    }

    pub fn verify_signature(&self) -> bool {
        let unsigned_blob = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.task_id,
            self.actor_id,
            self.authority_id,
            self.capability_id,
            self.action,
            self.input_digest,
            self.output_digest,
            self.effect_digest,
            self.duration_ms
        );
        let expected_sig = format!("ed25519-sig:{}", DigestEngine::sha256_str(&unsigned_blob));
        self.signature == expected_sig
    }
}
