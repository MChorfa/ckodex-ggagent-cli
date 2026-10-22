use crate::digest::DigestEngine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A Flight Recorder Entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderEvent {
    pub event_id: String,
    pub prev_hash: String,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub channel: String, // Telemetry, Execution, Decision, Evidence
    pub actor_id: String,
    pub authority_id: String,
    pub operation: String,
    pub fact_digest: String,
    pub policy_version: String,
    pub metadata: BTreeMap<String, String>,
    pub block_hash: String,
}

/// Flight Recorder Ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightRecorder {
    pub session_id: String,
    pub events: Vec<FlightRecorderEvent>,
    pub current_hash: String,
}

impl FlightRecorder {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            events: Vec::new(),
            current_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        }
    }

    pub fn record_event(
        &mut self,
        channel: impl Into<String>,
        actor_id: impl Into<String>,
        authority_id: impl Into<String>,
        operation: impl Into<String>,
        fact_digest: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> &FlightRecorderEvent {
        let sequence = self.events.len() as u64;
        let now = Utc::now();
        let prev_hash = self.current_hash.clone();
        let channel = channel.into();
        let actor_id = actor_id.into();
        let authority_id = authority_id.into();
        let operation = operation.into();
        let fact_digest = fact_digest.into();
        let policy_version = policy_version.into();

        let raw_block = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            prev_hash,
            sequence,
            channel,
            actor_id,
            authority_id,
            operation,
            fact_digest,
            policy_version
        );
        let block_hash = DigestEngine::sha256_str(&raw_block);
        self.current_hash = block_hash.clone();

        let event = FlightRecorderEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            prev_hash,
            sequence,
            timestamp: now,
            channel,
            actor_id,
            authority_id,
            operation,
            fact_digest,
            policy_version,
            metadata: BTreeMap::new(),
            block_hash,
        };

        self.events.push(event);
        self.events.last().unwrap()
    }

    /// Verify integrity of the hash chain
    pub fn verify_integrity(&self) -> bool {
        let mut expected_prev = "0000000000000000000000000000000000000000000000000000000000000000";
        for event in &self.events {
            if event.prev_hash != expected_prev {
                return false;
            }
            let raw_block = format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                event.prev_hash,
                event.sequence,
                event.channel,
                event.actor_id,
                event.authority_id,
                event.operation,
                event.fact_digest,
                event.policy_version
            );
            let calculated_hash = DigestEngine::sha256_str(&raw_block);
            if calculated_hash != event.block_hash {
                return false;
            }
            expected_prev = &event.block_hash;
        }
        true
    }
}
