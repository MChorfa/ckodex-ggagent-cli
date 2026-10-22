use crate::digest::DigestEngine;
use chrono::{DateTime, Utc};
use ggagent_kernel::vector_state::VectorState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Formal State Mutation Lineage:
/// M = <S0, Trigger, Authority, Transformation, S1, Evidence, Time>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMutationRecord {
    pub mutation_id: String,
    pub entity_id: String,
    pub initial_state: VectorState,
    pub trigger: String,
    pub authority: String,
    pub transformation: String,
    pub resulting_state: VectorState,
    pub evidence_digest: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: BTreeMap<String, String>,
}

impl StateMutationRecord {
    pub fn new(
        entity_id: impl Into<String>,
        initial: VectorState,
        trigger: impl Into<String>,
        authority: impl Into<String>,
        transformation: impl Into<String>,
        resulting: VectorState,
    ) -> Self {
        let now = Utc::now();
        let entity_id = entity_id.into();
        let initial_hash = DigestEngine::sha256_json(&initial).unwrap_or_default();
        let resulting_hash = DigestEngine::sha256_json(&resulting).unwrap_or_default();
        let evidence_digest = DigestEngine::sha256_str(&format!(
            "{}:{}:{}",
            entity_id, initial_hash, resulting_hash
        ));

        Self {
            mutation_id: uuid::Uuid::new_v4().to_string(),
            entity_id,
            initial_state: initial,
            trigger: trigger.into(),
            authority: authority.into(),
            transformation: transformation.into(),
            resulting_state: resulting,
            evidence_digest,
            timestamp: now,
            metadata: BTreeMap::new(),
        }
    }
}

/// Append-only Lineage Ledger
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LineageLedger {
    pub mutations: Vec<StateMutationRecord>,
}

impl LineageLedger {
    pub fn new() -> Self {
        Self {
            mutations: Vec::new(),
        }
    }

    pub fn record(&mut self, record: StateMutationRecord) {
        self.mutations.push(record);
    }

    pub fn history_for(&self, entity_id: &str) -> Vec<&StateMutationRecord> {
        self.mutations
            .iter()
            .filter(|m| m.entity_id == entity_id)
            .collect()
    }
}
