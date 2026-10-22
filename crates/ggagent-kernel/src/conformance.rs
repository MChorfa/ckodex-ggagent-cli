use crate::vector_state::VectorState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Required disposition from a conformance transition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConformanceDisposition {
    Admit,
    AdmitWithObligations,
    Deny,
    Escalate,
    SafeHold,
    Quarantine,
}

/// Stimulus / Operation / Event applied to state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceStimulus {
    pub name: String,
    pub payload: serde_json::Value,
    pub source: String,
}

/// Conformance Vector Transition contract:
/// delta(Pe, S0, X, C) = <d, O, S1, E, R>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVector {
    pub vector_id: String,
    pub description: String,
    pub effective_policy: String,
    pub initial_state: VectorState,
    pub stimulus: ConformanceStimulus,
    pub context: BTreeMap<String, String>,
    pub required_disposition: ConformanceDisposition,
    pub required_obligations: Vec<String>,
    pub expected_resulting_state: VectorState,
    pub required_evidence: Vec<String>,
    pub recovery_triggers: Vec<String>,
}

/// Result of evaluating a conformance transition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceEvaluationResult {
    pub vector_id: String,
    pub is_conformant: bool,
    pub observed_disposition: ConformanceDisposition,
    pub missing_obligations: Vec<String>,
    pub state_divergence: Option<String>,
    pub missing_evidence: Vec<String>,
}
