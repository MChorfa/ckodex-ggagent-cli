use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Presence dimension of vector state.
/// Rule: EMPTY != NEGATIVE, UNKNOWN != NEGATIVE, REDACTED != EMPTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Presence {
    #[default]
    Empty,
    Present,
    Unknown,
    Redacted,
}

/// Valence dimension: directional effect of evidence relative to a proposition.
/// Negative does not mean malicious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Valence {
    #[default]
    Neutral,
    Positive,
    Negative,
    Mixed,
    Unresolved,
}

/// Structural opposition / anti relation.
/// Dominates aggregate scoring. Never average away an anti contradiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AntiRelation {
    #[default]
    None,
    Attacks,
    Invalidates,
    Contradicts,
}

/// Coherence represents alignment across multiple representations of reality.
/// Decoherence is not just error=true; it is state divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Coherence {
    #[default]
    Coherent,
    PartiallyCoherent,
    Decoherent,
    Reconciling,
}

/// Epistemic evidence status.
/// Never silently promote INFERRED -> VERIFIED. Never convert UNKNOWN -> SUCCESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    #[default]
    Unknown,
    Observed,
    Verified,
    Inferred,
    Contradicted,
    Blocked,
    Parked,
    NotApplicable,
}

/// Formal lifecycle state of an agent or task FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    #[default]
    Idle,
    Submitted,
    Working,
    AuthRequired,
    AuthReceived,
    Executing,
    Degraded,
    Completed,
    Failed,
    Quarantined,
    Reconciling,
}

/// Operational runtime mode (canonical Day-2 modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeMode {
    #[default]
    Normal,
    Degraded,
    SafeHold,
    Quarantined,
    Recovering,
    Failed,
}

/// Canonical 7-Dimensional Vector State:
/// S(e, t) = <P, V, A, C, E, L, tau>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorState {
    pub entity_id: String,
    pub presence: Presence,
    pub valence: Valence,
    pub anti: AntiRelation,
    pub coherence: Coherence,
    pub evidence: EvidenceStatus,
    pub lifecycle: LifecycleState,
    pub mode: RuntimeMode,
    pub epoch: u64,
    pub timestamp: DateTime<Utc>,
    pub metadata: std::collections::BTreeMap<String, String>,
}

impl Default for VectorState {
    fn default() -> Self {
        Self {
            entity_id: String::new(),
            presence: Presence::Empty,
            valence: Valence::Neutral,
            anti: AntiRelation::None,
            coherence: Coherence::Coherent,
            evidence: EvidenceStatus::Unknown,
            lifecycle: LifecycleState::Idle,
            mode: RuntimeMode::Normal,
            epoch: 0,
            timestamp: Utc::now(),
            metadata: std::collections::BTreeMap::new(),
        }
    }
}

impl VectorState {
    pub fn new(entity_id: impl Into<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            ..Default::default()
        }
    }

    /// Hard invariant check:
    /// Invariant: An AntiRelation != None dominates and forces non-conformance.
    pub fn is_conformant(&self) -> bool {
        if self.anti != AntiRelation::None {
            return false;
        }
        if self.coherence == Coherence::Decoherent {
            return false;
        }
        if self.evidence == EvidenceStatus::Contradicted {
            return false;
        }
        true
    }

    /// Transition to next state incrementing epoch
    pub fn transition_to(&self, next_lifecycle: LifecycleState) -> Self {
        let mut next = self.clone();
        next.lifecycle = next_lifecycle;
        next.epoch += 1;
        next.timestamp = Utc::now();
        next
    }

    /// Set operational mode
    pub fn with_mode(mut self, mode: RuntimeMode) -> Self {
        self.mode = mode;
        self
    }

    /// Format vector state into standard notation: <P, V, A, C, E, L, tau>
    pub fn to_canonical_string(&self) -> String {
        format!(
            "⟨P:{:?}, V:{:?}, A:{:?}, C:{:?}, E:{:?}, L:{:?}, M:{:?}, τ:{}⟩",
            self.presence,
            self.valence,
            self.anti,
            self.coherence,
            self.evidence,
            self.lifecycle,
            self.mode,
            self.epoch
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hard_invariant_anti_dominance() {
        let mut state = VectorState::new("agent-001");
        state.presence = Presence::Present;
        state.valence = Valence::Positive;
        state.evidence = EvidenceStatus::Verified;
        state.lifecycle = LifecycleState::Executing;
        assert!(state.is_conformant());

        // Introduce anti relation
        state.anti = AntiRelation::Contradicts;
        assert!(
            !state.is_conformant(),
            "Anti relation MUST dominate and fail conformance"
        );
    }

    #[test]
    fn test_presence_rules() {
        let state = VectorState::default();
        assert_eq!(state.presence, Presence::Empty);
        assert_ne!(state.presence, Presence::Present);
    }

    #[test]
    fn test_property_anti_invariant_dominates_all_state_permutations() {
        let presences = [
            Presence::Empty,
            Presence::Present,
            Presence::Unknown,
            Presence::Redacted,
        ];
        let valences = [
            Valence::Positive,
            Valence::Negative,
            Valence::Neutral,
            Valence::Mixed,
            Valence::Unresolved,
        ];
        let coherences = [
            Coherence::Coherent,
            Coherence::PartiallyCoherent,
            Coherence::Decoherent,
            Coherence::Reconciling,
        ];
        let evidences = [
            EvidenceStatus::Observed,
            EvidenceStatus::Verified,
            EvidenceStatus::Inferred,
            EvidenceStatus::Unknown,
        ];
        let antis = [
            AntiRelation::Attacks,
            AntiRelation::Invalidates,
            AntiRelation::Contradicts,
        ];

        // Exhaustively verify that whenever anti != None, conformance is FALSE
        let mut count = 0;
        for p in presences {
            for v in valences {
                for c in coherences {
                    for e in evidences {
                        for a in antis {
                            let mut state = VectorState::new("test");
                            state.presence = p;
                            state.valence = v;
                            state.coherence = c;
                            state.evidence = e;
                            state.anti = a;
                            assert!(
                                !state.is_conformant(),
                                "Failed for permutation: {:?}",
                                state
                            );
                            count += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(count, 4 * 5 * 4 * 4 * 3); // 960 state permutations tested
    }

    #[test]
    fn test_property_epoch_strictly_monotonic() {
        let mut state = VectorState::new("agent-epoch");
        assert_eq!(state.epoch, 0);

        for step in 1..=500 {
            state = state.transition_to(LifecycleState::Working);
            assert_eq!(
                state.epoch, step as u64,
                "Epoch must increment strictly monotonically"
            );
        }
    }
}
