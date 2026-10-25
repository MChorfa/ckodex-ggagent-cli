//! # Governed Execution & Containment Domain Model
//!
//! Implements INVARITH × Governed Execution Canonical Reconciliation (v0.2.0):
//! 1. Isolation Class Spectrum: LocalDev < WasiComponent < OciGvisor < MicroVm < ConfidentialVm.
//!    Enforces GFX-S05: No execution/placement if minimum boundary cannot be established. No weaker fallback!
//! 2. Immutable ContextRoot & ContextFault detection: Authority precedes ContextRoot.
//! 3. 7-Stage Effect Safety Transactional FSM:
//!    PROPOSED -> AUTHORIZED -> PREPARED -> CLAIMED -> APPLYING -> RECONCILED -> COMMITTED
//!    Plus explicit IN_DOUBT handling (GFX-S09: On timeout/crash/partition, mark IN_DOUBT, observe and reconcile before any retry!).

use crate::error::KernelError;
use crate::lease::CapabilityLease;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Policy-selected isolation classes matching threat models (Section 5).
/// Ordered strictly by isolation strength (rank 1 through 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IsolationClass {
    /// OS Seatbelt / Landlock / SRT-style process sandbox (workstations, local dev convenience)
    LocalDev = 1,
    /// Constrained WASI Component runtime (Wasmtime, pure deterministic transformations)
    WasiComponent = 2,
    /// Userspace application kernel (gVisor runsc OCI container)
    OciGvisor = 3,
    /// Dedicated hardware virtual machine (KVM-backed microVM / Kata Containers)
    MicroVm = 4,
    /// Hardware-attested confidential enclave (AMD SEV-SNP / Intel TDX)
    ConfidentialVm = 5,
}

impl IsolationClass {
    pub fn rank(&self) -> u8 {
        *self as u8
    }

    /// Check if this isolation class satisfies the required minimum isolation class.
    pub fn meets_minimum(&self, required: &IsolationClass) -> bool {
        self.rank() >= required.rank()
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::LocalDev => "LocalDev (SRT / OS Seatbelt / Landlock process sandbox)",
            Self::WasiComponent => "WasiComponent (Constrained WASI plugin runtime)",
            Self::OciGvisor => "OciGvisor (gVisor runsc userspace kernel)",
            Self::MicroVm => "MicroVm (Hardware-isolated KVM microVM / Kata Containers)",
            Self::ConfidentialVm => "ConfidentialVm (Hardware enclave TDX / SEV-SNP)",
        }
    }
}

/// Enforceable isolation contract (GFX-S05).
/// For hostile or untrusted agent workloads, allow_downgrade MUST be false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationContract {
    pub required_class: IsolationClass,
    pub allow_downgrade: bool,
    pub tenant: String,
    pub workload_identity: String,
}

impl IsolationContract {
    pub fn new(
        required_class: IsolationClass,
        tenant: impl Into<String>,
        workload_identity: impl Into<String>,
    ) -> Self {
        Self {
            required_class,
            allow_downgrade: false, // Strict GFX-S05 default: no weaker fallback
            tenant: tenant.into(),
            workload_identity: workload_identity.into(),
        }
    }

    /// Verify that the host's available runtime satisfies the contract.
    pub fn validate_host_runtime(&self, available: &IsolationClass) -> Result<(), KernelError> {
        if available.meets_minimum(&self.required_class) {
            return Ok(());
        }

        if self.allow_downgrade {
            return Ok(());
        }

        Err(KernelError::IsolationViolation {
            required: format!("{:?} ({})", self.required_class, self.required_class.description()),
            available: format!("{:?} ({})", available, available.description()),
            reason: "GFX-S05 violation: Host cannot meet minimum isolation contract; silent fallback prohibited".into(),
        })
    }
}

/// ContextRoot: Immutable, decision-specific binding (Section 2.2).
/// Authority precedes ContextRoot. It binds the exact decision and observation cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRoot {
    pub context_id: String,
    pub authority_lease_id: String,
    pub decision_digest: String,
    pub observation_cut_digest: String,
    pub classification: String,
    pub created_at: DateTime<Utc>,
}

impl ContextRoot {
    pub fn new(
        context_id: impl Into<String>,
        authority_lease_id: impl Into<String>,
        decision_digest: impl Into<String>,
        observation_cut_digest: impl Into<String>,
        classification: impl Into<String>,
    ) -> Self {
        Self {
            context_id: context_id.into(),
            authority_lease_id: authority_lease_id.into(),
            decision_digest: decision_digest.into(),
            observation_cut_digest: observation_cut_digest.into(),
            classification: classification.into(),
            created_at: Utc::now(),
        }
    }

    /// Invariant: Authority precedes ContextRoot.
    /// The referenced lease must be valid and must have been created at or before ContextRoot.
    pub fn verify_authority_precedence(&self, lease: &CapabilityLease) -> Result<(), KernelError> {
        if self.authority_lease_id != lease.lease_id {
            return Err(KernelError::MissingAuthority(format!(
                "ContextRoot {} references lease {} but presented lease is {}",
                self.context_id, self.authority_lease_id, lease.lease_id
            )));
        }

        if lease.is_revoked {
            return Err(KernelError::LeaseExpiredOrRevoked {
                lease_id: lease.lease_id.clone(),
            });
        }

        if self.created_at < lease.valid_from {
            return Err(KernelError::InvalidStateTransition {
                from: "PreAuthority".into(),
                to: "ContextRootCreated".into(),
                reason: "ContextRoot timestamp precedes CapabilityLease validity start time".into(),
            });
        }

        Ok(())
    }
}

/// Explicit context faults distinguishing different epistemic breakdowns (Section 2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "fault_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextFault {
    Missing {
        resource: String,
    },
    Unavailable {
        resource: String,
        retry_after_ms: Option<u64>,
    },
    Stale {
        current_epoch: u64,
        requested_epoch: u64,
    },
    IntegrityFailure {
        expected_digest: String,
        actual_digest: String,
    },
    PolicyDenied {
        reason: String,
    },
}

/// The 7-Stage Effect Safety Transactional FSM (Sections 3 & 3.1).
/// PROPOSED -> AUTHORIZED -> PREPARED -> CLAIMED -> APPLYING -> RECONCILED -> COMMITTED
/// With explicit IN_DOUBT state to defeat blind retries after crashes or partitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectStage {
    /// Step 1: Untrusted agent proposes a typed operation & canonical parameters
    Proposed { proposed_at: DateTime<Utc> },
    /// Step 2: Guards evaluate invariants; scoped permit granted
    Authorized { authorized_at: DateTime<Utc> },
    /// Step 3: Intent and exact preconditions are durably journaled before side-effects
    Prepared {
        request_digest: String,
        fencing_token: String,
        prepared_at: DateTime<Utc>,
    },
    /// Step 4: Trusted broker exclusively claims the prepared intent (CAS + monotonic fence)
    Claimed {
        fencing_token: String,
        claimed_by: String,
        claimed_at: DateTime<Utc>,
    },
    /// Step 5: Broker performs operation under broker-owned capability
    Applying {
        remote_request_id: String,
        started_at: DateTime<Utc>,
    },
    /// Step 6: Target state is independently read back and reconciled against postconditions
    Reconciled {
        observed_digest: String,
        reconciled_at: DateTime<Utc>,
    },
    /// Step 7: Authorized state transition committed with verifiable cryptographic receipt
    Committed {
        receipt_id: String,
        effect_digest: String,
        generation: u64,
        committed_at: DateTime<Utc>,
    },
    /// Indeterminate outcome (timeout / network partition / ambiguous observation).
    /// NO BLIND RETRY PERMITTED. Requires registered reconciliation.
    InDoubt {
        reason: String,
        last_stage: String,
        requires_reconciliation: bool,
        detected_at: DateTime<Utc>,
    },
    /// Verified failed / non-applied terminal state
    ClosedFailed {
        error: String,
        closed_at: DateTime<Utc>,
    },
    /// Rejected by policy or lease guards
    Denied {
        reason: String,
        denied_at: DateTime<Utc>,
    },
    /// Rejected due to stale generation token
    Fenced {
        current_generation: u64,
        received_generation: u64,
        fenced_at: DateTime<Utc>,
    },
}

/// Tamper-evident, cryptographic hash-chained journal entry (GFX-S08).
/// Every state transition is cryptographically bound to the previous entry hash:
/// H_i = SHA-256(sequence || ":" || prev_hash || ":" || idempotency_key || ":" || stage_json)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub sequence_number: u64,
    pub timestamp: DateTime<Utc>,
    pub idempotency_key: String,
    pub stage: EffectStage,
    pub previous_entry_hash: String,
    pub entry_hash: String,
}

impl JournalEntry {
    pub fn compute_hash(
        sequence_number: u64,
        previous_entry_hash: &str,
        idempotency_key: &str,
        stage: &EffectStage,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence_number.to_be_bytes());
        hasher.update(b":");
        hasher.update(previous_entry_hash.as_bytes());
        hasher.update(b":");
        hasher.update(idempotency_key.as_bytes());
        hasher.update(b":");
        let stage_json = serde_json::to_string(stage).unwrap_or_default();
        hasher.update(stage_json.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn new(
        sequence_number: u64,
        previous_entry_hash: String,
        idempotency_key: String,
        stage: EffectStage,
    ) -> Self {
        let hash = Self::compute_hash(
            sequence_number,
            &previous_entry_hash,
            &idempotency_key,
            &stage,
        );
        Self {
            sequence_number,
            timestamp: Utc::now(),
            idempotency_key,
            stage,
            previous_entry_hash,
            entry_hash: hash,
        }
    }

    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_hash(
            self.sequence_number,
            &self.previous_entry_hash,
            &self.idempotency_key,
            &self.stage,
        );
        expected == self.entry_hash
    }
}

/// Append-only cryptographic journal chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalChain {
    pub entries: Vec<JournalEntry>,
    pub genesis_hash: String,
}

impl Default for JournalChain {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalChain {
    pub const GENESIS_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            genesis_hash: Self::GENESIS_HASH.to_string(),
        }
    }

    pub fn append(
        &mut self,
        idempotency_key: impl Into<String>,
        stage: EffectStage,
    ) -> &JournalEntry {
        let seq = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| self.genesis_hash.clone());

        let entry = JournalEntry::new(seq, prev_hash, idempotency_key.into(), stage);
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Cryptographically verify the entire journal chain from genesis to head.
    pub fn verify_chain(&self) -> Result<(), KernelError> {
        let mut expected_prev = self.genesis_hash.as_str();
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.sequence_number != idx as u64 {
                return Err(KernelError::DecoherenceDetected {
                    admitted: format!("seq_{}", idx),
                    runtime: format!("seq_{}", entry.sequence_number),
                });
            }

            if entry.previous_entry_hash != expected_prev {
                return Err(KernelError::DecoherenceDetected {
                    admitted: expected_prev.to_string(),
                    runtime: entry.previous_entry_hash.clone(),
                });
            }

            if !entry.verify_integrity() {
                return Err(KernelError::DecoherenceDetected {
                    admitted: entry.entry_hash.clone(),
                    runtime: "corrupted_hash".to_string(),
                });
            }

            expected_prev = &entry.entry_hash;
        }
        Ok(())
    }
}

/// Hard Invariant Dominance Evaluator (GFX-S17 / Section 23).
/// Invariant: Hard-veto Atomic Guards cannot be overridden by multi-model consensus,
/// high aggregate scores, cost optimization, or degraded policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardVetoEvaluator;

impl HardVetoEvaluator {
    /// Evaluates multi-model consensus and hard veto.
    /// If ANY hard veto is tripped, the verdict is strictly REJECTED / NON-CONFORMANT,
    /// regardless of 100% agreement across all models.
    pub fn evaluate_consensus(
        consensus_score: f64,
        participating_models: &[String],
        tripped_hard_veto: Option<&str>,
    ) -> Result<(), KernelError> {
        if let Some(veto) = tripped_hard_veto {
            return Err(KernelError::AntiInvariantViolation {
                invariant: veto.to_string(),
                context: format!(
                    "GFX-S17 Dominance: Hard veto '{}' overrides {:.1}% consensus across {:?} models",
                    veto,
                    consensus_score * 100.0,
                    participating_models
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_isolation_class_hierarchy_and_downgrade_prevention() {
        let contract =
            IsolationContract::new(IsolationClass::MicroVm, "tenant-alpha", "agent-worker-01");

        // Host with MicroVm or ConfidentialVm satisfies contract
        assert!(contract
            .validate_host_runtime(&IsolationClass::MicroVm)
            .is_ok());
        assert!(contract
            .validate_host_runtime(&IsolationClass::ConfidentialVm)
            .is_ok());

        // Attempting to run on LocalDev or OciGvisor fails closed with IsolationViolation
        let err = contract
            .validate_host_runtime(&IsolationClass::OciGvisor)
            .unwrap_err();
        assert!(matches!(err, KernelError::IsolationViolation { .. }));

        let err_local = contract
            .validate_host_runtime(&IsolationClass::LocalDev)
            .unwrap_err();
        assert!(matches!(err_local, KernelError::IsolationViolation { .. }));
    }

    #[test]
    fn test_context_root_authority_precedence() {
        let lease = CapabilityLease::new(
            "lease-root-1",
            "principal-1",
            "resource/1",
            vec!["read".into()],
            Utc::now() + Duration::hours(1),
        );

        let mut root = ContextRoot::new(
            "ctx-001",
            "lease-root-1",
            "sha256:decision",
            "sha256:obs",
            "RESTRICTED",
        );
        assert!(root.verify_authority_precedence(&lease).is_ok());

        // Reference wrong lease
        root.authority_lease_id = "lease-other".into();
        assert!(root.verify_authority_precedence(&lease).is_err());
    }

    #[test]
    fn test_effect_stage_fsm_representation() {
        let prep = EffectStage::Prepared {
            request_digest: "sha256:req".into(),
            fencing_token: "fence-1-task".into(),
            prepared_at: Utc::now(),
        };
        assert!(matches!(prep, EffectStage::Prepared { .. }));

        let indoubt = EffectStage::InDoubt {
            reason: "Upstream timeout after 5000ms".into(),
            last_stage: "APPLYING".into(),
            requires_reconciliation: true,
            detected_at: Utc::now(),
        };
        assert!(matches!(
            indoubt,
            EffectStage::InDoubt {
                requires_reconciliation: true,
                ..
            }
        ));
    }

    #[test]
    fn test_journal_chain_hash_chaining_and_tamper_detection() {
        let mut chain = JournalChain::new();
        chain.append(
            "task-01",
            EffectStage::Proposed {
                proposed_at: Utc::now(),
            },
        );
        chain.append(
            "task-01",
            EffectStage::Authorized {
                authorized_at: Utc::now(),
            },
        );
        chain.append(
            "task-01",
            EffectStage::Prepared {
                request_digest: "sha256:req".into(),
                fencing_token: "fence-1".into(),
                prepared_at: Utc::now(),
            },
        );

        // Verification of intact chain passes
        assert!(chain.verify_chain().is_ok());

        // Tampering with an intermediate entry breaks verification
        chain.entries[1].idempotency_key = "tampered-task-id".into();
        assert!(chain.verify_chain().is_err());
    }

    #[test]
    fn test_hard_veto_dominates_100_percent_consensus() {
        let models = vec![
            "gemini-2.5-pro".into(),
            "claude-3.7-sonnet".into(),
            "gpt-4.5".into(),
            "deepseek-r1".into(),
        ];

        // Without veto, consensus is accepted
        assert!(HardVetoEvaluator::evaluate_consensus(1.0, &models, None).is_ok());

        // With hard veto, 100% agreement of all 4 frontier models is categorically REJECTED
        let res = HardVetoEvaluator::evaluate_consensus(
            1.0,
            &models,
            Some("MANDATORY_ANTI_EXFILTRATION_BREACH"),
        );
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(matches!(err, KernelError::AntiInvariantViolation { .. }));
    }
}
