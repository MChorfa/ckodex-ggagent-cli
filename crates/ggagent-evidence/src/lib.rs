//! # ggagent-evidence
//!
//! Evidence Fabric for `ckodex-ggagent-cli`.
//!
//! Provides:
//! - Content-addressed SHA-256 digests
//! - Formal Execution Receipts with cryptographic signatures
//! - State Mutation Lineage (M = <S0, Trigger, Authority, Transformation, S1, Evidence, Time>)
//! - Dead Simple Signing Envelope (DSSE) & in-toto v1.0 supply chain attestations
//! - Tamper-evident, hash-chained Flight Recorder ledger

pub mod attestation;
pub mod digest;
pub mod flight_recorder;
pub mod lineage;
pub mod receipt;

pub use attestation::{DsseEnvelope, DsseSignature, InTotoStatement, InTotoSubject};
pub use digest::DigestEngine;
pub use flight_recorder::{FlightRecorder, FlightRecorderEvent};
pub use lineage::{LineageLedger, StateMutationRecord};
pub use receipt::{ExecutionReceipt, ExecutionReceiptParams};
