use crate::digest::DigestEngine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// in-toto v1.0 Resource Descriptor
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

/// in-toto v1.0 Statement Specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

impl InTotoStatement {
    pub fn new_execution_statement(
        subject_name: &str,
        subject_sha256: &str,
        predicate: serde_json::Value,
    ) -> Self {
        let mut digests = BTreeMap::new();
        digests.insert("sha256".into(), subject_sha256.into());

        Self {
            statement_type: "https://in-toto.io/Statement/v1".into(),
            subject: vec![InTotoSubject {
                name: subject_name.into(),
                digest: digests,
            }],
            predicate_type: "https://ckodex.io/attestation/execution-receipt/v1".into(),
            predicate,
        }
    }
}

/// DSSE Signature Entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

/// Dead Simple Signing Envelope (DSSE)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String, // base64 encoded payload
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    pub fn wrap_in_toto(statement: &InTotoStatement, key_id: &str) -> Self {
        let json_bytes = serde_json::to_vec(statement).unwrap_or_default();
        let payload_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &json_bytes);
        let sig_digest = DigestEngine::sha256_bytes(&json_bytes);

        Self {
            payload_type: "application/vnd.in-toto+json".into(),
            payload: payload_b64,
            signatures: vec![DsseSignature {
                keyid: key_id.into(),
                sig: format!("ed25519:{}", sig_digest),
            }],
        }
    }
}
