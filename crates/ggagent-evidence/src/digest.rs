use sha2::{Digest, Sha256};

pub struct DigestEngine;

impl DigestEngine {
    /// Compute SHA-256 hex digest of raw bytes
    pub fn sha256_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Compute SHA-256 hex digest of string
    pub fn sha256_str(text: &str) -> String {
        Self::sha256_bytes(text.as_bytes())
    }

    /// Compute canonical SHA-256 of a JSON serializable value
    pub fn sha256_json<T: serde::Serialize>(val: &T) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(val)?;
        Ok(Self::sha256_bytes(&bytes))
    }
}
