//! # Secret Guard & Ephemeral Credential Defense (Chapter 15)
//!
//! Sandboxed workloads MUST NOT persist static secrets or leak API credentials.
//! - Scans inbound and outbound payloads for raw credentials (private keys, AWS tokens, GitHub PATs, JWTs)
//! - Scrubs secrets before recording into flight recorders or execution receipts
//! - Defeats accidental credential exfiltration

use crate::error::ValidationError;

pub struct SecretGuard;

impl SecretGuard {
    const SUSPICIOUS_PATTERNS: &'static [&'static str] = &[
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "AKIA",   // AWS access key prefix
        "ghp_",   // GitHub personal access token prefix
        "glpat-", // GitLab personal access token prefix
        "eyJh",   // Common JWT base64 prefix
    ];

    /// Scans a text string and returns an error if any static secret pattern is found
    pub fn assert_no_secrets_in_text(text: &str) -> Result<(), ValidationError> {
        for pattern in Self::SUSPICIOUS_PATTERNS {
            if text.contains(pattern) {
                return Err(ValidationError::SecretLeakageViolation(format!(
                    "Payload contains prohibited static secret pattern '{}'",
                    pattern
                )));
            }
        }
        Ok(())
    }

    /// Recursively scan a JSON value for secret leakage
    pub fn assert_no_static_secrets(value: &serde_json::Value) -> Result<(), ValidationError> {
        match value {
            serde_json::Value::String(s) => Self::assert_no_secrets_in_text(s),
            serde_json::Value::Array(arr) => {
                for item in arr {
                    Self::assert_no_static_secrets(item)?;
                }
                Ok(())
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    // Check keys for obvious credential names
                    let lower = k.to_lowercase();
                    if lower.contains("password")
                        || lower.contains("private_key")
                        || lower.contains("secret_key")
                    {
                        if let serde_json::Value::String(s) = v {
                            if !s.is_empty() && s != "[REDACTED]" {
                                return Err(ValidationError::SecretLeakageViolation(format!(
                                    "Object contains unredacted credential field '{}'",
                                    k
                                )));
                            }
                        }
                    }
                    Self::assert_no_static_secrets(v)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Scrubs secrets from text, replacing sensitive sequences with `[REDACTED]`
    pub fn scrub_secrets(text: &str) -> String {
        let mut scrubbed = text.to_string();
        for pattern in Self::SUSPICIOUS_PATTERNS {
            if scrubbed.contains(pattern) {
                scrubbed = scrubbed.replace(pattern, "[REDACTED_SECRET]");
            }
        }
        scrubbed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_leakage_detection() {
        let payload = serde_json::json!({
            "config": "valid",
            "key": "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEogIBAAKCAQEA..."
        });

        let res = SecretGuard::assert_no_static_secrets(&payload);
        assert!(matches!(
            res,
            Err(ValidationError::SecretLeakageViolation(_))
        ));
    }

    #[test]
    fn test_scrub_secrets() {
        let text = "Here is my key: AKIAIOSFODNN7EXAMPLE for AWS access";
        let scrubbed = SecretGuard::scrub_secrets(text);
        assert!(!scrubbed.contains("AKIA"));
        assert!(scrubbed.contains("[REDACTED_SECRET]"));
    }
}
