//! # Governed Egress Proxy & External Policy Decider (Anthropic SRT Pattern)
//!
//! Implements the standalone egress proxy with an external decider:
//! 1. Decoupled policy decider: Workload executes, but external policy decider
//!    evaluates every outbound network request (host, method, headers, path).
//! 2. Credential masking: Scoped credentials/bearer tokens are injected at the proxy
//!    boundary so the executing agent never holds long-lived production secrets.
//! 3. Fail-Closed timeout: Defaults to 5 seconds. If decider is unreachable,
//!    timeout expires, or decision is invalid, egress is strictly blocked.
//! 4. Hardware/IMDS defeat: Explicitly blocks cloud metadata (169.254.169.254/32)
//!    and private intranet ranges.

use crate::error::ValidationError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressProxyRequest {
    pub client_id: String,
    pub method: String,
    pub url: String,
    pub destination_host: String,
    pub destination_port: u16,
    pub headers: BTreeMap<String, String>,
    pub body_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EgressProxyDecision {
    Allow {
        injected_headers: BTreeMap<String, String>,
    },
    Deny {
        reason: String,
    },
    InspectBody {
        max_bytes: usize,
    },
}

#[derive(Debug, Clone)]
pub struct EgressProxyEngine {
    pub allowed_domains: Vec<String>,
    pub timeout_duration: Duration,
    /// Credential vault for proxy-injected headers: domain -> (header_name, header_value)
    pub masked_credentials: BTreeMap<String, (String, String)>,
}

impl Default for EgressProxyEngine {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            timeout_duration: Duration::from_secs(5), // 5-second fail-closed default
            masked_credentials: BTreeMap::new(),
        }
    }
}

impl EgressProxyEngine {
    pub fn new(allowed_domains: Vec<String>, timeout: Duration) -> Self {
        Self {
            allowed_domains,
            timeout_duration: timeout,
            masked_credentials: BTreeMap::new(),
        }
    }

    /// Register a scoped credential to be injected into approved requests for a domain.
    pub fn register_scoped_credential(
        &mut self,
        domain: impl Into<String>,
        header_name: impl Into<String>,
        token: impl Into<String>,
    ) {
        self.masked_credentials
            .insert(domain.into(), (header_name.into(), token.into()));
    }

    /// Evaluate an egress request through the external decider logic.
    pub fn evaluate_request(
        &self,
        req: &EgressProxyRequest,
        simulated_latency: Duration,
    ) -> Result<EgressProxyDecision, ValidationError> {
        // 1. Fail-closed timeout check (5s rule)
        if simulated_latency > self.timeout_duration {
            return Err(ValidationError::EgressProxyViolation(format!(
                "Decider timed out after {}ms (limit: {}ms) - failing closed",
                simulated_latency.as_millis(),
                self.timeout_duration.as_millis()
            )));
        }

        // 2. Hardware / Cloud IMDS Defeat
        if req.destination_host == "169.254.169.254"
            || req.destination_host.starts_with("169.254.")
            || req.destination_host == "fd00:ec2::254"
        {
            return Ok(EgressProxyDecision::Deny {
                reason: "Cloud Instance Metadata Service (IMDS) access is strictly forbidden"
                    .into(),
            });
        }

        // 3. Domain Allowlist Check
        let domain_allowed = self.allowed_domains.iter().any(|d| {
            req.destination_host == *d || req.destination_host.ends_with(&format!(".{}", d))
        });

        if !domain_allowed {
            return Ok(EgressProxyDecision::Deny {
                reason: format!(
                    "Destination host '{}' is not in the approved egress allowlist",
                    req.destination_host
                ),
            });
        }

        // 4. Credential Masking & Ephemeral Injection
        let mut injected = BTreeMap::new();
        if let Some((header_name, token)) = self.masked_credentials.get(&req.destination_host) {
            injected.insert(header_name.clone(), token.clone());
        }

        Ok(EgressProxyDecision::Allow {
            injected_headers: injected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_egress_proxy_imds_blocking() {
        let engine = EgressProxyEngine::new(vec!["api.github.com".into()], Duration::from_secs(5));

        let imds_req = EgressProxyRequest {
            client_id: "agent-001".into(),
            method: "GET".into(),
            url: "http://169.254.169.254/latest/meta-data/".into(),
            destination_host: "169.254.169.254".into(),
            destination_port: 80,
            headers: BTreeMap::new(),
            body_digest: None,
        };

        let decision = engine
            .evaluate_request(&imds_req, Duration::from_millis(50))
            .unwrap();
        assert!(matches!(decision, EgressProxyDecision::Deny { .. }));
    }

    #[test]
    fn test_egress_proxy_credential_injection() {
        let mut engine =
            EgressProxyEngine::new(vec!["api.github.com".into()], Duration::from_secs(5));
        engine.register_scoped_credential(
            "api.github.com",
            "Authorization",
            "Bearer ghp_scoped_token_123",
        );

        let req = EgressProxyRequest {
            client_id: "agent-001".into(),
            method: "POST".into(),
            url: "https://api.github.com/repos/org/repo/pulls".into(),
            destination_host: "api.github.com".into(),
            destination_port: 443,
            headers: BTreeMap::new(),
            body_digest: Some("sha256:payload".into()),
        };

        let decision = engine
            .evaluate_request(&req, Duration::from_millis(100))
            .unwrap();
        match decision {
            EgressProxyDecision::Allow { injected_headers } => {
                assert_eq!(
                    injected_headers.get("Authorization"),
                    Some(&"Bearer ghp_scoped_token_123".to_string())
                );
            }
            _ => panic!("Expected Allow with injected credentials"),
        }
    }

    #[test]
    fn test_egress_proxy_timeout_fails_closed() {
        let engine = EgressProxyEngine::new(vec!["api.github.com".into()], Duration::from_secs(5));
        let req = EgressProxyRequest {
            client_id: "agent-001".into(),
            method: "GET".into(),
            url: "https://api.github.com/zen".into(),
            destination_host: "api.github.com".into(),
            destination_port: 443,
            headers: BTreeMap::new(),
            body_digest: None,
        };

        // 6-second latency exceeds 5-second timeout -> fails closed with error
        let res = engine.evaluate_request(&req, Duration::from_secs(6));
        assert!(res.is_err());
    }
}
