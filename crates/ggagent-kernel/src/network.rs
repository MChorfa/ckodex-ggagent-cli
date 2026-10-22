//! # Network Egress Policy & Domain Governance (Chapter 9)
//!
//! Enforces default-deny network egress policy for agent sandboxes:
//! - Strict domain and port allowlisting
//! - Cloud metadata service blocking (169.254.169.254 / IMDSv2 protection)
//! - Private intranet IP blocking (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
//! - Air-gap compliance: zero network egress when mode is AirGapped

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EgressMode {
    #[default]
    DefaultDeny,
    Allowlisted,
    AirGapped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEgressPolicy {
    pub mode: EgressMode,
    pub allowed_domains: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub block_cloud_metadata: bool,
    pub block_private_intranet: bool,
}

impl Default for NetworkEgressPolicy {
    fn default() -> Self {
        Self::new_hardened()
    }
}

impl NetworkEgressPolicy {
    /// Creates a hardened default-deny egress policy with metadata & intranet blocking
    pub fn new_hardened() -> Self {
        Self {
            mode: EgressMode::Allowlisted,
            allowed_domains: vec![
                "api.github.com".into(),
                "crates.io".into(),
                "static.crates.io".into(),
                "registry.npmjs.org".into(),
                "pypi.org".into(),
                "files.pythonhosted.org".into(),
            ],
            allowed_ports: vec![443, 80],
            block_cloud_metadata: true,
            block_private_intranet: true,
        }
    }

    /// Creates an air-gapped policy: zero network egress permitted
    pub fn new_airgapped() -> Self {
        Self {
            mode: EgressMode::AirGapped,
            allowed_domains: Vec::new(),
            allowed_ports: Vec::new(),
            block_cloud_metadata: true,
            block_private_intranet: true,
        }
    }

    pub fn allow_domain(&mut self, domain: impl Into<String>) -> &mut Self {
        self.allowed_domains.push(domain.into());
        self
    }

    pub fn allow_port(&mut self, port: u16) -> &mut Self {
        self.allowed_ports.push(port);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardened_policy_defaults() {
        let policy = NetworkEgressPolicy::new_hardened();
        assert_eq!(policy.mode, EgressMode::Allowlisted);
        assert!(policy.block_cloud_metadata);
        assert!(policy.block_private_intranet);
        assert!(policy.allowed_ports.contains(&443));
        assert!(policy.allowed_domains.contains(&"crates.io".to_string()));
    }

    #[test]
    fn test_airgapped_policy_blocks_all() {
        let policy = NetworkEgressPolicy::new_airgapped();
        assert_eq!(policy.mode, EgressMode::AirGapped);
        assert!(policy.allowed_domains.is_empty());
    }
}
