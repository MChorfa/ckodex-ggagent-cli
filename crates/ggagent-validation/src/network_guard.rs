//! # Network Egress Guard (Chapter 9)
//!
//! Enforces network boundary isolation for sandboxed workloads:
//! - Default-deny domain filtering
//! - Strict port enforcement (e.g. 443, 80 only)
//! - Cloud metadata service defeat (IMDSv2: 169.254.169.254, metadata.google.internal)
//! - Private intranet IP blocking (RFC 1918)
//! - Air-gapped absolute isolation

use crate::error::ValidationError;
use ggagent_kernel::network::{EgressMode, NetworkEgressPolicy};

pub struct NetworkEgressGuard;

impl NetworkEgressGuard {
    /// Validates an outbound network destination against the sandbox egress policy
    pub fn verify_egress(
        policy: &NetworkEgressPolicy,
        destination: &str,
        port: u16,
    ) -> Result<(), ValidationError> {
        // 1. Air-Gapped mode prohibits all egress
        if policy.mode == EgressMode::AirGapped {
            return Err(ValidationError::EgressViolation(format!(
                "Air-gapped sandbox strictly prohibits network egress to '{}:{}'",
                destination, port
            )));
        }

        // 2. Port check
        if !policy.allowed_ports.contains(&port) {
            return Err(ValidationError::EgressViolation(format!(
                "Outbound port {} is not in allowed port list {:?}",
                port, policy.allowed_ports
            )));
        }

        let dest_lower = destination.trim().to_lowercase();

        // 3. Cloud Instance Metadata Service (IMDS) Blocking
        if policy.block_cloud_metadata
            && (dest_lower == "169.254.169.254"
                || dest_lower == "metadata.google.internal"
                || dest_lower.starts_with("169.254."))
        {
            return Err(ValidationError::EgressViolation(format!(
                "Cloud instance metadata service access strictly prohibited: {}",
                destination
            )));
        }

        // 4. Private Intranet / Loopback Blocking (RFC 1918)
        if policy.block_private_intranet
            && (dest_lower == "localhost"
                || dest_lower.starts_with("127.")
                || dest_lower.starts_with("10.")
                || dest_lower.starts_with("192.168.")
                || Self::is_rfc1918_172(&dest_lower))
        {
            return Err(ValidationError::EgressViolation(format!(
                "Private intranet or loopback access blocked: {}",
                destination
            )));
        }

        // 5. Domain Allowlist Check
        let is_allowed = policy.allowed_domains.iter().any(|allowed| {
            if allowed.starts_with("*.") {
                let suffix = &allowed[1..]; // e.g. .github.com
                dest_lower.ends_with(suffix)
            } else {
                dest_lower == allowed.to_lowercase()
            }
        });

        if !is_allowed {
            return Err(ValidationError::EgressViolation(format!(
                "Destination '{}' is not in allowed domain list",
                destination
            )));
        }

        Ok(())
    }

    fn is_rfc1918_172(dest: &str) -> bool {
        if let Some(rest) = dest.strip_prefix("172.") {
            if let Some(second_octet_str) = rest.split('.').next() {
                if let Ok(second_octet) = second_octet_str.parse::<u8>() {
                    return (16..=31).contains(&second_octet);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_metadata_blocked() {
        let policy = NetworkEgressPolicy::new_hardened();
        let res = NetworkEgressGuard::verify_egress(&policy, "169.254.169.254", 80);
        assert!(matches!(res, Err(ValidationError::EgressViolation(_))));

        let res_gcp = NetworkEgressGuard::verify_egress(&policy, "metadata.google.internal", 80);
        assert!(matches!(res_gcp, Err(ValidationError::EgressViolation(_))));
    }

    #[test]
    fn test_intranet_blocked() {
        let policy = NetworkEgressPolicy::new_hardened();
        assert!(NetworkEgressGuard::verify_egress(&policy, "10.0.1.5", 443).is_err());
        assert!(NetworkEgressGuard::verify_egress(&policy, "192.168.1.1", 443).is_err());
        assert!(NetworkEgressGuard::verify_egress(&policy, "127.0.0.1", 443).is_err());
        assert!(NetworkEgressGuard::verify_egress(&policy, "localhost", 443).is_err());
    }

    #[test]
    fn test_allowlisted_domains_pass() {
        let policy = NetworkEgressPolicy::new_hardened();
        assert!(NetworkEgressGuard::verify_egress(&policy, "crates.io", 443).is_ok());
        assert!(NetworkEgressGuard::verify_egress(&policy, "api.github.com", 443).is_ok());
    }

    #[test]
    fn test_airgap_blocks_all() {
        let policy = NetworkEgressPolicy::new_airgapped();
        assert!(NetworkEgressGuard::verify_egress(&policy, "crates.io", 443).is_err());
    }
}
