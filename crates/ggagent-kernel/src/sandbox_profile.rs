//! # Sandbox Isolation Profiles & Syscall Containment (Chapter 11)
//!
//! Provides formal Linux Landlock filesystem and Seccomp-BPF isolation profiles for agents:
//! - Four Isolation Tiers: Minimal, Standard, Hardened, AirGapped
//! - Explicit read-only system roots vs mutable workspace directory
//! - Prohibited dangerous syscalls (`ptrace`, `bpf`, `kexec_load`, `reboot`, `mount`, `chroot`)
//! - Resource limits: max open files, max processes

use crate::error::KernelError;
use crate::network::NetworkEgressPolicy;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProfileTier {
    Minimal,
    Standard,
    #[default]
    Hardened,
    AirGapped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub tier: ProfileTier,
    pub workspace_root: String,
    pub readonly_paths: Vec<String>,
    pub readwrite_paths: Vec<String>,
    pub prohibited_syscalls: Vec<String>,
    pub egress_policy: NetworkEgressPolicy,
    pub max_open_files: u64,
    pub max_processes: u32,
}

impl SandboxProfile {
    pub fn new_hardened(workspace_root: impl Into<String>) -> Self {
        let ws = workspace_root.into();
        Self {
            tier: ProfileTier::Hardened,
            workspace_root: ws.clone(),
            readonly_paths: vec![
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/bin".into(),
                "/etc/ssl".into(),
            ],
            readwrite_paths: vec![ws],
            prohibited_syscalls: vec![
                "ptrace".into(),
                "bpf".into(),
                "kexec_load".into(),
                "reboot".into(),
                "mount".into(),
                "chroot".into(),
                "syslog".into(),
                "userfaultfd".into(),
            ],
            egress_policy: NetworkEgressPolicy::new_hardened(),
            max_open_files: 1024,
            max_processes: 64,
        }
    }

    pub fn new_airgapped(workspace_root: impl Into<String>) -> Self {
        let mut profile = Self::new_hardened(workspace_root);
        profile.tier = ProfileTier::AirGapped;
        profile.egress_policy = NetworkEgressPolicy::new_airgapped();
        profile
    }

    pub fn is_syscall_prohibited(&self, syscall: &str) -> bool {
        self.prohibited_syscalls.iter().any(|s| s == syscall)
    }

    /// Verifies whether write access is permitted for a path under this sandbox profile
    pub fn verify_write_access(&self, target_path: &Path) -> Result<(), KernelError> {
        let target_str = target_path.to_string_lossy();
        for ro in &self.readonly_paths {
            if target_str.starts_with(ro) {
                return Err(KernelError::MissingAuthority(format!(
                    "Write access denied: path '{}' is in ReadOnly sandbox scope '{}'",
                    target_str, ro
                )));
            }
        }

        let is_in_rw = self
            .readwrite_paths
            .iter()
            .any(|rw| target_str.starts_with(rw));
        if !is_in_rw {
            return Err(KernelError::MissingAuthority(format!(
                "Write access denied: path '{}' is outside sandbox ReadWrite scope",
                target_str
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardened_profile_syscall_filter() {
        let profile = SandboxProfile::new_hardened("/tmp/workspace");
        assert!(profile.is_syscall_prohibited("ptrace"));
        assert!(profile.is_syscall_prohibited("bpf"));
        assert!(profile.is_syscall_prohibited("mount"));
        assert!(!profile.is_syscall_prohibited("read"));
    }

    #[test]
    fn test_filesystem_boundary_verification() {
        let profile = SandboxProfile::new_hardened("/tmp/workspace");

        // Write to system path is blocked
        assert!(profile
            .verify_write_access(Path::new("/usr/bin/malicious"))
            .is_err());

        // Write outside workspace is blocked
        assert!(profile
            .verify_write_access(Path::new("/var/log/sys.log"))
            .is_err());

        // Write inside workspace is allowed
        assert!(profile
            .verify_write_access(Path::new("/tmp/workspace/src/lib.rs"))
            .is_ok());
    }
}
