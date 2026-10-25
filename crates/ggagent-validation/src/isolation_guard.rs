//! # Isolation Guard (Section 5, INVARITH v0.2.0)
//!
//! Enforces:
//! - GFX-S05: No execution/placement if minimum boundary cannot be established. No weaker fallback!
//! - GFX-S06: For hostile workers, no ambient host FS, sockets, secrets, IPC or direct external network.
//! - Verification of isolation contract compatibility across:
//!   `LocalDev < WasiComponent < OciGvisor < MicroVm < ConfidentialVm`.

use crate::error::ValidationError;
use ggagent_kernel::governed_execution::{IsolationClass, IsolationContract};

pub struct IsolationGuard;

impl IsolationGuard {
    /// Validate that the host environment runtime satisfies the workload's isolation contract.
    pub fn verify_isolation_boundary(
        contract: &IsolationContract,
        host_runtime: &IsolationClass,
    ) -> Result<(), ValidationError> {
        contract
            .validate_host_runtime(host_runtime)
            .map_err(|e| ValidationError::IsolationViolation(e.to_string()))
    }

    /// Check if a threat profile requires hardware virtualization (MicroVM / ConfidentialVM)
    pub fn is_hardware_isolation_mandatory(threat_profile: &str) -> bool {
        matches!(
            threat_profile,
            "hostile" | "adversarial" | "untrusted_binary" | "external_unreviewed"
        )
    }

    /// Evaluate whether a workload can be admitted to the requested runtime
    pub fn evaluate_placement(
        threat_profile: &str,
        requested_class: IsolationClass,
        host_runtime: IsolationClass,
    ) -> Result<(), ValidationError> {
        if Self::is_hardware_isolation_mandatory(threat_profile)
            && requested_class < IsolationClass::MicroVm
        {
            return Err(ValidationError::IsolationViolation(format!(
                "Threat profile '{}' mandates hardware MicroVm or higher; requested {:?}",
                threat_profile, requested_class
            )));
        }

        let contract = IsolationContract::new(requested_class, "governed-tenant", "workload-eval");
        Self::verify_isolation_boundary(&contract, &host_runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostile_workload_requires_microvm() {
        // Hostile workload requesting LocalDev is rejected
        assert!(IsolationGuard::evaluate_placement(
            "hostile",
            IsolationClass::LocalDev,
            IsolationClass::LocalDev
        )
        .is_err());

        // Hostile workload requesting MicroVm on MicroVm host succeeds
        assert!(IsolationGuard::evaluate_placement(
            "hostile",
            IsolationClass::MicroVm,
            IsolationClass::MicroVm
        )
        .is_ok());

        // Hostile workload requesting MicroVm on OciGvisor fails closed (no silent downgrade)
        assert!(IsolationGuard::evaluate_placement(
            "hostile",
            IsolationClass::MicroVm,
            IsolationClass::OciGvisor
        )
        .is_err());
    }

    #[test]
    fn test_trusted_workload_can_use_local_dev() {
        assert!(IsolationGuard::evaluate_placement(
            "trusted_dev",
            IsolationClass::LocalDev,
            IsolationClass::LocalDev
        )
        .is_ok());
    }
}
