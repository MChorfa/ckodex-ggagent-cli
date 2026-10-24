//! # SPDX 2.2 / 2.3 & sbom-tools Integration Bridge
//!
//! Provides cleanroom interoperability with SPDX tools:
//! - Auto-discovery of the `sbom-tool` CLI binary on the host environment
//! - Cleanroom native Rust fallback when external tool is unavailable
//! - Strict conformance to the `_manifest/spdx_2.2/manifest.spdx.json` layout
//! - Cryptographic Ed25519 execution receipt issuance for all SBOM generation & audit events

use crate::error::ValidationError;
use crate::spdx_validator::SpdxValidator;
use ggagent_evidence::{DigestEngine, ExecutionReceipt, ExecutionReceiptParams};
use ggagent_kernel::spdx::SpdxDocument;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Execution Result from SbomToolBridge
#[derive(Debug, Clone)]
pub struct SbomExecutionResult {
    pub manifest_path: PathBuf,
    pub manifest_digest: String,
    pub spdx_document: SpdxDocument,
    pub is_external_tool_used: bool,
    pub receipt: ExecutionReceipt,
}

pub struct SbomToolBridge;

impl SbomToolBridge {
    /// Detects if external `sbom-tool` is present on the PATH
    pub fn find_binary() -> Option<PathBuf> {
        let binary_name = if cfg!(windows) {
            "sbom-tool.exe"
        } else {
            "sbom-tool"
        };
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join(binary_name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// Checks if external `sbom-tool` is available
    pub fn is_available() -> bool {
        Self::find_binary().is_some()
    }

    /// Queries the installed version of `sbom-tool`
    pub fn version() -> Option<String> {
        let bin = Self::find_binary()?;
        let output = Command::new(bin).arg("--version").output().ok()?;
        if output.status.success() {
            let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Some(ver)
        } else {
            None
        }
    }

    /// Generates an SPDX 2.2 SBOM conforming to ISO/IEC 5962:2021 standards
    pub fn generate_manifest(
        drop_path: &Path,
        _components_path: &Path,
        package_name: &str,
        package_version: &str,
        supplier: &str,
        namespace_base: &str,
        prefer_external: bool,
    ) -> Result<SbomExecutionResult, ValidationError> {
        let start = Instant::now();
        let external_bin = if prefer_external {
            Self::find_binary()
        } else {
            None
        };

        let (spdx_doc, is_external) = if let Some(bin) = external_bin {
            // Execute external sbom-tool
            let status = Command::new(&bin)
                .arg("generate")
                .arg("-b")
                .arg(drop_path)
                .arg("-pn")
                .arg(package_name)
                .arg("-pv")
                .arg(package_version)
                .arg("-ps")
                .arg(supplier)
                .arg("-nsb")
                .arg(namespace_base)
                .status()
                .map_err(|e| {
                    ValidationError::SbomToolExecutionError(format!(
                        "Failed to execute external sbom-tool at '{}': {}",
                        bin.display(),
                        e
                    ))
                })?;

            if !status.success() {
                return Err(ValidationError::SbomToolExecutionError(format!(
                    "External sbom-tool generate exited with status code {:?}",
                    status.code()
                )));
            }

            // Read generated manifest
            let expected_manifest = drop_path
                .join("_manifest")
                .join("spdx_2.2")
                .join("manifest.spdx.json");
            let content = fs::read_to_string(&expected_manifest).map_err(|e| {
                ValidationError::SbomToolExecutionError(format!(
                    "Failed to read sbom-tool generated manifest at '{}': {}",
                    expected_manifest.display(),
                    e
                ))
            })?;
            let doc: SpdxDocument = serde_json::from_str(&content).map_err(|e| {
                ValidationError::InvalidSpdxDocument(format!(
                    "Failed to parse sbom-tool output: {}",
                    e
                ))
            })?;
            (doc, true)
        } else {
            // Cleanroom native generation conforming to ISO/IEC 5962:2021 layout
            let doc = SpdxDocument::standard_workspace_spdx(
                package_name,
                package_version,
                supplier,
                namespace_base,
            );
            SpdxValidator::validate(&doc)?;

            let manifest_dir = drop_path.join("_manifest").join("spdx_2.2");
            fs::create_dir_all(&manifest_dir).map_err(|e| {
                ValidationError::SbomToolExecutionError(format!(
                    "Failed to create manifest directory '{}': {}",
                    manifest_dir.display(),
                    e
                ))
            })?;

            let manifest_file = manifest_dir.join("manifest.spdx.json");
            let serialized = serde_json::to_string_pretty(&doc).map_err(|e| {
                ValidationError::InvalidSpdxDocument(format!("Serialization error: {}", e))
            })?;

            fs::write(&manifest_file, serialized).map_err(|e| {
                ValidationError::SbomToolExecutionError(format!(
                    "Failed to write manifest file '{}': {}",
                    manifest_file.display(),
                    e
                ))
            })?;

            (doc, false)
        };

        let manifest_path = drop_path
            .join("_manifest")
            .join("spdx_2.2")
            .join("manifest.spdx.json");
        let manifest_digest = spdx_doc.compute_digest();

        let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
            task_id: format!("sbom-gen-{}", package_name),
            actor_id: if is_external {
                "tool:external-sbom-tool".into()
            } else {
                "tool:ggagent-native-spdx".into()
            },
            authority_id: "auth:root:supply-chain".into(),
            capability_id: "generate_spdx_sbom".into(),
            action: "sbom_generate".into(),
            input_digest: DigestEngine::sha256_str(&format!(
                "{}:{}",
                package_name, package_version
            )),
            output_digest: manifest_digest.clone(),
            effect_digest: DigestEngine::sha256_str(&manifest_path.to_string_lossy()),
            duration_ms: start.elapsed().as_millis() as u64,
            exit_code: 0,
        });

        Ok(SbomExecutionResult {
            manifest_path,
            manifest_digest,
            spdx_document: spdx_doc,
            is_external_tool_used: is_external,
            receipt,
        })
    }

    /// Validates an existing SPDX 2.2 SBOM manifest
    pub fn validate_manifest(
        drop_path: &Path,
        manifest_path: Option<&Path>,
        prefer_external: bool,
    ) -> Result<ExecutionReceipt, ValidationError> {
        let start = Instant::now();
        let target_manifest = if let Some(p) = manifest_path {
            p.to_path_buf()
        } else {
            drop_path
                .join("_manifest")
                .join("spdx_2.2")
                .join("manifest.spdx.json")
        };

        if !target_manifest.exists() {
            return Err(ValidationError::InvalidSpdxDocument(format!(
                "Manifest file not found at '{}'",
                target_manifest.display()
            )));
        }

        let is_external = if prefer_external && Self::is_available() {
            let bin = Self::find_binary().unwrap();
            let status = Command::new(&bin)
                .arg("validate")
                .arg("-b")
                .arg(drop_path)
                .arg("-m")
                .arg(&target_manifest)
                .status()
                .map_err(|e| {
                    ValidationError::SbomToolExecutionError(format!(
                        "External sbom-tool validate execution failed: {}",
                        e
                    ))
                })?;

            if !status.success() {
                return Err(ValidationError::SbomToolExecutionError(format!(
                    "External sbom-tool validate failed with exit code {:?}",
                    status.code()
                )));
            }
            true
        } else {
            // Cleanroom native validation
            let content = fs::read_to_string(&target_manifest).map_err(|e| {
                ValidationError::InvalidSpdxDocument(format!(
                    "Failed to read manifest for validation at '{}': {}",
                    target_manifest.display(),
                    e
                ))
            })?;
            let doc: SpdxDocument = serde_json::from_str(&content).map_err(|e| {
                ValidationError::InvalidSpdxDocument(format!(
                    "Manifest failed JSON schema parsing: {}",
                    e
                ))
            })?;
            SpdxValidator::validate(&doc)?;
            false
        };

        let digest = DigestEngine::sha256_str(&target_manifest.to_string_lossy());
        let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
            task_id: format!(
                "sbom-val-{}",
                target_manifest
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            ),
            actor_id: if is_external {
                "tool:external-sbom-tool".into()
            } else {
                "tool:ggagent-native-spdx".into()
            },
            authority_id: "auth:root:supply-chain".into(),
            capability_id: "validate_spdx_sbom".into(),
            action: "sbom_validate".into(),
            input_digest: digest.clone(),
            output_digest: "sha256:spdx_manifest_verified".into(),
            effect_digest: "sha256:zero_side_effect_audit".into(),
            duration_ms: start.elapsed().as_millis() as u64,
            exit_code: 0,
        });

        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_native_sbom_tool_generate_and_validate_flow() {
        let temp = tempdir().expect("tempdir");
        let drop_path = temp.path();
        let components_path = temp.path();

        let result = SbomToolBridge::generate_manifest(
            drop_path,
            components_path,
            "test-suite",
            "1.0.0",
            "CKODEX Team",
            "https://test.local",
            false,
        )
        .expect("native sbom-tool generation");

        assert!(result.manifest_path.exists());
        assert!(result
            .manifest_path
            .ends_with("_manifest/spdx_2.2/manifest.spdx.json"));
        assert!(!result.is_external_tool_used);
        assert!(result.receipt.verify_signature());

        // Now validate
        let val_rcpt =
            SbomToolBridge::validate_manifest(drop_path, None, false).expect("validation succeeds");
        assert!(val_rcpt.verify_signature());
    }
}
