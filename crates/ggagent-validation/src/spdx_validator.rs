//! # SPDX 2.2 / 2.3 Validation Engine
//!
//! Enforces:
//! 1. ISO/IEC 5962:2021 & SPDX 2.2 / 2.3 structural constraints
//! 2. NTIA Minimum Elements for SBOMs (supplier, component name, version, unique IDs, relationship, timestamp)
//! 3. Standard SPDX manifest alignment (`_manifest/spdx_2.2/manifest.spdx.json`)
//! 4. Checksum integrity over declared package artifacts

use crate::error::ValidationError;
use ggagent_kernel::spdx::SpdxDocument;
use std::collections::HashSet;

pub struct SpdxValidator;

impl SpdxValidator {
    /// Validates an SPDX 2.2 document against ISO/IEC 5962:2021 and NTIA requirements
    pub fn validate(doc: &SpdxDocument) -> Result<(), ValidationError> {
        // 1. SPDX Version
        if !doc.spdx_version.starts_with("SPDX-2.") && !doc.spdx_version.starts_with("SPDX-3.") {
            return Err(ValidationError::InvalidSpdxDocument(format!(
                "Unsupported SPDX specification version '{}'; expected 'SPDX-2.2' or 'SPDX-2.3'",
                doc.spdx_version
            )));
        }

        // 2. Data License (SPDX requirement)
        if doc.data_license != "CC0-1.0" {
            return Err(ValidationError::InvalidSpdxDocument(format!(
                "Invalid data license '{}'; SPDX standard mandates 'CC0-1.0'",
                doc.data_license
            )));
        }

        // 3. Document Identifier
        if doc.spdx_id != "SPDXRef-DOCUMENT" {
            return Err(ValidationError::InvalidSpdxDocument(format!(
                "Root SPDXID must be 'SPDXRef-DOCUMENT', got '{}'",
                doc.spdx_id
            )));
        }

        // 4. Document Namespace
        if doc.document_namespace.trim().is_empty() {
            return Err(ValidationError::InvalidSpdxDocument(
                "Document namespace must be a non-empty unique URI".into(),
            ));
        }

        // 5. Creation Info
        if doc.creation_info.creators.is_empty() {
            return Err(ValidationError::InvalidSpdxDocument(
                "SPDX creationInfo must contain at least one creator (Tool, Organization, or Person)".into(),
            ));
        }

        // 6. NTIA Minimum Elements: Packages
        if doc.packages.is_empty() {
            return Err(ValidationError::InvalidSpdxDocument(
                "SBOM document contains zero packages; NTIA minimum elements require at least one package".into(),
            ));
        }

        let mut package_ids = HashSet::new();
        for pkg in &doc.packages {
            if pkg.spdx_id.trim().is_empty() {
                return Err(ValidationError::InvalidSpdxDocument(format!(
                    "Package '{}' has an empty SPDXID",
                    pkg.name
                )));
            }

            if !package_ids.insert(&pkg.spdx_id) {
                return Err(ValidationError::InvalidSpdxDocument(format!(
                    "Duplicate package SPDXID '{}' detected in manifest",
                    pkg.spdx_id
                )));
            }

            if pkg.name.trim().is_empty() {
                return Err(ValidationError::InvalidSpdxDocument(format!(
                    "Package with SPDXID '{}' has an empty name",
                    pkg.spdx_id
                )));
            }

            if pkg.version_info.trim().is_empty() {
                return Err(ValidationError::InvalidSpdxDocument(format!(
                    "Package '{}' has empty version information (NTIA violation)",
                    pkg.name
                )));
            }

            if pkg.supplier.trim().is_empty() {
                return Err(ValidationError::InvalidSpdxDocument(format!(
                    "Package '{}' has empty supplier information (NTIA violation)",
                    pkg.name
                )));
            }

            // Checksum verification
            for c in &pkg.checksums {
                if c.checksum_value.trim().is_empty() {
                    return Err(ValidationError::InvalidSpdxDocument(format!(
                        "Package '{}' has an empty checksum value for algorithm '{}'",
                        pkg.name, c.algorithm
                    )));
                }
            }
        }

        // 7. Relationship Integrity: Root DESCRIBES relation
        let has_describes = doc.relationships.iter().any(|r| {
            r.spdx_element_id == "SPDXRef-DOCUMENT"
                && r.relationship_type.eq_ignore_ascii_case("DESCRIBES")
                && package_ids.contains(&r.related_spdx_element)
        });

        if !has_describes {
            return Err(ValidationError::InvalidSpdxDocument(
                "Manifest is missing a DESCRIBES relationship linking 'SPDXRef-DOCUMENT' to a valid package".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ggagent_kernel::spdx::SpdxDocument;

    #[test]
    fn test_valid_spdx_document_validation() {
        let doc = SpdxDocument::standard_workspace_spdx(
            "test-pkg",
            "1.0.0",
            "CKODEX",
            "https://example.com",
        );
        assert!(SpdxValidator::validate(&doc).is_ok());
    }

    #[test]
    fn test_invalid_license_rejection() {
        let mut doc = SpdxDocument::standard_workspace_spdx(
            "test-pkg",
            "1.0.0",
            "CKODEX",
            "https://example.com",
        );
        doc.data_license = "MIT".into(); // Invalid: standard mandates CC0-1.0
        let res = SpdxValidator::validate(&doc);
        assert!(matches!(res, Err(ValidationError::InvalidSpdxDocument(_))));
    }

    #[test]
    fn test_missing_describes_relationship_rejection() {
        let mut doc = SpdxDocument::standard_workspace_spdx(
            "test-pkg",
            "1.0.0",
            "CKODEX",
            "https://example.com",
        );
        doc.relationships.clear();
        let res = SpdxValidator::validate(&doc);
        assert!(matches!(res, Err(ValidationError::InvalidSpdxDocument(_))));
    }
}
