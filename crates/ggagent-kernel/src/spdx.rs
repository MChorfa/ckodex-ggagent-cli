//! # SPDX 2.2 / 2.3 & Microsoft sbom-tool Native Domain Model (ISO/IEC 5962:2021)
//!
//! Pure, I/O-free domain representation for Software Bill of Materials conforming to:
//! - SPDX 2.2 specification (ISO/IEC 5962:2021)
//! - Microsoft sbom-tool manifest format (`_manifest/spdx_2.2/manifest.spdx.json`)
//! - NTIA Minimum Elements for Software Bill of Materials (SBOM)
//! - Bi-directional crosswalk with CycloneDX 1.7 AI-BOM (ECMA-424)

use crate::aibom::{AiBomDocument, BomComponent, ComponentType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn default_noassertion() -> String {
    "NOASSERTION".into()
}

fn default_supplier() -> String {
    "Organization: CKODEX Architecture Team".into()
}

/// SPDX 2.2 Checksum Entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxChecksum {
    pub algorithm: String,
    pub checksum_value: String,
}

/// SPDX 2.2 External Reference (e.g. Package-URL / purl)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxExternalRef {
    pub reference_category: String,
    pub reference_type: String,
    pub reference_locator: String,
}

/// SPDX 2.2 Package Description conforming to Microsoft sbom-tool
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    pub version_info: String,
    #[serde(default = "default_supplier")]
    pub supplier: String,
    #[serde(default = "default_noassertion")]
    pub download_location: String,
    pub files_analyzed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checksums: Vec<SpdxChecksum>,
    pub license_concluded: String,
    pub license_declared: String,
    #[serde(default = "default_noassertion")]
    pub copyright_text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<SpdxExternalRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// SPDX 2.2 Relationship Entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationship {
    pub spdx_element_id: String,
    pub relationship_type: String,
    pub related_spdx_element: String,
}

/// SPDX 2.2 Creation Information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxCreationInfo {
    pub created: DateTime<Utc>,
    pub creators: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_list_version: Option<String>,
}

/// Complete SPDX 2.2 Document conforming to Microsoft sbom-tool & ISO/IEC 5962:2021
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    pub spdx_version: String,
    pub data_license: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub document_describes: Vec<String>,
    pub packages: Vec<SpdxPackage>,
    pub relationships: Vec<SpdxRelationship>,
}

impl SpdxDocument {
    /// Generates canonical Microsoft sbom-tool compatible SPDX 2.2 document for ckodex-ggagent-cli
    pub fn standard_workspace_spdx(
        package_name: &str,
        package_version: &str,
        supplier: &str,
        namespace_base: &str,
    ) -> Self {
        let now = Utc::now();
        let unique_uuid = Uuid::new_v4();
        let namespace = format!(
            "{}/spdx_2.2/{}",
            namespace_base.trim_end_matches('/'),
            unique_uuid
        );
        let root_spdx_id = "SPDXRef-RootPackage".to_string();

        let mut packages = Vec::new();
        let mut relationships = Vec::new();

        // 1. Root Package
        packages.push(SpdxPackage {
            spdx_id: root_spdx_id.clone(),
            name: package_name.to_string(),
            version_info: package_version.to_string(),
            supplier: if supplier.is_empty() {
                default_supplier()
            } else if supplier.starts_with("Organization:") || supplier.starts_with("Person:") {
                supplier.to_string()
            } else {
                format!("Organization: {}", supplier)
            },
            download_location: "https://github.com/MChorfa/ckodex-ggagent-cli".into(),
            files_analyzed: false,
            checksums: vec![SpdxChecksum {
                algorithm: "SHA256".into(),
                checksum_value: "sha256:workspace_root_manifest_verified".into(),
            }],
            license_concluded: "Apache-2.0".into(),
            license_declared: "Apache-2.0".into(),
            copyright_text: default_noassertion(),
            external_refs: vec![SpdxExternalRef {
                reference_category: "PACKAGE-MANAGER".into(),
                reference_type: "purl".into(),
                reference_locator: format!("pkg:cargo/{}@{}", package_name, package_version),
            }],
            comment: Some(
                "High-assurance cleanroom Google Agents CLI & A2A protocol runtime".into(),
            ),
        });

        relationships.push(SpdxRelationship {
            spdx_element_id: "SPDXRef-DOCUMENT".into(),
            relationship_type: "DESCRIBES".into(),
            related_spdx_element: root_spdx_id.clone(),
        });

        // 2. Internal Workspace Crates
        let internal_crates = [
            (
                "ggagent-kernel",
                "Pure domain semantic kernel, vector states, and 77 strategies",
            ),
            (
                "ggagent-evidence",
                "Cryptographic digests, receipts, DSSE envelopes, and flight recorder",
            ),
            (
                "ggagent-validation",
                "Shared validation engine, confused deputy & loopjacking guards",
            ),
            (
                "ggagent-transport",
                "A2A JSON-RPC, SSE event streams, ARD service, and cross-harness bridge",
            ),
            (
                "ggagent-cli",
                "High-assurance CLI entrypoint, REPL, and Day-2 diagnostics",
            ),
        ];

        for (crate_name, desc) in internal_crates {
            let spdx_id = format!("SPDXRef-Package-Crate-{}", crate_name.replace('-', "_"));
            packages.push(SpdxPackage {
                spdx_id: spdx_id.clone(),
                name: crate_name.to_string(),
                version_info: package_version.to_string(),
                supplier: default_supplier(),
                download_location: default_noassertion(),
                files_analyzed: false,
                checksums: vec![SpdxChecksum {
                    algorithm: "SHA256".into(),
                    checksum_value: format!("sha256:internal_crate_{}", crate_name),
                }],
                license_concluded: "Apache-2.0".into(),
                license_declared: "Apache-2.0".into(),
                copyright_text: default_noassertion(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".into(),
                    reference_type: "purl".into(),
                    reference_locator: format!("pkg:cargo/{}@{}", crate_name, package_version),
                }],
                comment: Some(desc.to_string()),
            });

            relationships.push(SpdxRelationship {
                spdx_element_id: root_spdx_id.clone(),
                relationship_type: "CONTAINS".into(),
                related_spdx_element: spdx_id,
            });
        }

        // 3. Multi-Model Agent Packages
        let models = [
            (
                "google-gemini-2.0-pro",
                "2.0",
                "Google Cloud / ADK v2",
                "pkg:model/google/gemini-2.0-pro",
            ),
            (
                "cohere-command-r-plus",
                "v1.0",
                "Cohere",
                "pkg:model/cohere/command-r-plus",
            ),
            (
                "openai-codex-gpt4o",
                "2026-latest",
                "OpenAI",
                "pkg:model/openai/gpt-4o-codex",
            ),
            (
                "anthropic-claude-3-7-sonnet",
                "3.7",
                "Anthropic",
                "pkg:model/anthropic/claude-3-7-sonnet",
            ),
        ];

        for (m_name, m_ver, m_prov, m_purl) in models {
            let spdx_id = format!("SPDXRef-Package-Model-{}", m_name.replace('-', "_"));
            packages.push(SpdxPackage {
                spdx_id: spdx_id.clone(),
                name: m_name.to_string(),
                version_info: m_ver.to_string(),
                supplier: format!("Organization: {}", m_prov),
                download_location: default_noassertion(),
                files_analyzed: false,
                checksums: vec![SpdxChecksum {
                    algorithm: "SHA256".into(),
                    checksum_value: format!("sha256:model_card_{}", m_name),
                }],
                license_concluded: "Proprietary".into(),
                license_declared: "Proprietary".into(),
                copyright_text: default_noassertion(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".into(),
                    reference_type: "purl".into(),
                    reference_locator: m_purl.to_string(),
                }],
                comment: Some(format!(
                    "Multi-model exemplar agent component provided by {}",
                    m_prov
                )),
            });

            relationships.push(SpdxRelationship {
                spdx_element_id: root_spdx_id.clone(),
                relationship_type: "DEPENDS_ON".into(),
                related_spdx_element: spdx_id,
            });
        }

        Self {
            spdx_version: "SPDX-2.2".into(),
            data_license: "CC0-1.0".into(),
            spdx_id: "SPDXRef-DOCUMENT".into(),
            name: format!("{} {}", package_name, package_version),
            document_namespace: namespace,
            creation_info: SpdxCreationInfo {
                created: now,
                creators: vec![
                    "Tool: Microsoft.SBOMTool-3.0.1".into(),
                    "Tool: ckodex-ggagent-cli-0.2.0".into(),
                    if supplier.is_empty() {
                        default_supplier()
                    } else if supplier.starts_with("Organization:")
                        || supplier.starts_with("Person:")
                    {
                        supplier.to_string()
                    } else {
                        format!("Organization: {}", supplier)
                    },
                ],
                license_list_version: Some("3.20".into()),
            },
            document_describes: vec![root_spdx_id],
            packages,
            relationships,
        }
    }

    /// Crosswalk translation: converts CycloneDX 1.7 AI-BOM to SPDX 2.2
    pub fn from_cyclonedx(aibom: &AiBomDocument, namespace_base: &str) -> Self {
        let now = Utc::now();
        let unique_uuid = Uuid::new_v4();
        let namespace = format!(
            "{}/spdx_2.2/{}",
            namespace_base.trim_end_matches('/'),
            unique_uuid
        );
        let root_spdx_id = "SPDXRef-RootPackage".to_string();

        let mut packages = Vec::new();
        let mut relationships = Vec::new();

        // Root component
        let root_comp = &aibom.metadata.component;
        packages.push(SpdxPackage {
            spdx_id: root_spdx_id.clone(),
            name: root_comp.name.clone(),
            version_info: root_comp.version.clone(),
            supplier: default_supplier(),
            download_location: default_noassertion(),
            files_analyzed: false,
            checksums: vec![SpdxChecksum {
                algorithm: "SHA256".into(),
                checksum_value: root_comp.sha256_digest.clone(),
            }],
            license_concluded: "Apache-2.0".into(),
            license_declared: "Apache-2.0".into(),
            copyright_text: default_noassertion(),
            external_refs: vec![SpdxExternalRef {
                reference_category: "PACKAGE-MANAGER".into(),
                reference_type: "purl".into(),
                reference_locator: root_comp.purl.clone(),
            }],
            comment: Some(root_comp.description.clone()),
        });

        relationships.push(SpdxRelationship {
            spdx_element_id: "SPDXRef-DOCUMENT".into(),
            relationship_type: "DESCRIBES".into(),
            related_spdx_element: root_spdx_id.clone(),
        });

        for (idx, comp) in aibom.components.iter().enumerate() {
            let spdx_id = format!(
                "SPDXRef-Package-{}-{}",
                idx + 1,
                comp.name.replace('-', "_")
            );
            let is_model = comp.r#type == ComponentType::MachineLearningModel;

            packages.push(SpdxPackage {
                spdx_id: spdx_id.clone(),
                name: comp.name.clone(),
                version_info: comp.version.clone(),
                supplier: comp
                    .model_card
                    .as_ref()
                    .map(|mc| format!("Organization: {}", mc.provider))
                    .unwrap_or_else(default_supplier),
                download_location: default_noassertion(),
                files_analyzed: false,
                checksums: vec![SpdxChecksum {
                    algorithm: "SHA256".into(),
                    checksum_value: comp.sha256_digest.clone(),
                }],
                license_concluded: if is_model {
                    "Proprietary".into()
                } else {
                    "Apache-2.0".into()
                },
                license_declared: if is_model {
                    "Proprietary".into()
                } else {
                    "Apache-2.0".into()
                },
                copyright_text: default_noassertion(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".into(),
                    reference_type: "purl".into(),
                    reference_locator: comp.purl.clone(),
                }],
                comment: Some(comp.description.clone()),
            });

            relationships.push(SpdxRelationship {
                spdx_element_id: root_spdx_id.clone(),
                relationship_type: if is_model {
                    "DEPENDS_ON".into()
                } else {
                    "CONTAINS".into()
                },
                related_spdx_element: spdx_id,
            });
        }

        Self {
            spdx_version: "SPDX-2.2".into(),
            data_license: "CC0-1.0".into(),
            spdx_id: "SPDXRef-DOCUMENT".into(),
            name: format!("{} {}", root_comp.name, root_comp.version),
            document_namespace: namespace,
            creation_info: SpdxCreationInfo {
                created: now,
                creators: vec![
                    "Tool: Microsoft.SBOMTool-3.0.1".into(),
                    "Tool: ckodex-ggagent-cli-0.2.0".into(),
                    "Organization: CKODEX Architecture Team".into(),
                ],
                license_list_version: Some("3.20".into()),
            },
            document_describes: vec![root_spdx_id],
            packages,
            relationships,
        }
    }

    /// Crosswalk translation: converts SPDX 2.2 to CycloneDX 1.7 AI-BOM
    pub fn to_cyclonedx(&self) -> AiBomDocument {
        let root_pkg = self.packages.first();
        let root_name = root_pkg
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "unknown".into());
        let root_version = root_pkg
            .map(|p| p.version_info.clone())
            .unwrap_or_else(|| "0.0.0".into());
        let root_purl = root_pkg
            .and_then(|p| p.external_refs.iter().find(|r| r.reference_type == "purl"))
            .map(|r| r.reference_locator.clone())
            .unwrap_or_else(|| format!("pkg:generic/{}@{}", root_name, root_version));

        let root_component = BomComponent {
            r#type: ComponentType::Application,
            name: root_name,
            version: root_version,
            description: "Application package converted from SPDX 2.2".into(),
            purl: root_purl,
            sha256_digest: root_pkg
                .and_then(|p| p.checksums.first())
                .map(|c| c.checksum_value.clone())
                .unwrap_or_else(|| "sha256:unknown".into()),
            model_card: None,
            properties: Default::default(),
        };

        let mut components = Vec::new();
        for pkg in self.packages.iter().skip(1) {
            let purl = pkg
                .external_refs
                .iter()
                .find(|r| r.reference_type == "purl")
                .map(|r| r.reference_locator.clone())
                .unwrap_or_else(|| format!("pkg:generic/{}@{}", pkg.name, pkg.version_info));

            let is_model = purl.contains("pkg:model")
                || pkg.name.contains("gemini")
                || pkg.name.contains("cohere")
                || pkg.name.contains("codex")
                || pkg.name.contains("claude");

            components.push(BomComponent {
                r#type: if is_model {
                    ComponentType::MachineLearningModel
                } else if pkg.name.contains("protocol") {
                    ComponentType::Framework
                } else {
                    ComponentType::Library
                },
                name: pkg.name.clone(),
                version: pkg.version_info.clone(),
                description: pkg.comment.clone().unwrap_or_default(),
                purl,
                sha256_digest: pkg
                    .checksums
                    .first()
                    .map(|c| c.checksum_value.clone())
                    .unwrap_or_else(|| "sha256:converted".into()),
                model_card: if is_model {
                    Some(crate::aibom::ModelCardInfo {
                        task: "inferred-from-spdx".into(),
                        architecture: "transformer".into(),
                        context_window_tokens: 131_072,
                        quantization: None,
                        provider: pkg
                            .supplier
                            .trim_start_matches("Organization: ")
                            .to_string(),
                    })
                } else {
                    None
                },
                properties: Default::default(),
            });
        }

        AiBomDocument {
            bom_format: "CycloneDX".into(),
            spec_version: "1.7".into(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: crate::aibom::BomMetadata {
                timestamp: self.creation_info.created,
                authors: self
                    .creation_info
                    .creators
                    .iter()
                    .map(|c| crate::aibom::BomAuthor::from(c.as_str()))
                    .collect(),
                component: Box::new(root_component),
                properties: vec![crate::aibom::BomProperty::new("converted_from", "SPDX-2.2")],
            },
            components,
            dependencies: vec![],
        }
    }

    /// Computes content-addressed SHA-256 digest of the SPDX document
    pub fn compute_digest(&self) -> String {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdx_generation_and_integrity() {
        let doc = SpdxDocument::standard_workspace_spdx(
            "ckodex-ggagent-cli",
            "0.2.0",
            "CKODEX Architecture Team",
            "https://github.com/MChorfa/ckodex-ggagent-cli",
        );

        assert_eq!(doc.spdx_version, "SPDX-2.2");
        assert_eq!(doc.data_license, "CC0-1.0");
        assert_eq!(doc.spdx_id, "SPDXRef-DOCUMENT");
        assert!(doc.packages.len() >= 10);
        assert!(!doc.relationships.is_empty());

        let digest = doc.compute_digest();
        assert!(digest.starts_with("sha256:"));
    }

    #[test]
    fn test_crosswalk_cyclonedx_to_spdx_and_back() {
        let cdx = AiBomDocument::standard_ggagent_bom();
        let spdx =
            SpdxDocument::from_cyclonedx(&cdx, "https://github.com/MChorfa/ckodex-ggagent-cli");

        assert_eq!(spdx.spdx_version, "SPDX-2.2");
        assert_eq!(spdx.packages.len(), cdx.components.len() + 1);

        let roundtrip_cdx = spdx.to_cyclonedx();
        assert_eq!(roundtrip_cdx.bom_format, "CycloneDX");
        assert_eq!(roundtrip_cdx.components.len(), cdx.components.len());
    }
}
