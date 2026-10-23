//! # SBOM Semantic Analyzer & Regulatory Compliance Engine
//!
//! Provides comprehensive supply-chain domain analysis and assurance:
//! - Multi-format ingestion and normalization across CycloneDX (1.4-1.7) and SPDX (2.2-3.0)
//! - Semantic component, dependency, license, and vulnerability diffing via `DiffEngine`
//! - Regulatory compliance audits across NTIA, EU CRA (Phases 1 & 2), FDA, EO 14028, NIST SSDF
//! - Quality scoring with mathematical weights, actionable recommendations, and letter grades (A+, A, B, etc.)
//! - Cryptographic Ed25519 execution receipt issuance with SHA-256 digests for all SBOM analysis events

use crate::error::ValidationError;
use ggagent_evidence::{DigestEngine, ExecutionReceipt, ExecutionReceiptParams};
use sbom_tools::diff::{DiffEngine, DiffResult};
use sbom_tools::model::NormalizedSbom;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::quality::{
    ComplianceChecker, ComplianceLevel, ComplianceResult, QualityReport, QualityScorer,
    ScoringProfile,
};
use std::path::Path;
use std::time::Instant;

pub struct SbomAnalyzer;

impl SbomAnalyzer {
    /// Ingests and normalizes any CycloneDX or SPDX SBOM into unified `NormalizedSbom`
    pub fn parse(path: &Path) -> Result<NormalizedSbom, ValidationError> {
        parse_sbom(path).map_err(|e| {
            ValidationError::SbomAnalysisError(format!(
                "Failed to parse SBOM at '{}': {}",
                path.display(),
                e
            ))
        })
    }

    /// Performs semantic diff between two SBOM documents (version changes, additions, removals, license shifts)
    pub fn diff(
        old_path: &Path,
        new_path: &Path,
    ) -> Result<(DiffResult, ExecutionReceipt), ValidationError> {
        let start = Instant::now();
        let old_sbom = Self::parse(old_path)?;
        let new_sbom = Self::parse(new_path)?;

        let engine = DiffEngine::new();
        let diff_result = engine.diff(&old_sbom, &new_sbom).map_err(|e| {
            ValidationError::SbomAnalysisError(format!("Semantic diff failed: {}", e))
        })?;

        let elapsed = start.elapsed().as_millis() as u64;
        let input_digest = DigestEngine::sha256_str(&format!(
            "{}:{}",
            old_path.to_string_lossy(),
            new_path.to_string_lossy()
        ));
        let output_digest = DigestEngine::sha256_str(&format!(
            "score:{:.2},added:{},removed:{},modified:{}",
            diff_result.semantic_score,
            diff_result.components.added.len(),
            diff_result.components.removed.len(),
            diff_result.components.modified.len()
        ));

        let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
            task_id: format!(
                "sbom-diff-{}-to-{}",
                old_path.file_name().unwrap_or_default().to_string_lossy(),
                new_path.file_name().unwrap_or_default().to_string_lossy()
            ),
            actor_id: "validator:sbom-analyzer".into(),
            authority_id: "auth:root:supply-chain:diff".into(),
            capability_id: "semantic_sbom_diff".into(),
            action: "diff_sboms".into(),
            input_digest,
            output_digest,
            effect_digest: "sha256:zero_side_effect_diff".into(),
            duration_ms: elapsed,
            exit_code: 0,
        });

        Ok((diff_result, receipt))
    }

    /// Evaluates SBOM quality and scores completeness, licensing, and security best practices
    pub fn score(
        path: &Path,
        profile_name: Option<&str>,
    ) -> Result<(QualityReport, ExecutionReceipt), ValidationError> {
        let start = Instant::now();
        let sbom = Self::parse(path)?;

        let profile = match profile_name.unwrap_or("standard").to_lowercase().as_str() {
            "minimal" => ScoringProfile::Minimal,
            "security" => ScoringProfile::Security,
            "license" | "license-compliance" => ScoringProfile::LicenseCompliance,
            "cra" | "cyber-resilience" => ScoringProfile::Cra,
            "bsi" | "tr-03183" => ScoringProfile::BsiTr03183_2,
            "cbom" | "crypto" => ScoringProfile::Cbom,
            "ai" | "ai-readiness" | "model" => ScoringProfile::AiReadiness,
            "comprehensive" | "full" => ScoringProfile::Comprehensive,
            _ => ScoringProfile::Standard,
        };

        let scorer = QualityScorer::new(profile);
        let report = scorer.score(&sbom);
        let elapsed = start.elapsed().as_millis() as u64;

        let input_digest = DigestEngine::sha256_str(&path.to_string_lossy());
        let output_digest = DigestEngine::sha256_str(&format!(
            "grade:{:?},score:{},rec_count:{}",
            report.grade,
            report.overall_score,
            report.recommendations.len()
        ));

        let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
            task_id: format!(
                "sbom-score-{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
            actor_id: "validator:sbom-analyzer".into(),
            authority_id: "auth:root:supply-chain:quality".into(),
            capability_id: "score_sbom_quality".into(),
            action: "quality_score".into(),
            input_digest,
            output_digest,
            effect_digest: "sha256:zero_side_effect_quality_score".into(),
            duration_ms: elapsed,
            exit_code: 0,
        });

        Ok((report, receipt))
    }

    /// Evaluates SBOM compliance against regulatory frameworks (NTIA, CRA, FDA, EO 14028, NIST SSDF)
    pub fn check_compliance(
        path: &Path,
        framework: Option<&str>,
    ) -> Result<(ComplianceResult, ExecutionReceipt), ValidationError> {
        let start = Instant::now();
        let sbom = Self::parse(path)?;

        let level = match framework.unwrap_or("ntia").to_lowercase().as_str() {
            "cra1" | "cra-phase1" => ComplianceLevel::CraPhase1,
            "cra2" | "cra-phase2" | "cra" => ComplianceLevel::CraPhase2,
            "fda" | "fda-medical" => ComplianceLevel::FdaMedicalDevice,
            "eo14028" | "eo-14028" => ComplianceLevel::Eo14028,
            "ssdf" | "nist-ssdf" => ComplianceLevel::NistSsdf,
            "pqc" | "nist-pqc" => ComplianceLevel::NistPqc,
            "bsi" => ComplianceLevel::BsiTr03183_2,
            _ => ComplianceLevel::NtiaMinimum,
        };

        let checker = ComplianceChecker::new(level);
        let result = checker.check(&sbom);
        let elapsed = start.elapsed().as_millis() as u64;

        let input_digest = DigestEngine::sha256_str(&path.to_string_lossy());
        let output_digest = DigestEngine::sha256_str(&format!(
            "compliant:{},errors:{},warnings:{}",
            result.is_compliant, result.error_count, result.warning_count
        ));

        let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
            task_id: format!(
                "sbom-compliance-{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
            actor_id: "validator:sbom-analyzer".into(),
            authority_id: "auth:root:supply-chain:compliance".into(),
            capability_id: "check_sbom_compliance".into(),
            action: "compliance_check".into(),
            input_digest,
            output_digest,
            effect_digest: "sha256:zero_side_effect_compliance_audit".into(),
            duration_ms: elapsed,
            exit_code: if result.is_compliant { 0 } else { 1 },
        });

        Ok((result, receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sbom_analyzer_parse_and_score() {
        let temp = tempdir().expect("tempdir");
        let sbom_path = temp.path().join("sample_cyclonedx.json");

        // Create standard CycloneDX 1.7 AI-BOM
        let cdx = ggagent_kernel::aibom::AiBomDocument::standard_ggagent_bom();
        let serialized = serde_json::to_string_pretty(&cdx).expect("serialize cdx");
        std::fs::write(&sbom_path, &serialized).expect("write sbom");

        // Parse via SbomAnalyzer
        let parsed = SbomAnalyzer::parse(&sbom_path).expect("parse sbom succeeds");
        assert!(!parsed.components.is_empty());

        // Score via SbomAnalyzer
        let (report, receipt) =
            SbomAnalyzer::score(&sbom_path, Some("standard")).expect("score succeeds");
        assert!(receipt.verify_signature());
        assert!(report.overall_score > 0.0);

        // Check compliance against NTIA Minimum Elements
        let (compliance, comp_rcpt) =
            SbomAnalyzer::check_compliance(&sbom_path, Some("ntia")).expect("compliance check");
        assert!(comp_rcpt.verify_signature());
        assert_eq!(compliance.level, ComplianceLevel::NtiaMinimum);
    }

    #[test]
    fn test_sbom_analyzer_diff() {
        let temp = tempdir().expect("tempdir");
        let path1 = temp.path().join("sbom_v1.json");
        let path2 = temp.path().join("sbom_v2.json");

        let cdx1 = ggagent_kernel::aibom::AiBomDocument::standard_ggagent_bom();
        let mut cdx2 = cdx1.clone();
        // Remove one component in v2 to test diff
        cdx2.components.pop();

        std::fs::write(&path1, serde_json::to_string(&cdx1).unwrap()).unwrap();
        std::fs::write(&path2, serde_json::to_string(&cdx2).unwrap()).unwrap();

        let (diff_result, receipt) = SbomAnalyzer::diff(&path1, &path2).expect("diff succeeds");
        assert!(receipt.verify_signature());
        assert!(diff_result.semantic_score < 100.0);
        assert!(!diff_result.components.removed.is_empty());
    }
}
