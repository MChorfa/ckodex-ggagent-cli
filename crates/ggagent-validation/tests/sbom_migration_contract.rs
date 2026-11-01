//! Integration contracts for the Rust sbom-tools analyzer.
//! These tests do not exercise Microsoft's separate sbom-tool executable.

use ggagent_validation::SbomAnalyzer;
use sbom_tools::quality::{ComplianceChecker, ComplianceLevel, QualityScorer, ScoringProfile};
use std::fs;
use tempfile::tempdir;

const CDX: &str = r#"{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [{
    "type": "library",
    "bom-ref": "pkg:cargo/example@1.2.3",
    "name": "example",
    "version": "1.2.3",
    "purl": "pkg:cargo/example@1.2.3"
  }]
}"#;

#[test]
fn normalization_preserves_component_and_parse_paths_agree() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bom.json");
    fs::write(&path, CDX).unwrap();
    let from_path = SbomAnalyzer::parse(&path).unwrap();
    let from_string = SbomAnalyzer::parse_str(CDX).unwrap();
    assert_eq!(from_path.components.len(), 1);
    assert_eq!(from_string.components.len(), 1);
    let path_json = serde_json::to_value(&from_path).unwrap();
    let string_json = serde_json::to_value(&from_string).unwrap();
    assert_eq!(path_json, string_json);
    let serialized = path_json.to_string();
    assert!(serialized.contains("example"));
    assert!(serialized.contains("1.2.3"));
    assert!(SbomAnalyzer::parse_str("not an SBOM").is_err());
}

#[test]
fn compliance_verdict_counts_and_receipt_follow_checker() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bom.json");
    fs::write(&path, CDX).unwrap();
    let sbom = SbomAnalyzer::parse(&path).unwrap();
    let expected = ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(&sbom);
    let (actual, receipt) = SbomAnalyzer::check_compliance(&path, Some("ntia")).unwrap();
    assert_eq!(actual.level, ComplianceLevel::NtiaMinimum);
    assert_eq!(actual.is_compliant, expected.is_compliant);
    assert_eq!(actual.error_count, expected.error_count);
    assert_eq!(actual.warning_count, expected.warning_count);
    assert_eq!(actual.violations.len(), expected.violations.len());
    assert!(receipt.verify_signature());
}

#[test]
fn quality_score_tracks_selected_upstream_profile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bom.json");
    fs::write(&path, CDX).unwrap();
    let sbom = SbomAnalyzer::parse(&path).unwrap();
    let expected = QualityScorer::new(ScoringProfile::Standard).score(&sbom);
    let (actual, receipt) = SbomAnalyzer::score(&path, Some("standard")).unwrap();
    assert!(actual.overall_score.is_finite());
    assert!((actual.overall_score - expected.overall_score).abs() < 0.0001);
    assert_eq!(actual.recommendations.len(), expected.recommendations.len());
    assert!(receipt.verify_signature());
}
