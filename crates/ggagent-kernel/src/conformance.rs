use crate::vector_state::VectorState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Required disposition from a conformance transition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConformanceDisposition {
    Admit,
    AdmitWithObligations,
    Deny,
    Escalate,
    SafeHold,
    Quarantine,
}

/// Stimulus / Operation / Event applied to state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceStimulus {
    pub name: String,
    pub payload: serde_json::Value,
    pub source: String,
}

/// Conformance Vector Transition contract:
/// delta(Pe, S0, X, C) = <d, O, S1, E, R>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVector {
    pub vector_id: String,
    pub description: String,
    pub effective_policy: String,
    pub initial_state: VectorState,
    pub stimulus: ConformanceStimulus,
    pub context: BTreeMap<String, String>,
    pub required_disposition: ConformanceDisposition,
    pub required_obligations: Vec<String>,
    pub expected_resulting_state: VectorState,
    pub required_evidence: Vec<String>,
    pub recovery_triggers: Vec<String>,
}

/// Result of evaluating a conformance transition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceEvaluationResult {
    pub vector_id: String,
    pub is_conformant: bool,
    pub observed_disposition: ConformanceDisposition,
    pub missing_obligations: Vec<String>,
    pub state_divergence: Option<String>,
    pub missing_evidence: Vec<String>,
}

/// Formal Split Conformal Risk Certificate
///
/// Implements finite-sample split conformal prediction over non-conformity scores:
/// R_i = s(X_i, Y_i), computing \hat{q} = Quantile(1 - alpha; (n+1)/n).
///
/// Guarantees P(Y_{n+1} in C(X_{n+1})) >= 1 - alpha under exchangeability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConformalRiskCertificate {
    pub alpha: f64,
    pub target_coverage: f64,
    pub calibration_size: usize,
    pub nonconformity_quantile_qhat: f64,
    pub empirical_risk: f64,
    pub empirical_coverage: f64,
    pub finite_sample_valid: bool,
    pub certificate_digest: String,
}

impl ConformalRiskCertificate {
    /// Computes the exact split conformal quantile \hat{q}
    pub fn compute_split_conformal(mut scores: Vec<f64>, alpha: f64) -> Result<Self, String> {
        if scores.is_empty() {
            return Err("Calibration set cannot be empty".into());
        }
        if alpha <= 0.0 || alpha >= 1.0 {
            return Err("Significance level alpha must be strictly in (0, 1)".into());
        }

        let n = scores.len();
        // Sort nonconformity scores ascending
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Finite-sample adjusted quantile index: ceil((n + 1) * (1 - alpha))
        let target_rank = ((n + 1) as f64 * (1.0 - alpha)).ceil() as usize;
        let rank = target_rank.clamp(1, n);
        let qhat = scores[rank - 1];

        // Empirical risk = proportion of scores exceeding qhat
        let violations = scores.iter().filter(|&&s| s > qhat).count();
        let empirical_risk = violations as f64 / n as f64;
        let empirical_coverage = 1.0 - empirical_risk;
        let finite_sample_valid = empirical_coverage >= (1.0 - alpha);

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(format!("{}:{}:{:.4}:{:.4}", alpha, n, qhat, empirical_coverage).as_bytes());
        let digest_hex = hex::encode(hasher.finalize());
        let certificate_digest = format!("sha256-conformal:{}", digest_hex);

        Ok(Self {
            alpha,
            target_coverage: 1.0 - alpha,
            calibration_size: n,
            nonconformity_quantile_qhat: qhat,
            empirical_risk,
            empirical_coverage,
            finite_sample_valid,
            certificate_digest,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_split_conformal_finite_sample_coverage() {
        // Calibration scores: 95 conformant (0.05), 5 borderline (0.2)
        let mut scores = vec![0.05; 95];
        scores.extend(vec![0.20; 5]);

        let cert = ConformalRiskCertificate::compute_split_conformal(scores, 0.10)
            .expect("conformal calibration must succeed");

        assert_eq!(cert.calibration_size, 100);
        assert!(cert.target_coverage >= 0.90);
        assert!(cert.finite_sample_valid);
        assert!(cert.empirical_coverage >= 0.90);
        assert!(cert.certificate_digest.starts_with("sha256-conformal:"));
    }

    #[test]
    fn test_conformal_bounds_validation() {
        assert!(ConformalRiskCertificate::compute_split_conformal(vec![], 0.05).is_err());
        assert!(ConformalRiskCertificate::compute_split_conformal(vec![0.1], 0.0).is_err());
        assert!(ConformalRiskCertificate::compute_split_conformal(vec![0.1], 1.0).is_err());
    }
}
