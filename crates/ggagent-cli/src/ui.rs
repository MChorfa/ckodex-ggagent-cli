//! CKODEX Terminal UI & Multi-Format Rendering Engine (CKODEX-DS-3)
//!
//! Provides consistent design system styling, ANSI terminal cards, progress gauges,
//! shell autocompletion support, and multi-format exporters (JSON, SARIF v2.1.0, GFM Markdown).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;

/// Supported output formats for CLI commands
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Polished terminal card with ANSI styling and visual gauges
    Table,
    /// Machine-readable formatted JSON with execution receipts
    Json,
    /// OASIS SARIF v2.1.0 for GitHub / GitLab Code Scanning alerts
    Sarif,
    /// GitHub Flavored Markdown (GFM) for PR comments and CI summaries
    Markdown,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Sarif => write!(f, "sarif"),
            OutputFormat::Markdown => write!(f, "markdown"),
        }
    }
}

/// Diagnostic check item for Day-2 health evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticItem {
    pub id: usize,
    pub name: String,
    pub status: bool,
    pub details: String,
}

/// Diagnostic report summary for JSON/Markdown output
#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub status: String,
    pub checks_passed: usize,
    pub checks_total: usize,
    pub timestamp: String,
    pub checks: Vec<DiagnosticItem>,
}

/// ANSI Terminal Styler conforming to CKODEX-DS-3
#[allow(dead_code)]
pub struct Styler {
    enabled: bool,
}

impl Default for Styler {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl Styler {
    pub fn new() -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let is_term = std::io::stdout().is_terminal();
        Self {
            enabled: is_term && !no_color,
        }
    }

    pub fn with_enabled(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn bold(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn dim(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[2m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn green(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[32m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn bold_green(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1;32m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn red(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[31m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn bold_red(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1;31m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn yellow(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[33m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn bold_yellow(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1;33m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn cyan(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[36m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn bold_cyan(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1;36m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn magenta(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[35m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn bold_magenta(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1;35m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    pub fn badge_pass(&self, label: &str) -> String {
        if self.enabled {
            format!("\x1b[1;42;30m {} \x1b[0m", label)
        } else {
            format!("[{}]", label)
        }
    }

    pub fn badge_fail(&self, label: &str) -> String {
        if self.enabled {
            format!("\x1b[1;41;37m {} \x1b[0m", label)
        } else {
            format!("[{}]", label)
        }
    }

    pub fn badge_warn(&self, label: &str) -> String {
        if self.enabled {
            format!("\x1b[1;43;30m {} \x1b[0m", label)
        } else {
            format!("[{}]", label)
        }
    }

    pub fn badge_info(&self, label: &str) -> String {
        if self.enabled {
            format!("\x1b[1;46;30m {} \x1b[0m", label)
        } else {
            format!("[{}]", label)
        }
    }

    pub fn badge_receipt(&self, label: &str) -> String {
        if self.enabled {
            format!("\x1b[1;45;37m {} \x1b[0m", label)
        } else {
            format!("[{}]", label)
        }
    }

    /// Renders a visual score gauge, e.g. `[████████░░] 81.5%`
    pub fn gauge(&self, score: f64, max: f64, width: usize) -> String {
        let ratio = (score / max).clamp(0.0, 1.0);
        let filled = (ratio * width as f64).round() as usize;
        let empty = width.saturating_sub(filled);

        let bar_filled: String = "█".repeat(filled);
        let bar_empty: String = "░".repeat(empty);

        let colored_bar = if self.enabled {
            if ratio >= 0.85 {
                format!("\x1b[32m{}\x1b[2m{}\x1b[0m", bar_filled, bar_empty)
            } else if ratio >= 0.60 {
                format!("\x1b[33m{}\x1b[2m{}\x1b[0m", bar_filled, bar_empty)
            } else {
                format!("\x1b[31m{}\x1b[2m{}\x1b[0m", bar_filled, bar_empty)
            }
        } else {
            format!("{}{}", bar_filled, bar_empty)
        };

        let pct = ratio * 100.0;
        format!("[{}] {:>5.1}%", colored_bar, pct)
    }

    /// Renders a card header
    pub fn card_header(&self, title: &str, width: usize) -> String {
        let content_width = width.saturating_sub(4);
        let title_padded = if title.len() > content_width {
            &title[..content_width]
        } else {
            title
        };
        let line = "─".repeat(width.saturating_sub(title_padded.len() + 5));
        if self.enabled {
            format!(
                "\x1b[1;36m┌─ \x1b[1;37m{}\x1b[1;36m {}\x1b[0m",
                title_padded, line
            )
        } else {
            format!("┌─ {} {}", title_padded, line)
        }
    }

    /// Renders a card section title
    pub fn card_section(&self, title: &str) -> String {
        if self.enabled {
            format!("  \x1b[1;34m▸ {}\x1b[0m", title)
        } else {
            format!("  ▸ {}", title)
        }
    }

    /// Renders a key-value row inside a card
    pub fn card_row(&self, key: &str, val: &str, key_width: usize) -> String {
        if self.enabled {
            format!(
                "    \x1b[2m{:<width$}:\x1b[0m \x1b[1m{}\x1b[0m",
                key,
                val,
                width = key_width
            )
        } else {
            format!("    {:<width$}: {}", key, val, width = key_width)
        }
    }

    /// Renders a card footer
    pub fn card_footer(&self, width: usize) -> String {
        let line = "─".repeat(width.saturating_sub(2));
        if self.enabled {
            format!("\x1b[1;36m└{}\x1b[0m", line)
        } else {
            format!("└{}", line)
        }
    }
}

/// SARIF v2.1.0 Report Generator for Supply Chain and Compliance Audits
#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleConfig {
    pub level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

impl SarifReport {
    /// Builds a SARIF v2.1.0 document from SbomAnalyzer compliance violations
    pub fn from_compliance_violations(
        file_path: &str,
        framework_name: &str,
        violations: &[(String, String, String)], // (rule_id, severity, message)
    ) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for (rule_id, severity, message) in violations {
            let sarif_level = match severity.to_lowercase().as_str() {
                "error" | "high" | "critical" => "error",
                "warn" | "warning" | "medium" => "warning",
                _ => "note",
            };

            if seen_rules.insert(rule_id.clone()) {
                rules.push(SarifRule {
                    id: rule_id.clone(),
                    name: format!("SBOM-COMPLIANCE-{}", rule_id),
                    short_description: SarifMessage {
                        text: format!("{} Regulatory Rule: {}", framework_name, rule_id),
                    },
                    default_configuration: SarifRuleConfig {
                        level: sarif_level.to_string(),
                    },
                });
            }

            results.push(SarifResult {
                rule_id: rule_id.clone(),
                level: sarif_level.to_string(),
                message: SarifMessage {
                    text: message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: file_path.to_string(),
                        },
                    },
                }],
            });
        }

        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".into(),
            version: "2.1.0".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "ggagent-sbom-analyzer".into(),
                        version: "0.2.0".into(),
                        information_uri: "https://github.com/MChorfa/ckodex-ggagent-cli".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}

/// Helper for rendering a high-density interactive terminal dashboard (CKODEX-DS-3)
pub struct DashboardRenderer {
    styler: Styler,
}

impl Default for DashboardRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardRenderer {
    pub fn new() -> Self {
        Self {
            styler: Styler::new(),
        }
    }

    /// Renders the Day-2 Operational Diagnostics & Architecture Dashboard
    pub fn render_overview(
        &self,
        subsystems_ok: usize,
        subsystems_total: usize,
        strategies_count: usize,
        sbom_status: &str,
        mesh_status: &str,
    ) {
        let width = 76;
        println!(
            "{}",
            self.styler
                .card_header("CKODEX AGENTIC RUNTIME DASHBOARD (v0.2.0)", width)
        );
        println!(
            "  {}",
            self.styler
                .dim("Zero-Trust • Authority-Born • Pure Kernel • Evidence Fabric")
        );
        println!();

        println!("{}", self.styler.card_section("Day-2 Operational Health"));
        let ratio = subsystems_ok as f64 / subsystems_total as f64;
        let gauge_str = self
            .styler
            .gauge(subsystems_ok as f64, subsystems_total as f64, 18);
        println!(
            "{}",
            self.styler.card_row(
                "Subsystems Active",
                &format!("{}/{}  {}", subsystems_ok, subsystems_total, gauge_str),
                22
            )
        );
        let health_badge = if ratio >= 1.0 {
            self.styler.badge_pass("HEALTHY")
        } else {
            self.styler.badge_warn("DEGRADED")
        };
        println!(
            "{}",
            self.styler.card_row("Overall Health", &health_badge, 22)
        );
        println!();

        println!(
            "{}",
            self.styler
                .card_section("Supply Chain & SBOM Semantic Engine")
        );
        println!(
            "{}",
            self.styler.card_row("Engine Backend", sbom_status, 22)
        );
        println!(
            "{}",
            self.styler.card_row(
                "Standards Supported",
                "CycloneDX 1.4-1.7, SPDX 2.2/2.3, ISO/IEC 5962:2021",
                22
            )
        );
        println!(
            "{}",
            self.styler.card_row(
                "Compliance Frameworks",
                "NTIA Minimum Elements, EU CRA, FDA, EO 14028, NIST SSDF",
                22
            )
        );
        println!();

        println!(
            "{}",
            self.styler
                .card_section("Multi-Agent Mesh & Strategy Catalog")
        );
        println!(
            "{}",
            self.styler.card_row(
                "Cataloged Strategies",
                &format!(
                    "{} across 7 archetypes (Tier S, B, R, Peer)",
                    strategies_count
                ),
                22
            )
        );
        println!(
            "{}",
            self.styler
                .card_row("Mesh DAG Orchestrator", mesh_status, 22)
        );
        println!(
            "{}",
            self.styler.card_row(
                "Protocol Standard",
                "Google ADK v2 / A2A Protocol / ARD v1.0",
                22
            )
        );
        println!(
            "{}",
            self.styler.card_row(
                "Security Guards",
                "Confused Deputy (CVE-2026-18236) & Loopjacking Active",
                22
            )
        );
        println!();

        println!(
            "{}",
            self.styler.card_section("Evidence & Cryptographic Proof")
        );
        println!(
            "{}",
            self.styler.card_row(
                "Receipt Signature",
                "Ed25519 DSSE Envelope with SHA-256 Hashes",
                22
            )
        );
        println!(
            "{}",
            self.styler.card_row(
                "Vector State Model",
                "S(e,t) = ⟨P, V, A, C, E, L, τ⟩ Multi-Dimensional",
                22
            )
        );
        println!(
            "{}",
            self.styler
                .card_row("Timestamp", &Utc::now().to_rfc3339(), 22)
        );
        println!("{}", self.styler.card_footer(width));
    }

    /// Renders Day-2 diagnostics across table, json, or markdown formats
    pub fn render_diagnostics(&self, checks: &[DiagnosticItem], format: OutputFormat) {
        let total = checks.len();
        let passed = checks.iter().filter(|c| c.status).count();
        let is_healthy = passed == total;

        match format {
            OutputFormat::Table => {
                println!("🩺 Running CKODEX Deep Day-2 Diagnostics (Doctor)...\n");
                for c in checks {
                    let badge = if c.status {
                        self.styler.bold_green("[OK]")
                    } else {
                        self.styler.bold_red("[FAIL]")
                    };
                    println!("  {} {}: {}", badge, self.styler.bold(&c.name), c.details);
                }
                println!();
                if is_healthy {
                    println!(
                        "{} Overall System Health: NORMAL / COHERENT ({}/{} subsystems verified)",
                        self.styler.badge_pass("HEALTHY"),
                        passed,
                        total
                    );
                } else {
                    println!(
                        "{} Overall System Health: DEGRADED ({}/{} subsystems verified)",
                        self.styler.badge_warn("DEGRADED"),
                        passed,
                        total
                    );
                }
            }
            OutputFormat::Json => {
                let report = DiagnosticReport {
                    status: if is_healthy {
                        "HEALTHY".into()
                    } else {
                        "DEGRADED".into()
                    },
                    checks_passed: passed,
                    checks_total: total,
                    timestamp: Utc::now().to_rfc3339(),
                    checks: checks.to_vec(),
                };
                let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                println!("{}", json);
            }
            OutputFormat::Markdown => {
                println!("# 🩺 CKODEX Deep Day-2 Diagnostics Report\n");
                println!(
                    "- **Overall Health:** {} ({}/{} subsystems active)",
                    if is_healthy {
                        ":white_check_mark: HEALTHY"
                    } else {
                        ":warning: DEGRADED"
                    },
                    passed,
                    total
                );
                println!("- **Timestamp:** `{}`\n", Utc::now().to_rfc3339());
                println!("| # | Subsystem | Status | Details |");
                println!("|---|-----------|--------|---------|");
                for c in checks {
                    let status_icon = if c.status {
                        ":white_check_mark: PASS"
                    } else {
                        ":x: FAIL"
                    };
                    println!(
                        "| {} | {} | {} | {} |",
                        c.id, c.name, status_icon, c.details
                    );
                }
            }
            OutputFormat::Sarif => {
                let report = DiagnosticReport {
                    status: if is_healthy {
                        "HEALTHY".into()
                    } else {
                        "DEGRADED".into()
                    },
                    checks_passed: passed,
                    checks_total: total,
                    timestamp: Utc::now().to_rfc3339(),
                    checks: checks.to_vec(),
                };
                let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                println!("{}", json);
            }
        }
    }
}
