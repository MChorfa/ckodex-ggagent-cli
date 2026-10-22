use crate::error::TransportError;
use serde::{Deserialize, Serialize};

/// Supported AI Agent Harness Families
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessFamily {
    AntigravityGemini,
    ClaudeCode,
    CodexOpenAi,
    OpenCode,
    SamMesh,
    GoogleAgentsCli,
}

/// Harness Configuration Profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessProfile {
    pub family: HarnessFamily,
    pub config_dir: String,
    pub skills_dir: String,
    pub dispatch_command: String,
    pub discovery_protocol: String,
    pub capabilities: Vec<String>,
}

pub struct CrossHarnessBridge;

impl CrossHarnessBridge {
    /// Detects and returns configuration profiles for all major coding agent harnesses
    pub fn get_standard_profiles() -> Vec<HarnessProfile> {
        vec![
            HarnessProfile {
                family: HarnessFamily::AntigravityGemini,
                config_dir: "~/.gemini".into(),
                skills_dir: "~/.gemini/config/skills".into(),
                dispatch_command: "gemini -p \"<intent>\"".into(),
                discovery_protocol: "A2A + ARD + MCP".into(),
                capabilities: vec![
                    "a2a_streaming".into(),
                    "ard_discovery".into(),
                    "mcp_client".into(),
                ],
            },
            HarnessProfile {
                family: HarnessFamily::ClaudeCode,
                config_dir: "~/.claude".into(),
                skills_dir: ".claude/agents".into(),
                dispatch_command: "claude -p \"<intent>\"".into(),
                discovery_protocol: "CLAUDE.md + MCP".into(),
                capabilities: vec!["tool_use".into(), "subagents".into()],
            },
            HarnessProfile {
                family: HarnessFamily::CodexOpenAi,
                config_dir: "~/.codex".into(),
                skills_dir: ".codex/skills".into(),
                dispatch_command: "codex exec \"<intent>\"".into(),
                discovery_protocol: "Responses API + MCP".into(),
                capabilities: vec!["headless_exec".into(), "review".into()],
            },
            HarnessProfile {
                family: HarnessFamily::OpenCode,
                config_dir: "~/.opencode".into(),
                skills_dir: ".opencode/skills".into(),
                dispatch_command: "opencode run \"<intent>\"".into(),
                discovery_protocol: "OpenCode manifest".into(),
                capabilities: vec!["eval".into(), "refine".into()],
            },
            HarnessProfile {
                family: HarnessFamily::SamMesh,
                config_dir: "~/.sam".into(),
                skills_dir: "sam/skills".into(),
                dispatch_command: "sam-node call <agent> <tool>".into(),
                discovery_protocol: "A2A Mesh + ARD".into(),
                capabilities: vec!["mesh_discovery".into(), "p2p_rpc".into()],
            },
            HarnessProfile {
                family: HarnessFamily::GoogleAgentsCli,
                config_dir: "~/.agents".into(),
                skills_dir: ".agents/skills".into(),
                dispatch_command: "agents-cli eval run".into(),
                discovery_protocol: "ADK v2 + A2A".into(),
                capabilities: vec![
                    "adk_workflows".into(),
                    "playground".into(),
                    "cloud_deploy".into(),
                ],
            },
        ]
    }

    /// Translates an intent envelope into a harness-specific command line invocation
    pub fn format_dispatch(
        family: HarnessFamily,
        problem: &str,
        role_tier: &str,
    ) -> Result<String, TransportError> {
        let clean_problem = problem.replace('\"', "\\\"");
        match family {
            HarnessFamily::AntigravityGemini => Ok(format!("gemini -p \"{}\"", clean_problem)),
            HarnessFamily::CodexOpenAi => Ok(format!("codex exec \"{}\"", clean_problem)),
            HarnessFamily::ClaudeCode => Ok(format!(
                "claude -p \"{}\" --model {}",
                clean_problem, role_tier
            )),
            HarnessFamily::OpenCode => Ok(format!("opencode run --prompt \"{}\"", clean_problem)),
            HarnessFamily::SamMesh => Ok(format!("a2a call --task \"{}\"", clean_problem)),
            HarnessFamily::GoogleAgentsCli => {
                Ok(format!("agents-cli eval run --query \"{}\"", clean_problem))
            }
        }
    }
}
