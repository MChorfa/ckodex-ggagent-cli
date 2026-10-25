use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Resource type defined by the Agentic Resource Discovery (ARD) specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArdResourceType {
    Tool,
    McpServer,
    Skill,
    Agent,
    Service,
    Workflow,
}

/// Execution protocol used once discovery completes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArdProtocol {
    McpStdio,
    McpSse,
    A2aRpc,
    RestOpenApi,
    Grpc,
}

/// An endpoint exposed by a discovered resource
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArdEndpoint {
    pub name: String,
    pub protocol: ArdProtocol,
    pub uri: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// Capability descriptor in ARD document
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArdCapability {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub input_schema: Option<serde_json::Value>,
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
}

/// An individual resource entry within an ARD document
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArdResource {
    pub id: String,
    pub name: String,
    #[serde(alias = "type")]
    pub resource_type: ArdResourceType,
    pub version: String,
    pub description: String,
    pub endpoints: Vec<ArdEndpoint>,
    pub capabilities: Vec<ArdCapability>,
    #[serde(default)]
    pub required_authorities: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_ard_schema() -> String {
    "https://agenticresourcediscovery.org/schemas/v1/ard.json".into()
}

/// The canonical Agentic Resource Discovery Document (served at /.well-known/ard.json)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArdDocument {
    #[serde(rename = "$schema", default = "default_ard_schema")]
    pub schema: String,
    pub publisher: String,
    pub domain: String,
    pub version: String,
    #[serde(default = "Utc::now")]
    pub generated_at: DateTime<Utc>,
    pub resources: Vec<ArdResource>,
    #[serde(default)]
    pub registry_federation: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl Default for ArdDocument {
    fn default() -> Self {
        Self {
            schema: "https://agenticresourcediscovery.org/schemas/v1/ard.json".into(),
            publisher: "CKODEX Architecture Team".into(),
            domain: "local.ckodex.org".into(),
            version: "1.0.0".into(),
            generated_at: Utc::now(),
            resources: Vec::new(),
            registry_federation: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }
}

impl ArdDocument {
    pub fn new(publisher: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            publisher: publisher.into(),
            domain: domain.into(),
            ..Default::default()
        }
    }

    pub fn add_resource(&mut self, resource: ArdResource) {
        self.resources.push(resource);
    }

    pub fn find_resource_by_id(&self, id: &str) -> Option<&ArdResource> {
        self.resources.iter().find(|r| r.id == id)
    }

    pub fn find_resources_by_type(&self, rtype: ArdResourceType) -> Vec<&ArdResource> {
        self.resources
            .iter()
            .filter(|r| r.resource_type == rtype)
            .collect()
    }
}
