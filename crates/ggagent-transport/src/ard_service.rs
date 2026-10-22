use ggagent_kernel::ard::{
    ArdCapability, ArdDocument, ArdEndpoint, ArdProtocol, ArdResource, ArdResourceType,
};
use std::sync::{Arc, RwLock};

pub struct ArdService {
    document: Arc<RwLock<ArdDocument>>,
}

impl ArdService {
    pub fn new(domain: &str, publisher: &str) -> Self {
        let mut doc = ArdDocument::new(publisher, domain);

        // Register default local capabilities
        doc.add_resource(ArdResource {
            id: "ggagent-a2a-service".into(),
            name: "CKODEX A2A Agent Service".into(),
            resource_type: ArdResourceType::Agent,
            version: "2.0.0".into(),
            description: "High-assurance A2A protocol agent runtime with Confused Deputy defense"
                .into(),
            endpoints: vec![
                ArdEndpoint {
                    name: "rpc".into(),
                    protocol: ArdProtocol::A2aRpc,
                    uri: format!("https://{}/api/v1/a2a", domain),
                    headers: Default::default(),
                },
                ArdEndpoint {
                    name: "events".into(),
                    protocol: ArdProtocol::A2aRpc,
                    uri: format!("https://{}/api/v1/a2a/events", domain),
                    headers: Default::default(),
                },
            ],
            capabilities: vec![
                ArdCapability {
                    id: "evaluate_conformance".into(),
                    name: "Evaluate Conformance".into(),
                    description: "Runs conformance vector evaluation with hard anti-invariants"
                        .into(),
                    tags: vec!["governance".into(), "conformance".into()],
                    input_schema: None,
                    output_schema: None,
                },
                ArdCapability {
                    id: "subagent_dispatch".into(),
                    name: "Subagent Dispatch".into(),
                    description:
                        "Orchestrates multi-tier subagents across the 77 canonical strategies"
                            .into(),
                    tags: vec!["orchestration".into(), "subagents".into()],
                    input_schema: None,
                    output_schema: None,
                },
            ],
            required_authorities: vec!["ckodex:authority:root".into()],
            metadata: Default::default(),
        });

        // Register MCP Bridge capability
        doc.add_resource(ArdResource {
            id: "ggagent-mcp-bridge".into(),
            name: "CKODEX MCP Bridge".into(),
            resource_type: ArdResourceType::McpServer,
            version: "1.0.0".into(),
            description:
                "Model Context Protocol bridge for cross-harness tool discovery and execution"
                    .into(),
            endpoints: vec![ArdEndpoint {
                name: "mcp-sse".into(),
                protocol: ArdProtocol::McpSse,
                uri: format!("https://{}/mcp/sse", domain),
                headers: Default::default(),
            }],
            capabilities: vec![ArdCapability {
                id: "call_mcp_tool".into(),
                name: "Call MCP Tool".into(),
                description: "Calls local or remote MCP tools with capability lease fencing".into(),
                tags: vec!["mcp".into(), "tools".into()],
                input_schema: None,
                output_schema: None,
            }],
            required_authorities: vec!["ckodex:authority:workspace".into()],
            metadata: Default::default(),
        });

        Self {
            document: Arc::new(RwLock::new(doc)),
        }
    }

    pub fn get_document(&self) -> ArdDocument {
        self.document.read().unwrap().clone()
    }

    pub fn add_resource(&self, resource: ArdResource) {
        let mut doc = self.document.write().unwrap();
        doc.add_resource(resource);
    }
}
