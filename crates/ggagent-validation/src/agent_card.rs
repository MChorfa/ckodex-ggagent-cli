use crate::error::ValidationError;
use ggagent_kernel::a2a::AgentCard;

pub struct AgentCardValidator;

impl AgentCardValidator {
    /// Validates an A2A Agent Card discovery document
    pub fn validate(card: &AgentCard) -> Result<(), ValidationError> {
        if card.name.trim().is_empty() {
            return Err(ValidationError::InvalidAgentCard(
                "Agent name cannot be empty".into(),
            ));
        }

        if card.version.trim().is_empty() {
            return Err(ValidationError::InvalidAgentCard(
                "Agent version cannot be empty".into(),
            ));
        }

        if card.endpoints.rpc.trim().is_empty() {
            return Err(ValidationError::InvalidAgentCard(
                "RPC endpoint URI cannot be empty".into(),
            ));
        }

        if card.endpoints.events.trim().is_empty() {
            return Err(ValidationError::InvalidAgentCard(
                "Events endpoint URI cannot be empty".into(),
            ));
        }

        if card.capabilities.is_empty() {
            return Err(ValidationError::InvalidAgentCard(
                "Agent must declare at least one capability".into(),
            ));
        }

        for cap in &card.capabilities {
            if cap.id.trim().is_empty() {
                return Err(ValidationError::InvalidAgentCard(
                    "Capability id cannot be empty".into(),
                ));
            }
            if cap.description.trim().is_empty() {
                return Err(ValidationError::InvalidAgentCard(format!(
                    "Capability {} description cannot be empty",
                    cap.id
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ggagent_kernel::a2a::{A2AAuth, A2ACapability, A2AEndpoints};
    use std::collections::BTreeMap;

    #[test]
    fn test_valid_agent_card() {
        let card = AgentCard {
            schema: "https://a2aprotocol.org/schemas/v1/agent-card.json".into(),
            name: "ggagent-verifier".into(),
            version: "1.0.0".into(),
            description: "A2A compliant verifier".into(),
            endpoints: A2AEndpoints {
                rpc: "https://agent.local/api/v1/a2a".into(),
                events: "https://agent.local/api/v1/a2a/events".into(),
            },
            capabilities: vec![A2ACapability {
                id: "verify_contract".into(),
                description: "Verifies state transition contract".into(),
                parameters: BTreeMap::new(),
            }],
            authentication: A2AAuth {
                auth_type: "mtls_or_bearer".into(),
                token_endpoint: None,
            },
            metadata: BTreeMap::new(),
        };

        assert!(AgentCardValidator::validate(&card).is_ok());
    }
}
