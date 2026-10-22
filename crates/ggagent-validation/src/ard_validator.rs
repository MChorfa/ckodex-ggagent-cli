use crate::error::ValidationError;
use ggagent_kernel::ard::ArdDocument;

pub struct ArdValidator;

impl ArdValidator {
    /// Validates an Agentic Resource Discovery document according to ARD specification
    pub fn validate(doc: &ArdDocument) -> Result<(), ValidationError> {
        if doc.domain.trim().is_empty() {
            return Err(ValidationError::InvalidArdDocument(
                "Domain must be specified".into(),
            ));
        }

        if doc.publisher.trim().is_empty() {
            return Err(ValidationError::InvalidArdDocument(
                "Publisher must be specified".into(),
            ));
        }

        // Each resource must have unique id, valid endpoint, and non-empty name
        let mut seen_ids = std::collections::HashSet::new();
        for res in &doc.resources {
            if res.id.trim().is_empty() {
                return Err(ValidationError::InvalidArdDocument(
                    "Resource ID cannot be empty".into(),
                ));
            }
            if !seen_ids.insert(&res.id) {
                return Err(ValidationError::InvalidArdDocument(format!(
                    "Duplicate resource ID: {}",
                    res.id
                )));
            }
            if res.name.trim().is_empty() {
                return Err(ValidationError::InvalidArdDocument(format!(
                    "Resource {} has empty name",
                    res.id
                )));
            }
            if res.endpoints.is_empty() {
                return Err(ValidationError::InvalidArdDocument(format!(
                    "Resource {} must declare at least one endpoint",
                    res.id
                )));
            }
            for ep in &res.endpoints {
                if ep.uri.trim().is_empty() {
                    return Err(ValidationError::InvalidArdDocument(format!(
                        "Resource {} endpoint {} has empty URI",
                        res.id, ep.name
                    )));
                }
            }
        }

        Ok(())
    }
}
