use crate::error::KernelError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Google A2A typed role representation.
/// Vital defense against Confused Deputy (CVE-2026-18236 / ADK Issue #6461):
/// RemoteAgent turns MUST NOT be mapped to HumanUser or allowed to confirm dangerous tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum A2ARole {
    #[default]
    HumanUser,
    RemoteAgent,
    Tool,
    System,
}

/// Google A2A Task Lifecycle State Machine (as standardized under Linux Foundation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum A2ATaskState {
    #[default]
    TaskStateSubmitted,
    TaskStateWorking,
    TaskStateAuthRequired,
    TaskStateAuthReceived,
    TaskStateCompleted,
    TaskStateFailed,
    TaskStateCancelled,
}

/// A2A Message Part
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum A2APart {
    Text { text: String },
    Data { mime_type: String, data: String },
    ArtifactRef { uri: String, digest: String },
}

/// A2A Message Turn
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AMessage {
    pub message_id: String,
    pub role: A2ARole,
    pub sender_id: String,
    pub parts: Vec<A2APart>,
    pub timestamp: DateTime<Utc>,
    /// If this message claims to confirm or authorize an action, specify call_id
    pub confirmed_call_id: Option<String>,
}

/// Google A2A Task Entity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2ATask {
    pub task_id: String,
    pub session_id: String,
    pub state: A2ATaskState,
    pub initiator_role: A2ARole,
    pub capability_id: String,
    pub history: Vec<A2AMessage>,
    pub required_effect_digest: Option<String>,
    pub output_artifacts: Vec<String>,
    pub failure_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: BTreeMap<String, String>,
}

impl A2ATask {
    pub fn new(
        task_id: impl Into<String>,
        session_id: impl Into<String>,
        capability_id: impl Into<String>,
        initiator: A2ARole,
    ) -> Self {
        let now = Utc::now();
        Self {
            task_id: task_id.into(),
            session_id: session_id.into(),
            state: A2ATaskState::TaskStateSubmitted,
            initiator_role: initiator,
            capability_id: capability_id.into(),
            history: Vec::new(),
            required_effect_digest: None,
            output_artifacts: Vec::new(),
            failure_reason: None,
            created_at: now,
            updated_at: now,
            metadata: BTreeMap::new(),
        }
    }

    /// Advance task state according to A2A FSM transition rules
    pub fn transition_to(&mut self, next: A2ATaskState) -> Result<(), KernelError> {
        let valid = matches!(
            (self.state, next),
            (
                A2ATaskState::TaskStateSubmitted,
                A2ATaskState::TaskStateWorking
            ) | (
                A2ATaskState::TaskStateSubmitted,
                A2ATaskState::TaskStateCancelled
            ) | (
                A2ATaskState::TaskStateWorking,
                A2ATaskState::TaskStateAuthRequired
            ) | (
                A2ATaskState::TaskStateWorking,
                A2ATaskState::TaskStateCompleted
            ) | (
                A2ATaskState::TaskStateWorking,
                A2ATaskState::TaskStateFailed
            ) | (
                A2ATaskState::TaskStateWorking,
                A2ATaskState::TaskStateCancelled
            ) | (
                A2ATaskState::TaskStateAuthRequired,
                A2ATaskState::TaskStateAuthReceived
            ) | (
                A2ATaskState::TaskStateAuthRequired,
                A2ATaskState::TaskStateFailed
            ) | (
                A2ATaskState::TaskStateAuthRequired,
                A2ATaskState::TaskStateCancelled
            ) | (
                A2ATaskState::TaskStateAuthReceived,
                A2ATaskState::TaskStateWorking
            ) | (
                A2ATaskState::TaskStateAuthReceived,
                A2ATaskState::TaskStateCompleted
            ) | (
                A2ATaskState::TaskStateAuthReceived,
                A2ATaskState::TaskStateFailed
            )
        );

        if !valid {
            return Err(KernelError::InvalidA2ATransition {
                from: format!("{:?}", self.state),
                to: format!("{:?}", next),
            });
        }

        self.state = next;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Add a turn to history with Confused Deputy guard
    pub fn append_message(&mut self, msg: A2AMessage) -> Result<(), KernelError> {
        // Confused deputy check:
        // If message attempts to confirm a call/action, verify sender is human
        if msg.confirmed_call_id.is_some() && msg.role != A2ARole::HumanUser {
            self.state = A2ATaskState::TaskStateFailed;
            self.failure_reason =
                Some("Confused Deputy violation: non-human tried to grant approval".into());
            return Err(KernelError::ConfusedDeputyDetected {
                role: format!("{:?}", msg.role),
            });
        }

        self.history.push(msg);
        self.updated_at = Utc::now();
        Ok(())
    }
}

/// Agent Card discovery metadata (advertised at /.well-known/agent-card.json)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCard {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub endpoints: A2AEndpoints,
    pub capabilities: Vec<A2ACapability>,
    pub authentication: A2AAuth,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AEndpoints {
    pub rpc: String,
    pub events: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2ACapability {
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AAuth {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub token_endpoint: Option<String>,
}

/// A2A Real-time SSE Event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AEvent {
    pub event_id: String,
    pub task_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}
