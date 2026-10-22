use crate::error::TransportError;
use chrono::Utc;
use ggagent_kernel::a2a::{A2AMessage, A2ARole, A2ATask, A2ATaskState, AgentCard};
use ggagent_kernel::lease::AtomicEffectGuard;
use ggagent_validation::guards::SecurityGuards;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcErrorObject {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A2A JSON-RPC 2.0 Handler with In-Memory Task Registry & Security Guards
pub struct A2aRpcHandler {
    card: AgentCard,
    tasks: Arc<Mutex<HashMap<String, A2ATask>>>,
    effect_guards: Arc<Mutex<HashMap<String, AtomicEffectGuard>>>,
}

impl A2aRpcHandler {
    pub fn new(card: AgentCard) -> Self {
        Self {
            card,
            tasks: Arc::new(Mutex::new(HashMap::new())),
            effect_guards: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let res = match req.method.as_str() {
            "a2a.discover" => Ok(serde_json::to_value(&self.card).unwrap()),
            "a2a.capabilities.list" => Ok(serde_json::to_value(&self.card.capabilities).unwrap()),
            "a2a.task.submit" => self.handle_submit(req.params),
            "a2a.task.get" => self.handle_get(req.params),
            "a2a.task.cancel" => self.handle_cancel(req.params),
            "a2a.task.approve" => self.handle_approve(req.params),
            _ => Err(TransportError::JsonRpc {
                code: -32601,
                message: format!("Method not found: {}", req.method),
            }),
        };

        match res {
            Ok(val) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id,
                result: Some(val),
                error: None,
            },
            Err(err) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id,
                result: None,
                error: Some(JsonRpcErrorObject {
                    code: match &err {
                        TransportError::JsonRpc { code, .. } => *code,
                        _ => -32000,
                    },
                    message: err.to_string(),
                    data: None,
                }),
            },
        }
    }

    fn handle_submit(
        &self,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, TransportError> {
        let params =
            params.ok_or_else(|| TransportError::InvalidRequest("Missing params".into()))?;
        let capability_id = params
            .get("capability_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransportError::InvalidRequest("Missing capability_id".into()))?
            .to_string();

        let initiator_str = params
            .get("initiator_role")
            .and_then(|v| v.as_str())
            .unwrap_or("human_user");

        let initiator_role = match initiator_str {
            "remote_agent" => A2ARole::RemoteAgent,
            "tool" => A2ARole::Tool,
            _ => A2ARole::HumanUser,
        };

        let task_id = uuid::Uuid::new_v4().to_string();
        let session_id = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let mut task = A2ATask::new(task_id.clone(), session_id, capability_id, initiator_role);
        let _ = task.transition_to(A2ATaskState::TaskStateWorking);

        // If mutating action, create effect guard
        if let Some(effect_val) = params.get("effect_guard") {
            let action = effect_val
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("execute");
            let target = effect_val
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            let guard_params = effect_val
                .get("params")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            let guard = AtomicEffectGuard::new(action, target, guard_params);
            task.required_effect_digest = Some(guard.expected_effect_digest.clone());
            let mut guards = self.effect_guards.lock().unwrap();
            guards.insert(task_id.clone(), guard);
        }

        let mut tasks = self.tasks.lock().unwrap();
        tasks.insert(task_id.clone(), task.clone());

        Ok(serde_json::to_value(&task).unwrap())
    }

    fn handle_get(
        &self,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, TransportError> {
        let params =
            params.ok_or_else(|| TransportError::InvalidRequest("Missing params".into()))?;
        let task_id = params
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransportError::InvalidRequest("Missing task_id".into()))?;

        let tasks = self.tasks.lock().unwrap();
        let task = tasks
            .get(task_id)
            .ok_or_else(|| TransportError::TaskNotFound(task_id.to_string()))?;
        Ok(serde_json::to_value(task).unwrap())
    }

    fn handle_cancel(
        &self,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, TransportError> {
        let params =
            params.ok_or_else(|| TransportError::InvalidRequest("Missing params".into()))?;
        let task_id = params
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransportError::InvalidRequest("Missing task_id".into()))?;

        let mut tasks = self.tasks.lock().unwrap();
        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| TransportError::TaskNotFound(task_id.to_string()))?;
        let _ = task.transition_to(A2ATaskState::TaskStateCancelled);
        Ok(serde_json::to_value(task).unwrap())
    }

    fn handle_approve(
        &self,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, TransportError> {
        let params =
            params.ok_or_else(|| TransportError::InvalidRequest("Missing params".into()))?;
        let task_id = params
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransportError::InvalidRequest("Missing task_id".into()))?
            .to_string();

        let role_str = params
            .get("approver_role")
            .and_then(|v| v.as_str())
            .unwrap_or("remote_agent");

        let approver_role = match role_str {
            "human_user" => A2ARole::HumanUser,
            _ => A2ARole::RemoteAgent,
        };

        let sender_id = params
            .get("sender_id")
            .and_then(|v| v.as_str())
            .unwrap_or("peer")
            .to_string();

        // Construct approval message and test Confused Deputy guard
        let approval_msg = A2AMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            role: approver_role,
            sender_id,
            parts: vec![],
            timestamp: Utc::now(),
            confirmed_call_id: Some(task_id.clone()),
        };

        if let Err(err) = SecurityGuards::verify_approval_principal(&approval_msg) {
            return Err(TransportError::JsonRpc {
                code: -32001,
                message: format!("Security guard rejected approval: {}", err),
            });
        }

        // Test Loopjacking effect guard if provided
        if let Some(action_val) = params.get("material_action") {
            let action = action_val
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target = action_val
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let action_params = action_val
                .get("params")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            let guards = self.effect_guards.lock().unwrap();
            if let Some(guard) = guards.get(&task_id) {
                if let Err(err) =
                    SecurityGuards::verify_effect_guard(guard, action, target, &action_params)
                {
                    return Err(TransportError::JsonRpc {
                        code: -32002,
                        message: format!("Loopjacking guard failed: {}", err),
                    });
                }
            }
        }

        let mut tasks = self.tasks.lock().unwrap();
        let task = tasks
            .get_mut(&task_id)
            .ok_or_else(|| TransportError::TaskNotFound(task_id.clone()))?;
        let _ = task.append_message(approval_msg);
        let _ = task.transition_to(A2ATaskState::TaskStateAuthReceived);
        Ok(serde_json::to_value(task).unwrap())
    }
}
