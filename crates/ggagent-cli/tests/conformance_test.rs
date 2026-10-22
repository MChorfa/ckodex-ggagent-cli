use ggagent_evidence::{DsseEnvelope, FlightRecorder, InTotoStatement};
use ggagent_kernel::a2a::{A2AAuth, A2ACapability, A2AEndpoints, AgentCard};
use ggagent_kernel::conformance::{ConformanceDisposition, ConformanceStimulus, ConformanceVector};
use ggagent_kernel::vector_state::{LifecycleState, Presence, Valence, VectorState};
use ggagent_transport::a2a_rpc::{A2aRpcHandler, JsonRpcRequest};
use ggagent_transport::ard_service::ArdService;
use ggagent_validation::ArdValidator;
use std::collections::BTreeMap;

#[test]
fn test_conformance_vector_evaluation() {
    let mut initial = VectorState::new("agent-1");
    initial.presence = Presence::Present;
    initial.valence = Valence::Positive;
    initial.lifecycle = LifecycleState::Working;

    let vector = ConformanceVector {
        vector_id: "CV-001".into(),
        description: "Test state transition on verified stimulus".into(),
        effective_policy: "policy-v1".into(),
        initial_state: initial.clone(),
        stimulus: ConformanceStimulus {
            name: "verify_evidence".into(),
            payload: serde_json::json!({"digest": "abc"}),
            source: "verifier".into(),
        },
        context: BTreeMap::new(),
        required_disposition: ConformanceDisposition::Admit,
        required_obligations: vec!["emit_receipt".into()],
        expected_resulting_state: initial.transition_to(LifecycleState::Completed),
        required_evidence: vec!["receipt_signature".into()],
        recovery_triggers: vec![],
    };

    assert_eq!(vector.required_disposition, ConformanceDisposition::Admit);
    assert_eq!(
        vector.expected_resulting_state.lifecycle,
        LifecycleState::Completed
    );
    assert_eq!(vector.expected_resulting_state.epoch, 1);
}

#[test]
fn test_a2a_jsonrpc_flow_with_security_guards() {
    let card = AgentCard {
        schema: "https://a2aprotocol.org/schemas/v1/agent-card.json".into(),
        name: "test-agent".into(),
        version: "1.0.0".into(),
        description: "Integration test agent".into(),
        endpoints: A2AEndpoints {
            rpc: "http://localhost:8080/api/v1/a2a".into(),
            events: "http://localhost:8080/api/v1/a2a/events".into(),
        },
        capabilities: vec![A2ACapability {
            id: "test_cap".into(),
            description: "Test capability".into(),
            parameters: BTreeMap::new(),
        }],
        authentication: A2AAuth {
            auth_type: "mtls_or_bearer".into(),
            token_endpoint: None,
        },
        metadata: BTreeMap::new(),
    };

    let handler = A2aRpcHandler::new(card);

    // 1. Submit task with an AtomicEffectGuard
    let submit_req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(1),
        method: "a2a.task.submit".into(),
        params: Some(serde_json::json!({
            "capability_id": "test_cap",
            "initiator_role": "human_user",
            "effect_guard": {
                "action": "deploy",
                "target": "prod",
                "params": {"replicas": 3}
            }
        })),
    };
    let submit_res = handler.handle_request(submit_req);
    assert!(submit_res.error.is_none());
    let task_id = submit_res
        .result
        .unwrap()
        .get("task_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // 2. Confused Deputy Attack: remote peer agent attempts to approve the task
    let fake_approval = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(2),
        method: "a2a.task.approve".into(),
        params: Some(serde_json::json!({
            "task_id": task_id,
            "approver_role": "remote_agent",
            "sender_id": "attacker-peer",
        })),
    };
    let attack_res = handler.handle_request(fake_approval);
    assert!(
        attack_res.error.is_some(),
        "Confused deputy attempt MUST be rejected"
    );
    assert_eq!(attack_res.error.unwrap().code, -32001);

    // 3. Genuine human approval with matching effect guard
    let genuine_approval = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(3),
        method: "a2a.task.approve".into(),
        params: Some(serde_json::json!({
            "task_id": task_id,
            "approver_role": "human_user",
            "sender_id": "operator-alice",
            "material_action": {
                "action": "deploy",
                "target": "prod",
                "params": {"replicas": 3}
            }
        })),
    };
    let approved_res = handler.handle_request(genuine_approval);
    assert!(
        approved_res.error.is_none(),
        "Genuine human approval MUST succeed"
    );
}

#[test]
fn test_ard_service_and_document_validation() {
    let service = ArdService::new("agent.local", "CKODEX Team");
    let doc = service.get_document();

    assert!(ArdValidator::validate(&doc).is_ok());
    assert_eq!(doc.resources.len(), 2);
    assert!(doc.find_resource_by_id("ggagent-a2a-service").is_some());
    assert!(doc.find_resource_by_id("ggagent-mcp-bridge").is_some());
}

#[test]
fn test_flight_recorder_integrity() {
    let mut recorder = FlightRecorder::new("session-1");
    recorder.record_event(
        "Execution",
        "conductor",
        "auth:root",
        "step_1",
        "sha256:111",
        "v1.0",
    );
    recorder.record_event(
        "Decision",
        "conductor",
        "auth:root",
        "step_2",
        "sha256:222",
        "v1.0",
    );
    recorder.record_event(
        "Evidence",
        "conductor",
        "auth:root",
        "step_3",
        "sha256:333",
        "v1.0",
    );

    assert_eq!(recorder.events.len(), 3);
    assert!(
        recorder.verify_integrity(),
        "Flight recorder hash-chain must verify"
    );
}

#[test]
fn test_dsse_in_toto_statement() {
    let statement = InTotoStatement::new_execution_statement(
        "ggagent-binary",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        serde_json::json!({"action": "build", "exit_code": 0}),
    );
    let envelope = DsseEnvelope::wrap_in_toto(&statement, "key-001");
    assert_eq!(envelope.payload_type, "application/vnd.in-toto+json");
    assert!(!envelope.payload.is_empty());
    assert_eq!(envelope.signatures.len(), 1);
}
