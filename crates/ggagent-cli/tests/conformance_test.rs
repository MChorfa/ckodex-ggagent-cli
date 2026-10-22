use ggagent_evidence::{DsseEnvelope, FlightRecorder, InTotoStatement};
use ggagent_kernel::a2a::{A2AAuth, A2ACapability, A2AEndpoints, AgentCard};
use ggagent_kernel::conformance::{ConformanceDisposition, ConformanceStimulus, ConformanceVector};
use ggagent_kernel::coordinated_states::{
    AuthorityLifecycle, CandidateLifecycle, CoordinatedTaskState, ExecutionLifecycle,
    FailureClassification, ReclamationLifecycle,
};
use ggagent_kernel::lease::{AtomicEffectGuard, CapabilityLease, EffectDisposition};
use ggagent_kernel::vector_state::{LifecycleState, Presence, Valence, VectorState};
use ggagent_transport::a2a_rpc::{A2aRpcHandler, JsonRpcRequest};
use ggagent_transport::ard_service::ArdService;
use ggagent_validation::{
    ArdValidator, AtomicEffectBroker, EffectRequest, SecurityGuards, ValidationError,
    WorkspaceStagingGuard,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

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

// =========================================================================
// SANDBOXING & VIRTUALIZATION LABORATORY CONTRACTS (Chapters 24-30)
// =========================================================================

#[test]
fn test_lab1_authority_boundary_and_loopjacking_defeat() {
    let lease = CapabilityLease::new(
        "lease-sandboxed-01",
        "agent-worker",
        "storage/isolated",
        vec!["read_dataset".into()],
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    // 1. Prohibited operation is denied by authority boundary
    let denied = SecurityGuards::verify_lease(&lease, "delete_dataset");
    assert!(denied.is_err(), "Unauthorized operation must be denied");

    // 2. Loopjacking check: attacker attempts to mutate parameters under valid action
    let legitimate_params = serde_json::json!({"dataset_id": "ds-123", "filter": "train"});
    let guard = AtomicEffectGuard::new(
        "read_dataset",
        "storage/isolated",
        legitimate_params.clone(),
    );

    let tampered_params =
        serde_json::json!({"dataset_id": "ds-123", "filter": "ALL; DROP TABLE users;"});
    let result = SecurityGuards::verify_effect_guard(
        &guard,
        "read_dataset",
        "storage/isolated",
        &tampered_params,
    );
    assert!(
        matches!(result, Err(ValidationError::LoopjackingViolation { .. })),
        "Tampered parameters must fail use-time material binding"
    );
}

#[test]
fn test_lab2_generation_fencing_under_partitioned_handoff() {
    let mut broker = AtomicEffectBroker::new(1, "fence-1-cluster");

    let mut lease_worker1 = CapabilityLease::new(
        "lease-w1",
        "worker-alpha",
        "compute/cluster",
        vec!["scale".into()],
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    lease_worker1.generation = 1;

    let params = serde_json::json!({"replicas": 5});
    let guard = AtomicEffectGuard::new("scale", "compute/cluster", params.clone());

    // Worker 1 executes initial operation on generation 1
    let req1 = EffectRequest {
        lease: &lease_worker1,
        guard: &guard,
        received_generation: 1,
        idempotency_key: "scale-step-1",
        action: "scale",
        target: "compute/cluster",
        params: &params,
    };
    let committed = broker
        .execute_effect(&req1)
        .expect("Effect on generation 1 succeeds");
    assert!(matches!(committed, EffectDisposition::Committed { .. }));

    // Partition occurs: authority is handed off to Worker 2; generation advances 1 -> 2
    let gen2 = broker.advance_generation("fence-2-cluster");
    assert_eq!(gen2, 2);

    // Stale Worker 1 attempts to commit delayed effect on generation 1
    let req_stale = EffectRequest {
        lease: &lease_worker1,
        guard: &guard,
        received_generation: 1,
        idempotency_key: "scale-step-2",
        action: "scale",
        target: "compute/cluster",
        params: &params,
    };
    let stale_attempt = broker
        .execute_effect(&req_stale)
        .expect("Broker evaluates effect");

    match stale_attempt {
        EffectDisposition::Fenced {
            current_generation,
            received_generation,
            fencing_token,
        } => {
            assert_eq!(current_generation, 2);
            assert_eq!(received_generation, 1);
            assert_eq!(fencing_token, "fence-0-lease-w1");
        }
        other => panic!(
            "Expected Fenced disposition for stale generation, got {:?}",
            other
        ),
    }
}

#[test]
fn test_lab3_immutable_candidate_staging_defeats_toctou_and_symlink_escape() {
    let dir = tempdir().expect("tempdir creation");
    let ws_root = dir.path().join("sandbox_ws");
    let external_dir = dir.path().join("external");
    fs::create_dir_all(&ws_root).expect("ws dir");
    fs::create_dir_all(&external_dir).expect("ext dir");

    // 1. Defeat Symlink Traversal Escape (Chapter 21 & 28)
    let secret_file = external_dir.join("id_rsa");
    fs::write(&secret_file, b"-----BEGIN OPENSSH PRIVATE KEY-----").expect("write secret");

    let leak_link = ws_root.join("exfiltrate_key");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&secret_file, &leak_link).expect("create symlink");

    #[cfg(unix)]
    {
        let escape_check =
            WorkspaceStagingGuard::validate_path(&ws_root, Path::new("exfiltrate_key"));
        assert!(
            matches!(
                escape_check,
                Err(ValidationError::ContainmentEscapeViolation(_))
            ),
            "Symlink pointing outside workspace must be rejected as ContainmentEscapeViolation"
        );
    }

    // 2. Defeat TOCTOU Check-to-Use Workspace Mutation Race (Chapter 28 & 29)
    let patch_path = ws_root.join("patch.diff");
    fs::write(
        &patch_path,
        b"--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-broken\n+fixed\n",
    )
    .expect("write patch");

    // Seal candidate into immutable memory snapshot
    let sealed = WorkspaceStagingGuard::seal_candidate_file(&ws_root, Path::new("patch.diff"))
        .expect("seal candidate");
    let verified_digest = sealed.content_digest.clone();

    // Adversarial agent concurrently overwrites workspace file during review window
    fs::write(
        &patch_path,
        b"MALICIOUS CODE INJECTION OCCURRED DURING EVALUATION WINDOW",
    )
    .expect("tamper file");

    // The sealed candidate maintains its pristine verified content and SHA-256 digest
    assert_eq!(sealed.content_digest, verified_digest);
    assert_eq!(
        sealed.bytes,
        b"--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-broken\n+fixed\n"
    );
}

#[test]
fn test_lab4_4d_coordinated_state_cross_machine_invariants() {
    let mut task = CoordinatedTaskState::new("coord-task-1");

    // 1. Initial coordinates check
    assert_eq!(task.execution, ExecutionLifecycle::Requested);
    assert_eq!(task.authority, AuthorityLifecycle::Pending);
    assert_eq!(task.candidate, CandidateLifecycle::Absent);
    assert_eq!(task.reclamation, ReclamationLifecycle::Allocated);

    // 2. Running requires Active Authority
    let err_run = task.transition_execution(ExecutionLifecycle::Running);
    assert!(err_run.is_err(), "Cannot run with Pending authority");

    task.transition_authority(AuthorityLifecycle::Active)
        .expect("activate authority");
    task.transition_execution(ExecutionLifecycle::Running)
        .expect("run task");
    assert_eq!(task.execution, ExecutionLifecycle::Running);

    // 3. Staging and sealing candidate
    task.stage_candidate("sha256:cafe1234")
        .expect("stage candidate");
    assert_eq!(task.candidate, CandidateLifecycle::Staged);

    task.seal_candidate().expect("seal candidate");
    assert_eq!(task.candidate, CandidateLifecycle::Sealed);

    task.submit_candidate_for_review()
        .expect("submit for review");
    assert_eq!(task.candidate, CandidateLifecycle::UnderReview);

    // 4. Authority revocation immediately demotes Running to Stopping
    task.transition_authority(AuthorityLifecycle::Revoked)
        .expect("revoke authority");
    assert_eq!(task.execution, ExecutionLifecycle::Stopping);

    // 5. Failure classification marking (Chapter 30)
    task.mark_failure(
        FailureClassification::GovernanceFailure,
        "lease revoked by policy",
    );
    assert_eq!(task.execution, ExecutionLifecycle::Failed);
    assert_eq!(
        task.failure_classification,
        Some(FailureClassification::GovernanceFailure)
    );
}
