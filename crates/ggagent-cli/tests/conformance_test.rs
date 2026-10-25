use ggagent_evidence::{
    DsseEnvelope, ExecutionReceipt, ExecutionReceiptParams, FlightRecorder, ForensicBundle,
    InTotoStatement,
};
use ggagent_kernel::a2a::{A2AAuth, A2ACapability, A2AEndpoints, AgentCard};
use ggagent_kernel::budget::ExecutionBudget;
use ggagent_kernel::checkpoint::TaskCheckpoint;
use ggagent_kernel::conformance::{ConformanceDisposition, ConformanceStimulus, ConformanceVector};
use ggagent_kernel::coordinated_states::{
    AuthorityLifecycle, CandidateLifecycle, CoordinatedTaskState, ExecutionLifecycle,
    FailureClassification, ReclamationLifecycle,
};
use ggagent_kernel::handoff::{HandoffManifest, HandoffParams};
use ggagent_kernel::lease::{AtomicEffectGuard, CapabilityLease, EffectDisposition};
use ggagent_kernel::loops::{LoopCoordinator, LoopRole};
use ggagent_kernel::network::NetworkEgressPolicy;
use ggagent_kernel::sandbox_profile::SandboxProfile;
use ggagent_kernel::vector_state::{LifecycleState, Presence, Valence, VectorState};
use ggagent_transport::a2a_rpc::{A2aRpcHandler, JsonRpcRequest};
use ggagent_transport::ard_service::ArdService;
use ggagent_transport::cross_harness::{CrossHarnessBridge, HarnessFamily};
use ggagent_validation::{
    ArdValidator, AtomicEffectBroker, EffectRequest, HandoffValidator, NetworkEgressGuard,
    ReplayEngine, SecretGuard, SecurityGuards, ValidationError, WorkspaceStagingGuard,
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

    // 3. Unauthenticated spoofed human claim (claims human_user but lacks cryptographic auth token)
    let spoofed_human = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(3),
        method: "a2a.task.approve".into(),
        params: Some(serde_json::json!({
            "task_id": task_id,
            "approver_role": "human_user",
            "sender_id": "malicious-spoofer",
        })),
    };
    let spoofed_res = handler.handle_request(spoofed_human);
    assert!(
        spoofed_res.error.is_some(),
        "Spoofed unauthenticated human claim MUST be rejected"
    );
    assert_eq!(spoofed_res.error.unwrap().code, -32001);

    // 4. Genuine human approval with authenticated proof token and matching effect guard
    let genuine_approval = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(4),
        method: "a2a.task.approve".into(),
        params: Some(serde_json::json!({
            "task_id": task_id,
            "approver_role": "human_user",
            "auth_token": "human-auth-proof-operator-alice-9921",
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
        "Genuine authenticated human approval MUST succeed"
    );

    // 5. Official Google A2A 1.0 JSON-RPC method routing test (GetTask)
    let get_task_req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(5),
        method: "GetTask".into(),
        params: Some(serde_json::json!({
            "task_id": task_id
        })),
    };
    let get_task_res = handler.handle_request(get_task_req);
    assert!(
        get_task_res.error.is_none(),
        "Standard A2A 1.0 GetTask method MUST succeed"
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

#[test]
fn test_lab5_three_loop_architecture_responsibility_boundaries() {
    let mut task = CoordinatedTaskState::new("loop-task-1");
    task.transition_authority(AuthorityLifecycle::Active)
        .unwrap();
    task.transition_execution(ExecutionLifecycle::Running)
        .unwrap();

    // 1. Inner loop worker cannot expand lease or grant governance promotion
    let inner_promote =
        LoopCoordinator::validate_loop_action(LoopRole::InnerLoop, "promote", &task);
    assert!(
        inner_promote.is_err(),
        "Inner loop must not execute governance promotion"
    );

    let inner_expand =
        LoopCoordinator::validate_loop_action(LoopRole::InnerLoop, "expand_lease", &task);
    assert!(
        inner_expand.is_err(),
        "Inner loop must not expand its own lease"
    );

    // 2. Outer loop verifier cannot publish mutating side effects
    task.stage_candidate("sha256-test-patch").unwrap();
    task.seal_candidate().unwrap();
    let outer_publish =
        LoopCoordinator::validate_loop_action(LoopRole::OuterLoop, "publish", &task);
    assert!(
        outer_publish.is_err(),
        "Outer loop verifier must not publish mutations"
    );
}

#[test]
fn test_lab6_execution_budget_accounting_and_monotonic_attenuation() {
    let mut budget = ExecutionBudget::new(3, 1, 10_000, 30_000);

    // Consume steps
    assert!(budget.record_step().is_ok());
    assert!(budget.record_step().is_ok());
    assert_eq!(budget.remaining_steps(), 1);

    // Consume allowed mutating effect
    assert!(budget.record_mutating_effect().is_ok());
    assert_eq!(budget.remaining_effects(), 0);

    // Attempting an additional mutating effect is strictly rejected
    let over_effect = budget.record_mutating_effect();
    assert!(
        over_effect.is_err(),
        "Mutating effect exceeding budget must be rejected"
    );

    // Attenuation monotonicity: child cannot request more steps than remaining in parent
    let child_exceeded = budget.attenuate(5, 0, 1_000, 5_000);
    assert!(
        child_exceeded.is_err(),
        "Child attenuation exceeding remaining parent budget must fail"
    );

    let valid_child = budget.attenuate(1, 0, 1_000, 5_000);
    assert!(
        valid_child.is_ok(),
        "Attenuated budget within parent limits must succeed"
    );
}

#[test]
fn test_lab7_partitioned_handoff_and_budget_non_inflation() {
    let vstate = VectorState::new("handoff-task");
    let cstate = CoordinatedTaskState::new("handoff-task");
    let budget = ExecutionBudget::new(5, 2, 5_000, 15_000);
    let max_node_budget = ExecutionBudget::new(10, 5, 10_000, 30_000);

    // 1. Valid handoff manifest
    let manifest = HandoffManifest::new(HandoffParams {
        task_id: "handoff-task".into(),
        source_node_id: "node-west-1".into(),
        target_node_id: "node-east-1".into(),
        source_generation: 1,
        target_generation: 2,
        vector_state: vstate,
        coordinated_state: cstate,
        remaining_budget: budget,
    })
    .expect("create handoff manifest");

    assert!(manifest.verify_digest(), "Checkpoint digest must verify");
    assert!(
        HandoffValidator::validate_handoff(&manifest, 1, &max_node_budget).is_ok(),
        "Valid handoff must pass validation"
    );

    // 2. Budget inflation rejection
    let inflated_budget = ExecutionBudget::new(50, 20, 50_000, 100_000);
    let inflated_manifest = HandoffManifest::new(HandoffParams {
        task_id: "handoff-task".into(),
        source_node_id: "node-west-1".into(),
        target_node_id: "node-east-1".into(),
        source_generation: 1,
        target_generation: 2,
        vector_state: VectorState::new("handoff-task"),
        coordinated_state: CoordinatedTaskState::new("handoff-task"),
        remaining_budget: inflated_budget,
    })
    .expect("manifest with inflated budget");

    let res = HandoffValidator::validate_handoff(&inflated_manifest, 1, &max_node_budget);
    assert!(
        matches!(res, Err(ValidationError::BudgetExhaustionViolation(_))),
        "Budget inflation must be rejected by handoff validator"
    );
}

#[test]
fn test_lab8_ephemeral_secret_guard_and_scrubbing() {
    // 1. Rejection of unredacted private keys
    let leaky_payload = serde_json::json!({
        "task": "deploy",
        "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza..."
    });
    let res = SecretGuard::assert_no_static_secrets(&leaky_payload);
    assert!(
        matches!(res, Err(ValidationError::SecretLeakageViolation(_))),
        "Unredacted private key must trigger SecretLeakageViolation"
    );

    // 2. Secret scrubbing in logs/receipts
    let sensitive_text =
        "API request failed with token ghp_A1B2C3D4E5F6G7H8I9J0 and key AKIA112233445566";
    let scrubbed = SecretGuard::scrub_secrets(sensitive_text);
    assert!(!scrubbed.contains("ghp_"));
    assert!(!scrubbed.contains("AKIA"));
    assert!(scrubbed.contains("[REDACTED_SECRET]"));
}

#[test]
fn test_lab9_forensic_evidence_bundle_integrity() {
    let mut fr = FlightRecorder::new("flight-forensic-test");
    fr.record_event(
        "Telemetry",
        "worker-1",
        "auth:root",
        "start",
        "sha256:0",
        "v2.0",
    );
    fr.record_event(
        "Execution",
        "worker-1",
        "auth:root",
        "apply_patch",
        "sha256:1",
        "v2.0",
    );
    fr.record_event(
        "Evidence",
        "verifier",
        "auth:root",
        "verify_signature",
        "sha256:2",
        "v2.0",
    );

    let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
        task_id: "forensic-task-1".into(),
        actor_id: "worker-1".into(),
        authority_id: "auth:root".into(),
        capability_id: "patch_engine".into(),
        action: "apply".into(),
        input_digest: "sha256:input123".into(),
        output_digest: "sha256:output456".into(),
        effect_digest: "sha256:effect789".into(),
        duration_ms: 88,
        exit_code: 0,
    });

    let bundle = ForensicBundle::create(
        "forensic-task-1",
        VectorState::new("forensic-task-1"),
        CoordinatedTaskState::new("forensic-task-1"),
        &fr,
        vec![receipt],
        vec!["sha256:candidate_hash".into()],
        Some(FailureClassification::VerificationFailure),
    );

    assert!(
        bundle.verify_integrity(),
        "Bundle root digest and hash chains must verify"
    );
}

#[test]
fn test_lab10_network_egress_governance_and_imds_defeat() {
    let policy = NetworkEgressPolicy::new_hardened();

    // 1. Cloud instance metadata service (IMDSv2) access blocked
    let imds_res = NetworkEgressGuard::verify_egress(&policy, "169.254.169.254", 80);
    assert!(
        matches!(imds_res, Err(ValidationError::EgressViolation(_))),
        "Cloud metadata access must be blocked"
    );

    let gcp_meta = NetworkEgressGuard::verify_egress(&policy, "metadata.google.internal", 80);
    assert!(
        matches!(gcp_meta, Err(ValidationError::EgressViolation(_))),
        "GCP metadata access must be blocked"
    );

    // 2. Private intranet blocked
    assert!(NetworkEgressGuard::verify_egress(&policy, "10.100.1.1", 443).is_err());
    assert!(NetworkEgressGuard::verify_egress(&policy, "192.168.1.1", 443).is_err());
    assert!(NetworkEgressGuard::verify_egress(&policy, "127.0.0.1", 443).is_err());

    // 3. Prohibited port blocked
    assert!(NetworkEgressGuard::verify_egress(&policy, "crates.io", 22).is_err());

    // 4. Allowed domain on HTTPS passes
    assert!(NetworkEgressGuard::verify_egress(&policy, "crates.io", 443).is_ok());
    assert!(NetworkEgressGuard::verify_egress(&policy, "api.github.com", 443).is_ok());
}

#[test]
fn test_lab11_sandbox_profile_syscall_and_landlock_boundaries() {
    let profile = SandboxProfile::new_hardened("/home/agent/sandbox");

    // 1. Prohibited dangerous syscalls
    assert!(profile.is_syscall_prohibited("ptrace"));
    assert!(profile.is_syscall_prohibited("bpf"));
    assert!(profile.is_syscall_prohibited("kexec_load"));
    assert!(profile.is_syscall_prohibited("mount"));
    assert!(!profile.is_syscall_prohibited("epoll_wait"));

    // 2. Filesystem Landlock boundaries
    assert!(
        profile
            .verify_write_access(Path::new("/usr/local/bin/backdoor"))
            .is_err(),
        "Writing to system root must be denied"
    );
    assert!(
        profile
            .verify_write_access(Path::new("/home/agent/sandbox/candidate.patch"))
            .is_ok(),
        "Writing to workspace root must be permitted"
    );
}

#[test]
fn test_lab12_deterministic_checkpoint_and_replay_fencing() {
    let vstate = VectorState::new("task-durable-1");
    let cstate = CoordinatedTaskState::new("task-durable-1");
    let budget = ExecutionBudget::new(10, 5, 20_000, 60_000);
    let committed = vec![
        "sha256:side_effect_alpha".into(),
        "sha256:side_effect_beta".into(),
    ];

    let checkpoint =
        TaskCheckpoint::create("task-durable-1", 2, 4, vstate, cstate, budget, committed);

    assert!(
        checkpoint.verify_integrity(),
        "Checkpoint digest must be authentic"
    );

    // Resume via replay engine
    let mut broker = AtomicEffectBroker::new(2, "fence-2-task-durable-1");
    let resumed =
        ReplayEngine::resume_from_checkpoint(&checkpoint, &mut broker).expect("resume succeeds");

    // Generation must advance to 3
    assert_eq!(resumed.generation, 3);
    assert_eq!(broker.current_generation, 3);
    assert_eq!(resumed.fencing_token, "fence-3-task-durable-1");

    // Replay idempotency: previously committed side effects are present in cache
    assert!(broker.idempotency_cache.contains_key("hist-eff-0"));
    assert!(broker.idempotency_cache.contains_key("hist-eff-1"));
}

#[test]
fn test_lab13_cross_harness_adapter_compatibility() {
    let families = [
        HarnessFamily::AntigravityGemini,
        HarnessFamily::ClaudeCode,
        HarnessFamily::CodexOpenAi,
        HarnessFamily::CohereCommand,
        HarnessFamily::OpenCode,
        HarnessFamily::SamMesh,
        HarnessFamily::GoogleAgentsCli,
    ];

    let intent = "Run security audit on auth module";
    for fam in families {
        let cmd = CrossHarnessBridge::format_dispatch(fam, intent, "B");
        assert!(cmd.is_ok(), "Harness {:?} must format valid dispatch", fam);
        let formatted = cmd.unwrap();
        assert!(!formatted.is_empty());
        assert!(
            formatted.contains("Run security audit on auth module")
                || formatted.contains("agents-cli")
                || formatted.contains("sam-node")
        );
    }
}

#[test]
fn test_collaborative_mesh_dag_orchestration() {
    let temp = tempdir().expect("tempdir");
    let task_id = "test-mesh-001";
    let objective = "Hardened Clean Condamian domain refactor with NIST SP 800-53 controls";

    let report =
        ggagent_validation::MeshOrchestrator::execute_mesh(task_id, objective, temp.path())
            .expect("Collaborative mesh execution succeeds");

    assert_eq!(report.stages.len(), 4, "Mesh must execute exactly 4 stages");
    assert_eq!(report.stages[0].agent_id, "gemini-topology-planner");
    assert_eq!(report.stages[1].agent_id, "cohere-grounded-auditor");
    assert_eq!(report.stages[2].agent_id, "codex-security-patcher");
    assert_eq!(report.stages[3].agent_id, "claude-kernel-refactor");

    assert!(report.all_passed);
    assert_eq!(report.forensic_bundle.receipts.len(), 4);
    assert!(report.forensic_bundle.verify_integrity());
    assert_eq!(
        report.final_vector_state.mode,
        ggagent_kernel::vector_state::RuntimeMode::Normal
    );
}

#[test]
fn test_cyclonedx_1_7_aibom_generation_and_integrity() {
    let bom = ggagent_kernel::aibom::AiBomDocument::standard_ggagent_bom();
    assert_eq!(bom.bom_format, "CycloneDX");
    assert_eq!(bom.spec_version, "1.7");
    assert!(bom.serial_number.starts_with("urn:uuid:"));
    assert_eq!(bom.metadata.get_property("ecma_standard"), Some("ECMA-424"));

    // Check components
    let model_names: Vec<&str> = bom
        .components
        .iter()
        .filter(|c| c.r#type == ggagent_kernel::aibom::ComponentType::MachineLearningModel)
        .map(|c| c.name.as_str())
        .collect();

    assert!(model_names.contains(&"google-gemini-2.0-pro"));
    assert!(model_names.contains(&"cohere-command-r-plus"));
    assert!(model_names.contains(&"openai-codex-gpt4o"));
    assert!(model_names.contains(&"anthropic-claude-3-7-sonnet"));

    // Digest computation
    let digest = bom.compute_digest();
    assert!(digest.starts_with("sha256:"));

    // Serialization / Deserialization idempotency
    let serialized = serde_json::to_string(&bom).expect("serialize AI-BOM");
    let deserialized: ggagent_kernel::aibom::AiBomDocument =
        serde_json::from_str(&serialized).expect("deserialize AI-BOM");
    assert_eq!(deserialized.compute_digest(), digest);
}

#[test]
fn test_split_conformal_risk_calibration_certificate() {
    // Calibration nonconformity scores (e.g. from holdout validation set)
    let calibration_scores = vec![0.02, 0.05, 0.08, 0.12, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50];
    let alpha = 0.10; // 90% target coverage

    let cert = ggagent_kernel::conformance::ConformalRiskCertificate::compute_split_conformal(
        calibration_scores,
        alpha,
    )
    .expect("Conformal calculation succeeds");

    assert_eq!(cert.alpha, 0.10);
    assert_eq!(cert.target_coverage, 0.90);
    assert_eq!(cert.calibration_size, 10);
    assert!(cert.finite_sample_valid);
    assert!(cert.empirical_coverage >= 0.90);
    assert!(cert.certificate_digest.starts_with("sha256-conformal:"));
}

#[test]
fn test_spdx_tool_integration_and_spdx_validation() {
    let temp = tempdir().expect("tempdir");
    let drop_path = temp.path();
    let components_path = temp.path();

    // 1. Generate SPDX 2.2 manifest via SbomToolBridge
    let gen_result = ggagent_validation::SbomToolBridge::generate_manifest(
        drop_path,
        components_path,
        "ckodex-ggagent-cli",
        "0.2.0",
        "CKODEX Architecture Team",
        "https://github.com/MChorfa/ckodex-ggagent-cli",
        false,
    )
    .expect("generate manifest succeeds");

    assert!(gen_result.manifest_path.exists());
    assert!(gen_result
        .manifest_path
        .ends_with("_manifest/spdx_2.2/manifest.spdx.json"));
    assert_eq!(gen_result.spdx_document.spdx_version, "SPDX-2.2");
    assert_eq!(gen_result.spdx_document.data_license, "CC0-1.0");
    assert!(gen_result.receipt.verify_signature());

    // 2. Validate using SpdxValidator
    assert!(ggagent_validation::SpdxValidator::validate(&gen_result.spdx_document).is_ok());

    // 3. Audit using SbomToolBridge::validate_manifest
    let val_receipt = ggagent_validation::SbomToolBridge::validate_manifest(drop_path, None, false)
        .expect("validate manifest succeeds");
    assert!(val_receipt.verify_signature());
    assert_eq!(val_receipt.action, "sbom_validate");

    // 4. Bi-directional crosswalk conversion
    let cdx = gen_result.spdx_document.to_cyclonedx();
    assert_eq!(cdx.bom_format, "CycloneDX");
    assert_eq!(cdx.spec_version, "1.7");

    let roundtrip_spdx = ggagent_kernel::spdx::SpdxDocument::from_cyclonedx(
        &cdx,
        "https://github.com/MChorfa/ckodex-ggagent-cli",
    );
    assert_eq!(roundtrip_spdx.spdx_version, "SPDX-2.2");
    assert!(ggagent_validation::SpdxValidator::validate(&roundtrip_spdx).is_ok());
}

#[test]
fn test_sbom_analyzer_diff_quality_and_compliance() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cdx_path = temp.path().join("cyclonedx_1_7.json");
    let cdx_v2_path = temp.path().join("cyclonedx_1_7_v2.json");
    let spdx_path = temp.path().join("manifest.spdx.json");

    // 1. Generate & persist CycloneDX 1.7 AI-BOM
    let cdx = ggagent_kernel::aibom::AiBomDocument::standard_ggagent_bom();
    let cdx_json = serde_json::to_string_pretty(&cdx).expect("serialize cdx");
    std::fs::write(&cdx_path, cdx_json).expect("write cdx");

    // 2. Generate & persist SPDX 2.2 manifest
    let spdx = ggagent_kernel::spdx::SpdxDocument::from_cyclonedx(
        &cdx,
        "https://github.com/MChorfa/ckodex-ggagent-cli",
    );
    let spdx_json = serde_json::to_string_pretty(&spdx).expect("serialize spdx");
    std::fs::write(&spdx_path, spdx_json).expect("write spdx");

    // 3. Multi-format normalization parsing
    let parsed_cdx =
        ggagent_validation::SbomAnalyzer::parse(&cdx_path).expect("parse CycloneDX 1.7 succeeds");
    assert!(!parsed_cdx.components.is_empty());

    let parsed_spdx =
        ggagent_validation::SbomAnalyzer::parse(&spdx_path).expect("parse SPDX 2.2 succeeds");
    assert!(!parsed_spdx.components.is_empty());

    // 4. Create v2 CycloneDX with a component removed and one added
    let mut cdx_v2 = cdx.clone();
    cdx_v2.components.pop();
    cdx_v2.components.push(ggagent_kernel::aibom::BomComponent {
        r#type: ggagent_kernel::aibom::ComponentType::Library,
        name: "seccomp-bpf-filter-v2".into(),
        version: "2.0.0".into(),
        description: "Upgraded seccomp syscall filter".into(),
        purl: "pkg:generic/sandbox/seccomp-bpf@2.0.0".into(),
        sha256_digest: "sha256:upgraded_bpf_filter_verified".into(),
        model_card: None,
        properties: vec![],
    });
    std::fs::write(
        &cdx_v2_path,
        serde_json::to_string_pretty(&cdx_v2).expect("serialize cdx v2"),
    )
    .expect("write cdx v2");

    // 5. Semantic Diff via DiffEngine
    let (diff_result, diff_receipt) =
        ggagent_validation::SbomAnalyzer::diff(&cdx_path, &cdx_v2_path)
            .expect("semantic diff succeeds");
    assert!(diff_receipt.verify_signature());
    assert_eq!(diff_receipt.action, "diff_sboms");
    assert!(diff_result.semantic_score < 100.0);
    assert!(!diff_result.components.added.is_empty());
    assert!(!diff_result.components.removed.is_empty());

    // 6. Quality Scoring
    let (score_report, score_receipt) =
        ggagent_validation::SbomAnalyzer::score(&cdx_path, Some("standard"))
            .expect("quality score succeeds");
    assert!(score_receipt.verify_signature());
    assert_eq!(score_receipt.action, "quality_score");
    assert!(score_report.overall_score > 0.0);

    // 7. Compliance Audit (NTIA Minimum Elements)
    let (compliance_res, comp_receipt) =
        ggagent_validation::SbomAnalyzer::check_compliance(&cdx_path, Some("ntia"))
            .expect("compliance check succeeds");
    assert!(comp_receipt.verify_signature());
    assert_eq!(comp_receipt.action, "compliance_check");
    assert_eq!(
        compliance_res.level,
        ggagent_validation::ComplianceLevel::NtiaMinimum
    );
}

#[test]
fn test_developer_experience_and_sarif_generation() {
    let tmp = tempdir().expect("create tempdir");
    let cdx = ggagent_kernel::aibom::AiBomDocument::standard_ggagent_bom();
    let cdx_path = tmp.path().join("test-cdx.json");
    std::fs::write(&cdx_path, serde_json::to_string(&cdx).unwrap()).unwrap();

    // 1. Run compliance check
    let (comp_res, receipt) =
        ggagent_validation::SbomAnalyzer::check_compliance(&cdx_path, Some("ntia"))
            .expect("check compliance");
    assert!(receipt.verify_signature());

    // 2. Validate SARIF report generation structure
    let violations: Vec<(String, String, String)> = comp_res
        .violations
        .iter()
        .enumerate()
        .map(|(idx, v)| {
            (
                format!("RULE-{:03}", idx + 1),
                format!("{:?}", v.severity),
                v.message.clone(),
            )
        })
        .collect();

    let sarif_val = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ggagent-sbom-analyzer",
                    "version": "0.2.0",
                    "rules": violations.iter().map(|(id, sev, _)| {
                        serde_json::json!({
                            "id": id,
                            "defaultConfiguration": { "level": if sev == "Error" { "error" } else { "warning" } }
                        })
                    }).collect::<Vec<_>>()
                }
            },
            "results": violations.iter().map(|(id, sev, msg)| {
                serde_json::json!({
                    "ruleId": id,
                    "level": if sev == "Error" { "error" } else { "warning" },
                    "message": { "text": msg }
                })
            }).collect::<Vec<_>>()
        }]
    });

    assert_eq!(sarif_val["version"], "2.1.0");
    assert!(sarif_val["runs"][0]["results"].as_array().unwrap().len() >= comp_res.error_count);
}

#[test]
fn test_papercuts_and_underlying_risk_mitigations() {
    // 1. Stdin & string-based SBOM ingestion eliminates file-only papercut
    let cdx = ggagent_kernel::aibom::AiBomDocument::standard_ggagent_bom();
    let cdx_json = serde_json::to_string(&cdx).expect("serialize");
    let parsed = ggagent_validation::SbomAnalyzer::parse_str(&cdx_json)
        .expect("parse_str succeeds on string content");
    assert!(parsed.components.len() >= cdx.components.len());

    // 2. Strict compliance audit catches violations deterministically
    let temp = tempfile::tempdir().expect("tempdir");
    let cdx_file = temp.path().join("bom.json");
    std::fs::write(&cdx_file, &cdx_json).expect("write");
    let (comp_res, _) = ggagent_validation::SbomAnalyzer::check_compliance(&cdx_file, Some("ntia"))
        .expect("compliance check");
    // Standard AI-BOM without explicit NTIA supplier fields must be flagged non-compliant
    assert!(!comp_res.is_compliant);
    assert!(comp_res.error_count > 0);

    // 3. Tampered receipt detection: modifying any receipt field invalidates Ed25519 signature
    let mut receipt =
        ggagent_evidence::ExecutionReceipt::from_params(ggagent_evidence::ExecutionReceiptParams {
            task_id: "test-task-tamper".into(),
            actor_id: "actor:1".into(),
            authority_id: "auth:root".into(),
            capability_id: "cap:test".into(),
            action: "read".into(),
            input_digest: "sha256:0000".into(),
            output_digest: "sha256:1111".into(),
            effect_digest: "sha256:2222".into(),
            duration_ms: 5,
            exit_code: 0,
        });
    assert!(
        receipt.verify_signature(),
        "original signature must be valid"
    );
    // Tamper with output digest
    receipt.output_digest = "sha256:tampered_digest".into();
    assert!(
        !receipt.verify_signature(),
        "tampered receipt signature must be invalid"
    );

    // 4. Cleanroom SPDX 2.2 model contains zero proprietary Microsoft branding
    let spdx = ggagent_kernel::spdx::SpdxDocument::from_cyclonedx(
        &cdx,
        "https://github.com/MChorfa/ckodex-ggagent-cli",
    );
    let spdx_json = serde_json::to_string_pretty(&spdx).expect("serialize spdx");
    assert!(
        !spdx_json.to_lowercase().contains("microsoft"),
        "SPDX document must not contain Microsoft references"
    );
    assert!(spdx_json.contains("SPDX-2.2"));
    assert!(spdx_json.contains("CC0-1.0"));
}

#[test]
fn test_g0_through_g7_acceptance_gates_suite() {
    use ggagent_kernel::a2a::{A2AMessage, A2ARole, AgentCard};
    use ggagent_kernel::error::KernelError;

    // =========================================================================
    // Gate G0: Build & Artifact Integrity
    // Pinned digest, Ed25519 DSSE attestation, and reproducible in-toto envelope
    // =========================================================================
    let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
        task_id: "gate-g0-build".into(),
        actor_id: "builder:cleanroom".into(),
        authority_id: "auth:root:fabric".into(),
        capability_id: "cap:build".into(),
        action: "reproducible_build".into(),
        input_digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .into(),
        output_digest: "sha256:7fdc9f30123456789abcdef0123456789abcdef0123456789abcdef012345678"
            .into(),
        effect_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        duration_ms: 120,
        exit_code: 0,
    });
    assert!(
        receipt.verify_signature(),
        "G0: Build receipt Ed25519 signature must verify"
    );

    // =========================================================================
    // Gate G1: Kubernetes PSA Admission Rules
    // Hardened container invariants: runAsNonRoot, readOnlyRootFilesystem, drop ALL
    // =========================================================================
    let k8s_deployment_yaml = include_str!("../../../deploy/kubernetes/deployment.yaml");
    assert!(
        k8s_deployment_yaml.contains("runAsNonRoot: true"),
        "G1: Must enforce runAsNonRoot"
    );
    assert!(
        k8s_deployment_yaml.contains("readOnlyRootFilesystem: true"),
        "G1: Must enforce readOnlyRootFilesystem"
    );
    assert!(
        k8s_deployment_yaml.contains("drop:\n                - ALL"),
        "G1: Must drop ALL capabilities"
    );
    assert!(
        k8s_deployment_yaml.contains("seccompProfile:\n          type: RuntimeDefault"),
        "G1: Must use RuntimeDefault seccomp"
    );

    // =========================================================================
    // Gate G2: Identity & Authority Spoofing Rejection
    // Unauthenticated caller claiming HumanUser must be rejected fail-closed
    // =========================================================================
    let spoofed_human_msg = A2AMessage {
        message_id: "spoof-1".into(),
        role: A2ARole::HumanUser,
        sender_id: "malicious-caller".into(),
        parts: vec![],
        timestamp: chrono::Utc::now(),
        confirmed_call_id: Some("call-rm".into()),
    };
    let g2_res = SecurityGuards::verify_approval_principal(&spoofed_human_msg, None);
    assert!(
        matches!(g2_res, Err(ValidationError::ConfusedDeputyViolation { .. })),
        "G2: Unauthenticated human claim must be rejected"
    );

    let valid_token_res = SecurityGuards::verify_approval_principal(
        &spoofed_human_msg,
        Some("human-auth-proof-valid-operator-token"),
    );
    assert!(
        valid_token_res.is_ok(),
        "G2: Authenticated operator token must pass"
    );

    // =========================================================================
    // Gate G3: Sandbox Containment & Egress Defeat
    // IMDS 169.254.169.254/32 access must be rejected by NetworkGuard
    // =========================================================================
    let egress_policy = NetworkEgressPolicy::new_hardened();
    let g3_imds_res = NetworkEgressGuard::verify_egress(&egress_policy, "169.254.169.254", 80);
    assert!(
        matches!(g3_imds_res, Err(ValidationError::EgressViolation(..))),
        "G3: IMDS egress must be blocked"
    );

    let cilium_policy_yaml = include_str!("../../../deploy/kubernetes/cilium-egress-deny.yaml");
    assert!(
        cilium_policy_yaml.contains("169.254.169.254/32"),
        "G3: Cilium policy must explicitly deny IMDS"
    );

    // =========================================================================
    // Gate G4: Action Integrity & Loopjacking Defeat
    // Altered tool parameters fail AtomicEffectGuard at use-time
    // =========================================================================
    let legitimate_guard = AtomicEffectGuard::new(
        "patch",
        "kernel",
        serde_json::json!({"file": "lib.rs", "line": 42}),
    );
    let tampered_params = serde_json::json!({"file": "lib.rs", "line": 999});
    let g4_tamper_res =
        SecurityGuards::verify_effect_guard(&legitimate_guard, "patch", "kernel", &tampered_params);
    assert!(
        matches!(
            g4_tamper_res,
            Err(ValidationError::LoopjackingViolation { .. })
        ),
        "G4: Tampered parameters must trigger LoopjackingViolation"
    );

    // =========================================================================
    // Gate G5: Protocol Interoperability (Google A2A 1.0 JSON-RPC)
    // SendMessage, GetTask, CancelTask must route to standard handlers
    // =========================================================================
    let card = AgentCard {
        schema: "https://a2aprotocol.org/schemas/v1/agent-card.json".into(),
        name: "test-agent".into(),
        version: "1.0.0".into(),
        description: "Integration test agent".into(),
        endpoints: A2AEndpoints {
            rpc: "/api/v1/a2a".into(),
            events: "/api/v1/a2a/events".into(),
        },
        capabilities: vec![],
        authentication: A2AAuth {
            auth_type: "mtls_or_bearer".into(),
            token_endpoint: None,
        },
        metadata: std::collections::BTreeMap::new(),
    };
    let handler = A2aRpcHandler::new(card);
    let send_msg_req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(101),
        method: "SendMessage".into(),
        params: Some(serde_json::json!({
            "capability_id": "a2a.jsonrpc.v1",
            "session_id": "session-g5",
        })),
    };
    let send_res = handler.handle_request(send_msg_req);
    assert!(
        send_res.error.is_none(),
        "G5: Standard SendMessage RPC must succeed"
    );

    // =========================================================================
    // Gate G6: Evidence Independence (Three-Loop Separation)
    // InnerLoop cannot execute governance promotion or expand its own lease
    // =========================================================================
    let task_state = CoordinatedTaskState::new("task-g6");
    let g6_res = LoopCoordinator::validate_loop_action(LoopRole::InnerLoop, "promote", &task_state);
    assert!(
        matches!(g6_res, Err(KernelError::MissingAuthority(..))),
        "G6: InnerLoop worker cannot promote candidate"
    );

    // =========================================================================
    // Gate G7: Recovery & Resilience (Generation Fencing)
    // Advancing lease generation N -> N+1 must fence stale worker operations
    // =========================================================================
    let mut broker = AtomicEffectBroker::new(1, "fence-1-cluster");
    let mut lease = CapabilityLease::new(
        "lease-g7",
        "worker-1",
        "cluster:res",
        vec!["mutate".into()],
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    lease.generation = 1;
    let guard = AtomicEffectGuard::new("mutate", "cluster:res", serde_json::json!({}));

    // Advance broker generation to 2 (simulating partition recovery or handoff)
    broker.advance_generation("fence-2-cluster");

    let req_stale = EffectRequest {
        lease: &lease,
        guard: &guard,
        received_generation: 1, // stale generation 1
        idempotency_key: "step-stale-g7",
        action: "mutate",
        target: "cluster:res",
        params: &serde_json::json!({}),
    };

    let g7_fenced_res = broker
        .execute_effect(&req_stale)
        .expect("Broker evaluates effect");
    assert!(
        matches!(
            g7_fenced_res,
            EffectDisposition::Fenced {
                current_generation: 2,
                received_generation: 1,
                ..
            }
        ),
        "G7: Stale generation 1 must be fenced"
    );
}

#[test]
fn test_m2_governed_lifecycle_end_to_end() {
    use ggagent_kernel::a2a::{A2AMessage, A2ARole};
    use ggagent_kernel::budget::ExecutionBudget;
    use ggagent_kernel::coordinated_states::{
        CandidateLifecycle, CoordinatedTaskState, ExecutionLifecycle,
    };
    use ggagent_kernel::lease::{AtomicEffectGuard, CapabilityLease, EffectDisposition};
    use ggagent_kernel::loops::{LoopCoordinator, LoopRole};
    use ggagent_validation::effect_broker::{AtomicEffectBroker, EffectRequest};
    use ggagent_validation::guards::SecurityGuards;
    use ggagent_validation::workspace_staging::WorkspaceStagingGuard;
    use tempfile::tempdir;

    // Step 1: Discovery (ARD + A2A)
    let ard_service = ArdService::new("agent.local", "CKODEX Architecture Team");
    let ard_doc = ard_service.get_document();
    assert!(ArdValidator::validate(&ard_doc).is_ok());
    assert!(ard_doc.find_resource_by_id("ggagent-a2a-service").is_some());

    // Step 2: Intent Envelope & Root Authority Lease
    let root_lease = CapabilityLease::new(
        "root-lease-001",
        "principal:root-fabric",
        "resource:cluster/workloads",
        vec!["*".into()],
        chrono::Utc::now() + chrono::Duration::hours(2),
    );
    assert_eq!(root_lease.generation, 0);
    let parent_budget = ExecutionBudget::new(100, 10, 100_000, 60_000);

    // Step 3: Scoped Delegation & Monotonic Budget Attenuation
    let child_lease = root_lease
        .attenuate(
            "child-lease-worker-alpha",
            "worker:alpha",
            vec!["patch".into(), "test".into()],
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .expect("Attenuation succeeds");
    assert_eq!(child_lease.allowed_operations, vec!["patch", "test"]);
    assert_eq!(child_lease.generation, 0);

    let child_budget = parent_budget
        .attenuate(25, 2, 20_000, 15_000)
        .expect("Budget attenuation succeeds");
    assert_eq!(child_budget.max_steps, 25);
    assert_eq!(child_budget.max_mutating_effects, 2);

    // Step 4: Sandbox Execution & Candidate Sealing (defeating TOCTOU)
    let dir = tempdir().expect("tempdir");
    let ws_root = dir.path().join("sandbox_ws");
    std::fs::create_dir_all(&ws_root).expect("create ws dir");
    let patch_path = ws_root.join("patch.diff");
    std::fs::write(
        &patch_path,
        b"--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-old\n+new",
    )
    .expect("write patch");

    let sealed =
        WorkspaceStagingGuard::seal_candidate_file(&ws_root, std::path::Path::new("patch.diff"))
            .expect("Candidate sealed into immutable snapshot");
    assert!(!sealed.content_digest.is_empty());

    // Step 5: Use-Time Authorization (AtomicEffectGuard + Operator Proof Token)
    let mut task_state = CoordinatedTaskState::new("task-m2-e2e");
    task_state.execution = ExecutionLifecycle::Running;
    task_state.candidate = CandidateLifecycle::Sealed;

    let patch_params = serde_json::json!({
        "file": "crates/ggagent-kernel/src/lib.rs",
        "sha256": sealed.content_digest,
    });
    let effect_guard = AtomicEffectGuard::new("patch", "kernel", patch_params.clone());

    let operator_msg = A2AMessage {
        message_id: "msg-approval-m2".into(),
        role: A2ARole::HumanUser,
        sender_id: "operator:human".into(),
        parts: vec![],
        timestamp: chrono::Utc::now(),
        confirmed_call_id: Some("call-patch-001".into()),
    };
    // Verified with cryptographic operator proof token
    SecurityGuards::verify_approval_principal(
        &operator_msg,
        Some("human-auth-proof-operator-alice"),
    )
    .expect("Operator approval verified");
    SecurityGuards::verify_effect_guard(&effect_guard, "patch", "kernel", &patch_params)
        .expect("Use-time material binding matches");

    // Step 6: Three-Loop Independent OuterLoop Verification
    // Inner loop cannot promote; OuterLoop must evaluate and promote
    assert!(
        LoopCoordinator::validate_loop_action(LoopRole::InnerLoop, "promote", &task_state).is_err(),
        "Inner loop must not promote"
    );
    LoopCoordinator::validate_loop_action(LoopRole::OuterLoop, "review", &task_state)
        .expect("Outer loop can review sealed candidate");

    // Step 7: Cryptographic Evidence Publication
    let receipt = ExecutionReceipt::from_params(ExecutionReceiptParams {
        task_id: "task-m2-e2e".into(),
        actor_id: "verifier:outer-loop".into(),
        authority_id: "auth:root:fabric".into(),
        capability_id: "cap:patch".into(),
        action: "patch".into(),
        input_digest: "sha256:0000".into(),
        output_digest: format!("sha256:{}", sealed.content_digest),
        effect_digest: effect_guard.expected_effect_digest.clone(),
        duration_ms: 45,
        exit_code: 0,
    });
    assert!(
        receipt.verify_signature(),
        "Receipt signed by outer loop must verify"
    );

    // Step 8: Revocation, Partition Split-Brain Fencing & Lineage
    let mut broker = AtomicEffectBroker::new(1, "fence-1-task-m2");
    // Advance generation 1 -> 2 (simulating lease rotation / failover)
    broker.advance_generation("fence-2-task-m2");

    let mut stale_child_lease = child_lease.clone();
    stale_child_lease.generation = 1;
    let stale_req = EffectRequest {
        lease: &stale_child_lease,
        guard: &effect_guard,
        received_generation: 1, // stale generation 1
        idempotency_key: "step-m2-stale",
        action: "patch",
        target: "kernel",
        params: &patch_params,
    };
    let fenced = broker
        .execute_effect(&stale_req)
        .expect("Broker evaluates effect");
    assert!(matches!(
        fenced,
        EffectDisposition::Fenced {
            current_generation: 2,
            received_generation: 1,
            ..
        }
    ));
}

#[test]
fn test_lab14_invarith_7_stage_effect_safety_and_in_doubt_fsm() {
    use ggagent_kernel::governed_execution::EffectStage;
    use ggagent_validation::{AtomicEffectBroker, EffectRequest};

    let mut broker = AtomicEffectBroker::new(1, "fence-1-lab14");
    let mut lease = CapabilityLease::new(
        "lease-lab14",
        "worker-alpha",
        "kubernetes/deployments/production",
        vec!["rollout".into()],
        chrono::Utc::now() + chrono::Duration::hours(2),
    );
    lease.advance_generation();
    let params = serde_json::json!({
        "service": "checkout-api",
        "image": "registry.enterprise.io/checkout:v2.1.0@sha256:abcd"
    });
    let guard = AtomicEffectGuard::new(
        "rollout",
        "kubernetes/deployments/production",
        params.clone(),
    );

    let req = EffectRequest {
        lease: &lease,
        guard: &guard,
        received_generation: 1,
        idempotency_key: "idem-lab14-rollout-001",
        action: "rollout",
        target: "kubernetes/deployments/production",
        params: &params,
    };

    // Stage 1 & 2 & 3: Prepare effect before consequential side effects (GFX-S08)
    let prep_disp = broker
        .prepare_effect(&req)
        .expect("Prepare effect succeeds");
    match prep_disp {
        EffectDisposition::Prepared {
            ref fencing_token, ..
        } => {
            assert!(fencing_token.contains("fence-1"));
        }
        _ => panic!("Expected Prepared disposition"),
    }

    // Verify stage in journal
    let stage = broker.effect_journal.get("idem-lab14-rollout-001").unwrap();
    assert!(matches!(stage, EffectStage::Prepared { .. }));

    // Stage 4: Broker exclusively claims the prepared effect with CAS (GFX-S08)
    let claim_token = broker
        .claim_effect("idem-lab14-rollout-001", "broker-principal-secure")
        .unwrap();
    assert!(claim_token.contains("fence-1"));

    // Stage 5: Broker records APPLYING under broker-owned capability
    broker
        .record_applying("idem-lab14-rollout-001", "k8s-rpc-call-771")
        .unwrap();

    // Stage 6: Ambiguous external network outcome (upstream timeout / partition)
    // GFX-S09: On timeout/crash/partial outcome: mark IN_DOUBT, observe and reconcile before any retry!
    let in_doubt_disp = broker
        .reconcile_or_doubt(
            "idem-lab14-rollout-001",
            Err("ETIMEDOUT: Connection reset during mutate".into()),
        )
        .expect("Transitions to InDoubt");

    match in_doubt_disp {
        EffectDisposition::InDoubt {
            ref reason,
            ref last_stage,
            requires_reconciliation,
        } => {
            assert!(reason.contains("ETIMEDOUT"));
            assert_eq!(last_stage, "APPLYING");
            assert!(requires_reconciliation);
        }
        _ => panic!("Expected InDoubt disposition"),
    }

    // Stage 7: Subsequent blind retry MUST be blocked with InDoubt (Defeats blind retries & duplicate mutations)
    let retry_disp = broker.execute_effect(&req).expect("Retry evaluation");
    assert!(matches!(
        retry_disp,
        EffectDisposition::InDoubt {
            requires_reconciliation: true,
            ..
        }
    ));

    // Reconciliation resolution: postcondition read-back verifies desired state achieved
    let reconciled_disp = broker
        .reconcile_or_doubt(
            "idem-lab14-rollout-001",
            Ok("sha256:verified-postcondition-digest".into()),
        )
        .expect("Reconciliation succeeds");

    match reconciled_disp {
        EffectDisposition::Committed {
            ref effect_digest,
            generation,
            ..
        } => {
            assert_eq!(effect_digest, "sha256:verified-postcondition-digest");
            assert_eq!(generation, 1);
        }
        _ => panic!("Expected Committed disposition after reconciliation"),
    }
}

#[test]
fn test_lab15_isolation_class_hierarchy_and_downgrade_prevention() {
    use ggagent_kernel::governed_execution::{IsolationClass, IsolationContract};
    use ggagent_validation::IsolationGuard;

    // Isolation ranks: LocalDev (1) < WasiComponent (2) < OciGvisor (3) < MicroVm (4) < ConfidentialVm (5)
    assert!(IsolationClass::ConfidentialVm > IsolationClass::MicroVm);
    assert!(IsolationClass::MicroVm > IsolationClass::OciGvisor);
    assert!(IsolationClass::OciGvisor > IsolationClass::WasiComponent);
    assert!(IsolationClass::WasiComponent > IsolationClass::LocalDev);

    // GFX-S05: Hostile agent workloads mandate MicroVm hardware isolation
    let hostile_check = IsolationGuard::evaluate_placement(
        "hostile",
        IsolationClass::LocalDev,
        IsolationClass::LocalDev,
    );
    assert!(
        hostile_check.is_err(),
        "Hostile workload must reject LocalDev process sandbox"
    );

    // Hostile workload with MicroVm contract on gVisor host must fail closed (No silent downgrade!)
    let contract = IsolationContract::new(
        IsolationClass::MicroVm,
        "tenant-finance",
        "untrusted-tool-executor",
    );
    assert!(
        !contract.allow_downgrade,
        "Default allow_downgrade must be false"
    );

    let downgrade_res =
        IsolationGuard::verify_isolation_boundary(&contract, &IsolationClass::OciGvisor);
    assert!(
        downgrade_res.is_err(),
        "Must fail closed when host provides OciGvisor but MicroVm was contracted"
    );

    // Valid placement on hardware-isolated MicroVm
    let valid_res = IsolationGuard::verify_isolation_boundary(&contract, &IsolationClass::MicroVm);
    assert!(
        valid_res.is_ok(),
        "Must succeed when host matches required isolation"
    );

    // Valid placement on higher isolation (ConfidentialVm satisfies MicroVm)
    let enclave_res =
        IsolationGuard::verify_isolation_boundary(&contract, &IsolationClass::ConfidentialVm);
    assert!(
        enclave_res.is_ok(),
        "ConfidentialVm meets MicroVm minimum requirement"
    );
}

#[test]
fn test_lab16_context_root_authority_precedence_and_fault_defense() {
    use ggagent_kernel::governed_execution::{ContextFault, ContextRoot};
    use ggagent_validation::ContextGuard;

    let lease = CapabilityLease::new(
        "lease-auth-ctx-001",
        "principal:data-governance",
        "vector-db/customer-corpus",
        vec!["read".into(), "embed".into()],
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    let context_root = ContextRoot::new(
        "ctx-root-alpha",
        "lease-auth-ctx-001",
        "sha256:policy-decision-hash",
        "sha256:observation-cut-hash",
        "RESTRICTED-PII",
    );

    // ContextRoot preceded by valid authority succeeds
    assert!(ContextGuard::verify_context_precedence(&context_root, &lease).is_ok());

    // Mismatched authority lease reference fails closed
    let other_lease = CapabilityLease::new(
        "lease-wrong-id",
        "principal:unknown",
        "vector-db/customer-corpus",
        vec!["read".into()],
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    assert!(ContextGuard::verify_context_precedence(&context_root, &other_lease).is_err());

    // ContextFaults: None succeeds
    assert!(ContextGuard::assert_no_context_fault(None).is_ok());

    // ContextFault: Stale epoch fails closed (no silent hallucination)
    let stale = ContextFault::Stale {
        current_epoch: 10,
        requested_epoch: 9,
    };
    assert!(ContextGuard::assert_no_context_fault(Some(&stale)).is_err());

    // ContextFault: Integrity failure fails closed
    let corrupted = ContextFault::IntegrityFailure {
        expected_digest: "sha256:1111".into(),
        actual_digest: "sha256:2222".into(),
    };
    assert!(ContextGuard::assert_no_context_fault(Some(&corrupted)).is_err());

    // ContextFault: Policy denied fails closed
    let denied = ContextFault::PolicyDenied {
        reason: "Tenant classification boundary crossed".into(),
    };
    assert!(ContextGuard::assert_no_context_fault(Some(&denied)).is_err());
}

#[test]
fn test_lab17_srt_egress_proxy_external_decider_and_credential_injection() {
    use ggagent_validation::{EgressProxyDecision, EgressProxyEngine, EgressProxyRequest};
    use std::collections::BTreeMap;
    use std::time::Duration;

    let mut engine = EgressProxyEngine::new(
        vec!["api.github.com".into(), "registry.npmjs.org".into()],
        Duration::from_secs(5),
    );
    // Credential masking: agent never possesses static GitHub token; proxy injects it
    engine.register_scoped_credential(
        "api.github.com",
        "Authorization",
        "Bearer ghp_ephemeral_scoped_proxy_token_77",
    );

    // 1. Cloud IMDS exfiltration attempt is unconditionally DENIED
    let imds_req = EgressProxyRequest {
        client_id: "untrusted-agent".into(),
        method: "GET".into(),
        url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/".into(),
        destination_host: "169.254.169.254".into(),
        destination_port: 80,
        headers: BTreeMap::new(),
        body_digest: None,
    };
    let imds_dec = engine
        .evaluate_request(&imds_req, Duration::from_millis(10))
        .unwrap();
    match imds_dec {
        EgressProxyDecision::Deny { reason } => {
            assert!(
                reason.contains("prohibited metadata service") || reason.contains("IMDS"),
                "Expected metadata denial reason, got: {}",
                reason
            );
        }
        _ => panic!("IMDS must be denied"),
    }

    // 2. Unapproved domain is DENIED
    let evil_req = EgressProxyRequest {
        client_id: "untrusted-agent".into(),
        method: "POST".into(),
        url: "https://attacker.site/exfiltrate".into(),
        destination_host: "attacker.site".into(),
        destination_port: 443,
        headers: BTreeMap::new(),
        body_digest: Some("sha256:stolen-keys".into()),
    };
    let evil_dec = engine
        .evaluate_request(&evil_req, Duration::from_millis(10))
        .unwrap();
    assert!(matches!(evil_dec, EgressProxyDecision::Deny { .. }));

    // 3. Approved domain succeeds and has scoped credentials injected
    let gh_req = EgressProxyRequest {
        client_id: "coding-agent-01".into(),
        method: "GET".into(),
        url: "https://api.github.com/repos/org/repo/issues".into(),
        destination_host: "api.github.com".into(),
        destination_port: 443,
        headers: BTreeMap::new(),
        body_digest: None,
    };
    let gh_dec = engine
        .evaluate_request(&gh_req, Duration::from_millis(25))
        .unwrap();
    match gh_dec {
        EgressProxyDecision::Allow { injected_headers } => {
            assert_eq!(
                injected_headers.get("Authorization"),
                Some(&"Bearer ghp_ephemeral_scoped_proxy_token_77".to_string())
            );
        }
        _ => panic!("Approved domain must be Allowed with injected credentials"),
    }

    // 4. Timeout (>5 seconds) fails closed immediately
    let timeout_res = engine.evaluate_request(&gh_req, Duration::from_millis(5001));
    assert!(
        timeout_res.is_err(),
        "Request exceeding 5s timeout must fail closed"
    );
}

#[test]
fn test_lab18_tamper_evident_journal_chain_and_corruption_detection() {
    use ggagent_validation::{AtomicEffectBroker, EffectRequest};

    let mut broker = AtomicEffectBroker::new(1, "fence-1-lab18");
    let mut lease = CapabilityLease::new(
        "lease-lab18",
        "worker-secure",
        "database/records",
        vec!["insert".into()],
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    lease.advance_generation();
    let params = serde_json::json!({"row": "user_data"});
    let guard = AtomicEffectGuard::new("insert", "database/records", params.clone());

    let req = EffectRequest {
        lease: &lease,
        guard: &guard,
        received_generation: 1,
        idempotency_key: "idem-lab18-001",
        action: "insert",
        target: "database/records",
        params: &params,
    };

    // Execute full 7-stage effect
    let disp = broker.execute_effect(&req).expect("Execute succeeds");
    assert!(matches!(disp, EffectDisposition::Committed { .. }));

    // Journal chain must have valid cryptographic integrity across all transitions
    assert!(broker.verify_journal_integrity().is_ok());

    // Adversarial tampering attack: an attacker with memory/storage access mutates a past entry
    broker.journal_chain.entries[0].idempotency_key = "forged-idempotency-key".into();

    // Verification MUST immediately catch the hash decoherence (GFX-S08)
    let verify_err = broker.verify_journal_integrity();
    assert!(verify_err.is_err());
    let err_str = verify_err.unwrap_err().to_string();
    assert!(err_str.contains("Journal chain corruption"));
}

#[test]
fn test_lab19_in_flight_crash_recovery_advances_generation_and_fences() {
    use ggagent_validation::{AtomicEffectBroker, EffectRequest};

    let mut broker = AtomicEffectBroker::new(5, "fence-5-pre-crash");
    let mut lease = CapabilityLease::new(
        "lease-lab19",
        "worker-alpha",
        "vault/secrets/pki",
        vec!["rotate".into()],
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    lease.generation = 5;
    lease.fencing_token = "fence-5-lease-lab19".into();

    let params = serde_json::json!({"cert_id": "root-ca"});
    let guard = AtomicEffectGuard::new("rotate", "vault/secrets/pki", params.clone());

    let req = EffectRequest {
        lease: &lease,
        guard: &guard,
        received_generation: 5,
        idempotency_key: "idem-lab19-inflight",
        action: "rotate",
        target: "vault/secrets/pki",
        params: &params,
    };

    // Prepare and claim
    broker.prepare_effect(&req).unwrap();
    broker
        .claim_effect("idem-lab19-inflight", "broker-active")
        .unwrap();
    broker
        .record_applying("idem-lab19-inflight", "rpc-active-99")
        .unwrap();

    // Crash occurs while in APPLYING!
    // Crash recovery protocol is invoked upon daemon reboot:
    let in_doubt_keys = broker.recover_from_crash().expect("Recovery succeeds");
    assert_eq!(in_doubt_keys, vec!["idem-lab19-inflight".to_string()]);

    // Invariant: Generation MUST advance (5 -> 6) to fence any zombie RPC from the crashed session
    assert_eq!(broker.current_generation, 6);
    assert!(broker
        .authoritative_fencing_token
        .contains("fence-recovered-6"));

    // In-flight effect is held in IN_DOUBT (no blind retry allowed!)
    let cached = broker.idempotency_cache.get("idem-lab19-inflight").unwrap();
    assert!(matches!(
        cached,
        EffectDisposition::InDoubt {
            requires_reconciliation: true,
            ..
        }
    ));

    // Zombie worker retrying with generation 5 lease is strictly FENCED
    let retry_disp = broker.execute_effect(&req).unwrap();
    // Because it's IN_DOUBT in idempotency cache, it returns InDoubt
    assert!(matches!(retry_disp, EffectDisposition::InDoubt { .. }));

    // Explicit postcondition reconciliation commits the transaction with receipt
    let rec_disp = broker
        .reconcile_in_doubt_effect("idem-lab19-inflight", "sha256:verified-pki-rotation")
        .expect("Reconciliation commits");
    match rec_disp {
        EffectDisposition::Committed {
            generation,
            effect_digest,
            ..
        } => {
            assert_eq!(generation, 6);
            assert_eq!(effect_digest, "sha256:verified-pki-rotation");
        }
        _ => panic!("Expected committed postcondition"),
    }
}

#[test]
fn test_lab20_imds_obfuscated_encoding_evasion_defeat() {
    use ggagent_validation::{EgressProxyDecision, EgressProxyEngine, EgressProxyRequest};
    use std::collections::BTreeMap;
    use std::time::Duration;

    let engine = EgressProxyEngine::new(vec!["api.github.com".into()], Duration::from_secs(5));

    // Comprehensive adversarial evasion test cases
    let obfuscations = vec![
        ("169.254.169.254", "Standard IPv4 IMDS"),
        ("2852039166", "Dword / Decimal Integer notation"),
        ("0xa9.0xfe.0xa9.0xfe", "Hex dotted-quad notation"),
        ("0251.0376.0251.0376", "Octal dotted-quad notation"),
        ("[::ffff:169.254.169.254]", "Bracketed IPv6-mapped IPv4"),
        ("::ffff:169.254.169.254", "Unbracketed IPv6-mapped IPv4"),
        ("fd00:ec2::254", "AWS IPv6 IMDS endpoint"),
        ("[fd00:ec2::254]", "Bracketed AWS IPv6 IMDS endpoint"),
        ("127.0.0.1", "Localhost IPv4"),
        ("localhost", "Localhost string"),
        ("::1", "Localhost IPv6"),
    ];

    for (evasion_host, description) in obfuscations {
        let req = EgressProxyRequest {
            client_id: "malicious-agent".into(),
            method: "GET".into(),
            url: format!("http://{}/credentials", evasion_host),
            destination_host: evasion_host.into(),
            destination_port: 80,
            headers: BTreeMap::new(),
            body_digest: None,
        };

        let decision = engine
            .evaluate_request(&req, Duration::from_millis(5))
            .unwrap();
        match decision {
            EgressProxyDecision::Deny { reason } => {
                assert!(
                    reason.contains("prohibited metadata service")
                        || reason.contains("not in the approved"),
                    "Evasion '{}' ({}) must be denied with security reason, got: {}",
                    evasion_host,
                    description,
                    reason
                );
            }
            _ => panic!(
                "Evasion '{}' ({}) was permitted by egress proxy!",
                evasion_host, description
            ),
        }
    }
}

#[test]
fn test_lab21_gfx_s17_hard_veto_dominates_multi_model_consensus() {
    use ggagent_kernel::error::KernelError;
    use ggagent_kernel::governed_execution::HardVetoEvaluator;

    let unanimous_models = vec![
        "gemini-2.5-pro".into(),
        "claude-3.7-sonnet".into(),
        "o3-mini".into(),
        "deepseek-r1".into(),
    ];

    // Case 1: Unanimous consensus (100%) without veto passes
    let clean = HardVetoEvaluator::evaluate_consensus(1.0, &unanimous_models, None);
    assert!(clean.is_ok());

    // Case 2: Even with 100% agreement of 4 frontier models, a single hard veto
    // categorically forces a NON_CONFORMANT / AntiInvariantViolation rejection (GFX-S17)
    let veto_attempt = HardVetoEvaluator::evaluate_consensus(
        1.0,
        &unanimous_models,
        Some("ANTI_INVARIANT_UNAUTHORIZED_EXTERNAL_MUTATION"),
    );
    assert!(veto_attempt.is_err());
    match veto_attempt.unwrap_err() {
        KernelError::AntiInvariantViolation { invariant, context } => {
            assert_eq!(invariant, "ANTI_INVARIANT_UNAUTHORIZED_EXTERNAL_MUTATION");
            assert!(context.contains("GFX-S17 Dominance"));
            assert!(context.contains("100.0% consensus"));
        }
        other => panic!("Expected AntiInvariantViolation, got {:?}", other),
    }
}
