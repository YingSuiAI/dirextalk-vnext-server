use std::{str::FromStr, sync::Arc, time::Duration};

use dtx_domain::{HostId, JobId, JobResourceId, RequestId, RunId, TenantId, WorkerId};
use dtx_security::{CrashRequested, ExternalEffectPhase, FaultCheckpoint, FaultHook, FaultPoint};
use dtx_testkit::{
    AgentRuntimeError, AgentRuntimeOutput, CancelRun, CertificateAuthorizationError,
    CertificatePurpose, DestroyEphemeralGroupRequest, EnsureExecutorRequest, FakeAgentRuntime,
    FakeAgentWorld, FakeAwsError, FakeAwsProvider, FakeAwsWorld, ObserveExecutorRequest,
    ResourceLifecycle, ScriptedAgentOutput, ScriptedFaults, StartRun, TestCertificateAuthority,
    TestCertificateError, WorkloadIdentity,
};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::WebPkiClientVerifier,
};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn request(value: &str) -> RequestId {
    RequestId::from_str(value).expect("valid request ID fixture")
}

fn run(value: &str) -> RunId {
    RunId::from_str(value).expect("valid run ID fixture")
}

fn tenant(value: &str) -> TenantId {
    TenantId::from_str(value).expect("valid tenant ID fixture")
}

fn job(value: &str) -> JobId {
    JobId::from_str(value).expect("valid job ID fixture")
}

fn resource(value: &str) -> JobResourceId {
    JobResourceId::from_str(value).expect("valid resource ID fixture")
}

fn worker(value: &str) -> WorkerId {
    WorkerId::from_str(value).expect("valid worker ID fixture")
}

fn host(value: &str) -> HostId {
    HostId::from_str(value).expect("valid host ID fixture")
}

#[test]
fn fake_agent_resumes_committed_checkpoint_without_repeating_a_step() {
    let run_id = run("01890f00-0000-7000-8000-000000000001");
    let world = FakeAgentWorld::new([
        ScriptedAgentOutput::Checkpoint {
            state_digest: digest(0x11),
        },
        ScriptedAgentOutput::Completed {
            result_digest: digest(0x22),
        },
    ]);
    let runtime = FakeAgentRuntime::new(world.clone());
    let start = StartRun::new(
        request("01890f00-0000-7000-8000-000000000002"),
        run_id,
        7,
        digest(0x33),
    )
    .expect("valid start request");

    let first = runtime.start(&start).expect("start succeeds");
    assert_eq!(runtime.start(&start).expect("retry succeeds"), first);
    let AgentRuntimeOutput::Checkpoint(checkpoint) = first else {
        panic!("script must emit a checkpoint")
    };
    assert_eq!(world.applied_step_count(), 1);

    let restored_world = FakeAgentWorld::from_snapshot(world.snapshot());
    let restored_runtime = FakeAgentRuntime::new(restored_world.clone());
    let resume = dtx_testkit::ResumeRun::new(
        request("01890f00-0000-7000-8000-000000000003"),
        run_id,
        8,
        checkpoint,
    )
    .expect("valid resume request");
    let completed = restored_runtime.resume(&resume).expect("resume succeeds");
    assert_eq!(
        completed,
        AgentRuntimeOutput::Completed {
            result_digest: digest(0x22)
        }
    );
    assert_eq!(
        restored_runtime.resume(&resume).expect("retry succeeds"),
        completed
    );
    assert_eq!(restored_world.applied_step_count(), 2);

    let conflicting =
        StartRun::new(start.operation_id(), run_id, 7, digest(0x44)).expect("shape remains valid");
    assert_eq!(
        restored_runtime.start(&conflicting),
        Err(AgentRuntimeError::IdempotencyConflict)
    );
    let stale_cancel = CancelRun::new(request("01890f00-0000-7000-8000-000000000004"), run_id, 7)
        .expect("valid cancel request");
    assert_eq!(
        restored_runtime.cancel(&stale_cancel),
        Err(AgentRuntimeError::StaleLease)
    );
}

#[test]
fn fake_agent_cancel_is_idempotent() {
    let run_id = run("01890f00-0000-7000-8000-000000000011");
    let world = FakeAgentWorld::new([ScriptedAgentOutput::Checkpoint {
        state_digest: digest(0x51),
    }]);
    let runtime = FakeAgentRuntime::new(world);
    runtime
        .start(
            &StartRun::new(
                request("01890f00-0000-7000-8000-000000000012"),
                run_id,
                1,
                digest(0x52),
            )
            .expect("valid start"),
        )
        .expect("started");
    let cancel = CancelRun::new(request("01890f00-0000-7000-8000-000000000013"), run_id, 1)
        .expect("valid cancel");

    assert_eq!(
        runtime.cancel(&cancel).expect("cancel succeeds"),
        AgentRuntimeOutput::Cancelled
    );
    assert_eq!(
        runtime.cancel(&cancel).expect("cancel retry succeeds"),
        AgentRuntimeOutput::Cancelled
    );
}

#[test]
fn fake_agent_recovers_after_committed_step_without_repeating_it() {
    let run_id = run("01890f00-0000-7000-8000-000000000015");
    let world = FakeAgentWorld::new([ScriptedAgentOutput::Completed {
        result_digest: digest(0x55),
    }]);
    let start = StartRun::new(
        request("01890f00-0000-7000-8000-000000000016"),
        run_id,
        1,
        digest(0x56),
    )
    .expect("valid start");
    let crashing = FakeAgentRuntime::with_fault_hook(
        world.clone(),
        Arc::new(CrashOnce::new(
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        )),
    );

    assert!(matches!(
        crashing.start(&start),
        Err(AgentRuntimeError::CrashRequested(_))
    ));
    assert_eq!(world.applied_step_count(), 1);

    let recovered_world = FakeAgentWorld::from_snapshot(world.snapshot());
    let recovered = FakeAgentRuntime::new(recovered_world.clone());
    assert_eq!(
        recovered.start(&start).expect("idempotent retry succeeds"),
        AgentRuntimeOutput::Completed {
            result_digest: digest(0x55)
        }
    );
    assert_eq!(recovered_world.applied_step_count(), 1);
}

#[derive(Debug)]
struct CrashOnce {
    phase: ExternalEffectPhase,
    fired: std::sync::atomic::AtomicBool,
}

impl CrashOnce {
    fn new(phase: ExternalEffectPhase) -> Self {
        Self {
            phase,
            fired: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl FaultHook for CrashOnce {
    fn checkpoint(&self, checkpoint: &FaultCheckpoint) -> Result<(), CrashRequested> {
        if checkpoint.phase() == self.phase
            && !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            Err(CrashRequested::new(checkpoint.clone()))
        } else {
            Ok(())
        }
    }
}

fn ensure_request(operation_id: RequestId) -> EnsureExecutorRequest {
    EnsureExecutorRequest::new(
        operation_id,
        tenant("01890f00-0000-7000-8000-000000000021"),
        job("01890f00-0000-7000-8000-000000000022"),
        resource("01890f00-0000-7000-8000-000000000023"),
        worker("01890f00-0000-7000-8000-000000000024"),
        3,
        digest(0x61),
        digest(0x62),
        1_800_000_600_000,
    )
    .expect("valid ensure request")
}

#[test]
fn fake_aws_recovers_after_remote_commit_without_duplicate_executor() {
    let now = 1_800_000_000_000;
    let world = FakeAwsWorld::new();
    let ensure = ensure_request(request("01890f00-0000-7000-8000-000000000025"));
    let crashing = FakeAwsProvider::with_fault_hook(
        world.clone(),
        now,
        Arc::new(CrashOnce::new(
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        )),
    );

    assert!(matches!(
        crashing.ensure_executor(&ensure),
        Err(FakeAwsError::CrashRequested(_))
    ));
    assert_eq!(world.resource_count(), 1);
    assert_eq!(world.ensure_effect_count(), 1);

    let recovered = FakeAwsProvider::new(world.clone(), now);
    let observation = recovered
        .ensure_executor(&ensure)
        .expect("idempotent recovery succeeds");
    assert_eq!(world.resource_count(), 1);
    assert_eq!(world.ensure_effect_count(), 1);
    assert!(observation.tags().managed());
    assert_eq!(observation.tags().lifecycle(), ResourceLifecycle::Ephemeral);
    assert_eq!(observation.tags().expires_at_millis(), 1_800_000_600_000);
    assert_eq!(
        FakeAwsProvider::new(world.clone(), ensure.expires_at_millis() + 1)
            .ensure_executor(&ensure)
            .expect("a committed receipt survives crossing its expiry"),
        observation
    );

    let observed = recovered
        .observe_executor(&ObserveExecutorRequest::new(
            ensure.tenant_id(),
            ensure.resource_id(),
        ))
        .expect("observe succeeds")
        .expect("resource exists");
    assert_eq!(observed, observation);

    let conflicting = EnsureExecutorRequest::new(
        ensure.operation_id(),
        ensure.tenant_id(),
        ensure.job_id(),
        ensure.resource_id(),
        ensure.worker_id(),
        ensure.lease_epoch(),
        digest(0x7f),
        ensure.plan_hash(),
        ensure.expires_at_millis(),
    )
    .expect("valid conflicting shape");
    assert_eq!(
        recovered.ensure_executor(&conflicting),
        Err(FakeAwsError::IdempotencyConflict)
    );

    let destroy = DestroyEphemeralGroupRequest::new(
        request("01890f00-0000-7000-8000-000000000026"),
        ensure.tenant_id(),
        ensure.job_id(),
        4,
        ensure.plan_hash(),
    )
    .expect("valid destroy request");
    let destroyed = recovered
        .destroy_ephemeral_group(&destroy)
        .expect("destroy succeeds");
    assert_eq!(destroyed.destroyed_count(), 1);
    assert_eq!(
        recovered
            .destroy_ephemeral_group(&destroy)
            .expect("destroy retry succeeds"),
        destroyed
    );
}

#[test]
fn fake_aws_before_invoke_crash_has_no_side_effect_and_expired_specs_fail_closed() {
    let now = 1_800_000_000_000;
    let world = FakeAwsWorld::new();
    let ensure = ensure_request(request("01890f00-0000-7000-8000-000000000031"));
    let crashing = FakeAwsProvider::with_fault_hook(
        world.clone(),
        now,
        Arc::new(CrashOnce::new(ExternalEffectPhase::BeforeInvoke)),
    );
    assert!(matches!(
        crashing.ensure_executor(&ensure),
        Err(FakeAwsError::CrashRequested(_))
    ));
    assert_eq!(world.resource_count(), 0);

    let expired = EnsureExecutorRequest::new(
        request("01890f00-0000-7000-8000-000000000032"),
        ensure.tenant_id(),
        ensure.job_id(),
        ensure.resource_id(),
        ensure.worker_id(),
        ensure.lease_epoch(),
        ensure.spec_hash(),
        ensure.plan_hash(),
        now,
    )
    .expect("expired request remains structurally valid");
    assert_eq!(
        FakeAwsProvider::new(world, now).ensure_executor(&expired),
        Err(FakeAwsError::InvalidExpiry)
    );
}

#[test]
fn fake_aws_fault_attempts_advance_monotonically_across_retry() {
    let now = 1_800_000_000_000;
    let world = FakeAwsWorld::new();
    let ensure = ensure_request(request("01890f00-0000-7000-8000-000000000033"));
    let faults = Arc::new(ScriptedFaults::new());
    faults
        .arm_once(
            FaultCheckpoint::new(
                FaultPoint::parse("fake_aws_provider").expect("valid fake fault point"),
                ExternalEffectPhase::BeforeInvoke,
                ensure.operation_id(),
                1,
            )
            .expect("positive first attempt"),
        )
        .expect("unique fault plan");
    let provider = FakeAwsProvider::with_fault_hook(world.clone(), now, faults.clone());

    assert!(matches!(
        provider.ensure_executor(&ensure),
        Err(FakeAwsError::CrashRequested(_))
    ));
    assert_eq!(world.resource_count(), 0);
    provider
        .ensure_executor(&ensure)
        .expect("second attempt succeeds");
    assert_eq!(world.resource_count(), 1);
    faults.assert_consumed().expect("first attempt fired");
    assert_eq!(
        faults
            .transcript()
            .iter()
            .map(|entry| entry.checkpoint().attempt())
            .collect::<Vec<_>>(),
        vec![1, 2, 2]
    );
}

#[test]
fn fake_aws_destroy_is_idempotent_under_concurrency() {
    let now = 1_800_000_000_000;
    let world = FakeAwsWorld::new();
    let provider = Arc::new(FakeAwsProvider::new(world, now));
    let ensure = ensure_request(request("01890f00-0000-7000-8000-000000000035"));
    provider.ensure_executor(&ensure).expect("executor created");
    let destroy = DestroyEphemeralGroupRequest::new(
        request("01890f00-0000-7000-8000-000000000036"),
        ensure.tenant_id(),
        ensure.job_id(),
        4,
        ensure.plan_hash(),
    )
    .expect("valid destroy request");
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let provider = Arc::clone(&provider);
        let destroy = destroy.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            provider
                .destroy_ephemeral_group(&destroy)
                .expect("concurrent retry succeeds")
        }));
    }
    barrier.wait();

    for worker in workers {
        assert_eq!(worker.join().expect("worker finishes").destroyed_count(), 1);
    }
}

#[test]
fn fake_aws_resource_claims_and_fences_are_tenant_scoped() {
    let now = 1_800_000_000_000;
    let world = FakeAwsWorld::new();
    let provider = FakeAwsProvider::new(world.clone(), now);
    let tenant_a = tenant("01890f00-0000-7000-8000-000000000071");
    let tenant_b = tenant("01890f00-0000-7000-8000-000000000072");
    let shared_job = job("01890f00-0000-7000-8000-000000000073");
    let claimed_resource = resource("01890f00-0000-7000-8000-000000000074");
    let expires_at = now + 600_000;
    let ensure_a = EnsureExecutorRequest::new(
        request("01890f00-0000-7000-8000-000000000075"),
        tenant_a,
        shared_job,
        claimed_resource,
        worker("01890f00-0000-7000-8000-000000000076"),
        3,
        digest(0x81),
        digest(0x82),
        expires_at,
    )
    .expect("valid tenant A request");
    provider
        .ensure_executor(&ensure_a)
        .expect("tenant A claims its resource");

    let cross_tenant_claim = EnsureExecutorRequest::new(
        request("01890f00-0000-7000-8000-000000000077"),
        tenant_b,
        shared_job,
        claimed_resource,
        worker("01890f00-0000-7000-8000-000000000078"),
        99,
        digest(0x83),
        digest(0x84),
        expires_at,
    )
    .expect("valid hostile claim shape");
    assert_eq!(
        provider.ensure_executor(&cross_tenant_claim),
        Err(FakeAwsError::ResourceConflict)
    );
    assert!(
        provider
            .observe_executor(&ObserveExecutorRequest::new(tenant_b, claimed_resource))
            .expect("observation succeeds")
            .is_none()
    );

    let ensure_b = EnsureExecutorRequest::new(
        request("01890f00-0000-7000-8000-000000000079"),
        tenant_b,
        shared_job,
        resource("01890f00-0000-7000-8000-00000000007a"),
        worker("01890f00-0000-7000-8000-00000000007b"),
        99,
        digest(0x85),
        digest(0x86),
        expires_at,
    )
    .expect("valid tenant B request");
    provider
        .ensure_executor(&ensure_b)
        .expect("tenant B advances only its own fence");
    let ensure_a_again = EnsureExecutorRequest::new(
        request("01890f00-0000-7000-8000-00000000007c"),
        tenant_a,
        shared_job,
        resource("01890f00-0000-7000-8000-00000000007d"),
        worker("01890f00-0000-7000-8000-00000000007e"),
        3,
        digest(0x87),
        digest(0x88),
        expires_at,
    )
    .expect("valid second tenant A request");
    provider
        .ensure_executor(&ensure_a_again)
        .expect("tenant B's higher epoch must not fence tenant A");
    assert_eq!(world.resource_count(), 3);
}

#[test]
fn test_ca_authorizes_one_typed_identity_purpose_and_time_window() {
    let now = 1_800_000_000_000;
    let tenant_id = tenant("01890f00-0000-7000-8000-000000000041");
    let identity = WorkloadIdentity::Connector {
        tenant_id,
        connector_id: dtx_domain::ConnectorId::from_str("01890f00-0000-7000-8000-000000000042")
            .expect("valid connector"),
    };
    let ca = TestCertificateAuthority::new(now).expect("CA created");
    let certificate = ca
        .issue(&identity, CertificatePurpose::ClientAuth, now, 300)
        .expect("certificate issued");

    assert!(
        certificate
            .certificate_der()
            .windows(certificate.identity_uri().len())
            .any(|window| window == certificate.identity_uri().as_bytes())
    );
    assert_eq!(
        ca.authorize(&certificate, &identity, CertificatePurpose::ClientAuth, now),
        Ok(())
    );
    assert_eq!(
        ca.authorize(&certificate, &identity, CertificatePurpose::ServerAuth, now),
        Err(CertificateAuthorizationError::WrongPurpose)
    );
    let wrong_kind = WorkloadIdentity::Host {
        tenant_id,
        host_id: host("01890f00-0000-7000-8000-000000000043"),
    };
    assert_eq!(
        ca.authorize(
            &certificate,
            &wrong_kind,
            CertificatePurpose::ClientAuth,
            now
        ),
        Err(CertificateAuthorizationError::WrongIdentity)
    );
    assert_eq!(
        ca.authorize(
            &certificate,
            &identity,
            CertificatePurpose::ClientAuth,
            certificate.not_after_millis() + 1
        ),
        Err(CertificateAuthorizationError::Expired)
    );

    ca.revoke(certificate.serial())
        .expect("revocation succeeds");
    assert_eq!(
        ca.authorize(&certificate, &identity, CertificatePurpose::ClientAuth, now),
        Err(CertificateAuthorizationError::Revoked)
    );
    assert!(format!("{certificate:?}").contains("[REDACTED]"));
    assert!(!format!("{certificate:?}").contains(&certificate.private_key_len().to_string()));
}

#[test]
fn test_ca_rejects_non_short_lived_certificates() {
    let ca = TestCertificateAuthority::new(1_800_000_000_000).expect("CA created");
    let identity = WorkloadIdentity::Host {
        tenant_id: tenant("01890f00-0000-7000-8000-000000000051"),
        host_id: host("01890f00-0000-7000-8000-000000000052"),
    };

    assert!(matches!(
        ca.issue(
            &identity,
            CertificatePurpose::ClientAuth,
            1_800_000_000_000,
            901
        ),
        Err(TestCertificateError::LifetimeTooLong)
    ));
    assert_eq!(
        ca.issue(
            &identity,
            CertificatePurpose::ClientAuth,
            1_800_000_000_000 + 30 * 24 * 60 * 60 * 1_000,
            300,
        )
        .expect_err("a leaf cannot outlive its CA"),
        TestCertificateError::InvalidTime
    );
    assert!(matches!(
        TestCertificateAuthority::new(i64::MIN),
        Err(TestCertificateError::InvalidTime)
    ));
}

#[test]
fn test_ca_certificates_pass_rustls_chain_and_single_eku_verification() {
    let now_millis = 1_800_000_000_000_i64;
    let ca = TestCertificateAuthority::new(now_millis).expect("CA created");
    let client = ca
        .issue(
            &WorkloadIdentity::Connector {
                tenant_id: tenant("01890f00-0000-7000-8000-000000000061"),
                connector_id: dtx_domain::ConnectorId::from_str(
                    "01890f00-0000-7000-8000-000000000062",
                )
                .expect("valid connector"),
            },
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("client certificate issued");
    let server = ca
        .issue(
            &WorkloadIdentity::ControlServer {
                dns_name: "control.dirextalk.test".to_owned(),
            },
            CertificatePurpose::ServerAuth,
            now_millis,
            300,
        )
        .expect("server certificate issued");

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.ca_certificate_der().to_vec()))
        .expect("test root is valid");
    let roots = Arc::new(roots);
    let server_verifier = WebPkiServerVerifier::builder(Arc::clone(&roots))
        .build()
        .expect("server verifier builds");
    let client_verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .expect("client verifier builds");
    let now = UnixTime::since_unix_epoch(Duration::from_millis(
        u64::try_from(now_millis).expect("positive fixture time"),
    ));
    let server_name = ServerName::try_from("control.dirextalk.test").expect("valid DNS name");
    let server_der = CertificateDer::from(server.certificate_der().to_vec());
    let client_der = CertificateDer::from(client.certificate_der().to_vec());

    server_verifier
        .verify_server_cert(&server_der, &[], &server_name, &[], now)
        .expect("server certificate chain, DNS name, time, and EKU are valid");
    client_verifier
        .verify_client_cert(&client_der, &[], now)
        .expect("client certificate chain, time, and EKU are valid");
    assert!(
        client_verifier
            .verify_client_cert(&server_der, &[], now)
            .is_err(),
        "a server-only leaf must fail client authentication"
    );
    assert!(
        server_verifier
            .verify_server_cert(&client_der, &[], &server_name, &[], now)
            .is_err(),
        "a client-only leaf must fail server authentication"
    );
}
