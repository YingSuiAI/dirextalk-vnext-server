use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    str::FromStr,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dtx_domain::{
    HostCredentialId, HostId, JobId, JobResourceId, RequestId, Revision, RunId, TenantId, WorkerId,
};
use dtx_security::{
    CertificateFingerprint, CrashRequested, ExternalEffectPhase, FaultCheckpoint, FaultHook,
    FaultPoint, HostClientCertVerifier, HostCredentialAuthorizer, HostCredentialBinding,
    HostWorkloadIdentity, SecretBytes, TlsClientIdentity, build_host_mtls_server_config,
};
use dtx_testkit::{
    AgentRuntimeError, AgentRuntimeOutput, CancelRun, CertificateAuthorizationError,
    CertificatePurpose, DestroyEphemeralGroupRequest, EnsureExecutorRequest, FakeAgentRuntime,
    FakeAgentWorld, FakeAwsError, FakeAwsProvider, FakeAwsWorld, IssuedTestCertificate,
    ObserveExecutorRequest, ResourceLifecycle, ScriptedAgentOutput, ScriptedFaults, StartRun,
    TestCertificateAuthority, TestCertificateError, WorkloadIdentity,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
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
            .identity_uri()
            .starts_with(dtx_security::WORKLOAD_URI_PREFIX)
    );

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
    let now_millis = 1_800_000_000_000;
    let ca = TestCertificateAuthority::new(now_millis).expect("CA created");
    let identity = WorkloadIdentity::Host {
        tenant_id: tenant("01890f00-0000-7000-8000-000000000051"),
        host_id: host("01890f00-0000-7000-8000-000000000052"),
    };

    assert!(matches!(
        ca.issue(&identity, CertificatePurpose::ClientAuth, now_millis, 901),
        Err(TestCertificateError::LifetimeTooLong)
    ));
    assert_eq!(
        ca.issue(
            &identity,
            CertificatePurpose::ClientAuth,
            now_millis + 30 * 24 * 60 * 60 * 1_000,
            300,
        )
        .expect_err("a leaf cannot outlive its CA"),
        TestCertificateError::InvalidTime
    );
    assert!(matches!(
        TestCertificateAuthority::new(i64::MIN),
        Err(TestCertificateError::InvalidTime)
    ));
    assert!(matches!(
        ca.issue(
            &WorkloadIdentity::ControlServer {
                dns_name: "CONTROL.dirextalk.test".to_owned(),
            },
            CertificatePurpose::ServerAuth,
            now_millis,
            300,
        ),
        Err(TestCertificateError::InvalidIdentity)
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

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete Host certificate rejection matrix in one trust-boundary test.
fn production_host_verifier_requires_chain_eku_one_uri_san_and_registered_binding() {
    let now_millis = 1_800_000_000_000_i64;
    let tenant_id = tenant("01890f00-0000-7000-8000-000000000071");
    let host_id = host("01890f00-0000-7000-8000-000000000072");
    let credential_id = HostCredentialId::from_str("01890f00-0000-7000-8000-000000000073")
        .expect("valid credential fixture");
    let host_identity = HostWorkloadIdentity::new(tenant_id, host_id);
    let workload = WorkloadIdentity::from(host_identity);
    let ca = TestCertificateAuthority::new(now_millis).expect("CA created");
    let certificate = ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("Host client certificate issued");
    let binding = HostCredentialBinding::new(
        host_identity,
        credential_id,
        certificate.certificate_fingerprint(),
        u64::try_from(certificate.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(certificate.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("valid binding");
    let authorizer =
        Arc::new(HostCredentialAuthorizer::new_initial([binding]).expect("binding snapshot"));
    let roots = test_roots(&ca);
    let verifier = HostClientCertVerifier::new(Arc::clone(&roots), Arc::clone(&authorizer))
        .expect("Host verifier builds");
    let now = UnixTime::since_unix_epoch(Duration::from_millis(
        u64::try_from(now_millis).expect("positive fixture time"),
    ));
    let certificate_der = CertificateDer::from(certificate.certificate_der().to_vec());

    verifier
        .verify_client_cert(&certificate_der, &[], now)
        .expect("registered Host client certificate is valid");

    let wrong_host_binding = HostCredentialBinding::new(
        HostWorkloadIdentity::new(tenant_id, HostId::new()),
        credential_id,
        certificate.certificate_fingerprint(),
        u64::try_from(certificate.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(certificate.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("valid wrong-host binding");
    let wrong_host_verifier = HostClientCertVerifier::new(
        Arc::clone(&roots),
        Arc::new(
            HostCredentialAuthorizer::new_initial([wrong_host_binding])
                .expect("wrong-host snapshot"),
        ),
    )
    .expect("Host verifier builds");
    assert!(
        wrong_host_verifier
            .verify_client_cert(&certificate_der, &[], now)
            .is_err(),
        "the fingerprint cannot move to another Host identity"
    );

    let tenant_mismatch = HostCredentialBinding::new(
        HostWorkloadIdentity::new(tenant("01890f00-0000-7000-8000-000000000076"), host_id),
        credential_id,
        certificate.certificate_fingerprint(),
        u64::try_from(certificate.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(certificate.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("valid wrong-tenant binding");
    let tenant_mismatch_verifier = HostClientCertVerifier::new(
        Arc::clone(&roots),
        Arc::new(
            HostCredentialAuthorizer::new_initial([tenant_mismatch])
                .expect("wrong-tenant binding snapshot"),
        ),
    )
    .expect("Host verifier builds");
    assert!(
        tenant_mismatch_verifier
            .verify_client_cert(&certificate_der, &[], now)
            .is_err(),
        "the fingerprint cannot move to another tenant"
    );

    let expired_instant = UnixTime::since_unix_epoch(Duration::from_millis(
        u64::try_from(certificate.not_after_millis() + 1_000)
            .expect("positive expired fixture time"),
    ));
    assert!(
        verifier
            .verify_client_cert(&certificate_der, &[], expired_instant)
            .is_err(),
        "an expired Host certificate is rejected"
    );

    let connector = ca
        .issue(
            &WorkloadIdentity::Connector {
                tenant_id,
                connector_id: dtx_domain::ConnectorId::from_str(
                    "01890f00-0000-7000-8000-000000000074",
                )
                .expect("valid connector fixture"),
            },
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("Connector certificate issued");
    let connector_binding = HostCredentialBinding::new(
        host_identity,
        credential_id,
        connector.certificate_fingerprint(),
        u64::try_from(connector.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(connector.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("synthetic impersonation binding");
    let connector_verifier = HostClientCertVerifier::new(
        Arc::clone(&roots),
        Arc::new(
            HostCredentialAuthorizer::new_initial([connector_binding]).expect("binding snapshot"),
        ),
    )
    .expect("Host verifier builds");
    assert!(
        connector_verifier
            .verify_client_cert(
                &CertificateDer::from(connector.certificate_der().to_vec()),
                &[],
                now,
            )
            .is_err(),
        "a Connector URI can never impersonate a Host"
    );

    let unrestricted = ca
        .issue_without_extended_key_usage_for_test(
            &workload,
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("Host certificate without EKU issued");
    let unrestricted_binding = HostCredentialBinding::new(
        host_identity,
        credential_id,
        unrestricted.certificate_fingerprint(),
        u64::try_from(unrestricted.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(unrestricted.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("unrestricted binding");
    let unrestricted_verifier = HostClientCertVerifier::new(
        Arc::clone(&roots),
        Arc::new(
            HostCredentialAuthorizer::new_initial([unrestricted_binding])
                .expect("unrestricted binding snapshot"),
        ),
    )
    .expect("Host verifier builds");
    assert!(
        unrestricted_verifier
            .verify_client_cert(
                &CertificateDer::from(unrestricted.certificate_der().to_vec()),
                &[],
                now,
            )
            .is_err(),
        "a Host client must carry an explicit clientAuth EKU"
    );

    let server_only = ca
        .issue(&workload, CertificatePurpose::ServerAuth, now_millis, 300)
        .expect("Host server-only certificate issued");
    let server_only_binding = HostCredentialBinding::new(
        host_identity,
        credential_id,
        server_only.certificate_fingerprint(),
        u64::try_from(server_only.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(server_only.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("server-only binding");
    let server_only_verifier = HostClientCertVerifier::new(
        Arc::clone(&roots),
        Arc::new(
            HostCredentialAuthorizer::new_initial([server_only_binding]).expect("binding snapshot"),
        ),
    )
    .expect("Host verifier builds");
    assert!(
        server_only_verifier
            .verify_client_cert(
                &CertificateDer::from(server_only.certificate_der().to_vec()),
                &[],
                now,
            )
            .is_err(),
        "serverAuth EKU cannot authenticate a Host client"
    );

    let extra_san = ca
        .issue_with_additional_uri_san_for_test(
            &workload,
            CertificatePurpose::ClientAuth,
            "spiffe://dirextalk.internal/v1/tenants/01890f00-0000-7000-8000-000000000071/hosts/01890f00-0000-7000-8000-000000000075",
            now_millis,
            300,
        )
        .expect("malformed multi-SAN certificate issued");
    let extra_san_binding = HostCredentialBinding::new(
        host_identity,
        credential_id,
        extra_san.certificate_fingerprint(),
        u64::try_from(extra_san.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(extra_san.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("extra-SAN binding");
    let extra_san_verifier = HostClientCertVerifier::new(
        roots,
        Arc::new(
            HostCredentialAuthorizer::new_initial([extra_san_binding]).expect("binding snapshot"),
        ),
    )
    .expect("Host verifier builds");
    assert!(
        extra_san_verifier
            .verify_client_cert(
                &CertificateDer::from(extra_san.certificate_der().to_vec()),
                &[],
                now,
            )
            .is_err(),
        "Host certificates require exactly one URI SAN and no additional SANs"
    );

    let unknown = HostClientCertVerifier::new(
        test_roots(&ca),
        Arc::new(HostCredentialAuthorizer::new_initial([]).expect("empty snapshot")),
    )
    .expect("Host verifier builds");
    assert!(
        unknown
            .verify_client_cert(&certificate_der, &[], now)
            .is_err(),
        "an unregistered fingerprint is rejected"
    );

    let revoked_binding = HostCredentialBinding::new(
        host_identity,
        credential_id,
        certificate.certificate_fingerprint(),
        u64::try_from(certificate.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(certificate.not_after_millis() / 1_000).expect("positive fixture"),
        Some(u64::try_from(now_millis / 1_000).expect("positive fixture")),
    )
    .expect("revoked binding");
    let revoked = HostClientCertVerifier::new(
        test_roots(&ca),
        Arc::new(
            HostCredentialAuthorizer::new_initial([revoked_binding]).expect("binding snapshot"),
        ),
    )
    .expect("Host verifier builds");
    assert!(
        revoked
            .verify_client_cert(&certificate_der, &[], now)
            .is_err(),
        "application revocation is enforced during the TLS handshake"
    );

    let rogue_ca = TestCertificateAuthority::new(now_millis).expect("rogue CA created");
    let rogue_certificate = rogue_ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("rogue certificate issued");
    let rogue_binding = HostCredentialBinding::new(
        host_identity,
        credential_id,
        rogue_certificate.certificate_fingerprint(),
        u64::try_from(rogue_certificate.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(rogue_certificate.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("rogue binding");
    let untrusted = HostClientCertVerifier::new(
        test_roots(&ca),
        Arc::new(HostCredentialAuthorizer::new_initial([rogue_binding]).expect("binding snapshot")),
    )
    .expect("Host verifier builds");
    assert!(
        untrusted
            .verify_client_cert(
                &CertificateDer::from(rogue_certificate.certificate_der().to_vec()),
                &[],
                now,
            )
            .is_err(),
        "a fingerprint binding cannot bypass the configured CA roots"
    );

    let replacement = ca
        .issue(&workload, CertificatePurpose::ClientAuth, now_millis, 300)
        .expect("replacement Host client certificate issued");
    let replacement_binding = HostCredentialBinding::new(
        host_identity,
        HostCredentialId::from_str("01890f00-0000-7000-8000-000000000077")
            .expect("valid replacement credential fixture"),
        replacement.certificate_fingerprint(),
        u64::try_from(replacement.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(replacement.not_after_millis() / 1_000).expect("positive fixture"),
        None,
    )
    .expect("replacement credential binding");
    authorizer
        .replace(Revision::INITIAL, [replacement_binding])
        .expect("current credential snapshot rotates atomically");
    assert!(
        verifier
            .verify_client_cert(&certificate_der, &[], now)
            .is_err(),
        "the same verifier rejects the rotated-out Host credential"
    );
    verifier
        .verify_client_cert(
            &CertificateDer::from(replacement.certificate_der().to_vec()),
            &[],
            now,
        )
        .expect("the same verifier accepts the replacement current credential");
    let replacement_revoked = HostCredentialBinding::new(
        host_identity,
        HostCredentialId::from_str("01890f00-0000-7000-8000-000000000077")
            .expect("valid replacement credential fixture"),
        replacement.certificate_fingerprint(),
        u64::try_from(replacement.not_before_millis() / 1_000).expect("positive fixture"),
        u64::try_from(replacement.not_after_millis() / 1_000).expect("positive fixture"),
        Some(u64::try_from(now_millis / 1_000).expect("positive fixture")),
    )
    .expect("revoked replacement credential binding");
    authorizer
        .replace(
            Revision::new(2).expect("authorization revision two"),
            [replacement_revoked],
        )
        .expect("current credential revocation publishes atomically");
    assert!(
        verifier
            .verify_client_cert(
                &CertificateDer::from(replacement.certificate_der().to_vec()),
                &[],
                now,
            )
            .is_err(),
        "the same verifier observes current credential revocation"
    );

    assert_eq!(
        certificate.certificate_fingerprint(),
        CertificateFingerprint::from_certificate_der(certificate.certificate_der())
    );
}

fn test_roots(ca: &TestCertificateAuthority) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.ca_certificate_der().to_vec()))
        .expect("test root is valid");
    Arc::new(roots)
}

#[test]
fn tls_client_identity_consumes_a_secret_key_and_returns_redacted_configuration_errors() {
    let now_millis = 1_800_000_000_000_i64;
    let ca = TestCertificateAuthority::new(now_millis).expect("CA created");
    let certificate = ca
        .issue(
            &WorkloadIdentity::Host {
                tenant_id: tenant("01890f00-0000-7000-8000-000000000081"),
                host_id: host("01890f00-0000-7000-8000-000000000082"),
            },
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("Host certificate issued");
    certificate
        .into_tls_client_identity()
        .expect("issued fixture has a valid identity boundary")
        .into_client_config(test_roots(&ca))
        .expect("valid PKCS#8 key configures rustls");

    let key_canary = b"dirextalk-private-key-canary".to_vec();
    let invalid = TlsClientIdentity::new_pkcs8(
        vec![vec![1, 2, 3]],
        SecretBytes::new(key_canary.clone()).expect("bounded secret fixture"),
    )
    .expect("non-empty identity boundary");
    let error = invalid
        .into_client_config(test_roots(&ca))
        .expect_err("invalid private key is rejected");
    assert!(!format!("{error:?}").contains("dirextalk-private-key-canary"));
    assert!(!format!("{error}").contains("dirextalk-private-key-canary"));

    let certificate_canary = b"dirextalk-certificate-canary".to_vec();
    let verifier = HostClientCertVerifier::new(
        test_roots(&ca),
        Arc::new(HostCredentialAuthorizer::new_initial([]).expect("empty Host snapshot")),
    )
    .expect("Host verifier builds");
    let Err(server_error) = build_host_mtls_server_config(
        verifier,
        vec![certificate_canary.clone()],
        SecretBytes::new(key_canary.clone()).expect("bounded key canary"),
    ) else {
        panic!("invalid server identity must fail without logging secret material");
    };
    for rendered in [format!("{server_error:?}"), format!("{server_error}")] {
        assert!(!rendered.contains("dirextalk-private-key-canary"));
        assert!(!rendered.contains("dirextalk-certificate-canary"));
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the four real handshake outcomes in one ordered credential lifecycle.
fn loopback_rustls_mtls_enforces_live_host_identity_and_credential_state() {
    let now_millis = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_millis(),
    )
    .expect("current time fits the certificate fixture boundary");
    let now_seconds = u64::try_from(now_millis / 1_000).expect("current time is positive");
    let ca = TestCertificateAuthority::new(now_millis).expect("loopback CA created");
    let tenant_id = tenant("01890f00-0000-7000-8000-000000000091");
    let host_id = host("01890f00-0000-7000-8000-000000000092");
    let host_identity = HostWorkloadIdentity::new(tenant_id, host_id);
    let host_workload = WorkloadIdentity::from(host_identity);

    let host_certificate = ca
        .issue(
            &host_workload,
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("Host client certificate issued");
    let host_credential_id = HostCredentialId::from_str("01890f00-0000-7000-8000-000000000093")
        .expect("valid Host credential fixture");
    let active_host =
        loopback_host_binding(&host_certificate, host_identity, host_credential_id, None);
    let revoked_host = loopback_host_binding(
        &host_certificate,
        host_identity,
        host_credential_id,
        Some(now_seconds),
    );
    let authorizer = Arc::new(
        HostCredentialAuthorizer::new_initial([active_host])
            .expect("current Host credential snapshot"),
    );

    let control_server = ca
        .issue(
            &WorkloadIdentity::ControlServer {
                dns_name: "control.dirextalk.test".to_owned(),
            },
            CertificatePurpose::ServerAuth,
            now_millis,
            300,
        )
        .expect("control server certificate issued");
    let server_config = loopback_server_config(&ca, &control_server, Arc::clone(&authorizer))
        .expect("redacted loopback server configuration");
    let host_client =
        loopback_client_config(&ca, host_certificate).expect("redacted Host client configuration");
    assert_eq!(
        loopback_mtls_exchange(Arc::clone(&server_config), Arc::clone(&host_client)),
        (true, true),
        "a current Host exchanges application bytes over mTLS"
    );

    let connector_certificate = ca
        .issue(
            &WorkloadIdentity::Connector {
                tenant_id,
                connector_id: dtx_domain::ConnectorId::from_str(
                    "01890f00-0000-7000-8000-000000000094",
                )
                .expect("valid Connector fixture"),
            },
            CertificatePurpose::ClientAuth,
            now_millis,
            300,
        )
        .expect("Connector client certificate issued");
    let synthetic_connector_binding = loopback_host_binding(
        &connector_certificate,
        host_identity,
        HostCredentialId::from_str("01890f00-0000-7000-8000-000000000095")
            .expect("valid synthetic credential fixture"),
        None,
    );
    let synthetic_authorizer = Arc::new(
        HostCredentialAuthorizer::new_initial([synthetic_connector_binding])
            .expect("synthetic current snapshot publishes"),
    );
    let synthetic_server_config =
        loopback_server_config(&ca, &control_server, synthetic_authorizer)
            .expect("synthetic Connector rejection server builds");
    let connector_client = loopback_client_config(&ca, connector_certificate)
        .expect("redacted Connector client configuration");
    assert_eq!(
        loopback_mtls_exchange(synthetic_server_config, connector_client),
        (false, false),
        "a Connector identity cannot complete a Host mTLS handshake"
    );

    authorizer
        .replace(Revision::INITIAL, [revoked_host])
        .expect("Host revocation publishes");
    assert_eq!(
        loopback_mtls_exchange(Arc::clone(&server_config), host_client),
        (false, false),
        "an already configured Host client is rejected after live revocation"
    );

    let server_auth_client = ca
        .issue(
            &host_workload,
            CertificatePurpose::ServerAuth,
            now_millis,
            300,
        )
        .expect("serverAuth-only Host certificate issued");
    let server_auth_binding = loopback_host_binding(
        &server_auth_client,
        host_identity,
        HostCredentialId::from_str("01890f00-0000-7000-8000-000000000096")
            .expect("valid serverAuth credential fixture"),
        None,
    );
    let server_auth_authorizer = Arc::new(
        HostCredentialAuthorizer::new_initial([server_auth_binding])
            .expect("serverAuth synthetic current snapshot publishes"),
    );
    let server_auth_server_config =
        loopback_server_config(&ca, &control_server, server_auth_authorizer)
            .expect("serverAuth rejection server builds");
    let server_auth_client = loopback_client_config(&ca, server_auth_client)
        .expect("redacted serverAuth client configuration");
    assert_eq!(
        loopback_mtls_exchange(server_auth_server_config, server_auth_client),
        (false, false),
        "a serverAuth-only leaf cannot complete a client-auth handshake"
    );
}

fn loopback_host_binding(
    certificate: &IssuedTestCertificate,
    identity: HostWorkloadIdentity,
    credential_id: HostCredentialId,
    revoked_at_unix_seconds: Option<u64>,
) -> HostCredentialBinding {
    HostCredentialBinding::new(
        identity,
        credential_id,
        certificate.certificate_fingerprint(),
        u64::try_from(certificate.not_before_millis() / 1_000)
            .expect("fixture not-before is positive"),
        u64::try_from(certificate.not_after_millis() / 1_000)
            .expect("fixture not-after is positive"),
        revoked_at_unix_seconds,
    )
    .expect("valid loopback Host credential binding")
}

fn loopback_server_config(
    ca: &TestCertificateAuthority,
    certificate: &IssuedTestCertificate,
    authorizer: Arc<HostCredentialAuthorizer>,
) -> Result<Arc<ServerConfig>, ()> {
    let verifier = HostClientCertVerifier::new(test_roots(ca), authorizer).map_err(|_| ())?;
    let mut configured = None;
    certificate.expose_private_key(|private_key_der| {
        configured = Some(
            SecretBytes::new(private_key_der.to_vec())
                .map_err(|_| ())
                .and_then(|private_key| {
                    build_host_mtls_server_config(
                        verifier,
                        vec![certificate.certificate_der().to_vec()],
                        private_key,
                    )
                    .map_err(|_| ())
                })
                .map(Arc::new),
        );
    });
    configured.ok_or(())?
}

fn loopback_client_config(
    ca: &TestCertificateAuthority,
    certificate: IssuedTestCertificate,
) -> Result<Arc<ClientConfig>, ()> {
    certificate
        .into_tls_client_identity()
        .map_err(|_| ())?
        .into_client_config(test_roots(ca))
        .map(Arc::new)
        .map_err(|_| ())
}

fn loopback_mtls_exchange(
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
) -> (bool, bool) {
    const REQUEST: &[u8; 4] = b"ping";
    const RESPONSE: &[u8; 4] = b"pong";
    const IO_TIMEOUT: Duration = Duration::from_secs(3);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("loopback listener binds without secret context");
    let address = listener
        .local_addr()
        .expect("loopback listener has a local address");
    let server = thread::spawn(move || {
        let Ok((socket, _peer)) = listener.accept() else {
            return false;
        };
        if !configure_loopback_timeout(&socket, IO_TIMEOUT) {
            return false;
        }
        let Ok(connection) = ServerConnection::new(server_config) else {
            return false;
        };
        let mut tls = StreamOwned::new(connection, socket);
        let mut request = [0_u8; REQUEST.len()];
        if tls.read_exact(&mut request).is_err() || request != *REQUEST {
            return false;
        }
        tls.write_all(RESPONSE).is_ok() && tls.flush().is_ok()
    });

    let client_succeeded = (|| {
        let Ok(socket) = TcpStream::connect(address) else {
            return false;
        };
        if !configure_loopback_timeout(&socket, IO_TIMEOUT) {
            return false;
        }
        let Ok(connection) = ClientConnection::new(
            client_config,
            ServerName::try_from("control.dirextalk.test").expect("static canonical server name"),
        ) else {
            return false;
        };
        let mut tls = StreamOwned::new(connection, socket);
        let mut response = [0_u8; RESPONSE.len()];
        tls.write_all(REQUEST).is_ok()
            && tls.flush().is_ok()
            && tls.read_exact(&mut response).is_ok()
            && response == *RESPONSE
    })();
    let server_succeeded = server.join().unwrap_or(false);
    (client_succeeded, server_succeeded)
}

fn configure_loopback_timeout(socket: &TcpStream, timeout: Duration) -> bool {
    socket.set_read_timeout(Some(timeout)).is_ok()
        && socket.set_write_timeout(Some(timeout)).is_ok()
}
