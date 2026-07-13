use std::{
    future::Future,
    io::Write,
    pin::pin,
    task::{Context, Poll, Waker},
};

use dtx_domain::{RequestId, SecretId, TenantId};
use dtx_security::{
    EncryptedDataKey, ExternalEffectPhase, FaultCheckpoint, FaultHook, FaultPoint, KeyManagement,
    KeyManagementError, KmsContext, KmsKeyVersion, SecretBytes,
};
use dtx_testkit::{
    ArtifactKind, CanaryLeak, CanaryRepresentation, CanaryScanner, CanaryWriter, FakeKms,
    FaultDisposition, KmsOperation, RequiredFaultPoint, ScriptedFaults,
};
use dtx_wire::StableCode;
use uuid::{Uuid, Variant};

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("security fake unexpectedly returned a pending future"),
    }
}

fn stable(value: &str) -> StableCode {
    StableCode::parse(value).expect("test stable code must be valid")
}

fn kms_version(value: &str) -> KmsKeyVersion {
    KmsKeyVersion::new(stable(value))
}

fn kms_context() -> KmsContext {
    KmsContext::new(TenantId::new(), SecretId::new(), stable("aws.bootstrap"))
}

fn secret(value: &[u8]) -> SecretBytes {
    SecretBytes::new(value.to_vec()).expect("test secret must satisfy the boundary")
}

#[test]
fn fake_kms_binds_an_opaque_uuidv7_handle_to_exact_context() {
    let material = b"kms-canary-material-00000000000001";
    let version = kms_version("kms.test_v1");
    let kms = FakeKms::new(version.clone(), [secret(material)]);
    let context = kms_context();

    let generated = ready(kms.generate_data_key(&context)).expect("generation must succeed");
    generated.plaintext.expose(|bytes| {
        assert_eq!(
            bytes, material,
            "the fake must return the injected material without deriving its own key"
        );
    });
    assert_eq!(generated.encrypted.key_version(), &version);
    let handle = Uuid::from_slice(generated.encrypted.opaque_bytes())
        .expect("the opaque fake handle must be a UUID");
    assert_eq!(handle.to_string(), "00000000-0000-7000-8000-000000000001");
    assert_eq!(handle.get_version_num(), 7);
    assert_eq!(handle.get_variant(), Variant::RFC4122);

    let decrypted = ready(kms.decrypt_data_key(&generated.encrypted, &context))
        .expect("the exact context must decrypt");
    decrypted.expose(|bytes| assert_eq!(bytes, material));

    let wrong_context = KmsContext::new(
        TenantId::new(),
        context.secret_id(),
        context.purpose().clone(),
    );
    assert!(matches!(
        ready(kms.decrypt_data_key(&generated.encrypted, &wrong_context)),
        Err(KeyManagementError::ContextMismatch)
    ));

    let tampered = EncryptedDataKey::new(version, vec![0x5a; 16]).expect("valid test handle");
    assert!(matches!(
        ready(kms.decrypt_data_key(&tampered, &context)),
        Err(KeyManagementError::InvalidCiphertext)
    ));
}

#[test]
fn fake_kms_failures_and_transcript_are_deterministic_and_redacted() {
    let material = b"do-not-print-this-kms-canary-00001";
    let kms = FakeKms::new(kms_version("kms.test_v1"), [secret(material)]);
    let context = kms_context();
    kms.fail_next(KmsOperation::GenerateDataKey, KeyManagementError::Throttled);

    assert!(matches!(
        ready(kms.generate_data_key(&context)),
        Err(KeyManagementError::Throttled)
    ));
    let generated = ready(kms.generate_data_key(&context)).expect("one-shot failure is consumed");
    let unknown_version = EncryptedDataKey::new(
        kms_version("kms.unknown_v1"),
        generated.encrypted.opaque_bytes().to_vec(),
    )
    .expect("valid test handle");
    assert!(matches!(
        ready(kms.decrypt_data_key(&unknown_version, &context)),
        Err(KeyManagementError::UnknownKeyVersion)
    ));

    let rendered = format!("{kms:?} {:?}", kms.calls());
    assert!(!rendered.contains(std::str::from_utf8(material).expect("ASCII fixture")));
    assert!(!rendered.contains(&hex_lower(material)));
    assert_eq!(kms.calls().len(), 3);
}

#[test]
fn canary_scanner_detects_raw_hex_and_base64_variants_without_echoing_values() {
    let raw = (0_u8..32)
        .map(|value| 0xf0 | (value % 16))
        .collect::<Vec<_>>();
    let scanner = CanaryScanner::new([(stable("aws.bootstrap"), secret(&raw))])
        .expect("32-byte canary must be accepted");
    let cases = [
        (raw.clone(), CanaryRepresentation::Raw),
        (
            b"f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".to_vec(),
            CanaryRepresentation::HexLower,
        ),
        (
            b"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF".to_vec(),
            CanaryRepresentation::HexUpper,
        ),
        (
            b"8PHy8/T19vf4+fr7/P3+//Dx8vP09fb3+Pn6+/z9/v8=".to_vec(),
            CanaryRepresentation::Base64StandardPadded,
        ),
        (
            b"8PHy8/T19vf4+fr7/P3+//Dx8vP09fb3+Pn6+/z9/v8".to_vec(),
            CanaryRepresentation::Base64StandardUnpadded,
        ),
        (
            b"8PHy8_T19vf4-fr7_P3-__Dx8vP09fb3-Pn6-_z9_v8=".to_vec(),
            CanaryRepresentation::Base64UrlPadded,
        ),
        (
            b"8PHy8_T19vf4-fr7_P3-__Dx8vP09fb3-Pn6-_z9_v8".to_vec(),
            CanaryRepresentation::Base64UrlUnpadded,
        ),
    ];

    for (encoded, expected) in cases {
        let leak = scanner
            .scan_bytes(ArtifactKind::Trace, &encoded)
            .expect_err("every supported representation must be detected");
        assert_eq!(leak.representation(), expected);
        assert_eq!(leak.artifact_kind(), ArtifactKind::Trace);
        let rendered = leak.to_string();
        assert!(!rendered.contains(String::from_utf8_lossy(&raw).as_ref()));
        assert!(!rendered.contains(&hex_lower(&raw)));
    }
}

#[test]
fn canary_writer_detects_a_secret_split_across_write_chunks() {
    let raw = b"0123456789abcdef0123456789abcdef";
    let scanner = CanaryScanner::new([(stable("session.credential"), secret(raw))])
        .expect("32-byte canary must be accepted");
    let mut writer = CanaryWriter::new(Vec::new(), &scanner, ArtifactKind::Log);

    writer
        .write_all(&raw[..11])
        .expect("a secret prefix alone is not a leak");
    let error = writer
        .write_all(&raw[11..])
        .expect_err("the completed cross-chunk canary must fail the write");
    assert!(
        !error
            .to_string()
            .contains(std::str::from_utf8(raw).expect("ASCII fixture"))
    );
    assert_eq!(
        writer.violation().map(CanaryLeak::representation),
        Some(CanaryRepresentation::Raw)
    );
    assert!(
        writer.flush().is_err(),
        "flush must remain fail-closed after a detected leak"
    );
    assert!(
        writer.finish().is_err(),
        "finish must remain fail-closed after a detected leak"
    );
}

#[test]
fn canary_writer_flushes_clean_content_on_finish() {
    let scanner = CanaryScanner::new([(
        stable("session.credential"),
        secret(b"0123456789abcdef0123456789abcdef"),
    )])
    .expect("32-byte canary must be accepted");
    let mut writer = CanaryWriter::new(Vec::new(), &scanner, ArtifactKind::Golden);
    writer
        .write_all(b"safe structured log")
        .expect("clean write");
    assert_eq!(
        writer.finish().expect("clean tail must flush"),
        b"safe structured log"
    );
}

fn checkpoint() -> FaultCheckpoint {
    FaultCheckpoint::new(
        FaultPoint::parse("aws.ensure_executor").expect("valid fault point"),
        ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        RequestId::new(),
        1,
    )
    .expect("positive attempt")
}

#[test]
fn scripted_fault_is_one_shot_and_requires_consumption() {
    let checkpoint = checkpoint();
    let faults = ScriptedFaults::new();
    faults
        .arm_once(checkpoint.clone())
        .expect("first plan is unique");
    assert!(faults.assert_consumed().is_err());

    let first = faults.checkpoint(&checkpoint);
    let second = faults.checkpoint(&checkpoint);
    assert_eq!(
        first
            .expect_err("the armed checkpoint must crash")
            .checkpoint(),
        &checkpoint
    );
    assert!(second.is_ok(), "the same plan must not fire twice");
    faults.assert_consumed().expect("the one-shot plan fired");
    assert_eq!(faults.transcript().len(), 2);
    assert_eq!(
        faults.transcript()[0].disposition(),
        FaultDisposition::CrashRequested
    );
    assert_eq!(
        faults.transcript()[1].disposition(),
        FaultDisposition::Continued
    );
}

#[test]
fn scripted_fault_is_one_shot_under_concurrency() {
    let checkpoint = checkpoint();
    let faults = std::sync::Arc::new(ScriptedFaults::new());
    faults
        .arm_once(checkpoint.clone())
        .expect("first plan is unique");
    let start = std::sync::Arc::new(std::sync::Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let faults = std::sync::Arc::clone(&faults);
        let checkpoint = checkpoint.clone();
        let start = std::sync::Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            start.wait();
            faults.checkpoint(&checkpoint).is_err()
        }));
    }
    start.wait();
    let crashes = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker must finish"))
        .filter(|crashed| *crashed)
        .count();

    assert_eq!(crashes, 1);
    faults.assert_consumed().expect("the one-shot plan fired");
    assert_eq!(
        faults
            .transcript()
            .iter()
            .filter(|entry| entry.disposition() == FaultDisposition::CrashRequested)
            .count(),
        1
    );
}

#[test]
fn required_fault_point_registry_maps_all_fourteen_unique_stable_names() {
    let expected_phases = [
        (
            RequiredFaultPoint::CommandBeforeTransactionCommit,
            ExternalEffectPhase::BeforeInvoke,
        ),
        (
            RequiredFaultPoint::ResourceIntentCommittedBeforeProviderInvoke,
            ExternalEffectPhase::BeforeInvoke,
        ),
        (
            RequiredFaultPoint::ProviderCommittedBeforeResponse,
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        ),
        (
            RequiredFaultPoint::ProviderResponseBeforeLedger,
            ExternalEffectPhase::AfterReturnBeforeReceipt,
        ),
        (
            RequiredFaultPoint::LedgerCommittedBeforeOutbox,
            ExternalEffectPhase::AfterReceiptBeforePublish,
        ),
        (
            RequiredFaultPoint::ConnectorToolExecutedBeforeCheckpoint,
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        ),
        (
            RequiredFaultPoint::LeaseExpiredBeforeStaleSubmission,
            ExternalEffectPhase::BeforeInvoke,
        ),
        (
            RequiredFaultPoint::ArtifactUploadedBeforeVerification,
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        ),
        (
            RequiredFaultPoint::ResultVerifiedBeforeEphemeralDestroy,
            ExternalEffectPhase::BeforeInvoke,
        ),
        (
            RequiredFaultPoint::TerminateSucceededBeforeTerminalObservation,
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        ),
        (
            RequiredFaultPoint::JobCompletedBeforePersistentHandoff,
            ExternalEffectPhase::AfterReceiptBeforePublish,
        ),
        (
            RequiredFaultPoint::ProviderAheadOfRecoveredControlPlane,
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        ),
        (
            RequiredFaultPoint::JanitorRunningWithControlPlaneOffline,
            ExternalEffectPhase::BeforeInvoke,
        ),
        (
            RequiredFaultPoint::ManagedServiceDeployFailedBeforeRollback,
            ExternalEffectPhase::BeforeInvoke,
        ),
    ];
    let names = RequiredFaultPoint::ALL
        .into_iter()
        .map(|point| point.as_str().to_owned())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(RequiredFaultPoint::ALL.len(), 14);
    assert_eq!(names.len(), 14);
    assert_eq!(
        expected_phases.map(|(point, _)| point),
        RequiredFaultPoint::ALL
    );

    for (point, expected_phase) in expected_phases {
        let checkpoint = point
            .checkpoint(RequestId::new(), 1)
            .expect("registry checkpoint has a positive attempt");
        assert_eq!(checkpoint.point().as_str(), point.as_str());
        assert_eq!(checkpoint.phase(), expected_phase);
    }
    assert!(
        RequiredFaultPoint::ProviderCommittedBeforeResponse
            .checkpoint(RequestId::new(), 0)
            .is_err()
    );
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    value
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}
