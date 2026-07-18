use dtx_agent_control::{
    ApplyConfigCommand, CloseStreamCommand, CloseStreamReason, CommandAck, CommandError,
    CommandLog, CommandLogSnapshot, CommandLogState, ConfigEntry, ConnectorCredential,
    ConnectorCredentialAuthorization, ConnectorCredentialAuthorizationError,
    ConnectorCredentialError, ConnectorCredentialPresentation, ConnectorCredentialStatus,
    CredentialHelloOutcome, CredentialRotationDisposition, CredentialRotationRequest,
    CredentialRotationTranscript, EnrollmentError, EnrollmentIntent, EnrollmentIntentSnapshotState,
    EnrollmentIntentState, EnrollmentRequest, EnrollmentRequestDisposition, EnrollmentToken,
    EnrollmentTranscript, ExactCommandBytes, MAX_COMMAND_BYTES, MAX_ENROLLMENT_TTL_MILLIS,
    MAX_RUNTIME_CAPABILITIES, MAX_RUNTIME_QUEUE_DEPTH, RotateCredentialCommand, RuntimeClaims,
    RuntimeClaimsError, RuntimeClaimsSnapshot, ServerCommandPayload, Sha256Digest,
    command_payload_digest, raw_sha256_digest,
};
use dtx_connect_registry::{AdapterKind, ConnectorDesiredState};
use dtx_domain::{
    ConnectorCredentialId, ConnectorId, Ed25519PublicKey, EnrollmentIntentId, HostId, RequestId,
    Revision, RunId, TenantId,
};
use ed25519_dalek::{Signer, SigningKey};

fn keys(seed: u8) -> (SigningKey, Ed25519PublicKey) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let public = Ed25519PublicKey::try_from(signing.verifying_key().to_bytes()).unwrap();
    (signing, public)
}

fn payload_digest(bytes: &[u8]) -> Sha256Digest {
    command_payload_digest(bytes).unwrap()
}

fn enrollment_request(
    intent: &EnrollmentIntent,
    control: &SigningKey,
    refresh: &SigningKey,
) -> EnrollmentRequest {
    let transcript = EnrollmentTranscript::new(
        intent.tenant_id(),
        intent.host_id(),
        intent.connector_id(),
        intent.generation(),
        intent.spec_revision(),
        intent.request_id(),
        intent.token_digest(),
        Ed25519PublicKey::try_from(control.verifying_key().to_bytes()).unwrap(),
        Ed25519PublicKey::try_from(refresh.verifying_key().to_bytes()).unwrap(),
    )
    .unwrap();
    let bytes = transcript.signing_bytes();
    EnrollmentRequest::new(
        transcript,
        control.sign(&bytes).to_bytes(),
        refresh.sign(&bytes).to_bytes(),
    )
}

fn credential_for(request: &EnrollmentRequest, id: ConnectorCredentialId) -> ConnectorCredential {
    ConnectorCredential::new(
        id,
        request.transcript().tenant_id(),
        request.transcript().connector_id(),
        request.transcript().generation(),
        Revision::INITIAL,
        request.transcript().control_key(),
        request.transcript().refresh_key(),
        raw_sha256_digest(&[0x30, 0x01, 0x02]),
        vec![vec![0x30, 0x01, 0x02]],
        100,
        10_000,
    )
    .unwrap()
}

#[test]
fn certificate_only_reissue_keeps_the_connector_fence_and_retires_the_expired_credential() {
    let token = EnrollmentToken::from_bytes([7; 32]);
    let mut intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        100,
        300_000,
        &token,
    )
    .unwrap();
    let (control, _) = keys(21);
    let (refresh, _) = keys(22);
    let request = enrollment_request(&intent, &control, &refresh);
    let current = intent
        .consume(
            &token,
            &request,
            credential_for(&request, ConnectorCredentialId::new()),
            200,
        )
        .unwrap();
    let (_, replacement_control) = keys(23);
    let replacement = ConnectorCredential::new(
        ConnectorCredentialId::new(),
        current.tenant_id(),
        current.connector_id(),
        current.generation(),
        current.revision(),
        replacement_control,
        current.refresh_key(),
        raw_sha256_digest(&[0x30, 0x01, 0x03]),
        vec![vec![0x30, 0x01, 0x03]],
        10_000,
        20_000,
    )
    .unwrap();
    let mut authorization = ConnectorCredentialAuthorization::new(current.clone()).unwrap();
    authorization.propose_reissue(replacement.clone()).unwrap();
    assert_eq!(
        authorization.current().unwrap().generation(),
        replacement.generation()
    );
    assert_eq!(
        authorization.current().unwrap().revision(),
        replacement.revision()
    );
    assert_eq!(
        authorization.status(current.credential_id()),
        Some(ConnectorCredentialStatus::Current)
    );
    assert_eq!(
        authorization.status(replacement.credential_id()),
        Some(ConnectorCredentialStatus::Pending)
    );
    let outcome = authorization
        .accept_hello(
            ConnectorCredentialPresentation::new(
                replacement.tenant_id(),
                replacement.connector_id(),
                replacement.credential_id(),
                replacement.generation(),
                replacement.certificate_fingerprint(),
            ),
            11_000,
        )
        .unwrap();
    assert!(matches!(outcome, CredentialHelloOutcome::Promoted { .. }));
    assert_eq!(
        authorization.status(current.credential_id()),
        Some(ConnectorCredentialStatus::Retired)
    );
    assert_eq!(
        authorization.status(replacement.credential_id()),
        Some(ConnectorCredentialStatus::Current)
    );
}

#[test]
fn enrollment_is_one_time_exactly_replayable_and_changed_replay_conflicts() {
    let token = EnrollmentToken::from_bytes([7; 32]);
    let mut intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        100,
        300_000,
        &token,
    )
    .unwrap();
    let (control, _) = keys(11);
    let (refresh, _) = keys(12);
    let request = enrollment_request(&intent, &control, &refresh);
    let credential = credential_for(&request, ConnectorCredentialId::new());

    assert_eq!(
        intent.evaluate_request(&token, &request, 200),
        Ok(EnrollmentRequestDisposition::IssueCredential)
    );

    let first = intent
        .consume(&token, &request, credential.clone(), 200)
        .unwrap();
    let retry = intent
        .consume(
            &token,
            &request,
            credential_for(&request, ConnectorCredentialId::new()),
            999_999,
        )
        .unwrap();
    assert_eq!(first, retry);
    assert_eq!(
        intent.evaluate_request(&token, &request, 999_999),
        Ok(EnrollmentRequestDisposition::Replay(first.clone()))
    );
    assert_eq!(intent.state(), EnrollmentIntentState::Consumed);

    let (changed_refresh, _) = keys(13);
    let changed = enrollment_request(&intent, &control, &changed_refresh);
    assert_eq!(
        intent.consume(&token, &changed, credential, 201),
        Err(EnrollmentError::IdempotencyConflict)
    );
}

#[test]
fn enrollment_creation_retry_is_bound_to_operation_connector_token_and_lifetime() {
    let tenant_id = TenantId::new();
    let host_id = HostId::new();
    let connector_id = ConnectorId::new();
    let request_id = RequestId::new();
    let token = EnrollmentToken::from_bytes([0x71; 32]);
    let intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        tenant_id,
        host_id,
        connector_id,
        1,
        Revision::INITIAL,
        request_id,
        100,
        300_000,
        &token,
    )
    .unwrap();

    assert!(intent.matches_creation_request(tenant_id, connector_id, request_id, 300_000, &token,));
    assert!(!intent.matches_creation_request(
        tenant_id,
        ConnectorId::new(),
        request_id,
        300_000,
        &token,
    ));
    assert!(
        !intent.matches_creation_request(tenant_id, connector_id, request_id, 299_999, &token,)
    );
    assert!(!intent.matches_creation_request(
        tenant_id,
        connector_id,
        request_id,
        300_000,
        &EnrollmentToken::from_bytes([0x72; 32]),
    ));
}

#[test]
fn enrollment_expiry_revocation_and_proof_fail_closed() {
    let token = EnrollmentToken::from_bytes([8; 32]);
    let mut intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        100,
        MAX_ENROLLMENT_TTL_MILLIS,
        &token,
    )
    .unwrap();
    let (control, _) = keys(21);
    let (refresh, _) = keys(22);
    let mut request = enrollment_request(&intent, &control, &refresh);
    request = EnrollmentRequest::new(
        request.transcript().clone(),
        [0; 64],
        refresh
            .sign(&request.transcript().signing_bytes())
            .to_bytes(),
    );
    let credential = credential_for(&request, ConnectorCredentialId::new());
    assert_eq!(
        intent.consume(&token, &request, credential, 101),
        Err(EnrollmentError::InvalidProof)
    );
    intent.revoke(102).unwrap();
    assert_eq!(intent.state(), EnrollmentIntentState::Revoked);

    let too_long = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        100,
        MAX_ENROLLMENT_TTL_MILLIS + 1,
        &token,
    );
    assert!(matches!(too_long, Err(EnrollmentError::InvalidLifetime)));
}

#[test]
fn enrollment_snapshot_rejects_incoherent_state() {
    let token = EnrollmentToken::from_bytes([9; 32]);
    let intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        0,
        1_000,
        &token,
    )
    .unwrap();
    let mut snapshot = intent.snapshot();
    snapshot.expires_at_millis = snapshot.created_at_millis;
    assert!(EnrollmentIntent::try_from_snapshot(snapshot).is_err());
}

#[test]
fn enrollment_expiration_is_terminal_and_snapshot_safe() {
    let token = EnrollmentToken::from_bytes([91; 32]);
    let mut intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        100,
        500,
        &token,
    )
    .unwrap();
    assert_eq!(intent.state_at(599), EnrollmentIntentState::Open);
    assert_eq!(intent.state_at(600), EnrollmentIntentState::Expired);
    assert_eq!(intent.revoke(600), Err(EnrollmentError::Expired));
    intent.expire(600).unwrap();
    assert_eq!(intent.state(), EnrollmentIntentState::Expired);
    assert_eq!(intent.expire(999), Ok(()));

    let restored = EnrollmentIntent::try_from_snapshot(intent.snapshot()).unwrap();
    assert_eq!(restored.state(), EnrollmentIntentState::Expired);
}

#[test]
fn enrollment_snapshot_authenticates_the_exact_public_result_digest() {
    let token = EnrollmentToken::from_bytes([92; 32]);
    let mut intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        100,
        500,
        &token,
    )
    .unwrap();
    let (control, _) = keys(93);
    let (refresh, _) = keys(94);
    let request = enrollment_request(&intent, &control, &refresh);
    let credential = credential_for(&request, ConnectorCredentialId::new());
    intent.consume(&token, &request, credential, 200).unwrap();
    let mut snapshot = intent.snapshot();
    if let EnrollmentIntentSnapshotState::Consumed { result_digest, .. } = &mut snapshot.state {
        *result_digest = Sha256Digest::from_bytes([0; 32]);
    } else {
        panic!("consumed intent must persist its result digest");
    }
    assert_eq!(
        EnrollmentIntent::try_from_snapshot(snapshot),
        Err(EnrollmentError::InvalidSnapshot)
    );
}

#[test]
fn credential_rotation_has_one_exact_successor_and_no_resurrection() {
    let token = EnrollmentToken::from_bytes([10; 32]);
    let intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        0,
        1_000,
        &token,
    )
    .unwrap();
    let (control, _) = keys(31);
    let (refresh, _) = keys(32);
    let request = enrollment_request(&intent, &control, &refresh);
    let current = credential_for(&request, ConnectorCredentialId::new());
    let mut authorization = ConnectorCredentialAuthorization::new(current.clone()).unwrap();

    let (successor_control, successor_public) = keys(33);
    let successor_id = ConnectorCredentialId::new();
    let transcript = CredentialRotationTranscript::new(
        current.tenant_id(),
        current.connector_id(),
        RequestId::new(),
        current.credential_id(),
        current.generation(),
        1,
        Sha256Digest::from_bytes([43; 32]),
        Revision::new(4).unwrap(),
        [44; 32],
        successor_public,
    )
    .unwrap();
    let signing_bytes = transcript.signing_bytes();
    let rotation = CredentialRotationRequest::new(
        transcript,
        refresh.sign(&signing_bytes).to_bytes(),
        successor_control.sign(&signing_bytes).to_bytes(),
    );
    let successor = ConnectorCredential::new(
        successor_id,
        current.tenant_id(),
        current.connector_id(),
        2,
        Revision::new(4).unwrap(),
        successor_public,
        current.refresh_key(),
        raw_sha256_digest(&[1, 2, 3]),
        vec![vec![1, 2, 3]],
        200,
        20_000,
    )
    .unwrap();

    assert_eq!(
        authorization.evaluate_rotation_request(&rotation),
        Ok(CredentialRotationDisposition::IssueSuccessor)
    );

    let issued = authorization
        .propose_successor(&rotation, successor.clone())
        .unwrap();
    assert_eq!(issued, successor);
    assert_eq!(
        authorization.evaluate_rotation_request(&rotation),
        Ok(CredentialRotationDisposition::Replay(successor.clone()))
    );
    let mut tampered = authorization.snapshot();
    tampered.rotations[0].result_digest = Sha256Digest::from_bytes([0; 32]);
    assert_eq!(
        ConnectorCredentialAuthorization::try_from_snapshot(tampered),
        Err(ConnectorCredentialAuthorizationError::InvalidSnapshot)
    );
    assert_eq!(
        authorization
            .propose_successor(&rotation, successor.clone())
            .unwrap(),
        successor
    );
    authorization.promote_successor(successor_id).unwrap();
    assert_eq!(
        authorization.status(current.credential_id()),
        Some(ConnectorCredentialStatus::Retired)
    );
    assert_eq!(
        authorization.status(successor_id),
        Some(ConnectorCredentialStatus::Current)
    );
    assert_eq!(
        authorization.propose_successor(&rotation, successor),
        Ok(authorization.current().unwrap().clone())
    );
    authorization.revoke().unwrap();
    assert_eq!(
        authorization.promote_successor(current.credential_id()),
        Err(ConnectorCredentialAuthorizationError::Revoked)
    );
}

#[test]
fn credential_rotation_revision_must_strictly_advance() {
    let token = EnrollmentToken::from_bytes([14; 32]);
    let intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        0,
        1_000,
        &token,
    )
    .unwrap();
    let (control, _) = keys(34);
    let (refresh, _) = keys(35);
    let enrollment = enrollment_request(&intent, &control, &refresh);
    let enrolled = credential_for(&enrollment, ConnectorCredentialId::new());
    let current = ConnectorCredential::new(
        enrolled.credential_id(),
        enrolled.tenant_id(),
        enrolled.connector_id(),
        2,
        Revision::new(4).unwrap(),
        enrolled.control_key(),
        enrolled.refresh_key(),
        raw_sha256_digest(&[0x30, 0x01, 0x02]),
        vec![vec![0x30, 0x01, 0x02]],
        100,
        10_000,
    )
    .unwrap();
    let authorization = ConnectorCredentialAuthorization::new(current.clone()).unwrap();
    let (successor_control, successor_public) = keys(36);

    for revision in [Revision::new(4).unwrap(), Revision::new(3).unwrap()] {
        let transcript = CredentialRotationTranscript::new(
            current.tenant_id(),
            current.connector_id(),
            RequestId::new(),
            current.credential_id(),
            current.generation(),
            1,
            Sha256Digest::from_bytes([45; 32]),
            revision,
            [u8::try_from(revision.get()).unwrap(); 32],
            successor_public,
        )
        .unwrap();
        let signing_bytes = transcript.signing_bytes();
        let rotation = CredentialRotationRequest::new(
            transcript,
            refresh.sign(&signing_bytes).to_bytes(),
            successor_control.sign(&signing_bytes).to_bytes(),
        );
        assert_eq!(
            authorization.evaluate_rotation_request(&rotation),
            Err(ConnectorCredentialAuthorizationError::InvalidSuccessor)
        );
    }
}

#[test]
fn credential_snapshot_rejects_duplicate_history_identity() {
    let token = EnrollmentToken::from_bytes([11; 32]);
    let intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        0,
        1_000,
        &token,
    )
    .unwrap();
    let (control, _) = keys(41);
    let (refresh, _) = keys(42);
    let request = enrollment_request(&intent, &control, &refresh);
    let current = credential_for(&request, ConnectorCredentialId::new());
    let authorization = ConnectorCredentialAuthorization::new(current).unwrap();
    let mut snapshot = authorization.snapshot();
    snapshot.history.push(snapshot.history[0].clone());
    assert!(ConnectorCredentialAuthorization::try_from_snapshot(snapshot).is_err());
}

#[test]
#[allow(clippy::too_many_lines)]
fn only_the_exact_pending_successor_hello_promotes_and_retires_current() {
    let token = EnrollmentToken::from_bytes([51; 32]);
    let intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        0,
        1_000,
        &token,
    )
    .unwrap();
    let (control, _) = keys(52);
    let (refresh, _) = keys(53);
    let request = enrollment_request(&intent, &control, &refresh);
    let current = credential_for(&request, ConnectorCredentialId::new());
    let current_id = current.credential_id();
    let mut authorization = ConnectorCredentialAuthorization::new(current.clone()).unwrap();

    let (successor_control, successor_key) = keys(54);
    let transcript = CredentialRotationTranscript::new(
        current.tenant_id(),
        current.connector_id(),
        RequestId::new(),
        current_id,
        1,
        1,
        Sha256Digest::from_bytes([55; 32]),
        Revision::new(2).unwrap(),
        [56; 32],
        successor_key,
    )
    .unwrap();
    let bytes = transcript.signing_bytes();
    let rotation = CredentialRotationRequest::new(
        transcript,
        refresh.sign(&bytes).to_bytes(),
        successor_control.sign(&bytes).to_bytes(),
    );
    let successor = ConnectorCredential::new(
        ConnectorCredentialId::new(),
        current.tenant_id(),
        current.connector_id(),
        2,
        Revision::new(2).unwrap(),
        successor_key,
        current.refresh_key(),
        raw_sha256_digest(&[1, 2, 3]),
        vec![vec![1, 2, 3]],
        200,
        20_000,
    )
    .unwrap();
    let successor_id = successor.credential_id();
    authorization
        .propose_successor(&rotation, successor.clone())
        .unwrap();

    let wrong_tenant = ConnectorCredentialPresentation::new(
        TenantId::new(),
        successor.connector_id(),
        successor_id,
        2,
        successor.certificate_fingerprint(),
    );
    assert_eq!(
        authorization.accept_hello(wrong_tenant, 300),
        Err(ConnectorCredentialAuthorizationError::WrongTenant)
    );
    assert_eq!(
        authorization.status(successor_id),
        Some(ConnectorCredentialStatus::Pending)
    );

    let presentation = ConnectorCredentialPresentation::new(
        successor.tenant_id(),
        successor.connector_id(),
        successor_id,
        2,
        successor.certificate_fingerprint(),
    );
    assert_eq!(
        authorization.authorize_transport(presentation, 300),
        Ok(ConnectorCredentialStatus::Pending)
    );
    assert_eq!(
        authorization.accept_hello(presentation, 300),
        Ok(CredentialHelloOutcome::Promoted {
            retired_credential_id: current_id,
            credential_id: successor_id,
            generation: 2,
        })
    );
    assert_eq!(
        authorization.accept_hello(presentation, 301),
        Ok(CredentialHelloOutcome::Current {
            credential_id: successor_id,
            generation: 2,
        })
    );
    let old = ConnectorCredentialPresentation::new(
        current.tenant_id(),
        current.connector_id(),
        current_id,
        1,
        current.certificate_fingerprint(),
    );
    assert_eq!(
        authorization.authorize_transport(old, 301),
        Err(ConnectorCredentialAuthorizationError::Retired)
    );
    let restored =
        ConnectorCredentialAuthorization::try_from_snapshot(authorization.snapshot()).unwrap();
    assert_eq!(restored.current().unwrap(), &successor);
}

#[test]
fn changed_rotation_retry_conflicts_and_revocation_has_no_resurrection() {
    let token = EnrollmentToken::from_bytes([61; 32]);
    let intent = EnrollmentIntent::new(
        EnrollmentIntentId::new(),
        TenantId::new(),
        HostId::new(),
        ConnectorId::new(),
        1,
        Revision::INITIAL,
        RequestId::new(),
        0,
        1_000,
        &token,
    )
    .unwrap();
    let (control, _) = keys(62);
    let (refresh, _) = keys(63);
    let request = enrollment_request(&intent, &control, &refresh);
    let current = credential_for(&request, ConnectorCredentialId::new());
    let mut authorization = ConnectorCredentialAuthorization::new(current.clone()).unwrap();
    let operation_id = RequestId::new();

    let (successor_signing, successor_key) = keys(64);
    let transcript = CredentialRotationTranscript::new(
        current.tenant_id(),
        current.connector_id(),
        operation_id,
        current.credential_id(),
        1,
        1,
        Sha256Digest::from_bytes([65; 32]),
        Revision::new(2).unwrap(),
        [66; 32],
        successor_key,
    )
    .unwrap();
    let bytes = transcript.signing_bytes();
    let rotation = CredentialRotationRequest::new(
        transcript,
        refresh.sign(&bytes).to_bytes(),
        successor_signing.sign(&bytes).to_bytes(),
    );
    let successor = ConnectorCredential::new(
        ConnectorCredentialId::new(),
        current.tenant_id(),
        current.connector_id(),
        2,
        Revision::new(2).unwrap(),
        successor_key,
        current.refresh_key(),
        raw_sha256_digest(&[4, 5, 6]),
        vec![vec![4, 5, 6]],
        100,
        10_000,
    )
    .unwrap();
    authorization
        .propose_successor(&rotation, successor.clone())
        .unwrap();

    let (changed_signing, changed_key) = keys(68);
    let changed_transcript = CredentialRotationTranscript::new(
        current.tenant_id(),
        current.connector_id(),
        operation_id,
        current.credential_id(),
        1,
        1,
        Sha256Digest::from_bytes([65; 32]),
        Revision::new(2).unwrap(),
        [66; 32],
        changed_key,
    )
    .unwrap();
    let changed_bytes = changed_transcript.signing_bytes();
    let changed = CredentialRotationRequest::new(
        changed_transcript,
        refresh.sign(&changed_bytes).to_bytes(),
        changed_signing.sign(&changed_bytes).to_bytes(),
    );
    assert_eq!(
        authorization.propose_successor(&changed, successor.clone()),
        Err(ConnectorCredentialAuthorizationError::IdempotencyConflict)
    );

    authorization.revoke().unwrap();
    let restored =
        ConnectorCredentialAuthorization::try_from_snapshot(authorization.snapshot()).unwrap();
    assert_eq!(restored.current(), None);
    assert_eq!(restored.pending(), None);
    assert_eq!(
        restored.status(successor.credential_id()),
        Some(ConnectorCredentialStatus::Revoked)
    );
    assert_eq!(
        authorization.propose_successor(&rotation, successor),
        Err(ConnectorCredentialAuthorizationError::Revoked)
    );
}

#[test]
fn runtime_claims_are_bounded_canonical_untrusted_facts() {
    let run = RunId::new();
    let claims = RuntimeClaims::new(
        AdapterKind::Codex,
        "1.2.3".to_owned(),
        Sha256Digest::from_bytes([7; 32]),
        3,
        vec![run],
        None,
        vec!["tools.read".to_owned(), "multi_session".to_owned()],
    )
    .unwrap();
    assert_eq!(claims.active_run_ids(), &[run]);
    assert_eq!(claims.capabilities(), &["multi_session", "tools.read"]);

    let duplicate = RuntimeClaims::new(
        AdapterKind::Codex,
        "1".to_owned(),
        Sha256Digest::from_bytes([7; 32]),
        0,
        Vec::new(),
        None,
        vec!["same".to_owned(), "same".to_owned()],
    );
    assert_eq!(duplicate, Err(RuntimeClaimsError::DuplicateCapability));
}

#[test]
fn runtime_claim_snapshot_rejects_noncanonical_order() {
    let snapshot = RuntimeClaimsSnapshot {
        adapter_kind: AdapterKind::Eino,
        runtime_version: "1".to_owned(),
        adapter_build_digest: Sha256Digest::from_bytes([1; 32]),
        queue_depth: 0,
        active_run_ids: Vec::new(),
        stable_error_code: None,
        capabilities: vec!["z".to_owned(), "a".to_owned()],
    };
    assert_eq!(
        RuntimeClaims::try_from_snapshot(snapshot),
        Err(RuntimeClaimsError::NonCanonicalOrder)
    );
}

#[test]
fn runtime_claim_limits_and_active_run_identity_fail_closed() {
    let run = RunId::new();
    assert_eq!(
        RuntimeClaims::new(
            AdapterKind::Rig,
            "1.0".to_owned(),
            Sha256Digest::from_bytes([2; 32]),
            0,
            vec![run, run],
            None,
            Vec::new(),
        ),
        Err(RuntimeClaimsError::DuplicateActiveRun)
    );
    assert_eq!(
        RuntimeClaims::new(
            AdapterKind::Rig,
            "1.0".to_owned(),
            Sha256Digest::from_bytes([2; 32]),
            0,
            Vec::new(),
            Some("secret text".to_owned()),
            Vec::new(),
        ),
        Err(RuntimeClaimsError::InvalidErrorCode)
    );
    let too_many = (0..=MAX_RUNTIME_CAPABILITIES)
        .map(|index| format!("capability.{index}"))
        .collect();
    assert_eq!(
        RuntimeClaims::new(
            AdapterKind::Rig,
            "1.0".to_owned(),
            Sha256Digest::from_bytes([2; 32]),
            0,
            Vec::new(),
            None,
            too_many,
        ),
        Err(RuntimeClaimsError::TooManyCapabilities)
    );
}

#[test]
fn runtime_claim_wire_bounds_accept_utf8_and_reject_controls_or_queue_overflow() {
    let claims = RuntimeClaims::new(
        AdapterKind::Codex,
        "版本-1".to_owned(),
        Sha256Digest::from_bytes([3; 32]),
        MAX_RUNTIME_QUEUE_DEPTH,
        Vec::new(),
        Some("RUNTIME_BUSY".to_owned()),
        vec!["chat.streaming".to_owned()],
    )
    .unwrap();
    assert_eq!(claims.runtime_version(), "版本-1");
    assert_eq!(claims.stable_error_code(), Some("RUNTIME_BUSY"));
    assert_eq!(
        RuntimeClaims::new(
            AdapterKind::Codex,
            "bad\u{0085}version".to_owned(),
            Sha256Digest::from_bytes([3; 32]),
            0,
            Vec::new(),
            None,
            Vec::new(),
        ),
        Err(RuntimeClaimsError::InvalidRuntimeVersion)
    );
    assert_eq!(
        RuntimeClaims::new(
            AdapterKind::Codex,
            "1".to_owned(),
            Sha256Digest::from_bytes([3; 32]),
            MAX_RUNTIME_QUEUE_DEPTH + 1,
            Vec::new(),
            None,
            Vec::new(),
        ),
        Err(RuntimeClaimsError::InvalidQueueDepth)
    );
}

#[test]
fn credential_chain_is_leaf_first_bounded_and_fingerprint_authenticated() {
    let (_, control) = keys(81);
    let (_, refresh) = keys(82);
    let base = || {
        ConnectorCredential::new(
            ConnectorCredentialId::new(),
            TenantId::new(),
            ConnectorId::new(),
            1,
            Revision::INITIAL,
            control,
            refresh,
            raw_sha256_digest(&[1, 2, 3]),
            vec![vec![1, 2, 3]],
            0,
            1_000,
        )
    };
    assert!(base().is_ok());
    assert_eq!(
        ConnectorCredential::new(
            ConnectorCredentialId::new(),
            TenantId::new(),
            ConnectorId::new(),
            1,
            Revision::INITIAL,
            control,
            refresh,
            Sha256Digest::from_bytes([0; 32]),
            vec![vec![1, 2, 3]],
            0,
            1_000,
        ),
        Err(ConnectorCredentialError::InvalidCertificateFingerprint)
    );
    assert_eq!(
        ConnectorCredential::new(
            ConnectorCredentialId::new(),
            TenantId::new(),
            ConnectorId::new(),
            1,
            Revision::INITIAL,
            control,
            refresh,
            raw_sha256_digest(&[1]),
            vec![vec![1], vec![2], vec![3], vec![4], vec![5]],
            0,
            1_000,
        ),
        Err(ConnectorCredentialError::InvalidCertificateChain)
    );
}

#[test]
fn command_log_acks_only_contiguous_exact_commands_and_resumes_bytes() {
    let tenant = TenantId::new();
    let connector = ConnectorId::new();
    let mut log = CommandLog::new(tenant, connector, 3, Revision::new(7).unwrap()).unwrap();
    let first_bytes = ExactCommandBytes::new(vec![1, 2, 3]).unwrap();
    let first = log
        .append(
            3,
            Revision::new(7).unwrap(),
            RequestId::new(),
            ServerCommandPayload::CloseStream(dtx_agent_control::CloseStreamCommand::reconnect()),
            payload_digest(&[1]),
            first_bytes.clone(),
        )
        .unwrap()
        .clone();
    let second = log
        .append(
            3,
            Revision::new(7).unwrap(),
            RequestId::new(),
            ServerCommandPayload::ApplyConfig(
                ApplyConfigCommand::new(
                    Revision::new(8).unwrap(),
                    ConnectorDesiredState::Draining,
                    vec![ConfigEntry::new("profile".to_owned(), "safe".to_owned()).unwrap()],
                    Vec::new(),
                )
                .unwrap(),
            ),
            payload_digest(&[2]),
            ExactCommandBytes::new(vec![4, 5]).unwrap(),
        )
        .unwrap()
        .clone();

    assert_eq!(
        log.acknowledge(CommandAck::new(
            second.sequence(),
            second.payload_digest(),
            second.encoded_command_digest(),
            3,
            Revision::new(7).unwrap(),
        )),
        Err(CommandError::AckGap)
    );
    log.acknowledge(CommandAck::new(
        first.sequence(),
        first.payload_digest(),
        first.encoded_command_digest(),
        3,
        Revision::new(7).unwrap(),
    ))
    .unwrap();
    let replay = log.resume(1, 3, Revision::new(7).unwrap()).unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].exact_bytes(), second.exact_bytes());
    assert_eq!(first.exact_bytes(), &first_bytes);
}

#[test]
fn command_operation_exact_retry_is_stable_and_changed_retry_conflicts() {
    let mut log =
        CommandLog::new(TenantId::new(), ConnectorId::new(), 1, Revision::INITIAL).unwrap();
    let operation = RequestId::new();
    let payload =
        ServerCommandPayload::CloseStream(dtx_agent_control::CloseStreamCommand::reconnect());
    let first = log
        .append(
            1,
            Revision::INITIAL,
            operation,
            payload.clone(),
            payload_digest(&[7]),
            ExactCommandBytes::new(vec![7]).unwrap(),
        )
        .unwrap()
        .clone();
    let retry = log
        .append(
            1,
            Revision::INITIAL,
            operation,
            payload,
            payload_digest(&[7]),
            ExactCommandBytes::new(vec![7]).unwrap(),
        )
        .unwrap();
    assert_eq!(retry.sequence(), first.sequence());
    assert_eq!(
        log.append(
            1,
            Revision::INITIAL,
            operation,
            ServerCommandPayload::CloseStream(dtx_agent_control::CloseStreamCommand::reconnect(),),
            payload_digest(&[7]),
            ExactCommandBytes::new(vec![8]).unwrap(),
        ),
        Err(CommandError::IdempotencyConflict)
    );
}

#[test]
fn fence_advancing_command_is_a_barrier_but_owner_revoke_can_supersede_it() {
    let mut log =
        CommandLog::new(TenantId::new(), ConnectorId::new(), 1, Revision::INITIAL).unwrap();
    log.append(
        1,
        Revision::INITIAL,
        RequestId::new(),
        ServerCommandPayload::ApplyConfig(
            ApplyConfigCommand::new(
                Revision::new(2).unwrap(),
                ConnectorDesiredState::Draining,
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
        ),
        payload_digest(&[1]),
        ExactCommandBytes::new(vec![1]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        log.append(
            1,
            Revision::INITIAL,
            RequestId::new(),
            ServerCommandPayload::CloseStream(CloseStreamCommand::reconnect()),
            payload_digest(&[2]),
            ExactCommandBytes::new(vec![2]).unwrap(),
        ),
        Err(CommandError::UnacknowledgedCommands)
    );
    log.append(
        1,
        Revision::INITIAL,
        RequestId::new(),
        ServerCommandPayload::CloseStream(CloseStreamCommand::revoked()),
        payload_digest(&[3]),
        ExactCommandBytes::new(vec![3]).unwrap(),
    )
    .unwrap();
    log.finalize_revoke_fence(1, Revision::INITIAL, 1, Revision::new(2).unwrap())
        .unwrap();
    assert_eq!(log.spec_revision(), Revision::new(2).unwrap());
    assert!(CommandLog::try_from_snapshot(log.snapshot()).is_ok());
}

#[test]
fn terminal_revoke_can_supersede_a_full_unacknowledged_backlog() {
    let mut log =
        CommandLog::new(TenantId::new(), ConnectorId::new(), 1, Revision::INITIAL).unwrap();
    for _ in 0..4_096 {
        log.append(
            1,
            Revision::INITIAL,
            RequestId::new(),
            ServerCommandPayload::CloseStream(CloseStreamCommand::reconnect()),
            payload_digest(&[1]),
            ExactCommandBytes::new(vec![1]).unwrap(),
        )
        .unwrap();
    }

    log.append(
        1,
        Revision::INITIAL,
        RequestId::new(),
        ServerCommandPayload::CloseStream(CloseStreamCommand::revoked()),
        payload_digest(&[2]),
        ExactCommandBytes::new(vec![2]).unwrap(),
    )
    .unwrap();
    log.finalize_revoke_fence(1, Revision::INITIAL, 1, Revision::new(2).unwrap())
        .unwrap();

    assert_eq!(log.commands().len(), 4_097);
    assert!(CommandLog::try_from_snapshot(log.snapshot()).is_ok());
}

#[test]
fn command_snapshot_rejects_digest_or_sequence_tampering() {
    let mut log =
        CommandLog::new(TenantId::new(), ConnectorId::new(), 1, Revision::INITIAL).unwrap();
    log.append(
        1,
        Revision::INITIAL,
        RequestId::new(),
        ServerCommandPayload::CloseStream(dtx_agent_control::CloseStreamCommand::reconnect()),
        payload_digest(&[1]),
        ExactCommandBytes::new(vec![1]).unwrap(),
    )
    .unwrap();
    let mut snapshot: CommandLogSnapshot = log.snapshot();
    snapshot.commands[0].encoded_command_digest = Sha256Digest::from_bytes([0; 32]);
    assert!(CommandLog::try_from_snapshot(snapshot).is_err());
}

#[test]
fn command_wire_digests_and_closed_payload_limits_match_agent_control_v1() {
    let bytes = ExactCommandBytes::new(vec![1, 2, 3]).unwrap();
    assert_ne!(payload_digest(&[1, 2, 3]), bytes.encoded_command_digest());
    assert!(ExactCommandBytes::new(vec![0; MAX_COMMAND_BYTES]).is_ok());
    assert_eq!(
        ExactCommandBytes::new(vec![0; MAX_COMMAND_BYTES + 1]),
        Err(CommandError::InvalidCommandBytes)
    );

    let config = ApplyConfigCommand::new(
        Revision::INITIAL,
        ConnectorDesiredState::Running,
        vec![
            ConfigEntry::new("profile".to_owned(), "safe".to_owned()).unwrap(),
            ConfigEntry::new("model".to_owned(), "agent-v1".to_owned()).unwrap(),
        ],
        Vec::new(),
    )
    .unwrap();
    assert_eq!(config.adapter_config()[0].key(), "model");
    assert!(!format!("{:?}", config.adapter_config()[0]).contains("agent-v1"));
    assert_eq!(
        ConfigEntry::new("api-key".to_owned(), "public".to_owned()),
        Err(CommandError::InvalidConfigEntry),
    );
    assert_eq!(
        ConfigEntry::new("profile".to_owned(), "sk-test-secret-canary".to_owned()),
        Err(CommandError::InvalidConfigEntry),
    );
    assert_eq!(
        ConfigEntry::new("profile".to_owned(), "my-opaque-token-123".to_owned()),
        Err(CommandError::InvalidConfigEntry),
    );
    assert_eq!(
        ApplyConfigCommand::new(
            Revision::INITIAL,
            ConnectorDesiredState::Running,
            vec![
                ConfigEntry::new("profile".to_owned(), "safe".to_owned()).unwrap(),
                ConfigEntry::new("profile".to_owned(), "default".to_owned()).unwrap(),
            ],
            Vec::new(),
        ),
        Err(CommandError::InvalidConfigEntry)
    );
    assert_eq!(
        CloseStreamCommand::drained().reason(),
        CloseStreamReason::Drained
    );
    assert_eq!(
        CloseStreamCommand::new(
            CloseStreamReason::Reconnect,
            "bad-code".to_owned(),
            String::new(),
        ),
        Err(CommandError::InvalidCloseStreamMetadata)
    );
}

#[test]
fn command_cursor_replays_uncommitted_ack_and_rejects_stale_fences_without_mutation() {
    let mut log =
        CommandLog::new(TenantId::new(), ConnectorId::new(), 1, Revision::INITIAL).unwrap();
    let command = log
        .append(
            1,
            Revision::INITIAL,
            RequestId::new(),
            ServerCommandPayload::CloseStream(CloseStreamCommand::reconnect()),
            payload_digest(&[19]),
            ExactCommandBytes::new(vec![1, 9]).unwrap(),
        )
        .unwrap()
        .clone();
    assert_eq!(
        log.append(
            2,
            Revision::INITIAL,
            RequestId::new(),
            ServerCommandPayload::CloseStream(CloseStreamCommand::reconnect()),
            payload_digest(&[2]),
            ExactCommandBytes::new(vec![2]).unwrap(),
        ),
        Err(CommandError::StaleFence)
    );
    assert_eq!(log.commands().len(), 1);
    assert_eq!(
        log.acknowledge(CommandAck::new(
            1,
            Sha256Digest::from_bytes([0; 32]),
            command.encoded_command_digest(),
            1,
            Revision::INITIAL,
        )),
        Err(CommandError::DigestMismatch)
    );
    assert_eq!(log.acknowledged_sequence(), 0);

    // The Connector may be ahead because its exact ACK was lost. The server
    // still replays from its own committed cursor instead of trusting Hello.
    assert_eq!(
        log.resume(1, 1, Revision::INITIAL).unwrap()[0].exact_bytes(),
        command.exact_bytes()
    );
    assert_eq!(
        log.advance_fence(1, Revision::INITIAL, 1, Revision::new(2).unwrap()),
        Err(CommandError::UnacknowledgedCommands)
    );
    log.acknowledge(CommandAck::new(
        1,
        command.payload_digest(),
        command.encoded_command_digest(),
        1,
        Revision::INITIAL,
    ))
    .unwrap();
    log.acknowledge(CommandAck::new(
        1,
        command.payload_digest(),
        command.encoded_command_digest(),
        1,
        Revision::INITIAL,
    ))
    .unwrap();
    assert_eq!(
        log.resume(0, 1, Revision::INITIAL),
        Err(CommandError::StaleCursor)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn drain_stop_rotate_and_revoke_commands_survive_rehydration() {
    let mut log =
        CommandLog::new(TenantId::new(), ConnectorId::new(), 1, Revision::INITIAL).unwrap();
    let drain = log
        .append(
            1,
            Revision::INITIAL,
            RequestId::new(),
            ServerCommandPayload::ApplyConfig(
                ApplyConfigCommand::new(
                    Revision::new(2).unwrap(),
                    ConnectorDesiredState::Draining,
                    vec![ConfigEntry::new("profile".to_owned(), "safe".to_owned()).unwrap()],
                    Vec::new(),
                )
                .unwrap(),
            ),
            payload_digest(&[71]),
            ExactCommandBytes::new(vec![71]).unwrap(),
        )
        .unwrap()
        .clone();
    log.acknowledge(CommandAck::new(
        drain.sequence(),
        drain.payload_digest(),
        drain.encoded_command_digest(),
        1,
        Revision::INITIAL,
    ))
    .unwrap();
    log.advance_fence(1, Revision::INITIAL, 1, Revision::new(2).unwrap())
        .unwrap();

    let stop = log
        .append(
            1,
            Revision::new(2).unwrap(),
            RequestId::new(),
            ServerCommandPayload::ApplyConfig(
                ApplyConfigCommand::new(
                    Revision::new(3).unwrap(),
                    ConnectorDesiredState::Stopped,
                    Vec::new(),
                    vec![ConfigEntry::new("shutdown".to_owned(), "graceful".to_owned()).unwrap()],
                )
                .unwrap(),
            ),
            payload_digest(&[72]),
            ExactCommandBytes::new(vec![72]).unwrap(),
        )
        .unwrap()
        .clone();
    log.acknowledge(CommandAck::new(
        stop.sequence(),
        stop.payload_digest(),
        stop.encoded_command_digest(),
        1,
        Revision::new(2).unwrap(),
    ))
    .unwrap();
    log.advance_fence(1, Revision::new(2).unwrap(), 1, Revision::new(3).unwrap())
        .unwrap();
    let rotate = log
        .append(
            1,
            Revision::new(3).unwrap(),
            RequestId::new(),
            ServerCommandPayload::RotateCredential(
                RotateCredentialCommand::new([73; 32], Revision::new(4).unwrap(), 10_000).unwrap(),
            ),
            payload_digest(&[73]),
            ExactCommandBytes::new(vec![73]).unwrap(),
        )
        .unwrap()
        .clone();
    log.acknowledge(CommandAck::new(
        rotate.sequence(),
        rotate.payload_digest(),
        rotate.encoded_command_digest(),
        1,
        Revision::new(3).unwrap(),
    ))
    .unwrap();
    log.advance_fence(1, Revision::new(3).unwrap(), 2, Revision::new(4).unwrap())
        .unwrap();
    log.append(
        2,
        Revision::new(4).unwrap(),
        RequestId::new(),
        ServerCommandPayload::CloseStream(CloseStreamCommand::revoked()),
        payload_digest(&[74]),
        ExactCommandBytes::new(vec![74]).unwrap(),
    )
    .unwrap();
    log.revoke().unwrap();

    let restored = CommandLog::try_from_snapshot(log.snapshot()).unwrap();
    assert_eq!(restored.state(), CommandLogState::Revoked);
    assert_eq!(restored.commands().len(), 4);
    assert!(matches!(
        restored.commands()[0].payload(),
        ServerCommandPayload::ApplyConfig(command)
            if command.desired_state() == ConnectorDesiredState::Draining
    ));
    assert!(matches!(
        restored.commands()[1].payload(),
        ServerCommandPayload::ApplyConfig(command)
            if command.desired_state() == ConnectorDesiredState::Stopped
    ));
    assert!(matches!(
        restored.commands()[2].payload(),
        ServerCommandPayload::RotateCredential(_)
    ));
    assert!(matches!(
        restored.commands()[3].payload(),
        ServerCommandPayload::CloseStream(command)
            if command.reason() == dtx_agent_control::CloseStreamReason::Revoked
    ));
}
