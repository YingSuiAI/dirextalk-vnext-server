#![allow(unused_imports, dead_code)]

#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
pub(crate) mod support;

pub(crate) use std::{
    error::Error,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
pub(crate) use base64ct::{Base64UrlUnpadded, Encoding};
pub(crate) use dtx_domain::{
    Clock, ClockError, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId, EnvelopeId,
    IdentityId, MailboxId,
};
pub(crate) use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IDENTITY_LOG_WIRE_VERSION,
    IdentityLogEventPayloadV1, IdentityLogEventV1, KeyAcceptancePurposeV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input, key_rotation_acceptance_input,
    recovery_rotation_authorization_input,
};
pub(crate) use dtx_identity_persistence::{
    CreateHistoryRecoveryRequestCommand, DEVICE_SESSION_SECRET_HASH_DOMAIN,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentRepository,
    DeviceSessionCompletionCommand, DeviceSessionCredential, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogRepository, IdentityPgStore, device_session_proof_input,
    history_recovery_request_signature_input, history_recovery_request_unsigned_canonical_bytes,
};
pub(crate) use dtx_mailbox::{
    AttachmentCapability, AttachmentCreate, AttachmentError, AttachmentManifest,
    AttachmentRepository, AttachmentStatus, MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS,
    MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, MAX_ACTIVE_ENVELOPE_BYTES, MAX_OPAQUE_CIPHERTEXT_BYTES,
    MailboxPersistenceError, MailboxPgStore, MailboxRegistrationCommand, MailboxRepository,
};
pub(crate) use dtx_mailbox_node::{
    ACCOUNT_READ_CURSOR_QUERY_V1_CONTENT_TYPE, ACCOUNT_READ_CURSOR_QUERY_V1_PATH,
    ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE, ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
    DEVICE_HISTORY_GRANT_RECEIPT_V2_CONTENT_TYPE, DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
    DEVICE_HISTORY_GRANT_V1_PATH, DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
    DEVICE_HISTORY_GRANT_V2_PATH, DEVICE_SESSION_AUTHORIZATION_SCHEME,
    IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE, IDENTITY_MAILBOX_ACK_V2_PATH,
    IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE, IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
    IDENTITY_MAILBOX_PULL_V3_PATH, MAILBOX_ACK_CONTENT_TYPE, MAILBOX_ACK_PATH_TEMPLATE,
    MAILBOX_ACK_RECEIPT_CONTENT_TYPE, MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME,
    MAILBOX_ENQUEUE_PATH_TEMPLATE, MAILBOX_ENVELOPE_CONTENT_TYPE,
    MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE, MAILBOX_PULL_CONTENT_TYPE, MAILBOX_PULL_PATH_TEMPLATE,
    MAILBOX_PULL_RECEIPT_CONTENT_TYPE, MAILBOX_REGISTER_CONTENT_TYPE,
    MAILBOX_REGISTER_PATH_TEMPLATE, MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE, MailboxNodeState,
    mailbox_router_with_state,
};
pub(crate) use dtx_realtime_sync::{
    HEARTBEAT_INTERVAL_MILLIS, InvalidationKind, LEASE_TTL_MILLIS, OUTBOX_CLAIM_TTL_MILLIS,
    RealtimeSyncError, RealtimeSyncStore, ReplayPage,
};
pub(crate) use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
pub(crate) use ed25519_dalek::{Signer, SigningKey};
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
pub(crate) use tower::ServiceExt;
pub(crate) use uuid::Uuid;

pub(crate) const AUDIENCE: &str = "https://mailbox.test";
pub(crate) const NOW: i64 = 2_000;
pub(crate) const EXPIRY: i64 = 600_000;

pub(crate) struct RecoveredDevice {
    pub(crate) active: ActiveDevice,
    pub(crate) request_id: DeviceEnrollmentChallengeId,
    pub(crate) request_digest: Sha256Digest,
    pub(crate) approved_head: IdentityLogHead,
    pub(crate) recipient_package_digest: Sha256Digest,
}

pub(crate) struct ActiveDevice {
    pub(crate) root: SigningKey,
    pub(crate) recovery: SigningKey,
    pub(crate) identity_id: IdentityId,
    pub(crate) device_id: DeviceId,
    pub(crate) session_id: DeviceSessionId,
    pub(crate) session_secret: [u8; 32],
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn enroll_history_recovery_device(
    store: &IdentityPgStore,
    owner: &ActiveDevice,
    observed_head: IdentityLogHead,
    candidate_seed: u8,
    encryption_seed: u8,
    session_secret: [u8; 32],
    capability_bytes: [u8; 32],
    request_expires_at: i64,
) -> Result<RecoveredDevice, Box<dyn Error>> {
    let candidate = SigningKey::from_bytes(&[candidate_seed; 32]);
    let candidate_public = public_key(&candidate)?;
    let recipient_key = DeviceEncryptionPublicKey::try_from([encryption_seed; 32])?;
    let candidate_device_id = DeviceId::new();
    let request_id = DeviceEnrollmentChallengeId::new();
    let issued_at = UtcMillis::new(NOW + 1)?;
    let expires_at = UtcMillis::new(request_expires_at)?;
    let unsigned = history_recovery_request_unsigned_canonical_bytes(
        request_id,
        owner.identity_id,
        candidate_device_id,
        candidate_public,
        recipient_key,
        observed_head,
        issued_at,
        expires_at,
    )?;
    let candidate_signature = signature(
        &candidate,
        &history_recovery_request_signature_input(&unsigned),
    );
    let CanonicalValue::Map(mut request_fields) = decode_deterministic_cbor(&unsigned)? else {
        return Err("history recovery unsigned request is not a map".into());
    };
    request_fields.push((
        CanonicalValue::Unsigned(12),
        candidate_signature.to_canonical_value(),
    ));
    let exact_request = encode_deterministic_cbor(&CanonicalValue::Map(request_fields))?;
    let request = CreateHistoryRecoveryRequestCommand::new(
        Sha256Digest::hash_domain(
            b"test-history-recovery-request\0",
            request_id.to_string().as_bytes(),
        ),
        request_id,
        owner.identity_id,
        candidate_device_id,
        candidate_public,
        recipient_key,
        observed_head,
        issued_at,
        expires_at,
        DeviceEnrollmentCapability::new(capability_bytes)?,
        candidate_signature,
        exact_request,
    )?;
    let request_digest = request.request_digest();
    let created = DeviceEnrollmentRepository
        .create_history_recovery_request(store, request, issued_at)
        .await?;
    assert_eq!(created.challenge().challenge_id(), request_id);

    let device_add = device_add(
        &owner.root,
        &candidate,
        owner.identity_id,
        candidate_device_id,
        encryption_seed,
        observed_head.hash(),
        observed_head.sequence().get() + 1,
        NOW + 2,
    )?;
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::hash_domain(
            b"test-history-recovery-approval\0",
            request_id.to_string().as_bytes(),
        ),
        request_id,
        DeviceEnrollmentCapability::new(capability_bytes)?,
        observed_head.hash(),
        device_add.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        DeviceEnrollmentRepository
            .approve(
                store,
                approval,
                DeviceSessionCredential::new(owner.session_id, owner.session_secret)?,
                UtcMillis::new(NOW + 2)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let approved_head = IdentityLogRepository::new()
        .load(store, owner.identity_id)
        .await?
        .ok_or("identity missing after V40 recovery approval")?
        .head();

    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            owner.identity_id,
            candidate_device_id,
            [candidate_seed.wrapping_add(1); 32],
            AUDIENCE,
            UtcMillis::new(NOW + 3)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let session_proof = signature(
        &candidate,
        &device_session_proof_input(
            owner.identity_id,
            candidate_device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    assert!(matches!(
        DeviceSessionRepository
            .complete(
                store,
                &DeviceSessionCompletionCommand::new(
                    Sha256Digest::hash_domain(
                        b"test-history-recovery-session\0",
                        request_id.to_string().as_bytes(),
                    ),
                    owner.identity_id,
                    candidate_device_id,
                    challenge.challenge_id(),
                    session_id,
                    *challenge.nonce(),
                    session_secret,
                    session_proof,
                )?,
                UtcMillis::new(NOW + 3)?,
            )
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(RecoveredDevice {
        active: ActiveDevice {
            root: SigningKey::from_bytes(&owner.root.to_bytes()),
            recovery: SigningKey::from_bytes(&owner.recovery.to_bytes()),
            identity_id: owner.identity_id,
            device_id: candidate_device_id,
            session_id,
            session_secret,
        },
        request_id,
        request_digest,
        approved_head,
        recipient_package_digest: Sha256Digest::hash_domain(
            b"dirextalk.history-recovery-recipient-package.v1\0",
            recipient_key.as_bytes(),
        ),
    })
}

pub(crate) async fn create_ready_history_attachment(
    store: &MailboxPgStore,
    owner: &ActiveDevice,
    seed: u8,
    expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<(Uuid, Sha256Digest), Box<dyn Error>> {
    let object_id = Uuid::now_v7();
    let ciphertext = vec![0x7d; 64];
    let chunk_digest = Sha256Digest::from_bytes(Sha256::digest(&ciphertext).into());
    let mut manifest_bytes = b"DTXA1".to_vec();
    manifest_bytes.extend_from_slice(&1_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&0_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&u32::try_from(ciphertext.len())?.to_be_bytes());
    manifest_bytes.extend_from_slice(chunk_digest.as_bytes());
    manifest_bytes.extend_from_slice(&17_u32.to_be_bytes());
    manifest_bytes.extend_from_slice(&[0x7e; 17]);
    let manifest = AttachmentManifest::parse(manifest_bytes.clone()).unwrap();
    let manifest_digest = Sha256Digest::from_bytes(Sha256::digest(&manifest_bytes).into());
    let upload = AttachmentCapability::new([seed; 32]);
    let read = AttachmentCapability::new([seed.wrapping_add(1); 32]);
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;
    assert_eq!(
        AttachmentRepository
            .create(
                store,
                &credential,
                &AttachmentCreate {
                    object_id,
                    owner_identity_id: owner.identity_id,
                    owner_device_id: owner.device_id,
                    manifest_digest,
                    chunk_count: 1,
                    ciphertext_bytes: u64::try_from(ciphertext.len())?,
                    expires_at,
                },
                &upload,
                &read,
                now,
            )
            .await
            .unwrap(),
        AttachmentStatus::Created,
    );
    assert_eq!(
        AttachmentRepository
            .put_chunk(
                store,
                object_id,
                0,
                &upload,
                Sha256Digest::hash_domain(
                    b"test-history-recovery-attachment-chunk\0",
                    object_id.as_bytes(),
                ),
                chunk_digest,
                &ciphertext,
                UtcMillis::new(now.get() + 1)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Created,
    );
    assert_eq!(
        AttachmentRepository
            .finalize(
                store,
                object_id,
                &upload,
                &manifest,
                UtcMillis::new(now.get() + 2)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Ready,
    );
    Ok((object_id, manifest_digest))
}

pub(crate) async fn enroll_active_device(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    enroll_active_device_at(
        store,
        root_seed,
        recovery_seed,
        device_seed,
        session_secret,
        NOW,
    )
    .await
}

pub(crate) async fn enroll_active_device_at(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
    now: i64,
) -> Result<ActiveDevice, Box<dyn Error>> {
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let genesis = genesis(&root, &recovery, now - 1_000)?;
    let identity_id = genesis.identity_id();
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-bootstrap\0", &[root_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(now - 800)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let device_id = DeviceId::new();
    let initial = device_add(
        &root,
        &device,
        identity_id,
        device_id,
        device_seed.wrapping_add(1),
        genesis.entry_hash()?,
        2,
        now - 700,
    )?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(b"test-mailbox-initial\0", &[root_seed]),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(now - 500)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            identity_id,
            device_id,
            [device_seed; 32],
            AUDIENCE,
            UtcMillis::new(now)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-session\0", &[root_seed]),
        identity_id,
        device_id,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &completion, UtcMillis::new(now)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        root,
        recovery,
        identity_id,
        device_id,
        session_id,
        session_secret,
    })
}

pub(crate) async fn add_active_device(
    store: &IdentityPgStore,
    owner: &ActiveDevice,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, owner.identity_id)
        .await?
        .ok_or("identity missing before second device add")?
        .head();
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let device_id = DeviceId::new();
    let event = device_add(
        &owner.root,
        &device,
        owner.identity_id,
        device_id,
        device_seed.wrapping_add(1),
        head.hash(),
        head.sequence().get() + 1,
        NOW - 100,
    )?;
    let command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-additional-device\0", &[device_seed]),
        Some(head),
        event.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(store, &command, UtcMillis::new(NOW - 50)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            owner.identity_id,
            device_id,
            [device_seed; 32],
            AUDIENCE,
            UtcMillis::new(NOW)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            owner.identity_id,
            device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-additional-session\0", &[device_seed]),
        owner.identity_id,
        device_id,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &completion, UtcMillis::new(NOW)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        root: SigningKey::from_bytes(&owner.root.to_bytes()),
        recovery: SigningKey::from_bytes(&owner.recovery.to_bytes()),
        identity_id: owner.identity_id,
        device_id,
        session_id,
        session_secret,
    })
}

pub(crate) async fn revoke_active_device(
    store: &IdentityPgStore,
    active: &ActiveDevice,
) -> Result<(), Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, active.identity_id)
        .await?
        .ok_or("identity log missing before mailbox owner revoke")?
        .head();
    let revoke = signed_event(
        &active.root,
        active.identity_id,
        head.sequence().get() + 1,
        Some(head.hash()),
        3_000,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: active.device_id,
        },
    )?;
    let command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(
            b"test-mailbox-revoke\0",
            active.device_id.to_string().as_bytes(),
        ),
        Some(head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(store, &command, UtcMillis::new(3_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    Ok(())
}

pub(crate) fn mailbox_registration_body(
    mailbox_id: MailboxId,
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    capability: [u8; 32],
    expires_at: UtcMillis,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let capability_hash =
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &capability);
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(mailbox_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(owner_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(owner_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            capability_hash.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(6), expires_at.to_canonical_value()),
    ]))?)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn device_history_grant_body(
    identity_id: IdentityId,
    new_device_id: DeviceId,
    identity_head: Sha256Digest,
    authorization_kind: u64,
    authorizer_id: String,
    authorizer: &SigningKey,
    new_device: &SigningKey,
    history_seed: u8,
    pop_seed: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unsigned = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(new_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            identity_head.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bytes(vec![history_seed; 32]),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Unsigned(authorization_kind),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(authorizer_id),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(vec![pop_seed; 32]),
        ),
        (
            CanonicalValue::Unsigned(10),
            UtcMillis::new(NOW)?.to_canonical_value(),
        ),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned)?;
    let mut grant_input = b"dirextalk.device-history-grant.v1\0".to_vec();
    grant_input.extend_from_slice(&unsigned_bytes);
    let mut pop_input = b"dirextalk.device-history-grant-pop.v1\0".to_vec();
    pop_input.extend_from_slice(&unsigned_bytes);
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!()
    };
    fields.push((
        CanonicalValue::Unsigned(11),
        signature(authorizer, &grant_input).to_canonical_value(),
    ));
    fields.push((
        CanonicalValue::Unsigned(12),
        signature(new_device, &pop_input).to_canonical_value(),
    ));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn device_history_grant_body_v2(
    idempotency_key: &str,
    identity_id: IdentityId,
    request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
    approved_head_hash: Sha256Digest,
    candidate_device_id: DeviceId,
    provider_device_id: DeviceId,
    authority_id: &str,
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    provider_highwater: u64,
    recipient_package_digest: Sha256Digest,
    attachment_digest: Sha256Digest,
    opaque_offer: &[u8],
    granted_at: UtcMillis,
    expires_at: UtcMillis,
    provider: &SigningKey,
    authority: &SigningKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let idempotency_key_hash = Sha256Digest::hash_domain(
        b"dirextalk.mailbox-http-history-grant-idempotency-key.v2\0",
        idempotency_key.as_bytes(),
    );
    let offer_digest =
        Sha256Digest::hash_domain(b"dirextalk.device-history-offer.v2\0", opaque_offer);
    let unsigned = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            recovery_request_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(5),
            approved_head_hash.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(candidate_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(provider_device_id.to_string()),
        ),
        (CanonicalValue::Unsigned(8), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(authority_id.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(mailbox_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Text(envelope_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(12),
            CanonicalValue::Unsigned(provider_highwater),
        ),
        (
            CanonicalValue::Unsigned(13),
            CanonicalValue::Unsigned(provider_highwater + 1),
        ),
        (
            CanonicalValue::Unsigned(14),
            recipient_package_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(15),
            attachment_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(16),
            offer_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(17),
            granted_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(18),
            expires_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(19),
            idempotency_key_hash.to_canonical_value(),
        ),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned)?;
    let mut provider_input = b"dirextalk.device-history-grant-provider.v2\0".to_vec();
    provider_input.extend_from_slice(&unsigned_bytes);
    let mut authority_input = b"dirextalk.device-history-grant-authority.v2\0".to_vec();
    authority_input.extend_from_slice(&unsigned_bytes);
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!()
    };
    fields.push((
        CanonicalValue::Unsigned(20),
        signature(provider, &provider_input).to_canonical_value(),
    ));
    fields.push((
        CanonicalValue::Unsigned(21),
        signature(authority, &authority_input).to_canonical_value(),
    ));
    fields.push((
        CanonicalValue::Unsigned(22),
        CanonicalValue::Bytes(opaque_offer.to_vec()),
    ));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

pub(crate) fn assert_v3_single_envelope(
    bytes: &[u8],
    expected_highwater: u64,
    expected_floor: u64,
    expected_envelope: EnvelopeId,
    expected_ciphertext: &[u8],
) -> Result<(), Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V3 pull receipt not a map".into());
    };
    if fields.len() != 6
        || fields[3].1 != CanonicalValue::Unsigned(expected_highwater)
        || fields[4].1 != CanonicalValue::Unsigned(expected_floor)
    {
        return Err("V3 pull head/floor mismatch".into());
    }
    let CanonicalValue::Array(segments) = &fields[5].1 else {
        return Err("V3 pull segments missing".into());
    };
    let [CanonicalValue::Map(segment)] = segments.as_slice() else {
        return Err("V3 pull must contain one envelope".into());
    };
    if segment.len() != 5
        || segment[0].1 != CanonicalValue::Unsigned(1)
        || segment[1].1 != CanonicalValue::Unsigned(expected_highwater)
        || segment[2].1 != CanonicalValue::Text(expected_envelope.to_string())
        || segment[3].1 != CanonicalValue::Bytes(expected_ciphertext.to_vec())
    {
        return Err("V3 pull envelope mismatch".into());
    }
    Ok(())
}

pub(crate) fn account_read_cursor_write_body(
    conversation_digest: Sha256Digest,
    base_revision: u64,
    revision: u64,
    encrypted_cursor: &[u8],
    identity_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            conversation_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(base_revision),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Unsigned(revision),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Bytes(encrypted_cursor.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(6),
            identity_head.to_canonical_value(),
        ),
    ]))?)
}

pub(crate) fn account_read_cursor_query_body(
    conversation_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            conversation_digest.to_canonical_value(),
        ),
    ]))?)
}

pub(crate) fn mailbox_envelope_body(
    envelope_id: EnvelopeId,
    opaque_ciphertext: &[u8],
    expires_at: UtcMillis,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(envelope_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(opaque_ciphertext.to_vec()),
        ),
        (CanonicalValue::Unsigned(4), expires_at.to_canonical_value()),
    ]))?)
}

pub(crate) fn mailbox_pull_body(
    after_sequence: SafeUint,
    limit: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            after_sequence.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(u64::from(limit)),
        ),
    ]))?)
}

pub(crate) fn mailbox_ack_body(envelope_ids: &[EnvelopeId]) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Array(
                envelope_ids
                    .iter()
                    .map(|id| CanonicalValue::Text(id.to_string()))
                    .collect(),
            ),
        ),
    ]))?)
}

pub(crate) async fn send_registration(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    mailbox_id: MailboxId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri(MAILBOX_REGISTER_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string()))
            .header(header::CONTENT_TYPE, MAILBOX_REGISTER_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(session_id, session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

pub(crate) async fn send_envelope(
    app: axum::Router,
    idempotency_key: &str,
    capability: [u8; 32],
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri(
                MAILBOX_ENQUEUE_PATH_TEMPLATE
                    .replace("{mailbox_id}", &mailbox_id.to_string())
                    .replace("{envelope_id}", &envelope_id.to_string()),
            )
            .header(header::CONTENT_TYPE, MAILBOX_ENVELOPE_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                mailbox_capability_authorization(capability),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

pub(crate) async fn send_pull(
    app: axum::Router,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    mailbox_id: MailboxId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(MAILBOX_PULL_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string()))
            .header(header::CONTENT_TYPE, MAILBOX_PULL_CONTENT_TYPE)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(session_id, session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

pub(crate) async fn send_acknowledgement(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    mailbox_id: MailboxId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(MAILBOX_ACK_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string()))
            .header(header::CONTENT_TYPE, MAILBOX_ACK_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(session_id, session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_v2(
    app: axum::Router,
    path: &str,
    content_type: &str,
    idempotency_key: Option<&str>,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::AUTHORIZATION,
            device_session_authorization(session_id, session_secret),
        );
    if let Some(key) = idempotency_key {
        request = request.header("idempotency-key", key);
    }
    app.oneshot(request.body(Body::from(body))?)
        .await
        .map_err(Into::into)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test helper mirrors the complete public mailbox HTTP request boundary"
)]
pub(crate) async fn send_network_mailbox_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    origin: &str,
    path: &str,
    content_type: &str,
    idempotency_key: Option<&str>,
    authorization: String,
    body: Vec<u8>,
) -> Result<reqwest::Response, Box<dyn Error>> {
    let mut request = client
        .request(method, format!("{origin}{path}"))
        .header(header::CONTENT_TYPE.as_str(), content_type)
        .header(header::AUTHORIZATION.as_str(), authorization)
        .body(body);
    if let Some(idempotency_key) = idempotency_key {
        request = request.header("idempotency-key", idempotency_key);
    }
    Ok(request.send().await?)
}

pub(crate) fn assert_network_content_type(response: &reqwest::Response, expected: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE.as_str())
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

pub(crate) async fn assert_network_mailbox_error(
    response: reqwest::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL.as_str())
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS.as_str())
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await?)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    Ok(())
}

pub(crate) fn device_session_authorization(
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
) -> String {
    format!(
        "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
        Base64UrlUnpadded::encode_string(&session_secret)
    )
}

pub(crate) fn mailbox_capability_authorization(capability: [u8; 32]) -> String {
    format!(
        "{MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME} {}",
        Base64UrlUnpadded::encode_string(&capability)
    )
}

pub(crate) fn assert_content_type(response: &axum::response::Response, expected: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

pub(crate) async fn response_bytes(
    response: axum::response::Response,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(to_bytes(response.into_body(), 300_000).await?.to_vec())
}

pub(crate) async fn assert_mailbox_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let body: serde_json::Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    Ok(())
}

pub(crate) fn assert_pull_receipt(
    bytes: &[u8],
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    opaque_ciphertext: &[u8],
) -> Result<(), Box<dyn Error>> {
    let value = decode_deterministic_cbor(bytes)?;
    let CanonicalValue::Map(fields) = value else {
        return Err("mailbox pull receipt was not a map".into());
    };
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[1].1, CanonicalValue::Text(mailbox_id.to_string()));
    assert_eq!(fields[2].1, SafeUint::new(1)?.to_canonical_value());
    let CanonicalValue::Array(envelopes) = &fields[3].1 else {
        return Err("mailbox pull receipt envelopes were not an array".into());
    };
    assert_eq!(envelopes.len(), 1);
    let CanonicalValue::Map(envelope) = &envelopes[0] else {
        return Err("mailbox pull receipt envelope was not a map".into());
    };
    assert_eq!(envelope[1].1, CanonicalValue::Text(envelope_id.to_string()));
    assert_eq!(
        envelope[2].1,
        CanonicalValue::Bytes(opaque_ciphertext.to_vec())
    );
    Ok(())
}

pub(crate) fn assert_empty_pull_receipt(
    bytes: &[u8],
    mailbox_id: MailboxId,
) -> Result<(), Box<dyn Error>> {
    let value = decode_deterministic_cbor(bytes)?;
    let CanonicalValue::Map(fields) = value else {
        return Err("empty mailbox pull receipt was not a map".into());
    };
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[1].1, CanonicalValue::Text(mailbox_id.to_string()));
    assert_eq!(fields[2].1, SafeUint::new(1)?.to_canonical_value());
    assert_eq!(fields[3].1, CanonicalValue::Array(Vec::new()));
    Ok(())
}

pub(crate) fn genesis(
    root: &SigningKey,
    recovery: &SigningKey,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let recovery_key = public_key(recovery)?;
    let identity_id = IdentityId::derive(root_key.as_domain_key());
    let recovery_acceptance_signature = signature(
        recovery,
        &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key)?,
    );
    signed_event(
        root,
        identity_id,
        1,
        None,
        occurred_at,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn device_add(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    encryption_seed: u8,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let device_key = public_key(device)?;
    let certificate_unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        device_key,
        DeviceEncryptionPublicKey::try_from([encryption_seed; 32])?,
        root_key,
        UtcMillis::new(occurred_at - 1)?,
    )?;
    let certificate = DeviceCertificateV1::signed(
        certificate_unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(certificate_unsigned.signing_digest()?),
        ),
    )?;
    signed_event(
        root,
        identity_id,
        sequence,
        Some(previous_hash),
        occurred_at,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

pub(crate) fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous_hash: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let signer_key = public_key(signer)?;
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        SafeUint::new(sequence)?,
        previous_hash,
        UtcMillis::new(occurred_at)?,
        payload,
        signer_key,
    )?;
    Ok(IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest()?),
        ),
    )?)
}

pub(crate) fn public_key(key: &SigningKey) -> Result<SigningPublicKey, Box<dyn Error>> {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).map_err(Into::into)
}

pub(crate) fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

pub(crate) struct FixedClock(pub(crate) i64);

impl Clock for FixedClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0)
    }
}
