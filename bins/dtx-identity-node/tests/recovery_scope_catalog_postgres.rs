#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{Clock, ClockError, DeviceId, DeviceSessionId, IdentityId};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    DEVICE_ENROLLMENT_CAPABILITY_HEADER, DEVICE_SESSION_AUTHORIZATION_SCHEME,
    IdentityBootstrapState, RECOVERY_RESPONSE_CAPABILITY_HEADER,
    RECOVERY_SCOPE_CATALOG_CONTENT_TYPE, RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE, RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PREPARATION_PATH_TEMPLATE, RECOVERY_SCOPE_CATALOG_PREPARATIONS_PATH,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE,
    RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE, identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::{
    CATALOG_CIPHERTEXT_HASH_DOMAIN, CATALOG_HEAD_SIGNATURE_DOMAIN,
    CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN, CreateDeviceEnrollmentChallengeCommand,
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability,
    DeviceEnrollmentChallengeOutcome, DeviceEnrollmentRepository, DeviceSessionCompletionCommand,
    DeviceSessionCredential, DeviceSessionOutcome, DeviceSessionRepository, IdentityAppendCommand,
    IdentityAppendOutcome, IdentityLogHead, IdentityLogRepository, IdentityPgStore,
    MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES, PREPARATION_SIGNATURE_DOMAIN,
    PROVIDER_CIPHERTEXT_HASH_DOMAIN, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, RECIPIENT_KEY_HASH_DOMAIN,
    RESPONSE_CAPABILITY_HASH_DOMAIN, device_session_proof_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use tower::ServiceExt;

const AUDIENCE: &str = "https://identity.test";
const AUTHORITY_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a3";
const PROVIDER_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a4";
const CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a5";
const SECOND_CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a6";

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/PostgreSQL workflow proves exact replay, capability separation, H+1, invalidation, revocation, and response redaction together"
)]
async fn catalog_http_workflow_is_exact_capability_gated_and_fail_closed()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let clock = Arc::new(TestClock::new(5_000));
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            clock.clone(),
            AUDIENCE,
        ),
    );
    let identity_repository = IdentityLogRepository::new();
    let enrollment_repository = DeviceEnrollmentRepository;

    let root = key(1);
    let recovery = key(2);
    let authority = key(3);
    let provider = key(4);
    let candidate = key(5);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let head1 = committed(
        identity_repository
            .append(&store, &append_command(1, None, &genesis)?, at(1_001))
            .await?,
    )?;
    let authority_device = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let authority_add = device_add(
        &root,
        identity_id,
        authority_device,
        &authority,
        33,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        identity_repository
            .append(
                &store,
                &append_command(2, Some(head1), &authority_add)?,
                at(1_011),
            )
            .await?,
    )?;
    let provider_device = DeviceId::from_str(PROVIDER_DEVICE)?;
    let provider_add = device_add(
        &root,
        identity_id,
        provider_device,
        &provider,
        44,
        3,
        head2.hash(),
        1_020,
    );
    let head3 = committed(
        identity_repository
            .append(
                &store,
                &append_command(3, Some(head2), &provider_add)?,
                at(1_021),
            )
            .await?,
    )?;
    let authority_session = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        11,
        at(2_000),
    )
    .await?;
    let provider_session = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        12,
        at(2_000),
    )
    .await?;

    let runtime_acl: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT
             has_table_privilege(current_user,'identity.recovery_scope_catalogs','SELECT,INSERT'),
             NOT has_table_privilege(current_user,'identity.recovery_scope_catalogs','UPDATE,DELETE'),
             has_table_privilege(current_user,'identity.recovery_scope_catalog_preparations','SELECT,INSERT'),
             NOT has_table_privilege(current_user,'identity.recovery_scope_catalog_preparations','DELETE')",
    )
    .fetch_one(harness.identity_runtime_pool())
    .await?;
    assert_eq!(runtime_acl, (true, true, true, true));

    let catalog = catalog_body(identity_id, head3, &authority, safe(1), None, [31; 32])?;
    let (first, second) = tokio::join!(
        send_catalog(
            app.clone(),
            "catalog-publish-0001",
            &authority_session,
            1,
            RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
            catalog.clone(),
        ),
        send_catalog(
            app.clone(),
            "catalog-publish-0001",
            &authority_session,
            1,
            RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
            catalog.clone(),
        ),
    );
    let first = first?;
    let second = second?;
    assert_created_and_replayed(&first, &second);
    assert_catalog_headers(&first, RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE);
    let first_head = to_bytes(first.into_body(), 16_384).await?.to_vec();
    let second_head = to_bytes(second.into_body(), 16_384).await?.to_vec();
    assert_eq!(first_head, second_head);
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 0, 0));
    let catalog_head_digest = Sha256Digest::hash_domain(
        dtx_identity_persistence::CATALOG_HEAD_DIGEST_DOMAIN,
        &first_head,
    );

    let changed = catalog_body(identity_id, head3, &authority, safe(1), None, [32; 32])?;
    let changed_response = send_catalog(
        app.clone(),
        "catalog-publish-0001",
        &authority_session,
        1,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        changed,
    )
    .await?;
    assert_error(
        changed_response,
        StatusCode::CONFLICT,
        "IDEMPOTENCY_CONFLICT",
    )
    .await?;
    let gap = catalog_body(
        identity_id,
        head3,
        &authority,
        safe(3),
        Some(catalog_head_digest),
        [33; 32],
    )?;
    let gap_response = send_catalog(
        app.clone(),
        "catalog-publish-gap",
        &authority_session,
        3,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        gap,
    )
    .await?;
    assert_error(
        gap_response,
        StatusCode::CONFLICT,
        "RECOVERY_CATALOG_CONFLICT",
    )
    .await?;
    let wrong_media = send_catalog(
        app.clone(),
        "catalog-publish-media",
        &authority_session,
        2,
        "application/cbor",
        catalog.clone(),
    )
    .await?;
    assert_error(
        wrong_media,
        StatusCode::UNPROCESSABLE_ENTITY,
        "RECOVERY_CATALOG_INVALID",
    )
    .await?;
    let oversized = send_catalog(
        app.clone(),
        "catalog-publish-oversized",
        &authority_session,
        2,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        vec![0; MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES + 1],
    )
    .await?;
    assert_error(
        oversized,
        StatusCode::UNPROCESSABLE_ENTITY,
        "RECOVERY_CATALOG_INVALID",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 0, 0));

    let candidate_device = DeviceId::from_str(CANDIDATE_DEVICE)?;
    let enrollment_capability = [41; 32];
    let challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([42; 32]),
                identity_id,
                candidate_device,
                public(&candidate),
                DeviceEncryptionPublicKey::try_from([55; 32])?,
                DeviceEnrollmentCapability::new(enrollment_capability)?,
            )?,
            at(4_000),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(challenge) = challenge else {
        return Err("ordinary enrollment challenge must be new".into());
    };
    let response_capability = [61; 32];
    let equal_capability_preparation = preparation_body(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        enrollment_capability,
    )?;
    let equal_capability_response = send_preparation(
        app.clone(),
        "catalog-preparation-equal-capabilities",
        enrollment_capability,
        enrollment_capability,
        equal_capability_preparation,
    )
    .await?;
    assert_error(
        equal_capability_response,
        StatusCode::UNAUTHORIZED,
        "RECOVERY_RESPONSE_CAPABILITY_REJECTED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 0, 0));
    let preparation = preparation_body(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        response_capability,
    )?;
    let (prepare_first, prepare_second) = tokio::join!(
        send_preparation(
            app.clone(),
            "catalog-preparation-0001",
            enrollment_capability,
            response_capability,
            preparation.clone(),
        ),
        send_preparation(
            app.clone(),
            "catalog-preparation-0001",
            enrollment_capability,
            response_capability,
            preparation.clone(),
        ),
    );
    let prepare_first = prepare_first?;
    let prepare_second = prepare_second?;
    assert_created_and_replayed(&prepare_first, &prepare_second);
    assert_catalog_headers(&prepare_first, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 0));

    let wrong_capability = send_status(app.clone(), challenge.challenge_id(), [62; 32]).await?;
    assert_error(
        wrong_capability,
        StatusCode::UNAUTHORIZED,
        "RECOVERY_RESPONSE_CAPABILITY_REJECTED",
    )
    .await?;
    let pending = send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(pending.status(), StatusCode::OK);
    assert_catalog_headers(&pending, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_redacted_status(pending, 1).await?;

    let invalid_provider = provider_body(
        challenge.challenge_id(),
        catalog_head_digest,
        authority_device,
        &authority,
        Sha256Digest::from_bytes([99; 32]),
        [55; 32],
    )?;
    let invalid_provider_response = send_provider_response(
        app.clone(),
        "catalog-provider-invalid",
        &authority_session,
        challenge.challenge_id(),
        invalid_provider,
    )
    .await?;
    assert_error(
        invalid_provider_response,
        StatusCode::PRECONDITION_FAILED,
        "RECOVERY_PREPARATION_INVALIDATED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 0));

    let candidate_add = device_add(
        &root,
        identity_id,
        candidate_device,
        &candidate,
        55,
        4,
        head3.hash(),
        5_200,
    );
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([71; 32]),
        challenge.challenge_id(),
        DeviceEnrollmentCapability::new(enrollment_capability)?,
        head3.hash(),
        candidate_add.to_deterministic_cbor()?,
    )?;
    let head4 = committed(
        enrollment_repository
            .approve(
                &store,
                approval,
                DeviceSessionCredential::new(
                    provider_session.session_id,
                    provider_session.session_secret,
                )?,
                at(5_201),
            )
            .await?,
    )?;
    clock.set(5_300);
    let provider_response_body = provider_body(
        challenge.challenge_id(),
        catalog_head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
    )?;
    let (provider_first, provider_second) = tokio::join!(
        send_provider_response(
            app.clone(),
            "catalog-provider-0001",
            &provider_session,
            challenge.challenge_id(),
            provider_response_body.clone(),
        ),
        send_provider_response(
            app.clone(),
            "catalog-provider-0001",
            &provider_session,
            challenge.challenge_id(),
            provider_response_body.clone(),
        ),
    );
    let provider_first = provider_first?;
    let provider_second = provider_second?;
    assert_eq!(provider_first.status(), StatusCode::OK);
    assert_eq!(provider_second.status(), StatusCode::OK);
    assert_catalog_headers(&provider_first, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_catalog_headers(&provider_second, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(
        to_bytes(provider_first.into_body(), 1_100_000).await?,
        to_bytes(provider_second.into_body(), 1_100_000).await?
    );
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 1));
    let ready = send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_catalog_headers(&ready, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    let ready_bytes = to_bytes(ready.into_body(), 1_100_000).await?;
    let CanonicalValue::Map(ready_fields) = decode_deterministic_cbor(&ready_bytes)? else {
        return Err("ready status must be a map".into());
    };
    assert_eq!(ready_fields.len(), 6);
    assert_eq!(ready_fields[2].1, CanonicalValue::Unsigned(2));
    assert_eq!(
        ready_fields[3].1,
        decode_deterministic_cbor(&provider_response_body)?
    );
    let ready_replay = send_preparation(
        app.clone(),
        "catalog-preparation-0001",
        enrollment_capability,
        response_capability,
        preparation.clone(),
    )
    .await?;
    assert_eq!(ready_replay.status(), StatusCode::OK);
    assert_catalog_headers(&ready_replay, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(
        to_bytes(ready_replay.into_body(), 1_100_000).await?,
        ready_bytes
    );

    clock.set(5_400);
    let rotated = catalog_body(
        identity_id,
        head4,
        &authority,
        safe(2),
        Some(catalog_head_digest),
        [34; 32],
    )?;
    let rotated_response = send_catalog(
        app.clone(),
        "catalog-publish-0002",
        &authority_session,
        2,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        rotated,
    )
    .await?;
    assert_eq!(rotated_response.status(), StatusCode::CREATED);
    assert_catalog_headers(&rotated_response, RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE);
    let rotated_head = to_bytes(rotated_response.into_body(), 16_384)
        .await?
        .to_vec();
    let rotated_head_digest = Sha256Digest::hash_domain(
        dtx_identity_persistence::CATALOG_HEAD_DIGEST_DOMAIN,
        &rotated_head,
    );
    let invalidated =
        send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(invalidated.status(), StatusCode::PRECONDITION_FAILED);
    let invalidated_bytes = assert_redacted_status(invalidated, 4).await?;
    let invalidated_replay = send_preparation(
        app.clone(),
        "catalog-preparation-0001",
        enrollment_capability,
        response_capability,
        preparation.clone(),
    )
    .await?;
    assert_eq!(invalidated_replay.status(), StatusCode::OK);
    assert_catalog_headers(
        &invalidated_replay,
        RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(invalidated_replay.into_body(), 1_100_000).await?,
        invalidated_bytes
    );

    let cancelled_candidate = key(6);
    let cancelled_candidate_device = DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?;
    let cancelled_enrollment_capability = [91; 32];
    let cancelled_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([92; 32]),
                identity_id,
                cancelled_candidate_device,
                public(&cancelled_candidate),
                DeviceEncryptionPublicKey::try_from([66; 32])?,
                DeviceEnrollmentCapability::new(cancelled_enrollment_capability)?,
            )?,
            at(5_401),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(cancelled_challenge) = cancelled_challenge else {
        return Err("cancelled enrollment challenge must be new".into());
    };
    let cancelled_response_capability = [93; 32];
    let cancelled_preparation = preparation_body(
        cancelled_challenge.challenge_id(),
        identity_id,
        cancelled_candidate_device,
        &cancelled_candidate,
        [66; 32],
        head4,
        cancelled_response_capability,
    )?;
    let prepared = send_preparation(
        app.clone(),
        "catalog-preparation-cancelled",
        cancelled_enrollment_capability,
        cancelled_response_capability,
        cancelled_preparation,
    )
    .await?;
    assert_eq!(prepared.status(), StatusCode::CREATED);
    enrollment_repository
        .cancel(
            &store,
            cancelled_challenge.challenge_id(),
            DeviceEnrollmentCapability::new(cancelled_enrollment_capability)?,
            at(5_402),
        )
        .await?;
    clock.set(5_403);
    let cancelled_status = send_status(
        app.clone(),
        cancelled_challenge.challenge_id(),
        cancelled_response_capability,
    )
    .await?;
    assert_eq!(cancelled_status.status(), StatusCode::PRECONDITION_FAILED);
    assert_redacted_status(cancelled_status, 4).await?;
    let cancelled_provider = provider_body(
        cancelled_challenge.challenge_id(),
        rotated_head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [66; 32],
    )?;
    let cancelled_provider_response = send_provider_response(
        app.clone(),
        "catalog-provider-cancelled",
        &provider_session,
        cancelled_challenge.challenge_id(),
        cancelled_provider,
    )
    .await?;
    assert_error(
        cancelled_provider_response,
        StatusCode::GONE,
        "RECOVERY_PREPARATION_REVOKED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (2, 2, 1));

    let revoke = signed_event(
        &root,
        identity_id,
        5,
        Some(head4.hash()),
        5_500,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: provider_device,
        },
    );
    committed(
        identity_repository
            .append(
                &store,
                &append_command(81, Some(head4), &revoke)?,
                at(5_501),
            )
            .await?,
    )?;
    clock.set(5_600);
    let revoked_provider = send_provider_response(
        app.clone(),
        "catalog-provider-0001",
        &provider_session,
        challenge.challenge_id(),
        provider_response_body,
    )
    .await?;
    assert_error(
        revoked_provider,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (2, 2, 1));

    clock.set(200_000);
    let expired = send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(expired.status(), StatusCode::GONE);
    let expired_bytes = assert_redacted_status(expired, 3).await?;
    let expired_replay = send_preparation(
        app.clone(),
        "catalog-preparation-0001",
        enrollment_capability,
        response_capability,
        preparation,
    )
    .await?;
    assert_eq!(expired_replay.status(), StatusCode::OK);
    assert_catalog_headers(&expired_replay, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(
        to_bytes(expired_replay.into_body(), 1_100_000).await?,
        expired_bytes
    );

    sqlx::query("REVOKE SELECT ON identity.recovery_scope_catalogs FROM dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;
    clock.set(6_000);
    let unavailable = send_status(app, challenge.challenge_id(), response_capability).await?;
    assert_error(
        unavailable,
        StatusCode::SERVICE_UNAVAILABLE,
        "IDENTITY_SERVICE_UNAVAILABLE",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (2, 2, 1));
    Ok(())
}

#[derive(Clone, Copy)]
struct Session {
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

async fn session(
    store: &IdentityPgStore,
    identity: IdentityId,
    device: DeviceId,
    signing: &SigningKey,
    seed: u8,
    now: UtcMillis,
) -> Result<Session, Box<dyn Error>> {
    let challenge = DeviceSessionRepository
        .issue_challenge(store, identity, device, [seed; 32], AUDIENCE, now)
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret = [seed.wrapping_add(1); 32];
    let secret_hash = Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        signing,
        &device_session_proof_input(
            identity,
            device,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let command = DeviceSessionCompletionCommand::new(
        Sha256Digest::from_bytes([seed.wrapping_add(2); 32]),
        identity,
        device,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &command, at(now.get() + 1))
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(Session {
        session_id,
        session_secret,
    })
}

async fn send_catalog(
    app: axum::Router,
    idempotency: &str,
    session: &Session,
    generation: u64,
    content_type: &str,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(
                    RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE
                        .replace("{generation}", &generation.to_string()),
                )
                .header(header::CONTENT_TYPE, content_type)
                .header("idempotency-key", idempotency)
                .header(header::AUTHORIZATION, authorization(session))
                .body(Body::from(body))?,
        )
        .await?)
}

async fn send_preparation(
    app: axum::Router,
    idempotency: &str,
    enrollment_capability: [u8; 32],
    response_capability: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(RECOVERY_SCOPE_CATALOG_PREPARATIONS_PATH)
                .header(
                    header::CONTENT_TYPE,
                    RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
                )
                .header("idempotency-key", idempotency)
                .header(
                    DEVICE_ENROLLMENT_CAPABILITY_HEADER,
                    Base64UrlUnpadded::encode_string(&enrollment_capability),
                )
                .header(
                    RECOVERY_RESPONSE_CAPABILITY_HEADER,
                    Base64UrlUnpadded::encode_string(&response_capability),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn send_status(
    app: axum::Router,
    request_id: dtx_domain::DeviceEnrollmentChallengeId,
    response_capability: [u8; 32],
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(
                    RECOVERY_SCOPE_CATALOG_PREPARATION_PATH_TEMPLATE
                        .replace("{request_id}", &request_id.to_string()),
                )
                .header(
                    RECOVERY_RESPONSE_CAPABILITY_HEADER,
                    Base64UrlUnpadded::encode_string(&response_capability),
                )
                .body(Body::empty())?,
        )
        .await?)
}

async fn send_provider_response(
    app: axum::Router,
    idempotency: &str,
    session: &Session,
    request_id: dtx_domain::DeviceEnrollmentChallengeId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(
                    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE
                        .replace("{request_id}", &request_id.to_string()),
                )
                .header(
                    header::CONTENT_TYPE,
                    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
                )
                .header("idempotency-key", idempotency)
                .header(header::AUTHORIZATION, authorization(session))
                .body(Body::from(body))?,
        )
        .await?)
}

fn authorization(session: &Session) -> String {
    format!(
        "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {}.{}",
        session.session_id,
        Base64UrlUnpadded::encode_string(&session.session_secret)
    )
}

async fn assert_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
    assert_catalog_headers(&response, "application/json");
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await?)?;
    assert_eq!(body["error"]["code"], expected_code);
    Ok(())
}

fn assert_catalog_headers(response: &axum::response::Response, content_type: &str) {
    assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
}

fn assert_created_and_replayed(
    first: &axum::response::Response,
    second: &axum::response::Response,
) {
    assert!(
        (first.status() == StatusCode::CREATED && second.status() == StatusCode::OK)
            || (first.status() == StatusCode::OK && second.status() == StatusCode::CREATED)
    );
}

async fn assert_redacted_status(
    response: axum::response::Response,
    expected_state: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    assert_catalog_headers(&response, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    let body = to_bytes(response.into_body(), 1_100_000).await?;
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(&body)? else {
        return Err("status must be a map".into());
    };
    assert_eq!(fields.len(), 6);
    assert_eq!(fields[2].1, CanonicalValue::Unsigned(expected_state));
    assert_eq!(fields[3].1, CanonicalValue::Null);
    Ok(body.to_vec())
}

async fn recovery_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<(i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM identity.recovery_scope_catalogs WHERE identity_id=$1),
            (SELECT count(*) FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1),
            (SELECT count(*) FROM identity.recovery_scope_catalog_preparations
                WHERE identity_id=$1 AND provider_response_bytes IS NOT NULL)",
    )
    .bind(identity.to_string())
    .fetch_one(harness.admin_pool())
    .await
}

fn catalog_body(
    identity: IdentityId,
    head: IdentityLogHead,
    signer: &SigningKey,
    generation: SafeUint,
    previous: Option<Sha256Digest>,
    merkle: [u8; 32],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let ciphertext = b"opaque-encrypted-catalog-v1".to_vec();
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(identity.to_string())),
        field(3, generation.to_canonical_value()),
        field(
            4,
            previous.map_or(CanonicalValue::Null, |value| value.to_canonical_value()),
        ),
        field(5, CanonicalValue::Unsigned(1)),
        field(6, CanonicalValue::Bytes(merkle.to_vec())),
        field(
            7,
            Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(8, head.sequence().to_canonical_value()),
        field(9, head.hash().to_canonical_value()),
        field(10, at(2_500).to_canonical_value()),
        field(11, at(250_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, CATALOG_HEAD_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(12, signature.to_canonical_value()));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Map(signed_fields)),
        field(2, CanonicalValue::Bytes(ciphertext)),
    ]))?)
}

fn preparation_body(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    identity: IdentityId,
    device: DeviceId,
    signer: &SigningKey,
    recipient: [u8; 32],
    head: IdentityLogHead,
    response_capability: [u8; 32],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(device.to_string())),
        field(5, public(signer).to_canonical_value()),
        field(6, CanonicalValue::Bytes(recipient.to_vec())),
        field(7, head.sequence().to_canonical_value()),
        field(8, head.hash().to_canonical_value()),
        field(9, CanonicalValue::Bytes(vec![60; 32])),
        field(10, at(4_500).to_canonical_value()),
        field(11, at(200_000).to_canonical_value()),
        field(
            12,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
    ]);
    let signature = domain_signature(signer, PREPARATION_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(13, signature.to_canonical_value()));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(
        signed_fields,
    ))?)
}

fn provider_body(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    catalog: Sha256Digest,
    device: DeviceId,
    signer: &SigningKey,
    authority: Sha256Digest,
    recipient: [u8; 32],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let ciphertext = b"opaque-hpke-response-v1".to_vec();
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, catalog.to_canonical_value()),
        field(4, CanonicalValue::Text(device.to_string())),
        field(5, public(signer).to_canonical_value()),
        field(6, authority.to_canonical_value()),
        field(
            7,
            Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, &recipient).to_canonical_value(),
        ),
        field(8, CanonicalValue::Bytes(ciphertext.clone())),
        field(
            9,
            Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(10, at(200_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(11, signature.to_canonical_value()));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(
        signed_fields,
    ))?)
}

fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
    let root_key = public(root);
    let recovery_key = public(recovery);
    let identity = IdentityId::derive(root_key.as_domain_key());
    signed_event(
        root,
        identity,
        1,
        None,
        1_000,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: signature(
                recovery,
                &genesis_recovery_acceptance_input(identity, root_key, recovery_key).unwrap(),
            ),
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "test fixture names every signed device-add binding explicitly"
)]
fn device_add(
    root: &SigningKey,
    identity: IdentityId,
    device: DeviceId,
    key: &SigningKey,
    encryption: u8,
    sequence: u64,
    previous: Sha256Digest,
    time: i64,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        device,
        public(key),
        DeviceEncryptionPublicKey::try_from([encryption; 32]).unwrap(),
        public(root),
        at(time),
    )
    .unwrap();
    let certificate = DeviceCertificateV1::signed(
        unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap();
    signed_event(
        root,
        identity,
        sequence,
        Some(previous),
        time,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    time: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        safe(sequence),
        previous,
        at(time),
        payload,
        public(signer),
    )
    .unwrap();
    IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}

fn append_command(
    seed: u8,
    expected: Option<IdentityLogHead>,
    event: &IdentityLogEventV1,
) -> Result<IdentityAppendCommand, Box<dyn Error>> {
    Ok(IdentityAppendCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        expected,
        event.to_deterministic_cbor()?,
    )?)
}

fn committed(outcome: IdentityAppendOutcome) -> Result<IdentityLogHead, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt.head()),
        other => Err(format!("expected committed identity head: {other:?}").into()),
    }
}

fn domain_signature(
    key: &SigningKey,
    domain: &[u8],
    value: &CanonicalValue,
) -> Result<Ed25519Signature, Box<dyn Error>> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&encode_deterministic_cbor(value)?);
    Ok(signature(key, &input))
}

fn field(key: u64, value: CanonicalValue) -> (CanonicalValue, CanonicalValue) {
    (CanonicalValue::Unsigned(key), value)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).unwrap()
}

fn at(value: i64) -> UtcMillis {
    UtcMillis::new(value).unwrap()
}

struct TestClock(AtomicI64);

impl TestClock {
    const fn new(value: i64) -> Self {
        Self(AtomicI64::new(value))
    }

    fn set(&self, value: i64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
