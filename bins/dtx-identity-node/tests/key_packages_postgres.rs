#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{Clock, ClockError, DeviceId, DeviceSessionId, IdentityId, KeyPackageId};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    DEVICE_SESSION_AUTHORIZATION_SCHEME, IdentityBootstrapState, KEY_PACKAGE_CLAIM_CONTENT_TYPE,
    KEY_PACKAGE_CLAIM_PATH, KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE,
    KEY_PACKAGE_PUBLISH_CONTENT_TYPE, KEY_PACKAGE_PUBLISH_PATH_TEMPLATE,
    KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE, identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository,
    IdentityPgStore, device_session_proof_input, key_package_publish_signature_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

const AUDIENCE: &str = "https://identity.test";

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/PostgreSQL boundary test keeps opaque package binding, one-time claim, response-loss replay, and revocation rechecks coherent"
)]
async fn opaque_key_packages_are_device_bound_idempotent_and_claimed_once()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        ),
    );
    let publisher = enroll_active_device(&store, 61, 62, 63, [64; 32]).await?;
    let requester = enroll_active_device(&store, 71, 72, 73, [74; 32]).await?;

    let zero_head_package_id = KeyPackageId::new();
    let zero_head_publish = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        zero_head_package_id,
        SafeUint::new(0)?,
        publisher.head_hash,
        UtcMillis::new(600_000)?,
        &[0x00],
    )?;
    let zero_head_response = send_key_package_publish(
        app.clone(),
        "key-package-publish-zero-head",
        publisher.session_id,
        publisher.session_secret,
        zero_head_package_id,
        zero_head_publish,
    )
    .await?;
    assert_eq!(
        zero_head_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_safe_error(zero_head_response, "KEY_PACKAGE_INVALID").await?;

    let invalid_signature_package_id = KeyPackageId::new();
    let mut invalid_signature_publish = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        invalid_signature_package_id,
        publisher.head_sequence,
        publisher.head_hash,
        UtcMillis::new(600_000)?,
        &[0x01],
    )?;
    let signature_tail = invalid_signature_publish
        .last_mut()
        .ok_or("key package signature test body was unexpectedly empty")?;
    *signature_tail ^= 1;
    let invalid_signature_response = send_key_package_publish(
        app.clone(),
        "key-package-publish-invalid-signature",
        publisher.session_id,
        publisher.session_secret,
        invalid_signature_package_id,
        invalid_signature_publish,
    )
    .await?;
    assert_eq!(
        invalid_signature_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_safe_error(invalid_signature_response, "KEY_PACKAGE_INVALID").await?;

    let package_id = KeyPackageId::new();
    let expires_at = UtcMillis::new(600_000)?;
    let package_bytes = vec![0xd0, 0x0d, 0xfe, 0xed];
    let publish_body = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        package_id,
        publisher.head_sequence,
        publisher.head_hash,
        expires_at,
        &package_bytes,
    )?;
    let publish_response = send_key_package_publish(
        app.clone(),
        "key-package-publish-0001",
        publisher.session_id,
        publisher.session_secret,
        package_id,
        publish_body.clone(),
    )
    .await?;
    assert_eq!(publish_response.status(), StatusCode::CREATED);
    assert_eq!(
        publish_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE)
    );
    let publish_receipt = to_bytes(publish_response.into_body(), 16_384)
        .await?
        .to_vec();
    let publish_replay = send_key_package_publish(
        app.clone(),
        "key-package-publish-0001",
        publisher.session_id,
        publisher.session_secret,
        package_id,
        publish_body.clone(),
    )
    .await?;
    assert_eq!(publish_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(publish_replay.into_body(), 16_384).await?.to_vec(),
        publish_receipt
    );

    let changed_publish = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        package_id,
        publisher.head_sequence,
        publisher.head_hash,
        expires_at,
        &[0x00, 0x01, 0x02],
    )?;
    let publish_conflict = send_key_package_publish(
        app.clone(),
        "key-package-publish-0001",
        publisher.session_id,
        publisher.session_secret,
        package_id,
        changed_publish,
    )
    .await?;
    assert_eq!(publish_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(publish_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let claim_body = key_package_claim_body(publisher.identity_id, publisher.device_id)?;
    let (first_claim, second_claim) = tokio::join!(
        send_key_package_claim(
            app.clone(),
            "key-package-claim-0001",
            requester.session_id,
            requester.session_secret,
            claim_body.clone(),
        ),
        send_key_package_claim(
            app.clone(),
            "key-package-claim-0001",
            requester.session_id,
            requester.session_secret,
            claim_body.clone(),
        ),
    );
    let first_claim = first_claim?;
    let second_claim = second_claim?;
    assert!(
        (first_claim.status() == StatusCode::CREATED && second_claim.status() == StatusCode::OK)
            || (first_claim.status() == StatusCode::OK
                && second_claim.status() == StatusCode::CREATED)
    );
    assert_eq!(
        first_claim
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE)
    );
    assert_eq!(
        to_bytes(first_claim.into_body(), 131_072).await?.to_vec(),
        publish_body
    );
    assert_eq!(
        to_bytes(second_claim.into_body(), 131_072).await?.to_vec(),
        publish_body
    );
    let claim_count: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.key_package_claims")
        .fetch_one(harness.identity_runtime_pool())
        .await?;
    assert_eq!(claim_count, 1);

    let changed_claim = key_package_claim_body(requester.identity_id, requester.device_id)?;
    let claim_conflict = send_key_package_claim(
        app.clone(),
        "key-package-claim-0001",
        requester.session_id,
        requester.session_secret,
        changed_claim,
    )
    .await?;
    assert_eq!(claim_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(claim_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let exhausted = send_key_package_claim(
        app.clone(),
        "key-package-claim-0002",
        requester.session_id,
        requester.session_secret,
        claim_body.clone(),
    )
    .await?;
    assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);
    assert_safe_error(exhausted, "KEY_PACKAGE_UNAVAILABLE").await?;

    let revoked_target_package_id = KeyPackageId::new();
    let revoked_target_package = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        revoked_target_package_id,
        publisher.head_sequence,
        publisher.head_hash,
        expires_at,
        &[0x01, 0x23, 0x45, 0x67],
    )?;
    let published_before_target_revoke = send_key_package_publish(
        app.clone(),
        "key-package-publish-0002",
        publisher.session_id,
        publisher.session_secret,
        revoked_target_package_id,
        revoked_target_package,
    )
    .await?;
    assert_eq!(published_before_target_revoke.status(), StatusCode::CREATED);

    revoke_active_device(&store, &publisher).await?;
    let revoked_target_claim = send_key_package_claim(
        app.clone(),
        "key-package-claim-0003",
        requester.session_id,
        requester.session_secret,
        claim_body.clone(),
    )
    .await?;
    assert_eq!(revoked_target_claim.status(), StatusCode::NOT_FOUND);
    assert_safe_error(revoked_target_claim, "KEY_PACKAGE_UNAVAILABLE").await?;

    revoke_active_device(&store, &requester).await?;
    let revoked_requester_claim = send_key_package_claim(
        app,
        "key-package-claim-0001",
        requester.session_id,
        requester.session_secret,
        claim_body,
    )
    .await?;
    assert_eq!(revoked_requester_claim.status(), StatusCode::UNAUTHORIZED);
    assert_safe_error(revoked_requester_claim, "DEVICE_AUTHENTICATION_FAILED").await?;

    let pruned: i64 = sqlx::query_scalar("SELECT identity.prune_expired_key_packages($1, $2)")
        .bind(1_000_000_i64)
        .bind(16_i32)
        .fetch_one(harness.identity_runtime_pool())
        .await?;
    assert_eq!(pruned, 2);
    let retained: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM identity.key_packages),
             (SELECT count(*) FROM identity.key_package_publish_claims),
             (SELECT count(*) FROM identity.key_package_claims),
             (SELECT count(*) FROM identity.key_package_claim_receipts)",
    )
    .fetch_one(harness.identity_runtime_pool())
    .await?;
    assert_eq!(retained, (0, 0, 0, 0));
    Ok(())
}

struct ActiveDevice {
    root: SigningKey,
    device: SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    head_sequence: SafeUint,
    head_hash: Sha256Digest,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

async fn enroll_active_device(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-key-package-bootstrap\0", &[root_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(1_200)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let device_id = DeviceId::new();
    let initial = device_add(
        &root,
        &device,
        identity_id,
        device_id,
        genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let head_hash = initial.entry_hash()?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(b"test-key-package-initial\0", &[root_seed]),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(1_300)?,
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
            UtcMillis::new(2_000)?,
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
        Sha256Digest::hash_domain(b"test-key-package-session\0", &[root_seed]),
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
            .complete(store, &completion, UtcMillis::new(2_000)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        root,
        device,
        identity_id,
        device_id,
        head_sequence: SafeUint::new(2)?,
        head_hash,
        session_id,
        session_secret,
    })
}

async fn revoke_active_device(
    store: &IdentityPgStore,
    active: &ActiveDevice,
) -> Result<(), Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, active.identity_id)
        .await?
        .ok_or("identity log missing before device revoke")?
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
            b"test-key-package-revoke\0",
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

#[allow(clippy::too_many_arguments)]
fn key_package_publish_body(
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    package_id: KeyPackageId,
    head_sequence: SafeUint,
    head_hash: Sha256Digest,
    expires_at: UtcMillis,
    opaque_key_package: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let detached_signature = signature(
        device,
        &key_package_publish_signature_input(
            identity_id,
            device_id,
            package_id,
            head_sequence,
            head_hash,
            expires_at,
            opaque_key_package,
        )?,
    );
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(package_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            head_sequence.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(6), head_hash.to_canonical_value()),
        (CanonicalValue::Unsigned(7), expires_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Bytes(opaque_key_package.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(9),
            detached_signature.to_canonical_value(),
        ),
    ]))?)
}

fn key_package_claim_body(
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(target_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
    ]))?)
}

async fn send_key_package_publish(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    package_id: KeyPackageId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri(KEY_PACKAGE_PUBLISH_PATH_TEMPLATE.replace("{package_id}", &package_id.to_string()))
            .header(header::CONTENT_TYPE, KEY_PACKAGE_PUBLISH_CONTENT_TYPE)
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

async fn send_key_package_claim(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(KEY_PACKAGE_CLAIM_PATH)
            .header(header::CONTENT_TYPE, KEY_PACKAGE_CLAIM_CONTENT_TYPE)
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

fn device_session_authorization(session_id: DeviceSessionId, session_secret: [u8; 32]) -> String {
    format!(
        "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
        Base64UrlUnpadded::encode_string(&session_secret)
    )
}

async fn assert_safe_error(
    response: axum::response::Response,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
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
    let body = to_bytes(response.into_body(), 16_384).await?;
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    Ok(())
}

fn genesis(
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
fn device_add(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
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
        DeviceEncryptionPublicKey::try_from([7_u8; 32])?,
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

fn signed_event(
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

fn public_key(key: &SigningKey) -> Result<SigningPublicKey, Box<dyn Error>> {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).map_err(Into::into)
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0)
    }
}
