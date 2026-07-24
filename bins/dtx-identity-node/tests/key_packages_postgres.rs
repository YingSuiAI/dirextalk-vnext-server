#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_contact::{contact_receipt_capability_hash, invite_capability_hash};
use dtx_domain::{
    Clock, ClockError, DeviceId, DeviceSessionId, IdentityId, InviteCapabilityId, KeyPackageId,
    RequestId,
};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    IdentityLogPageV1, UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1,
    device_certificate_signature_input, genesis_recovery_acceptance_input,
    identity_log_signature_input,
};
use dtx_identity_node::{
    CONTACT_INVITE_CONTENT_TYPE, CONTACT_INVITE_SECRET_HEADER, CONTACT_INVITES_PATH,
    CONTACT_PENDING_CONTENT_TYPE, CONTACT_RECEIPT_CONTENT_TYPE, CONTACT_RECEIPT_PATH,
    CONTACT_RECEIPT_SECRET_HEADER, CONTACT_REQUEST_CONTENT_TYPE, CONTACT_REQUESTS_PATH,
    CONTACT_REVIEW_CONTENT_TYPE, CONTACT_REVIEW_PATH, DEVICE_SESSION_AUTHORIZATION_SCHEME,
    IDENTITY_ORIGIN_HEADER, IdentityBootstrapState, KEY_PACKAGE_CLAIM_CONTENT_TYPE,
    KEY_PACKAGE_CLAIM_PATH, KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE,
    KEY_PACKAGE_FEDERATED_CLAIM_CONTENT_TYPE, KEY_PACKAGE_FEDERATED_CLAIM_PATH,
    KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER, KEY_PACKAGE_PUBLISH_CONTENT_TYPE,
    KEY_PACKAGE_PUBLISH_PATH_TEMPLATE, KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE,
    identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionOutcome,
    DeviceSessionRepository, FEDERATED_KEY_PACKAGE_CLAIM_METHOD, FEDERATED_KEY_PACKAGE_CLAIM_PATH,
    IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository, IdentityPgStore,
    KeyPackageClaimCommand, device_session_proof_input, federated_key_package_claim_body_digest,
    federated_key_package_claim_signature_input, key_package_publish_signature_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

const AUDIENCE: &str = "https://identity.test";

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

fn contact_invite_body(
    owner: &ActiveDevice,
    invite_id: InviteCapabilityId,
    secret: [u8; 32],
    max_uses: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut fields = vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(invite_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(owner.identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(owner.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            invite_capability_hash(&secret).to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Unsigned(u64::from(max_uses)),
        ),
        (
            CanonicalValue::Unsigned(7),
            UtcMillis::new(1_900)?.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(8),
            UtcMillis::new(600_000)?.to_canonical_value(),
        ),
    ];
    let unsigned = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone()))?;
    let mut input = b"dirextalk.contact-invite-signature.v1\0".to_vec();
    input.extend_from_slice(&unsigned);
    fields.push((
        CanonicalValue::Unsigned(9),
        signature(&owner.device, &input).to_canonical_value(),
    ));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

fn contact_request_body(
    request_id: RequestId,
    invite_id: InviteCapabilityId,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    receipt_secret: [u8; 32],
    sealed_request: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let receipt_hash = contact_receipt_capability_hash(&receipt_secret);
    let aad = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(invite_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(target_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            receipt_hash.to_canonical_value(),
        ),
    ]);
    let digest = contact_test_digest(
        b"dirextalk.contact-request-sealed-aad.v1\0",
        &encode_deterministic_cbor(&aad)?,
    );
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(invite_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(target_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            receipt_hash.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Bytes(sealed_request.to_vec()),
        ),
        (CanonicalValue::Unsigned(8), digest.to_canonical_value()),
    ]))?)
}

fn contact_review_body(
    request_id: RequestId,
    invite_id: InviteCapabilityId,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    sealed_delivery: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let aad = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(invite_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(target_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
        (CanonicalValue::Unsigned(6), CanonicalValue::Unsigned(1)),
    ]);
    let digest = contact_test_digest(
        b"dirextalk.contact-delivery-sealed-aad.v1\0",
        &encode_deterministic_cbor(&aad)?,
    );
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(request_id.to_string()),
        ),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(sealed_delivery.to_vec()),
        ),
        (CanonicalValue::Unsigned(5), digest.to_canonical_value()),
    ]))?)
}

fn contact_test_digest(domain: &[u8], exact: &[u8]) -> Sha256Digest {
    Sha256Digest::hash_domain(domain, exact)
}

async fn send_contact_invite(
    app: axum::Router,
    idempotency_key: &str,
    owner: &ActiveDevice,
    secret: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(CONTACT_INVITES_PATH)
            .header(header::CONTENT_TYPE, CONTACT_INVITE_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(owner.session_id, owner.session_secret),
            )
            .header(
                CONTACT_INVITE_SECRET_HEADER,
                Base64UrlUnpadded::encode_string(&secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_contact_request(
    app: axum::Router,
    secret: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(CONTACT_REQUESTS_PATH)
            .header(header::CONTENT_TYPE, CONTACT_REQUEST_CONTENT_TYPE)
            .header(
                CONTACT_INVITE_SECRET_HEADER,
                Base64UrlUnpadded::encode_string(&secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_contact_pending(
    app: axum::Router,
    owner: &ActiveDevice,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .uri(CONTACT_REQUESTS_PATH)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(owner.session_id, owner.session_secret),
            )
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_contact_review(
    app: axum::Router,
    idempotency_key: &str,
    owner: &ActiveDevice,
    request_id: RequestId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(CONTACT_REVIEW_PATH.replace("{request_id}", &request_id.to_string()))
            .header(header::CONTENT_TYPE, CONTACT_REVIEW_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(owner.session_id, owner.session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_contact_receipt(
    app: axum::Router,
    request_id: RequestId,
    secret: [u8; 32],
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .uri(CONTACT_RECEIPT_PATH.replace("{request_id}", &request_id.to_string()))
            .header(
                CONTACT_RECEIPT_SECRET_HEADER,
                Base64UrlUnpadded::encode_string(&secret),
            )
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
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

#[allow(clippy::too_many_arguments)]
fn federated_key_package_claim_proof(
    requester: &ActiveDevice,
    requester_origin: &str,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    exact_claim_body: &[u8],
    idempotency_key: &str,
    nonce: [u8; 32],
) -> Result<String, Box<dyn Error>> {
    let idempotency_key_hash = Sha256Digest::hash_domain(
        b"dirextalk.key-package-http-claim-idempotency-key.v1\0",
        idempotency_key.as_bytes(),
    );
    let command = KeyPackageClaimCommand::new(
        idempotency_key_hash,
        target_identity_id,
        target_device_id,
        exact_claim_body.to_vec(),
    )?;
    let body_digest = federated_key_package_claim_body_digest(&command);
    let issued_at = UtcMillis::new(1_900)?;
    let expires_at = UtcMillis::new(301_900)?;
    let signature = signature(
        &requester.device,
        &federated_key_package_claim_signature_input(
            requester_origin,
            requester.identity_id,
            requester.device_id,
            target_identity_id,
            target_device_id,
            FEDERATED_KEY_PACKAGE_CLAIM_METHOD,
            FEDERATED_KEY_PACKAGE_CLAIM_PATH,
            body_digest,
            issued_at,
            expires_at,
            nonce,
            idempotency_key_hash,
        )?,
    );
    let exact = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(requester_origin.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(requester.identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(requester.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(target_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(FEDERATED_KEY_PACKAGE_CLAIM_METHOD.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(FEDERATED_KEY_PACKAGE_CLAIM_PATH.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(9),
            body_digest.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(10), issued_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(11),
            expires_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(12),
            CanonicalValue::Bytes(nonce.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(13),
            idempotency_key_hash.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(14), signature.to_canonical_value()),
    ]))?;
    Ok(Base64UrlUnpadded::encode_string(&exact))
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

async fn send_federated_key_package_claim(
    app: axum::Router,
    requester_origin: &str,
    idempotency_key: &str,
    proof: &str,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(KEY_PACKAGE_FEDERATED_CLAIM_PATH)
            .header(
                header::CONTENT_TYPE,
                KEY_PACKAGE_FEDERATED_CLAIM_CONTENT_TYPE,
            )
            .header(header::ACCEPT, KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(IDENTITY_ORIGIN_HEADER, requester_origin)
            .header(KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER, proof)
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

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    include!("fixtures/key_packages_publish.inc.rs");
    include!("fixtures/key_packages_federated.inc.rs");
    include!("fixtures/contact_delivery.inc.rs");
}
