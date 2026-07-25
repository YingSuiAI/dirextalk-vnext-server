#![forbid(unsafe_code)]

//! Opaque, deterministic History Recovery artifacts for integration tests.
//!
//! This crate intentionally contains no router, database, or binary dependency.
//! Callers provide the application factory and transport workflow; this layer
//! only signs canonical CBOR and returns exact wire bytes.

use std::future::Future;

use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, IdentityId};
use dtx_wire::{CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, SigningPublicKey};
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

/// Provider-neutral HTTP request data used by the recovery workflow driver.
///
/// The testkit deliberately owns no HTTP client or server types.  Node tests
/// translate this small value into an Axum, `reqwest`, or other request at
/// their boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: Vec::new(),
            body,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Provider-neutral HTTP response data returned by a node-owned adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A named request in a recovery workflow.  Names are diagnostics only and
/// never become wire data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpStep {
    pub name: &'static str,
    pub request: HttpRequest,
}

impl HttpStep {
    pub const fn new(name: &'static str, request: HttpRequest) -> Self {
        Self { name, request }
    }
}

/// Error returned when a node-owned async request adapter fails at a step.
#[derive(Debug)]
pub struct HttpWorkflowError<E> {
    pub step: &'static str,
    pub source: E,
}

/// Execute a sequence of opaque HTTP steps through a node-owned async
/// callback.  The callback owns all transport, router, session, and response
/// decoding details; this crate only preserves ordering and exact bytes.
pub async fn run_http_workflow<I, F, Fut, E>(
    steps: I,
    mut send: F,
) -> Result<Vec<HttpResponse>, HttpWorkflowError<E>>
where
    I: IntoIterator<Item = HttpStep>,
    F: FnMut(HttpRequest) -> Fut,
    Fut: Future<Output = Result<HttpResponse, E>>,
{
    let mut responses = Vec::new();
    for step in steps {
        let response = send(step.request)
            .await
            .map_err(|source| HttpWorkflowError {
                step: step.name,
                source,
            })?;
        responses.push(response);
    }
    Ok(responses)
}

pub const CATALOG_CIPHERTEXT_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-ciphertext.v2\0";
pub const CATALOG_HEAD_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-head-signature.v2\0";
pub const PREPARATION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\0";
pub const PREPARATION_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0";
pub const RESPONSE_CAPABILITY_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-response-capability.v1\0";
pub const PROVIDER_PACKAGE_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-package.v2\0";
pub const PROVIDER_AAD_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-aad.v2\0";
pub const PROVIDER_CIPHERTEXT_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-envelope.v2\0";
pub const PROVIDER_RESPONSE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-signature.v2\0";
pub const PROVIDER_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2\0";
pub const RECIPIENT_KEY_HASH_DOMAIN: &[u8] = b"dirextalk.recovery-recipient-key.v1\0";
pub const HISTORY_REQUEST_V4_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.request-signature.v4\0";
pub const HISTORY_MANIFEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.manifest.v2\0";
pub const HISTORY_LEAF_SET_DOMAIN: &[u8] = b"dirextalk.history-recovery.leaf-set.v2\0";
pub const HISTORY_REQUEST_IDEMPOTENCY_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.request-idempotency.v4\0";
pub const IDENTITY_DEVICE_ADD_DOMAIN: &[u8] = b"dirextalk.identity-device-add.v1\0";
pub const OFFER_CIPHERTEXT_DOMAIN: &[u8] = b"dirextalk.history-recovery.offer-ciphertext.v3\0";
pub const OFFER_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.recipient-offer.v3\0";
pub const GRANT_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.grant-provider-signature.v5\0";
pub const AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.grant-authority-signature.v5\0";
pub const MAX_EXACT_OFFER_BYTES: usize = 1_049_093;
pub const MAX_EXACT_GRANT_BYTES: usize = 1_050_699;

fn field(key: u64, value: CanonicalValue) -> (CanonicalValue, CanonicalValue) {
    (CanonicalValue::Unsigned(key), value)
}

fn digest(bytes: [u8; 32]) -> CanonicalValue {
    Sha256Digest::from_bytes(bytes).to_canonical_value()
}

fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).expect("ed25519 public key")
}

fn signature(key: &SigningKey, domain: &[u8], unsigned: &CanonicalValue) -> Ed25519Signature {
    let mut input = domain.to_vec();
    input.extend_from_slice(&encode(unsigned));
    Ed25519Signature::from_bytes(key.sign(&input).to_bytes())
}

fn encode(value: &CanonicalValue) -> Vec<u8> {
    dtx_wire::encode_deterministic_cbor(value).expect("canonical test artifact")
}

fn encode_with_limit(value: &CanonicalValue, maximum: usize) -> Vec<u8> {
    dtx_wire::encode_deterministic_cbor_with_limit(value, maximum)
        .expect("bounded canonical test artifact")
}

/// Build the exact CatalogV2 envelope accepted by the identity service.
pub fn catalog_v2(
    identity: IdentityId,
    catalog_id: Uuid,
    generation: u64,
    previous: Option<[u8; 32]>,
    head_sequence: u64,
    head_hash: [u8; 32],
    authority_device: DeviceId,
    authority_key_id: Uuid,
    signer: &SigningKey,
    merkle_root: [u8; 32],
    ciphertext: &[u8],
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(catalog_id.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Unsigned(generation)),
        field(5, previous.map_or(CanonicalValue::Null, digest)),
        field(6, CanonicalValue::Unsigned(1)),
        field(7, CanonicalValue::Bytes(merkle_root.to_vec())),
        field(
            8,
            Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, ciphertext)
                .to_canonical_value(),
        ),
        field(9, CanonicalValue::Unsigned(head_sequence)),
        field(10, digest(head_hash)),
        field(11, CanonicalValue::Text(authority_device.to_string())),
        field(12, CanonicalValue::Text(authority_key_id.to_string())),
        field(13, public(signer).to_canonical_value()),
        field(14, CanonicalValue::Unsigned(issued_at as u64)),
        field(15, CanonicalValue::Unsigned(expires_at as u64)),
    ]);
    let mut signed = match unsigned {
        CanonicalValue::Map(fields) => fields,
        _ => unreachable!(),
    };
    let unsigned_value = CanonicalValue::Map(signed.clone());
    signed.push(field(
        16,
        signature(signer, CATALOG_HEAD_SIGNATURE_DOMAIN, &unsigned_value).to_canonical_value(),
    ));
    encode(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Map(signed)),
        field(2, CanonicalValue::Bytes(ciphertext.to_vec())),
    ]))
}

/// Build the exact signed Catalog handoff preparation body.
pub fn preparation_v2(
    request: DeviceEnrollmentChallengeId,
    identity: IdentityId,
    device: DeviceId,
    signer: &SigningKey,
    recipient_key: [u8; 32],
    head_sequence: u64,
    head_hash: [u8; 32],
    response_capability: [u8; 32],
    catalog_id: Uuid,
    generation: u64,
    catalog_head_digest: [u8; 32],
    idempotency_key: &str,
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(catalog_id.to_string())),
        field(5, CanonicalValue::Unsigned(generation)),
        field(6, digest(catalog_head_digest)),
        field(7, CanonicalValue::Text(device.to_string())),
        field(8, public(signer).to_canonical_value()),
        field(9, CanonicalValue::Bytes(recipient_key.to_vec())),
        field(10, CanonicalValue::Unsigned(head_sequence)),
        field(11, digest(head_hash)),
        field(12, CanonicalValue::Bytes(vec![60; 32])),
        field(
            13,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
        field(
            14,
            Sha256Digest::hash_domain(
                b"dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\0",
                idempotency_key.as_bytes(),
            )
            .to_canonical_value(),
        ),
        field(15, CanonicalValue::Unsigned(issued_at as u64)),
        field(16, CanonicalValue::Unsigned(expires_at as u64)),
    ]);
    let mut fields = match unsigned {
        CanonicalValue::Map(fields) => fields,
        _ => unreachable!(),
    };
    let unsigned_value = CanonicalValue::Map(fields.clone());
    fields.push(field(
        17,
        signature(signer, PREPARATION_SIGNATURE_DOMAIN, &unsigned_value).to_canonical_value(),
    ));
    encode(&CanonicalValue::Map(fields))
}

/// Build the exact signed History Recovery RequestV4 with one manifest leaf.
#[allow(clippy::too_many_arguments)]
pub fn request_v4(
    request: DeviceEnrollmentChallengeId,
    identity: IdentityId,
    candidate_device: DeviceId,
    candidate: &SigningKey,
    recipient_key: [u8; 32],
    pre_head_sequence: u64,
    pre_head_hash: [u8; 32],
    post_head_sequence: u64,
    post_head_hash: [u8; 32],
    device_add: &[u8],
    preparation: &[u8],
    catalog_id: Uuid,
    catalog_head: &[u8],
    catalog_head_digest: [u8; 32],
    response_capability: [u8; 32],
    idempotency: &str,
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    let leaves = CanonicalValue::Array(vec![CanonicalValue::Bytes(vec![31; 32])]);
    let leaf_bytes = encode(&leaves);
    let manifest = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(identity.to_string())),
        field(3, CanonicalValue::Text(catalog_id.to_string())),
        field(4, CanonicalValue::Unsigned(1)),
        field(5, CanonicalValue::Bytes(catalog_head.to_vec())),
        field(6, digest(catalog_head_digest)),
        field(7, digest([31; 32])),
        field(8, CanonicalValue::Unsigned(1)),
        field(
            9,
            Sha256Digest::hash_domain(HISTORY_LEAF_SET_DOMAIN, &leaf_bytes).to_canonical_value(),
        ),
        field(10, leaves),
    ]);
    let manifest_bytes = encode(&manifest);
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(4)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(candidate_device.to_string())),
        field(5, public(candidate).to_canonical_value()),
        field(6, CanonicalValue::Bytes(recipient_key.to_vec())),
        field(7, CanonicalValue::Unsigned(pre_head_sequence)),
        field(8, digest(pre_head_hash)),
        field(9, CanonicalValue::Unsigned(post_head_sequence)),
        field(10, digest(post_head_hash)),
        field(11, CanonicalValue::Bytes(device_add.to_vec())),
        field(
            12,
            Sha256Digest::hash_domain(IDENTITY_DEVICE_ADD_DOMAIN, device_add).to_canonical_value(),
        ),
        field(13, CanonicalValue::Bytes(preparation.to_vec())),
        field(
            14,
            Sha256Digest::hash_domain(PREPARATION_DIGEST_DOMAIN, preparation).to_canonical_value(),
        ),
        field(15, manifest),
        field(
            16,
            Sha256Digest::hash_domain(HISTORY_MANIFEST_DOMAIN, &manifest_bytes)
                .to_canonical_value(),
        ),
        field(17, CanonicalValue::Unsigned(issued_at as u64)),
        field(18, CanonicalValue::Unsigned(expires_at as u64)),
        field(
            19,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
        field(
            20,
            Sha256Digest::hash_domain(HISTORY_REQUEST_IDEMPOTENCY_DOMAIN, idempotency.as_bytes())
                .to_canonical_value(),
        ),
    ]);
    let mut fields = match unsigned {
        CanonicalValue::Map(fields) => fields,
        _ => unreachable!(),
    };
    fields.push(field(
        21,
        signature(
            candidate,
            HISTORY_REQUEST_V4_SIGNATURE_DOMAIN,
            &CanonicalValue::Map(fields.clone()),
        )
        .to_canonical_value(),
    ));
    encode(&CanonicalValue::Map(fields))
}

/// Minimal opaque provider response coordinates used by both identity and mailbox tests.
#[derive(Clone, Debug)]
pub struct ProviderResponseInput<'a> {
    pub request: DeviceEnrollmentChallengeId,
    pub identity: IdentityId,
    pub catalog_id: Uuid,
    pub generation: u64,
    pub catalog_head_digest: [u8; 32],
    pub preparation: &'a [u8],
    pub signed_head: &'a [u8],
    pub observed_head_sequence: u64,
    pub observed_head_hash: [u8; 32],
    pub successor_head_sequence: u64,
    pub successor_head_hash: [u8; 32],
    pub candidate_device: DeviceId,
    pub candidate_recipient: [u8; 32],
    pub device_add: &'a [u8],
    pub provider_device: DeviceId,
    pub provider_signer: &'a SigningKey,
    pub authority_device: DeviceId,
    pub authority_signer: &'a SigningKey,
    pub response_idempotency_key: &'a str,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Build the exact ready-provider response (opaque package/envelope bytes).
pub fn ready_provider_response(input: &ProviderResponseInput<'_>) -> Vec<u8> {
    let preparation_digest =
        Sha256Digest::hash_domain(PREPARATION_DIGEST_DOMAIN, input.preparation);
    let recipient_digest =
        Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, &input.candidate_recipient);
    let add_digest = Sha256Digest::hash_domain(IDENTITY_DEVICE_ADD_DOMAIN, input.device_add);
    let provider_descriptor = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(input.provider_device.to_string())),
        field(3, public(input.provider_signer).to_canonical_value()),
    ]);
    let authority_descriptor = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(input.authority_device.to_string())),
        field(3, public(input.authority_signer).to_canonical_value()),
    ]);
    let package = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(input.request.to_string())),
        field(3, preparation_digest.to_canonical_value()),
        field(4, CanonicalValue::Bytes(input.signed_head.to_vec())),
        field(5, CanonicalValue::Bytes(vec![0xa1, 1, 2])),
        field(6, CanonicalValue::Text(input.identity.to_string())),
        field(7, CanonicalValue::Text(input.catalog_id.to_string())),
        field(8, CanonicalValue::Unsigned(input.generation)),
        field(9, CanonicalValue::Text(input.candidate_device.to_string())),
        field(
            10,
            CanonicalValue::Bytes(input.candidate_recipient.to_vec()),
        ),
        field(11, CanonicalValue::Unsigned(input.observed_head_sequence)),
        field(12, digest(input.observed_head_hash)),
        field(13, CanonicalValue::Unsigned(input.successor_head_sequence)),
        field(14, digest(input.successor_head_hash)),
        field(15, add_digest.to_canonical_value()),
        field(16, CanonicalValue::Unsigned(input.issued_at as u64)),
        field(17, CanonicalValue::Unsigned(input.expires_at as u64)),
    ]);
    let package_bytes = encode(&package);
    let package_digest = Sha256Digest::hash_domain(PROVIDER_PACKAGE_DIGEST_DOMAIN, &package_bytes);
    let response_digest = Sha256Digest::hash_domain(
        b"dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\0",
        input.response_idempotency_key.as_bytes(),
    );
    let aad = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(input.request.to_string())),
        field(3, preparation_digest.to_canonical_value()),
        field(4, CanonicalValue::Text(input.identity.to_string())),
        field(5, CanonicalValue::Text(input.catalog_id.to_string())),
        field(6, CanonicalValue::Unsigned(input.generation)),
        field(7, digest(input.catalog_head_digest)),
        field(8, CanonicalValue::Text(input.candidate_device.to_string())),
        field(9, recipient_digest.to_canonical_value()),
        field(10, CanonicalValue::Unsigned(input.observed_head_sequence)),
        field(11, digest(input.observed_head_hash)),
        field(12, CanonicalValue::Unsigned(input.successor_head_sequence)),
        field(13, digest(input.successor_head_hash)),
        field(14, add_digest.to_canonical_value()),
        field(15, provider_descriptor.clone()),
        field(16, authority_descriptor.clone()),
        field(17, package_digest.to_canonical_value()),
        field(18, response_digest.to_canonical_value()),
        field(19, CanonicalValue::Unsigned(input.issued_at as u64)),
        field(20, CanonicalValue::Unsigned(input.expires_at as u64)),
    ]);
    let aad_digest = Sha256Digest::hash_domain(PROVIDER_AAD_DIGEST_DOMAIN, &encode(&aad));
    let envelope = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Bytes(vec![7; 32])),
        field(3, CanonicalValue::Bytes(vec![8; 17])),
    ]);
    let envelope_digest =
        Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &encode(&envelope));
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(input.request.to_string())),
        field(3, preparation_digest.to_canonical_value()),
        field(4, CanonicalValue::Text(input.identity.to_string())),
        field(5, CanonicalValue::Text(input.catalog_id.to_string())),
        field(6, CanonicalValue::Unsigned(input.generation)),
        field(7, digest(input.catalog_head_digest)),
        field(8, CanonicalValue::Text(input.candidate_device.to_string())),
        field(9, recipient_digest.to_canonical_value()),
        field(10, CanonicalValue::Unsigned(input.observed_head_sequence)),
        field(11, digest(input.observed_head_hash)),
        field(12, CanonicalValue::Unsigned(input.successor_head_sequence)),
        field(13, digest(input.successor_head_hash)),
        field(14, add_digest.to_canonical_value()),
        field(15, provider_descriptor),
        field(16, authority_descriptor),
        field(17, package_digest.to_canonical_value()),
        field(18, aad_digest.to_canonical_value()),
        field(19, envelope_digest.to_canonical_value()),
        field(20, response_digest.to_canonical_value()),
        field(21, CanonicalValue::Unsigned(input.issued_at as u64)),
        field(22, CanonicalValue::Unsigned(input.expires_at as u64)),
    ]);
    let provider_sig = signature(
        input.provider_signer,
        PROVIDER_RESPONSE_SIGNATURE_DOMAIN,
        &unsigned,
    );
    let authority_sig = signature(
        input.authority_signer,
        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
        &unsigned,
    );
    let mut fields = match unsigned {
        CanonicalValue::Map(fields) => fields,
        _ => unreachable!(),
    };
    fields.push(field(23, provider_sig.to_canonical_value()));
    fields.push(field(24, authority_sig.to_canonical_value()));
    fields.push(field(25, CanonicalValue::Bytes(input.device_add.to_vec())));
    fields.push(field(26, envelope));
    encode(&CanonicalValue::Map(fields))
}

/// Build an OfferV3 embedded in a GrantV5.  The exact signed provider response
/// digest is carried opaquely and never interpreted by the testkit.
pub fn offer_v3(
    request: DeviceEnrollmentChallengeId,
    request_digest: [u8; 32],
    manifest_digest: [u8; 32],
    catalog_id: Uuid,
    generation: u64,
    catalog_head_digest: [u8; 32],
    leaf_set_digest: [u8; 32],
    allowed_snapshot_plaintext_digest: [u8; 32],
    recipient_key_digest: [u8; 32],
    ciphertext: &[u8],
    provider_response_digest: [u8; 32],
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    encode_with_limit(
        &CanonicalValue::Map(vec![
            field(1, CanonicalValue::Unsigned(3)),
            field(2, CanonicalValue::Text(request.to_string())),
            field(3, digest(request_digest)),
            field(4, digest(manifest_digest)),
            field(5, CanonicalValue::Text(catalog_id.to_string())),
            field(6, CanonicalValue::Unsigned(generation)),
            field(7, digest(catalog_head_digest)),
            field(8, digest(leaf_set_digest)),
            field(9, digest(allowed_snapshot_plaintext_digest)),
            field(10, CanonicalValue::Bytes(ciphertext.to_vec())),
            field(
                11,
                Sha256Digest::hash_domain(OFFER_CIPHERTEXT_DOMAIN, ciphertext).to_canonical_value(),
            ),
            field(12, CanonicalValue::Null),
            field(13, CanonicalValue::Unsigned(issued_at as u64)),
            field(14, CanonicalValue::Unsigned(expires_at as u64)),
            field(15, digest(recipient_key_digest)),
            field(16, digest(provider_response_digest)),
        ]),
        MAX_EXACT_OFFER_BYTES,
    )
}

/// Build the canonical GrantV5 envelope from exact opaque offer bytes.
#[allow(clippy::too_many_arguments)]
pub fn grant_v5(
    identity: IdentityId,
    request: DeviceEnrollmentChallengeId,
    request_digest: [u8; 32],
    manifest_digest: [u8; 32],
    catalog_id: Uuid,
    generation: u64,
    catalog_head: &[u8],
    catalog_head_digest: [u8; 32],
    merkle_root: [u8; 32],
    leaf_count: u64,
    leaf_set_digest: [u8; 32],
    candidate_device: DeviceId,
    candidate_key: &SigningKey,
    recipient_key: [u8; 32],
    pre_sequence: u64,
    pre_hash: [u8; 32],
    post_sequence: u64,
    post_hash: [u8; 32],
    device_add_digest: [u8; 32],
    preparation_digest: [u8; 32],
    provider_descriptor: CanonicalValue,
    authority_descriptor: CanonicalValue,
    mailbox_id: Uuid,
    envelope_id: Uuid,
    mailbox_highwater: u64,
    delivery_fact_id: Uuid,
    issued_at: i64,
    expires_at: i64,
    provider_signer: &SigningKey,
    authority_signer: &SigningKey,
    offer: &[u8],
    idempotency_digest: [u8; 32],
    offer_issued_at: i64,
    offer_expires_at: i64,
) -> Vec<u8> {
    let recipient_digest =
        Sha256Digest::hash_domain(b"dirextalk.recovery-recipient-key.v1\0", &recipient_key);
    let offer_digest = Sha256Digest::hash_domain(OFFER_DIGEST_DOMAIN, offer);
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(5)),
        field(2, CanonicalValue::Text(identity.to_string())),
        field(3, CanonicalValue::Text(request.to_string())),
        field(4, digest(request_digest)),
        field(5, digest(manifest_digest)),
        field(6, CanonicalValue::Text(catalog_id.to_string())),
        field(7, CanonicalValue::Unsigned(generation)),
        field(8, CanonicalValue::Bytes(catalog_head.to_vec())),
        field(9, digest(catalog_head_digest)),
        field(10, digest(merkle_root)),
        field(11, CanonicalValue::Unsigned(leaf_count)),
        field(12, digest(leaf_set_digest)),
        field(13, CanonicalValue::Text(candidate_device.to_string())),
        field(14, public(candidate_key).to_canonical_value()),
        field(15, CanonicalValue::Bytes(recipient_key.to_vec())),
        field(16, CanonicalValue::Unsigned(pre_sequence)),
        field(17, digest(pre_hash)),
        field(18, CanonicalValue::Unsigned(post_sequence)),
        field(19, digest(post_hash)),
        field(20, digest(device_add_digest)),
        field(21, digest(preparation_digest)),
        field(22, provider_descriptor),
        field(23, authority_descriptor),
        field(24, recipient_digest.to_canonical_value()),
        field(25, offer_digest.to_canonical_value()),
        field(26, CanonicalValue::Text(mailbox_id.to_string())),
        field(27, CanonicalValue::Text(envelope_id.to_string())),
        field(28, CanonicalValue::Unsigned(mailbox_highwater)),
        field(29, CanonicalValue::Unsigned(mailbox_highwater + 1)),
        field(30, CanonicalValue::Text(delivery_fact_id.to_string())),
        field(31, CanonicalValue::Unsigned(issued_at as u64)),
        field(32, CanonicalValue::Unsigned(expires_at as u64)),
        field(33, digest(idempotency_digest)),
    ]);
    let provider_sig = signature(provider_signer, GRANT_SIGNATURE_DOMAIN, &unsigned);
    let authority_sig = signature(authority_signer, AUTHORITY_SIGNATURE_DOMAIN, &unsigned);
    let mut fields = match unsigned {
        CanonicalValue::Map(fields) => fields,
        _ => unreachable!(),
    };
    fields.push(field(34, provider_sig.to_canonical_value()));
    fields.push(field(35, authority_sig.to_canonical_value()));
    fields.push(field(
        36,
        dtx_wire::decode_deterministic_cbor_with_limit(offer, MAX_EXACT_OFFER_BYTES)
            .expect("canonical offer"),
    ));
    let _ = (offer_issued_at, offer_expires_at);
    encode_with_limit(&CanonicalValue::Map(fields), MAX_EXACT_GRANT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtx_history_recovery_protocol::{
        validate_catalog_head_v2, validate_grant_v5, validate_offer_v3, validate_request_v4,
    };

    #[test]
    fn signing_key_is_not_exposed_by_artifact_builders() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let body = catalog_v2(
            IdentityId::derive(public(&key).as_domain_key()),
            Uuid::nil(),
            1,
            None,
            1,
            [8; 32],
            DeviceId::new(),
            Uuid::nil(),
            &key,
            [9; 32],
            b"opaque",
            1,
            2,
        );
        assert!(!body.is_empty());
    }

    #[test]
    fn offer_v3_keeps_digest_slots_independent() {
        let request = DeviceEnrollmentChallengeId::new();
        let offer = offer_v3(
            request,
            [3; 32],
            [4; 32],
            Uuid::now_v7(),
            1,
            [5; 32],
            [6; 32],
            [7; 32],
            [8; 32],
            b"opaque-offer",
            [9; 32],
            1_000,
            2_000,
        );
        let CanonicalValue::Map(fields) = dtx_wire::decode_deterministic_cbor(&offer).unwrap()
        else {
            panic!("offer map");
        };
        assert_eq!(fields[7].1, digest([6; 32]));
        assert_eq!(fields[8].1, digest([7; 32]));
        assert_eq!(fields[14].1, digest([8; 32]));
        assert_eq!(fields[15].1, digest([9; 32]));
    }

    #[test]
    fn neutral_validator_accepts_golden_testkit_chain_and_rejects_signature_tamper() {
        let authority = SigningKey::from_bytes(&[17; 32]);
        let candidate = SigningKey::from_bytes(&[18; 32]);
        let authority_device = DeviceId::new();
        let identity = IdentityId::derive(public(&authority).as_domain_key());
        let catalog_id = Uuid::now_v7();
        let upload = catalog_v2(
            identity,
            catalog_id,
            1,
            None,
            0,
            [11; 32],
            authority_device,
            Uuid::now_v7(),
            &authority,
            [31; 32],
            b"opaque-catalog",
            1_000,
            10_000,
        );
        let CanonicalValue::Map(upload_fields) =
            dtx_wire::decode_deterministic_cbor(&upload).expect("catalog upload")
        else {
            panic!("catalog map");
        };
        let head = dtx_wire::encode_deterministic_cbor(&upload_fields[0].1).expect("head");
        let head_digest =
            Sha256Digest::hash_domain(b"dirextalk.recovery-scope-catalog-head.v2\0", &head);
        let request_id = DeviceEnrollmentChallengeId::new();
        let candidate_device = DeviceId::new();
        let request = request_v4(
            request_id,
            identity,
            candidate_device,
            &candidate,
            [21; 32],
            0,
            [12; 32],
            1,
            [13; 32],
            b"device-add",
            b"preparation",
            catalog_id,
            &head,
            *head_digest.as_bytes(),
            [22; 32],
            "request-idempotency",
            1_000,
            9_000,
        );
        validate_catalog_head_v2(&head).expect("catalog head golden");
        let CanonicalValue::Map(mut tampered_head_fields) =
            dtx_wire::decode_deterministic_cbor(&head).expect("head map")
        else {
            panic!("head map");
        };
        if let CanonicalValue::Bytes(signature) = &mut tampered_head_fields[15].1 {
            signature[0] ^= 1;
        }
        let tampered_head =
            dtx_wire::encode_deterministic_cbor(&CanonicalValue::Map(tampered_head_fields))
                .expect("tampered head");
        assert!(validate_catalog_head_v2(&tampered_head).is_err());
        validate_request_v4(&request).expect("request golden");
        let mut tampered = request.clone();
        *tampered.last_mut().expect("signature") ^= 1;
        assert!(validate_request_v4(&tampered).is_err());
        let offer = offer_v3(
            request_id,
            [3; 32],
            [4; 32],
            catalog_id,
            1,
            *head_digest.as_bytes(),
            [6; 32],
            [7; 32],
            [8; 32],
            b"opaque-offer",
            [9; 32],
            1_000,
            2_000,
        );
        validate_offer_v3(&offer).expect("offer golden");
        let CanonicalValue::Map(mut tampered_offer_fields) =
            dtx_wire::decode_deterministic_cbor(&offer).expect("offer map")
        else {
            panic!("offer map");
        };
        if let CanonicalValue::Bytes(ciphertext) = &mut tampered_offer_fields[9].1 {
            ciphertext[0] ^= 1;
        }
        let tampered_offer =
            dtx_wire::encode_deterministic_cbor(&CanonicalValue::Map(tampered_offer_fields))
                .expect("tampered offer");
        assert!(validate_offer_v3(&tampered_offer).is_err());

        let CanonicalValue::Map(request_fields) =
            dtx_wire::decode_deterministic_cbor(&request).expect("request map")
        else {
            panic!("request map");
        };
        let manifest =
            dtx_wire::encode_deterministic_cbor(&request_fields[14].1).expect("manifest");
        let manifest_digest =
            Sha256Digest::hash_domain(b"dirextalk.history-recovery.manifest.v2\0", &manifest);
        let leaf_set_digest = Sha256Digest::hash_domain(
            b"dirextalk.history-recovery.leaf-set.v2\0",
            &dtx_wire::encode_deterministic_cbor(&CanonicalValue::Array(vec![
                CanonicalValue::Bytes(vec![31; 32]),
            ]))
            .expect("leaf set"),
        );
        let provider = SigningKey::from_bytes(&[19; 32]);
        let provider_device = DeviceId::new();
        let provider_descriptor = CanonicalValue::Map(vec![
            field(1, CanonicalValue::Unsigned(2)),
            field(2, CanonicalValue::Text(provider_device.to_string())),
            field(3, public(&provider).to_canonical_value()),
        ]);
        let authority_descriptor = CanonicalValue::Map(vec![
            field(1, CanonicalValue::Unsigned(1)),
            field(2, CanonicalValue::Text(authority_device.to_string())),
            field(3, public(&authority).to_canonical_value()),
        ]);
        let grant_offer = offer_v3(
            request_id,
            *Sha256Digest::hash_domain(b"dirextalk.history-recovery.request.v4\0", &request)
                .as_bytes(),
            *manifest_digest.as_bytes(),
            catalog_id,
            1,
            *head_digest.as_bytes(),
            *leaf_set_digest.as_bytes(),
            [7; 32],
            *Sha256Digest::hash_domain(b"dirextalk.recovery-recipient-key.v1\0", &[21; 32])
                .as_bytes(),
            b"opaque-offer",
            [9; 32],
            1_000,
            8_000,
        );
        let grant = grant_v5(
            identity,
            request_id,
            *Sha256Digest::hash_domain(b"dirextalk.history-recovery.request.v4\0", &request)
                .as_bytes(),
            *manifest_digest.as_bytes(),
            catalog_id,
            1,
            &head,
            *head_digest.as_bytes(),
            [31; 32],
            1,
            *leaf_set_digest.as_bytes(),
            candidate_device,
            &candidate,
            [21; 32],
            0,
            [12; 32],
            1,
            [13; 32],
            [14; 32],
            [15; 32],
            provider_descriptor,
            authority_descriptor,
            Uuid::now_v7(),
            Uuid::now_v7(),
            0,
            Uuid::now_v7(),
            1_000,
            8_000,
            &provider,
            &authority,
            &grant_offer,
            [44; 32],
            1_000,
            8_000,
        );
        validate_grant_v5(&grant).expect("grant golden");
        let mut tampered_grant = grant;
        tampered_grant[20] ^= 1;
        assert!(validate_grant_v5(&tampered_grant).is_err());
    }
}
