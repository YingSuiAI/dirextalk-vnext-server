use super::{
    Base64UrlUnpadded, Body, CanonicalValue, DEVICE_ENROLLMENT_CAPABILITY_HEADER,
    DEVICE_SESSION_AUTHORIZATION_SCHEME, DeserializeOwned, DeviceEncryptionPublicKey,
    DeviceEnrollmentCapability, DeviceEnrollmentChallengeId, DeviceEnrollmentFailure, DeviceId,
    DeviceSessionCredential, DeviceSessionFailure, DeviceSessionId, Ed25519Signature, Encoding,
    HeaderMap, IDEMPOTENCY_KEY_HEADER, IdentityId, MAX_DEVICE_SESSION_REQUEST_BYTES, SafeUint,
    Sha256Digest, SigningPublicKey, UtcMillis, Zeroize, decode_deterministic_cbor,
    encode_deterministic_cbor, header, is_base64url_byte, to_bytes,
};
use dtx_identity_log::{IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1, IdentityLogEventV1};
use dtx_identity_persistence::{
    CatalogPreparationCommand, HISTORY_RECOVERY_REQUEST_V4_DIGEST_DOMAIN,
    HISTORY_RECOVERY_REQUEST_V4_SIGNATURE_DOMAIN, RecoveryResponseCapability, catalog_merkle_root,
    parse_signed_catalog_head_v2,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashSet;
use uuid::Uuid;

pub(crate) async fn parse_json_body<T>(body: Body) -> Result<T, DeviceSessionFailure>
where
    T: DeserializeOwned,
{
    let bytes = to_bytes(body, MAX_DEVICE_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
    if bytes.is_empty() {
        return Err(DeviceSessionFailure::InvalidRequest);
    }
    serde_json::from_slice(&bytes).map_err(|_| DeviceSessionFailure::InvalidRequest)
}

pub(crate) fn decode_base64url_32(value: &str) -> Result<[u8; 32], DeviceSessionFailure> {
    if value.len() != 43 || !value.bytes().all(is_base64url_byte) {
        return Err(DeviceSessionFailure::InvalidRequest);
    }
    let mut buffer = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(value, &mut buffer)
        .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
    if decoded.len() != 32 {
        buffer.zeroize();
        return Err(DeviceSessionFailure::InvalidRequest);
    }
    let result = buffer;
    Ok(result)
}

pub(crate) struct DeviceEnrollmentCandidateRequest {
    pub(crate) identity_id: IdentityId,
    pub(crate) target_device_id: DeviceId,
    pub(crate) target_device_signing_key: SigningPublicKey,
    pub(crate) target_device_encryption_key: DeviceEncryptionPublicKey,
    pub(crate) capability: DeviceEnrollmentCapability,
}

pub(crate) struct HistoryRecoveryCandidateRequest {
    pub(crate) request_id: DeviceEnrollmentChallengeId,
    pub(crate) identity_id: IdentityId,
    pub(crate) target_device_id: DeviceId,
    pub(crate) target_device_signing_key: SigningPublicKey,
    pub(crate) recipient_encryption_key: DeviceEncryptionPublicKey,
    pub(crate) observed_head_sequence: SafeUint,
    pub(crate) observed_head_hash: Sha256Digest,
    pub(crate) issued_at: UtcMillis,
    pub(crate) expires_at: UtcMillis,
    pub(crate) candidate_signature: Ed25519Signature,
    pub(crate) capability: DeviceEnrollmentCapability,
    pub(crate) exact_signed_request: Vec<u8>,
}

/// Exact candidate-signed History Recovery Request V4.  Nested catalog and
/// DeviceAdd objects remain opaque bytes after structural validation; their
/// owning validators consume the same bytes at the catalog boundary.
pub(crate) struct HistoryRecoveryRequestV4 {
    pub(crate) request_id: DeviceEnrollmentChallengeId,
    pub(crate) identity_id: IdentityId,
    pub(crate) target_device_id: DeviceId,
    pub(crate) target_device_signing_key: SigningPublicKey,
    pub(crate) recipient_encryption_key: DeviceEncryptionPublicKey,
    pub(crate) pre_head_sequence: SafeUint,
    pub(crate) pre_head_hash: Sha256Digest,
    pub(crate) post_head_sequence: SafeUint,
    pub(crate) post_head_hash: Sha256Digest,
    pub(crate) device_add_bytes: Vec<u8>,
    pub(crate) device_add_digest: Sha256Digest,
    pub(crate) preparation_bytes: Vec<u8>,
    pub(crate) preparation_digest: Sha256Digest,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) manifest_digest: Sha256Digest,
    pub(crate) issued_at: UtcMillis,
    pub(crate) expires_at: UtcMillis,
    pub(crate) response_capability_digest: Sha256Digest,
    pub(crate) idempotency_digest: Sha256Digest,
    pub(crate) candidate_signature: Ed25519Signature,
    pub(crate) exact_signed_request: Vec<u8>,
    pub(crate) request_digest: Sha256Digest,
}

pub(crate) fn parse_history_recovery_request_v4_identity(
    bytes: &[u8],
) -> Result<(DeviceEnrollmentChallengeId, IdentityId), DeviceEnrollmentFailure> {
    if bytes.is_empty() || bytes.len() > 37_114 {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 21)?;
    Ok((
        parse_cbor_challenge_id(cbor_field(fields, 2)?)?,
        parse_cbor_identity_id(cbor_field(fields, 3)?)?,
    ))
}

pub(crate) fn parse_history_recovery_request_v4(
    bytes: &[u8],
    enrollment_capability: DeviceEnrollmentCapability,
    response_capability: &RecoveryResponseCapability,
) -> Result<HistoryRecoveryRequestV4, DeviceEnrollmentFailure> {
    if bytes.is_empty() || bytes.len() > 37_114 {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 21)?;
    if cbor_field(fields, 1)? != &CanonicalValue::Unsigned(4) {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let unsigned = encode_deterministic_cbor(&CanonicalValue::Map(
        fields.iter().take(20).cloned().collect(),
    ))
    .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let request_id = parse_cbor_challenge_id(cbor_field(fields, 2)?)?;
    let identity_id = parse_cbor_identity_id(cbor_field(fields, 3)?)?;
    let target_device_id = parse_cbor_device_id(cbor_field(fields, 4)?)?;
    let target_device_signing_key =
        SigningPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(fields, 5)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let recipient_encryption_key =
        DeviceEncryptionPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(fields, 6)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    if target_device_signing_key.as_bytes() == recipient_encryption_key.as_bytes() {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let pre_head_sequence = match cbor_field(fields, 7)? {
        CanonicalValue::Unsigned(v) => {
            SafeUint::new(*v).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
        }
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    let pre_head_hash = Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 8)?)?);
    let post_head_sequence = match cbor_field(fields, 9)? {
        CanonicalValue::Unsigned(v) => {
            SafeUint::new(*v).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
        }
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    if post_head_sequence.get()
        != pre_head_sequence
            .get()
            .checked_add(1)
            .ok_or(DeviceEnrollmentFailure::InvalidRequest)?
    {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let post_head_hash = Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 10)?)?);
    let device_add_bytes = parse_cbor_bounded_bytes(cbor_field(fields, 11)?, 533)?;
    if device_add_bytes.is_empty() || device_add_bytes.len() > 533 {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let device_add_digest = Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 12)?)?);
    let expected_device_add =
        Sha256Digest::hash_domain(b"dirextalk.identity-device-add.v1\0", &device_add_bytes);
    if device_add_digest != expected_device_add {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let device_add = IdentityLogEventV1::decode_and_verify(&device_add_bytes)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    if device_add.wire() != IDENTITY_LOG_WIRE_VERSION
        || device_add.identity_id() != identity_id
        || device_add.sequence().get()
            != pre_head_sequence
                .get()
                .checked_add(1)
                .ok_or(DeviceEnrollmentFailure::InvalidRequest)?
        || device_add.previous_event_hash() != Some(pre_head_hash)
    {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = device_add.payload() else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    if certificate.identity_id() != identity_id
        || certificate.device_id() != target_device_id
        || certificate.device_signing_key() != target_device_signing_key
        || certificate.device_encryption_key() != recipient_encryption_key
    {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let preparation_bytes = parse_cbor_bounded_bytes(cbor_field(fields, 13)?, 532)?;
    if preparation_bytes.is_empty() || preparation_bytes.len() > 532 {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let preparation_digest = Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 14)?)?);
    let expected_preparation = Sha256Digest::hash_domain(
        b"dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0",
        &preparation_bytes,
    );
    if preparation_digest != expected_preparation {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let preparation_value = decode_deterministic_cbor(&preparation_bytes)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let preparation_fields = exact_cbor_fields(&preparation_value, 17)?;
    let preparation_idempotency =
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(preparation_fields, 14)?)?);
    let preparation = CatalogPreparationCommand::parse_v2(
        preparation_idempotency,
        preparation_bytes.clone(),
        enrollment_capability,
        response_capability,
    )
    .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let manifest_value = cbor_field(fields, 15)?;
    let manifest_fields = exact_cbor_fields(&manifest_value, 10)?;
    if cbor_field(manifest_fields, 1)? != &CanonicalValue::Unsigned(2) {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    if cbor_field(manifest_fields, 2)? != &CanonicalValue::Text(identity_id.to_string()) {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let manifest_catalog_id = match cbor_field(manifest_fields, 3)? {
        CanonicalValue::Text(value) => parse_uuid_v7_text(value)?,
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    let manifest_generation = match cbor_field(manifest_fields, 4)? {
        CanonicalValue::Unsigned(value) if *value > 0 => {
            SafeUint::new(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
        }
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    let signed_head_bytes = match cbor_field(manifest_fields, 5)? {
        CanonicalValue::Bytes(value) if !value.is_empty() && value.len() <= 466 => value,
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    let signed_head = parse_signed_catalog_head_v2(signed_head_bytes)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let signed_head_digest =
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(manifest_fields, 6)?)?);
    let merkle_root = Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(manifest_fields, 7)?)?);
    let leaf_count = match cbor_field(manifest_fields, 8)? {
        CanonicalValue::Unsigned(value) if (1..=1023).contains(value) => *value as usize,
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    let leaf_set_digest =
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(manifest_fields, 9)?)?);
    let CanonicalValue::Array(leaf_set) = cbor_field(manifest_fields, 10)? else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    if leaf_set.len() != leaf_count {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let mut seen = HashSet::with_capacity(leaf_set.len());
    let mut leaf_digests = Vec::with_capacity(leaf_set.len());
    for leaf in leaf_set {
        let CanonicalValue::Bytes(bytes) = leaf else {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        };
        if bytes.len() != 32 || !seen.insert(bytes.as_slice()) {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        }
        leaf_digests.push(Sha256Digest::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
        ));
    }
    let leaf_set_bytes = encode_deterministic_cbor(cbor_field(manifest_fields, 10)?)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    if leaf_set_digest
        != Sha256Digest::hash_domain(b"dirextalk.history-recovery.leaf-set.v2\0", &leaf_set_bytes)
        || manifest_catalog_id != signed_head.catalog_id
        || manifest_generation != signed_head.generation
        || signed_head_digest != signed_head.digest
        || catalog_merkle_root(&leaf_digests) != Some(merkle_root)
        || merkle_root != signed_head.merkle_root
        || signed_head.identity_id != identity_id
        || manifest_catalog_id != preparation.catalog_id
        || manifest_generation != preparation.catalog_generation
        || signed_head_digest != preparation.catalog_head_digest
    {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let manifest_bytes = encode_deterministic_cbor(manifest_value)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let manifest_digest = Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 16)?)?);
    if manifest_digest
        != Sha256Digest::hash_domain(b"dirextalk.history-recovery.manifest.v2\0", &manifest_bytes)
    {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let issued_at = parse_cbor_utc_nonnegative(cbor_field(fields, 17)?)?;
    let expires_at = parse_cbor_utc_nonnegative(cbor_field(fields, 18)?)?;
    if issued_at >= expires_at {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    if preparation.request_id != request_id
        || preparation.identity_id != identity_id
        || preparation.candidate_device_id != target_device_id
        || preparation.candidate_signing_key != target_device_signing_key
        || preparation.candidate_recipient_key != recipient_encryption_key
        || preparation.observed_head
            != dtx_identity_persistence::IdentityLogHead::observed(
                identity_id,
                pre_head_sequence,
                pre_head_hash,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
        || issued_at < preparation.issued_at
        || expires_at > preparation.expires_at
        || preparation.digest != preparation_digest
    {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let response_capability_digest =
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 19)?)?);
    let idempotency_digest = Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 20)?)?);
    let candidate_signature =
        Ed25519Signature::from_bytes(parse_cbor_bytes(cbor_field(fields, 21)?)?);
    let key = VerifyingKey::from_bytes(target_device_signing_key.as_bytes())
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    key.verify(
        &{
            let mut i = Vec::with_capacity(
                HISTORY_RECOVERY_REQUEST_V4_SIGNATURE_DOMAIN.len() + unsigned.len(),
            );
            i.extend_from_slice(HISTORY_RECOVERY_REQUEST_V4_SIGNATURE_DOMAIN);
            i.extend_from_slice(&unsigned);
            i
        },
        &Signature::from_bytes(candidate_signature.as_bytes()),
    )
    .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    Ok(HistoryRecoveryRequestV4 {
        request_id,
        identity_id,
        target_device_id,
        target_device_signing_key,
        recipient_encryption_key,
        pre_head_sequence,
        pre_head_hash,
        post_head_sequence,
        post_head_hash,
        device_add_bytes,
        device_add_digest,
        preparation_bytes,
        preparation_digest,
        manifest_bytes,
        manifest_digest,
        issued_at,
        expires_at,
        response_capability_digest,
        idempotency_digest,
        candidate_signature,
        exact_signed_request: bytes.to_vec(),
        request_digest: Sha256Digest::hash_domain(HISTORY_RECOVERY_REQUEST_V4_DIGEST_DOMAIN, bytes),
    })
}

fn parse_cbor_utc_nonnegative(
    value: &CanonicalValue,
) -> Result<UtcMillis, DeviceEnrollmentFailure> {
    match value {
        CanonicalValue::Unsigned(v) => {
            UtcMillis::new(i64::try_from(*v).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?)
                .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
        }
        _ => Err(DeviceEnrollmentFailure::InvalidRequest),
    }
}

fn parse_uuid_v7_text(value: &str) -> Result<Uuid, DeviceEnrollmentFailure> {
    let uuid = Uuid::parse_str(value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    if uuid.to_string() != value || uuid.get_version_num() != 7 {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    Ok(uuid)
}

pub(crate) struct DeviceEnrollmentCompletionRequest {
    pub(crate) challenge_id: DeviceEnrollmentChallengeId,
    pub(crate) capability: DeviceEnrollmentCapability,
    pub(crate) exact_device_add_bytes: Vec<u8>,
}

pub(crate) fn parse_device_enrollment_candidate(
    bytes: &[u8],
) -> Result<DeviceEnrollmentCandidateRequest, DeviceEnrollmentFailure> {
    if bytes.is_empty() {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 6)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let identity_id = parse_cbor_identity_id(cbor_field(fields, 2)?)?;
    let target_device_id = parse_cbor_device_id(cbor_field(fields, 3)?)?;
    let target_device_signing_key =
        SigningPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(fields, 4)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let target_device_encryption_key =
        DeviceEncryptionPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(fields, 5)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let capability =
        DeviceEnrollmentCapability::new(parse_cbor_bytes::<32>(cbor_field(fields, 6)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    Ok(DeviceEnrollmentCandidateRequest {
        identity_id,
        target_device_id,
        target_device_signing_key,
        target_device_encryption_key,
        capability,
    })
}

pub(crate) fn parse_history_recovery_request(
    bytes: &[u8],
) -> Result<HistoryRecoveryCandidateRequest, DeviceEnrollmentFailure> {
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 13)?;
    if cbor_field(fields, 1)? != &CanonicalValue::Unsigned(2) {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    if cbor_field(fields, 9)? != &CanonicalValue::Unsigned(1) {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let exact_signed_request = encode_deterministic_cbor(&CanonicalValue::Map(
        fields.iter().take(12).cloned().collect(),
    ))
    .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    Ok(HistoryRecoveryCandidateRequest {
        request_id: parse_cbor_challenge_id(cbor_field(fields, 2)?)?,
        identity_id: parse_cbor_identity_id(cbor_field(fields, 3)?)?,
        target_device_id: parse_cbor_device_id(cbor_field(fields, 4)?)?,
        target_device_signing_key: SigningPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(
            fields, 5,
        )?)?)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
        recipient_encryption_key: DeviceEncryptionPublicKey::try_from(parse_cbor_bytes::<32>(
            cbor_field(fields, 6)?,
        )?)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
        observed_head_sequence: match cbor_field(fields, 7)? {
            CanonicalValue::Unsigned(value) => {
                SafeUint::new(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
            }
            _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
        },
        observed_head_hash: Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 8)?)?),
        issued_at: match cbor_field(fields, 10)? {
            CanonicalValue::Negative(value) => {
                UtcMillis::new(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
            }
            CanonicalValue::Unsigned(value) => UtcMillis::new(
                i64::try_from(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
        },
        expires_at: match cbor_field(fields, 11)? {
            CanonicalValue::Negative(value) => {
                UtcMillis::new(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
            }
            CanonicalValue::Unsigned(value) => UtcMillis::new(
                i64::try_from(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
        },
        candidate_signature: Ed25519Signature::from_bytes(parse_cbor_bytes(cbor_field(
            fields, 12,
        )?)?),
        capability: DeviceEnrollmentCapability::new(parse_cbor_bytes(cbor_field(fields, 13)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
        exact_signed_request,
    })
}

pub(crate) fn parse_device_enrollment_completion(
    bytes: &[u8],
) -> Result<DeviceEnrollmentCompletionRequest, DeviceEnrollmentFailure> {
    if bytes.is_empty() {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 4)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let challenge_id = parse_cbor_challenge_id(cbor_field(fields, 2)?)?;
    let capability =
        DeviceEnrollmentCapability::new(parse_cbor_bytes::<32>(cbor_field(fields, 3)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let exact_device_add_bytes = match cbor_field(fields, 4)? {
        CanonicalValue::Bytes(value) if !value.is_empty() => value.clone(),
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    Ok(DeviceEnrollmentCompletionRequest {
        challenge_id,
        capability,
        exact_device_add_bytes,
    })
}

pub(crate) async fn parse_device_enrollment_status_request(
    challenge_id: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<(DeviceEnrollmentChallengeId, DeviceEnrollmentCapability), DeviceEnrollmentFailure> {
    if headers.contains_key(header::CONTENT_TYPE)
        || headers.contains_key(header::CONTENT_ENCODING)
        || headers.contains_key(header::IF_MATCH)
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
    {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    }
    let body = to_bytes(body, 1)
        .await
        .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    if !body.is_empty() {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    }
    let challenge_id = challenge_id
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    let capability = parse_device_enrollment_capability(headers)?;
    Ok((challenge_id, capability))
}

pub(crate) fn parse_device_enrollment_capability(
    headers: &HeaderMap,
) -> Result<DeviceEnrollmentCapability, DeviceEnrollmentFailure> {
    let mut values = headers.get_all(DEVICE_ENROLLMENT_CAPABILITY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    };
    if values.next().is_some() {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    let bytes =
        decode_base64url_32(value).map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    DeviceEnrollmentCapability::new(bytes).map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)
}

pub(crate) fn exact_cbor_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], DeviceEnrollmentFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(DeviceEnrollmentFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

pub(crate) fn cbor_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, DeviceEnrollmentFailure> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(DeviceEnrollmentFailure::InvalidRequest)?,
        )
        .map(|(_, value)| value)
        .ok_or(DeviceEnrollmentFailure::InvalidRequest)
}

pub(crate) fn require_cbor_version(value: &CanonicalValue) -> Result<(), DeviceEnrollmentFailure> {
    if value == &CanonicalValue::Unsigned(1) {
        Ok(())
    } else {
        Err(DeviceEnrollmentFailure::InvalidRequest)
    }
}

pub(crate) fn parse_cbor_identity_id(
    value: &CanonicalValue,
) -> Result<IdentityId, DeviceEnrollmentFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_device_id(
    value: &CanonicalValue,
) -> Result<DeviceId, DeviceEnrollmentFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_challenge_id(
    value: &CanonicalValue,
) -> Result<DeviceEnrollmentChallengeId, DeviceEnrollmentFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_bytes<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], DeviceEnrollmentFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
}

fn parse_cbor_bounded_bytes(
    value: &CanonicalValue,
    maximum: usize,
) -> Result<Vec<u8>, DeviceEnrollmentFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    if value.is_empty() || value.len() > maximum {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    Ok(value.clone())
}

/// Strictly parses an opaque short-lived device-session capability.
///
/// The returned credential owns a zeroizing secret buffer. Callers still must
/// invoke [`DeviceSessionRepository::authenticate`] within their own durable
/// authorization transaction; parsing a header alone never authorizes a
/// request.
///
/// # Errors
///
/// Rejects missing, duplicate, malformed, noncanonical, or all-zero values
/// without reflecting the credential in an error response.
pub fn parse_device_session_authorization(
    headers: &HeaderMap,
) -> Result<DeviceSessionCredential, DeviceSessionAuthorizationError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(DeviceSessionAuthorizationError);
    };
    if values.next().is_some() {
        return Err(DeviceSessionAuthorizationError);
    }
    let value = value
        .to_str()
        .map_err(|_| DeviceSessionAuthorizationError)?;
    let prefix = format!("{DEVICE_SESSION_AUTHORIZATION_SCHEME} ");
    let value = value
        .strip_prefix(&prefix)
        .ok_or(DeviceSessionAuthorizationError)?;
    let (session_id, secret) = value
        .split_once('.')
        .ok_or(DeviceSessionAuthorizationError)?;
    if secret.contains('.') {
        return Err(DeviceSessionAuthorizationError);
    }
    let session_id = session_id
        .parse::<DeviceSessionId>()
        .map_err(|_| DeviceSessionAuthorizationError)?;
    let secret = decode_base64url_32(secret).map_err(|_| DeviceSessionAuthorizationError)?;
    DeviceSessionCredential::new(session_id, secret).map_err(|_| DeviceSessionAuthorizationError)
}

/// Opaque parser failure for a short-lived session capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSessionAuthorizationError;
