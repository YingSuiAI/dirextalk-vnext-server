use super::{
    Base64UrlUnpadded, Body, CanonicalValue, DEVICE_ENROLLMENT_CAPABILITY_HEADER,
    DEVICE_SESSION_AUTHORIZATION_SCHEME, DeserializeOwned, DeviceEncryptionPublicKey,
    DeviceEnrollmentCapability, DeviceEnrollmentChallengeId, DeviceEnrollmentFailure, DeviceId,
    DeviceSessionCredential, DeviceSessionFailure, DeviceSessionId, Ed25519Signature, Encoding,
    HeaderMap, IDEMPOTENCY_KEY_HEADER, IdentityId, MAX_DEVICE_SESSION_REQUEST_BYTES, SafeUint,
    Sha256Digest, SigningPublicKey, UtcMillis, Zeroize, decode_deterministic_cbor,
    encode_deterministic_cbor, header, is_base64url_byte, to_bytes,
};

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
