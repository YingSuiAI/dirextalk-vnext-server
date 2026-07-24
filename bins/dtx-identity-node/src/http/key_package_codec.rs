use super::*;

pub(crate) struct KeyPackagePublishRequest {
    pub(crate) identity_id: IdentityId,
    pub(crate) device_id: DeviceId,
    pub(crate) package_id: KeyPackageId,
    pub(crate) published_head_sequence: SafeUint,
    pub(crate) published_head_hash: Sha256Digest,
    pub(crate) expires_at: UtcMillis,
    pub(crate) opaque_key_package: Vec<u8>,
    pub(crate) detached_signature: Ed25519Signature,
    pub(crate) history_recovery_scope: Option<HistoryRecoveryKeyPackageScope>,
}

pub(crate) struct KeyPackageClaimRequest {
    pub(crate) target_identity_id: IdentityId,
    pub(crate) target_device_id: DeviceId,
    pub(crate) history_recovery_scope: Option<HistoryRecoveryKeyPackageScope>,
}

pub(crate) fn parse_key_package_publish(
    bytes: &[u8],
) -> Result<KeyPackagePublishRequest, KeyPackageFailure> {
    if bytes.is_empty() {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| KeyPackageFailure::InvalidRequest)?;
    let field_count = match &value {
        CanonicalValue::Map(fields) => fields.len(),
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    if !matches!(field_count, 9 | 12) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let fields = key_package_cbor_fields(&value, field_count)?;
    let version = if field_count == 12 { 2 } else { 1 };
    if key_package_cbor_field(fields, 1)? != &CanonicalValue::Unsigned(version) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let identity_id = key_package_parse_identity_id(key_package_cbor_field(fields, 2)?)?;
    let device_id = key_package_parse_device_id(key_package_cbor_field(fields, 3)?)?;
    let package_id = key_package_parse_package_id(key_package_cbor_field(fields, 4)?)?;
    let published_head_sequence = key_package_parse_safe_uint(key_package_cbor_field(fields, 5)?)?;
    let published_head_hash = Sha256Digest::from_bytes(key_package_parse_bytes::<32>(
        key_package_cbor_field(fields, 6)?,
    )?);
    let expires_at = key_package_parse_utc_millis(key_package_cbor_field(fields, 7)?)?;
    let opaque_key_package = match key_package_cbor_field(fields, 8)? {
        CanonicalValue::Bytes(value) if !value.is_empty() => value.clone(),
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    let detached_signature = Ed25519Signature::from_bytes(key_package_parse_bytes::<64>(
        key_package_cbor_field(fields, 9)?,
    )?);
    let history_recovery_scope = if version == 2 {
        if key_package_cbor_field(fields, 12)? != &CanonicalValue::Unsigned(1) {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        Some(
            HistoryRecoveryKeyPackageScope::new(
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 10,
                )?)?),
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 11,
                )?)?),
            )
            .map_err(|_| KeyPackageFailure::InvalidRequest)?,
        )
    } else {
        None
    };
    Ok(KeyPackagePublishRequest {
        identity_id,
        device_id,
        package_id,
        published_head_sequence,
        published_head_hash,
        expires_at,
        opaque_key_package,
        detached_signature,
        history_recovery_scope,
    })
}

pub(crate) fn parse_key_package_claim(
    bytes: &[u8],
) -> Result<KeyPackageClaimRequest, KeyPackageFailure> {
    if bytes.is_empty() {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| KeyPackageFailure::InvalidRequest)?;
    let field_count = match &value {
        CanonicalValue::Map(fields) => fields.len(),
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    if !matches!(field_count, 3 | 6) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let fields = key_package_cbor_fields(&value, field_count)?;
    let version = if field_count == 6 { 2 } else { 1 };
    if key_package_cbor_field(fields, 1)? != &CanonicalValue::Unsigned(version) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let history_recovery_scope = if version == 2 {
        if key_package_cbor_field(fields, 6)? != &CanonicalValue::Unsigned(1) {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        Some(
            HistoryRecoveryKeyPackageScope::new(
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 4,
                )?)?),
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 5,
                )?)?),
            )
            .map_err(|_| KeyPackageFailure::InvalidRequest)?,
        )
    } else {
        None
    };
    Ok(KeyPackageClaimRequest {
        target_identity_id: key_package_parse_identity_id(key_package_cbor_field(fields, 2)?)?,
        target_device_id: key_package_parse_device_id(key_package_cbor_field(fields, 3)?)?,
        history_recovery_scope,
    })
}

pub(crate) fn parse_federated_key_package_claim_proof(
    headers: &HeaderMap,
) -> Result<FederatedKeyPackageClaimProof, KeyPackageFailure> {
    let proof = single_graphic_header(
        headers,
        KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER,
        1,
        MAX_KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER_BYTES,
    )
    .map_err(|()| KeyPackageFailure::AuthenticationRejected)?;
    if !proof.bytes().all(is_base64url_byte) {
        return Err(KeyPackageFailure::AuthenticationRejected);
    }
    let mut decoded = vec![0_u8; MAX_KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER_BYTES * 3 / 4];
    let exact = Base64UrlUnpadded::decode(proof, &mut decoded)
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
    if Base64UrlUnpadded::encode_string(exact) != proof {
        decoded.zeroize();
        return Err(KeyPackageFailure::AuthenticationRejected);
    }
    let value =
        decode_deterministic_cbor(exact).map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
    decoded.zeroize();
    let fields = key_package_cbor_fields(&value, 14)
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
    if key_package_cbor_field(fields, 1).map_err(|_| KeyPackageFailure::AuthenticationRejected)?
        != &CanonicalValue::Unsigned(2)
    {
        return Err(KeyPackageFailure::AuthenticationRejected);
    }
    let text = |key| -> Result<String, KeyPackageFailure> {
        match key_package_cbor_field(fields, key)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?
        {
            CanonicalValue::Text(value) => Ok(value.clone()),
            _ => Err(KeyPackageFailure::AuthenticationRejected),
        }
    };
    FederatedKeyPackageClaimProof::new(
        text(2)?,
        key_package_parse_identity_id(
            key_package_cbor_field(fields, 3)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_device_id(
            key_package_cbor_field(fields, 4)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_identity_id(
            key_package_cbor_field(fields, 5)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_device_id(
            key_package_cbor_field(fields, 6)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        text(7)?,
        text(8)?,
        Sha256Digest::from_bytes(
            key_package_parse_bytes::<32>(
                key_package_cbor_field(fields, 9)
                    .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
            )
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        ),
        key_package_parse_utc_millis(
            key_package_cbor_field(fields, 10)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_utc_millis(
            key_package_cbor_field(fields, 11)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_bytes::<32>(
            key_package_cbor_field(fields, 12)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        Sha256Digest::from_bytes(
            key_package_parse_bytes::<32>(
                key_package_cbor_field(fields, 13)
                    .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
            )
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        ),
        Ed25519Signature::from_bytes(
            key_package_parse_bytes::<64>(
                key_package_cbor_field(fields, 14)
                    .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
            )
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        ),
    )
    .map_err(|_| KeyPackageFailure::AuthenticationRejected)
}

pub(crate) fn key_package_cbor_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], KeyPackageFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(KeyPackageFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

pub(crate) fn key_package_cbor_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, KeyPackageFailure> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(KeyPackageFailure::InvalidRequest)?,
        )
        .map(|(_, value)| value)
        .ok_or(KeyPackageFailure::InvalidRequest)
}

pub(crate) fn key_package_parse_identity_id(
    value: &CanonicalValue,
) -> Result<IdentityId, KeyPackageFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value.parse().map_err(|_| KeyPackageFailure::InvalidRequest)
}

pub(crate) fn key_package_parse_device_id(
    value: &CanonicalValue,
) -> Result<DeviceId, KeyPackageFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value.parse().map_err(|_| KeyPackageFailure::InvalidRequest)
}

pub(crate) fn key_package_parse_package_id(
    value: &CanonicalValue,
) -> Result<KeyPackageId, KeyPackageFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value.parse().map_err(|_| KeyPackageFailure::InvalidRequest)
}

pub(crate) fn key_package_parse_safe_uint(
    value: &CanonicalValue,
) -> Result<SafeUint, KeyPackageFailure> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    SafeUint::new(*value).map_err(|_| KeyPackageFailure::InvalidRequest)
}

pub(crate) fn key_package_parse_utc_millis(
    value: &CanonicalValue,
) -> Result<UtcMillis, KeyPackageFailure> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| KeyPackageFailure::InvalidRequest)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    UtcMillis::new(value).map_err(|_| KeyPackageFailure::InvalidRequest)
}

pub(crate) fn key_package_parse_bytes<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], KeyPackageFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| KeyPackageFailure::InvalidRequest)
}
