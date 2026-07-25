async fn finish<T>(
    tx: crate::IdentitySession<'_>,
    result: Result<T, IdentityPersistenceError>,
) -> Result<T, IdentityPersistenceError> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

fn numbered_fields(
    value: &CanonicalValue,
    count: usize,
) -> Result<Vec<&CanonicalValue>, IdentityPersistenceError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(invalid("numbered CBOR map"));
    };
    if fields.len() != count {
        return Err(invalid("numbered CBOR field count"));
    }
    fields
        .iter()
        .zip(1_u64..)
        .map(|((key, value), expected_key)| {
            if key == &CanonicalValue::Unsigned(expected_key) {
                Ok(value)
            } else {
                Err(invalid("numbered CBOR keys"))
            }
        })
        .collect()
}
fn parse_identity(value: &CanonicalValue) -> Result<IdentityId, IdentityPersistenceError> {
    let CanonicalValue::Text(value) = value else {
        return Err(invalid("identity ID"));
    };
    IdentityId::from_str(value).map_err(|_| invalid("identity ID"))
}
fn parse_device(value: &CanonicalValue) -> Result<DeviceId, IdentityPersistenceError> {
    let CanonicalValue::Text(value) = value else {
        return Err(invalid("device ID"));
    };
    DeviceId::from_str(value).map_err(|_| invalid("device ID"))
}
fn parse_device_uuid_text(value: &CanonicalValue) -> Result<DeviceId, IdentityPersistenceError> {
    parse_device(value)
}
fn parse_uuid(value: &CanonicalValue) -> Result<Uuid, IdentityPersistenceError> {
    let CanonicalValue::Text(value) = value else {
        return Err(invalid("UUID"));
    };
    Uuid::parse_str(value).map_err(|_| invalid("UUID"))
}
fn parse_uuid_v7(value: &CanonicalValue, label: &'static str) -> Result<Uuid, IdentityPersistenceError> {
    let CanonicalValue::Text(text) = value else {
        return Err(invalid(label));
    };
    let uuid = parse_uuid(value)?;
    if uuid.get_version_num() != 7
        || uuid.get_variant() != uuid::Variant::RFC4122
        || uuid.hyphenated().to_string() != *text
    {
        return Err(invalid(label));
    }
    Ok(uuid)
}
fn parse_challenge(
    value: &CanonicalValue,
) -> Result<DeviceEnrollmentChallengeId, IdentityPersistenceError> {
    let CanonicalValue::Text(value) = value else {
        return Err(invalid("request ID"));
    };
    DeviceEnrollmentChallengeId::from_str(value).map_err(|_| invalid("request ID"))
}
fn parse_safe_uint(value: &CanonicalValue) -> Result<SafeUint, IdentityPersistenceError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(invalid("safe uint"));
    };
    SafeUint::new(*value).map_err(|_| invalid("safe uint"))
}
fn parse_positive_safe_uint(value: &CanonicalValue) -> Result<SafeUint, IdentityPersistenceError> {
    let value = parse_safe_uint(value)?;
    if value.get() == 0 {
        Err(invalid("positive uint"))
    } else {
        Ok(value)
    }
}
fn parse_utc(value: &CanonicalValue) -> Result<UtcMillis, IdentityPersistenceError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(invalid("UTC millis"));
    };
    UtcMillis::new(i64::try_from(*value).map_err(|_| invalid("UTC millis"))?)
        .map_err(|_| invalid("UTC millis"))
}
fn parse_digest(value: &CanonicalValue) -> Result<Sha256Digest, IdentityPersistenceError> {
    Ok(Sha256Digest::from_bytes(parse_fixed(value)?))
}
fn parse_optional_digest(
    value: &CanonicalValue,
) -> Result<Option<Sha256Digest>, IdentityPersistenceError> {
    if value == &CanonicalValue::Null {
        Ok(None)
    } else {
        parse_digest(value).map(Some)
    }
}
fn parse_signature(value: &CanonicalValue) -> Result<Ed25519Signature, IdentityPersistenceError> {
    Ok(Ed25519Signature::from_bytes(parse_fixed(value)?))
}
fn parse_fixed<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], IdentityPersistenceError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(invalid("fixed bytes"));
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| invalid("fixed bytes"))
}
fn parse_bounded_bytes(
    value: &CanonicalValue,
    max: usize,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(invalid("bounded bytes"));
    };
    if value.is_empty() || value.len() > max {
        Err(invalid("bounded bytes"))
    } else {
        Ok(value.clone())
    }
}
fn verify_signature(
    key: SigningPublicKey,
    domain: &[u8],
    unsigned: &CanonicalValue,
    signature: Ed25519Signature,
) -> Result<(), IdentityPersistenceError> {
    let bytes =
        encode_deterministic_cbor_with_limit(unsigned, MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES)
            .map_err(|_| invalid("signature input"))?;
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&bytes);
    VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| invalid("signing key"))?
        .verify(&input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| invalid("signature"))
}
fn to_i64(value: SafeUint) -> Result<i64, IdentityPersistenceError> {
    i64::try_from(value.get()).map_err(|_| invalid("safe integer"))
}
fn safe_uint(value: i64) -> Result<SafeUint, IdentityPersistenceError> {
    SafeUint::new(u64::try_from(value).map_err(|_| corrupt("safe integer"))?)
        .map_err(|_| corrupt("safe integer"))
}
fn utc(value: i64) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(value).map_err(|_| corrupt("UTC millis"))
}
fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], IdentityPersistenceError> {
    value.try_into().map_err(|_| corrupt("fixed bytes"))
}
fn digest(value: &[u8]) -> Result<Sha256Digest, IdentityPersistenceError> {
    Ok(Sha256Digest::from_bytes(fixed(value)?))
}
fn signing_key(value: &[u8]) -> Result<SigningPublicKey, IdentityPersistenceError> {
    SigningPublicKey::try_from(fixed(value)?).map_err(|_| corrupt("signing key"))
}
fn parse_device_uuid(value: Uuid) -> Result<DeviceId, IdentityPersistenceError> {
    DeviceId::from_str(&value.to_string()).map_err(|_| corrupt("device ID"))
}
fn invalid(label: &'static str) -> IdentityPersistenceError {
    IdentityPersistenceError::InvalidCommand(label)
}
fn corrupt(label: &'static str) -> IdentityPersistenceError {
    IdentityPersistenceError::CorruptData(label)
}
