fn identity_log_wire_line(wire: WireVersion) -> Result<IdentityLogWireLine, IdentityLogError> {
    if wire == IDENTITY_LOG_V1_0_WIRE_VERSION {
        Ok(IdentityLogWireLine::FrozenV1_0)
    } else if wire == IDENTITY_LOG_WIRE_VERSION {
        Ok(IdentityLogWireLine::CurrentV1_1)
    } else {
        Err(IdentityLogError::InvalidWireVersion)
    }
}

fn validate_wire_version(wire: WireVersion) -> Result<(), IdentityLogError> {
    identity_log_wire_line(wire).map(|_| ())
}

fn identity_value(identity_id: IdentityId) -> CanonicalValue {
    CanonicalValue::Text(identity_id.to_string())
}

fn device_id_value(device_id: DeviceId) -> CanonicalValue {
    CanonicalValue::Text(device_id.to_string())
}

fn signature_input(domain: &[u8], digest: Sha256Digest) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + digest.as_bytes().len());
    input.extend_from_slice(domain);
    input.extend_from_slice(digest.as_bytes());
    input
}

fn canonical_hash<T>(domain: &[u8], value: &T) -> Result<Sha256Digest, IdentityLogError>
where
    T: CanonicalEncode + ?Sized,
{
    let bytes = encode_deterministic_cbor(value).map_err(|_| IdentityLogError::InvalidCanonical)?;
    Ok(Sha256Digest::hash_domain(domain, &bytes))
}

fn verify_signature(
    signer: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), IdentityLogError> {
    let key = VerifyingKey::from_bytes(signer.as_bytes())
        .map_err(|_| IdentityLogError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    key.verify_strict(input, &signature)
        .map_err(|_| IdentityLogError::InvalidSignature)
}

fn validate_relay_urls(relay_urls: &[String]) -> Result<(), IdentityLogError> {
    if relay_urls.is_empty() || relay_urls.len() > MAX_RELAY_URLS {
        return Err(IdentityLogError::InvalidRelayDescriptor);
    }
    if relay_urls
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(IdentityLogError::InvalidRelayDescriptor);
    }
    if relay_urls.iter().all(|url| valid_relay_url(url)) {
        Ok(())
    } else {
        Err(IdentityLogError::InvalidRelayDescriptor)
    }
}

fn valid_relay_url(value: &str) -> bool {
    if value.len() > MAX_RELAY_URL_BYTES
        || !value.is_ascii()
        || !value.starts_with("https://")
        || value.contains(['@', '?', '#', '\\'])
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return false;
    }
    let authority_and_path = &value["https://".len()..];
    let authority = authority_and_path
        .split_once('/')
        .map_or(authority_and_path, |(authority, _)| authority);
    !authority.is_empty()
        && !authority.ends_with('.')
        && authority.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
        && authority.bytes().any(|byte| byte.is_ascii_alphanumeric())
}

fn page_exact_fields(
    value: &CanonicalValue,
    count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], IdentityLogPageError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(IdentityLogPageError::InvalidCanonical);
    };
    if fields.len() != count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(IdentityLogPageError::InvalidCanonical)
    } else {
        Ok(fields)
    }
}

fn page_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, IdentityLogPageError> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(IdentityLogPageError::InvalidCanonical)?,
        )
        .map(|(_, value)| value)
        .ok_or(IdentityLogPageError::InvalidCanonical)
}

fn decode_page_wire(value: &CanonicalValue) -> Result<(), IdentityLogPageError> {
    let fields = page_exact_fields(value, 2)?;
    if page_decode_unsigned(page_field(fields, 1)?)? != IDENTITY_LOG_PAGE_WIRE_MAJOR
        || page_decode_unsigned(page_field(fields, 2)?)? != IDENTITY_LOG_PAGE_WIRE_MINOR
    {
        return Err(IdentityLogPageError::InvalidCanonical);
    }
    Ok(())
}

fn page_decode_unsigned(value: &CanonicalValue) -> Result<u64, IdentityLogPageError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(IdentityLogPageError::InvalidCanonical);
    };
    Ok(*value)
}

fn page_decode_safe_uint(value: &CanonicalValue) -> Result<SafeUint, IdentityLogPageError> {
    SafeUint::new(page_decode_unsigned(value)?).map_err(|_| IdentityLogPageError::InvalidCanonical)
}

fn page_decode_digest(value: &CanonicalValue) -> Result<Sha256Digest, IdentityLogPageError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(IdentityLogPageError::InvalidCanonical);
    };
    let bytes = value
        .as_slice()
        .try_into()
        .map_err(|_| IdentityLogPageError::InvalidCanonical)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn page_decode_identity_id(value: &CanonicalValue) -> Result<IdentityId, IdentityLogPageError> {
    let CanonicalValue::Text(value) = value else {
        return Err(IdentityLogPageError::InvalidCanonical);
    };
    IdentityId::from_str(value).map_err(|_| IdentityLogPageError::InvalidCanonical)
}

fn page_decode_event_bytes(value: &CanonicalValue) -> Result<Vec<u8>, IdentityLogPageError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(IdentityLogPageError::InvalidCanonical);
    };
    if value.is_empty() || value.len() > MAX_IDENTITY_LOG_PAGE_EVENT_BYTES {
        return Err(IdentityLogPageError::PageTooLarge);
    }
    Ok(value.clone())
}

fn exact_fields(
    value: &CanonicalValue,
    count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], IdentityLogError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    if fields.len() != count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(IdentityLogError::InvalidCanonical)
    } else {
        Ok(fields)
    }
}

fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, IdentityLogError> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(IdentityLogError::InvalidCanonical)?,
        )
        .map(|(_, value)| value)
        .ok_or(IdentityLogError::InvalidCanonical)
}

fn decode_payload(
    kind: IdentityLogEventKindV1,
    value: &CanonicalValue,
    wire: WireVersion,
) -> Result<IdentityLogEventPayloadV1, IdentityLogError> {
    match kind {
        IdentityLogEventKindV1::Genesis => {
            let fields = exact_fields(value, 3)?;
            Ok(IdentityLogEventPayloadV1::Genesis {
                root_signing_key: decode_signing_key(field(fields, 1)?)?,
                recovery_signing_key: decode_signing_key(field(fields, 2)?)?,
                recovery_acceptance_signature: decode_signature(field(fields, 3)?)?,
            })
        }
        IdentityLogEventKindV1::DeviceAdd => {
            let fields = exact_fields(value, 1)?;
            Ok(IdentityLogEventPayloadV1::DeviceAdd {
                certificate: decode_device_certificate(field(fields, 1)?)?,
            })
        }
        IdentityLogEventKindV1::DeviceRevoke => {
            let fields = exact_fields(value, 1)?;
            Ok(IdentityLogEventPayloadV1::DeviceRevoke {
                device_id: decode_device_id(field(fields, 1)?)?,
            })
        }
        IdentityLogEventKindV1::RootRotate => {
            let fields = exact_fields(value, 2)?;
            Ok(IdentityLogEventPayloadV1::RootRotate {
                new_root_signing_key: decode_signing_key(field(fields, 1)?)?,
                acceptance_signature: decode_signature(field(fields, 2)?)?,
            })
        }
        IdentityLogEventKindV1::RecoveryRotate => {
            let wire_line = identity_log_wire_line(wire)?;
            let fields = exact_fields(
                value,
                match wire_line {
                    IdentityLogWireLine::FrozenV1_0 => 2,
                    IdentityLogWireLine::CurrentV1_1 => 3,
                },
            )?;
            Ok(IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: decode_signing_key(field(fields, 1)?)?,
                acceptance_signature: decode_signature(field(fields, 2)?)?,
                recovery_authorization_signature: match wire_line {
                    IdentityLogWireLine::FrozenV1_0 => None,
                    IdentityLogWireLine::CurrentV1_1 => Some(decode_signature(field(fields, 3)?)?),
                },
            })
        }
        IdentityLogEventKindV1::RecoveryRestore => {
            let fields = exact_fields(value, 4)?;
            Ok(IdentityLogEventPayloadV1::RecoveryRestore {
                new_root_signing_key: decode_signing_key(field(fields, 1)?)?,
                new_recovery_signing_key: decode_signing_key(field(fields, 2)?)?,
                root_acceptance_signature: decode_signature(field(fields, 3)?)?,
                recovery_acceptance_signature: decode_signature(field(fields, 4)?)?,
            })
        }
        IdentityLogEventKindV1::RelayDescriptor => {
            let fields = exact_fields(value, 1)?;
            Ok(IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: decode_relay_descriptor(field(fields, 1)?)?,
            })
        }
    }
}

fn decode_device_certificate(
    value: &CanonicalValue,
) -> Result<DeviceCertificateV1, IdentityLogError> {
    let fields = exact_fields(value, 8)?;
    let wire = decode_wire_version(field(fields, 1)?)?;
    let identity_id = decode_identity_id(field(fields, 2)?)?;
    let device_id = decode_device_id(field(fields, 3)?)?;
    let device_signing_key = decode_signing_key(field(fields, 4)?)?;
    let device_encryption_key = decode_encryption_key(field(fields, 5)?)?;
    let issuer_root_key = decode_signing_key(field(fields, 6)?)?;
    let issued_at = decode_utc_millis(field(fields, 7)?)?;
    let signature = decode_signature(field(fields, 8)?)?;
    let unsigned = UnsignedDeviceCertificateV1::new(
        wire,
        identity_id,
        device_id,
        device_signing_key,
        device_encryption_key,
        issuer_root_key,
        issued_at,
    )?;
    DeviceCertificateV1::signed(unsigned, signature)
}

fn decode_relay_descriptor(value: &CanonicalValue) -> Result<RelayDescriptorV1, IdentityLogError> {
    let fields = exact_fields(value, 3)?;
    let wire = decode_wire_version(field(fields, 1)?)?;
    let CanonicalValue::Array(urls) = field(fields, 2)? else {
        return Err(IdentityLogError::InvalidRelayDescriptor);
    };
    let relay_urls = urls
        .iter()
        .map(|url| match url {
            CanonicalValue::Text(value) => Ok(value.clone()),
            _ => Err(IdentityLogError::InvalidRelayDescriptor),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expires_at = decode_utc_millis(field(fields, 3)?)?;
    RelayDescriptorV1::new(wire, relay_urls, expires_at)
}

fn decode_wire_version(value: &CanonicalValue) -> Result<WireVersion, IdentityLogError> {
    let fields = exact_fields(value, 2)?;
    let wire = WireVersion::new(
        decode_protocol_version(field(fields, 1)?)?,
        decode_protocol_version(field(fields, 2)?)?,
    );
    validate_wire_version(wire)?;
    Ok(wire)
}

fn decode_protocol_version(value: &CanonicalValue) -> Result<ProtocolVersion, IdentityLogError> {
    let fields = exact_fields(value, 2)?;
    Ok(ProtocolVersion::new(
        decode_u16(field(fields, 1)?)?,
        decode_u16(field(fields, 2)?)?,
    ))
}

fn decode_u16(value: &CanonicalValue) -> Result<u16, IdentityLogError> {
    u16::try_from(decode_unsigned(value)?).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_unsigned(value: &CanonicalValue) -> Result<u64, IdentityLogError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    Ok(*value)
}

fn decode_safe_uint(value: &CanonicalValue) -> Result<SafeUint, IdentityLogError> {
    SafeUint::new(decode_unsigned(value)?).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_optional_digest(
    value: &CanonicalValue,
) -> Result<Option<Sha256Digest>, IdentityLogError> {
    if value == &CanonicalValue::Null {
        Ok(None)
    } else {
        decode_digest(value).map(Some)
    }
}

fn decode_digest(value: &CanonicalValue) -> Result<Sha256Digest, IdentityLogError> {
    let bytes = decode_exact_bytes::<32>(value)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn decode_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, IdentityLogError> {
    let raw = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| IdentityLogError::InvalidCanonical)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(IdentityLogError::InvalidCanonical),
    };
    UtcMillis::new(raw).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_identity_id(value: &CanonicalValue) -> Result<IdentityId, IdentityLogError> {
    let CanonicalValue::Text(value) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    IdentityId::from_str(value).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_device_id(value: &CanonicalValue) -> Result<DeviceId, IdentityLogError> {
    let CanonicalValue::Text(value) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    DeviceId::from_str(value).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_signing_key(value: &CanonicalValue) -> Result<SigningPublicKey, IdentityLogError> {
    SigningPublicKey::try_from(decode_exact_bytes::<32>(value)?)
        .map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_encryption_key(
    value: &CanonicalValue,
) -> Result<DeviceEncryptionPublicKey, IdentityLogError> {
    DeviceEncryptionPublicKey::try_from(decode_exact_bytes::<32>(value)?)
        .map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_signature(value: &CanonicalValue) -> Result<Ed25519Signature, IdentityLogError> {
    Ok(Ed25519Signature::from_bytes(decode_exact_bytes::<64>(
        value,
    )?))
}

fn decode_exact_bytes<const N: usize>(value: &CanonicalValue) -> Result<[u8; N], IdentityLogError> {
    let CanonicalValue::Bytes(bytes) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| IdentityLogError::InvalidCanonical)
}
