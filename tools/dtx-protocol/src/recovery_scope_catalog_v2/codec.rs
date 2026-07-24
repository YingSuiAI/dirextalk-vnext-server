use super::*;
pub(crate) fn require_json_keys(
    value: &Value,
    expected: &[&str],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolToolError::new(format!("{label} must be an object")))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "{label} exact JSON key set drifted"
        )))
    }
}

pub(crate) fn json_field<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Value, ProtocolToolError> {
    value
        .get(field)
        .ok_or_else(|| ProtocolToolError::new(format!("{label} missing {field}")))
}

pub(crate) fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProtocolToolError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolToolError::new(format!("Catalog V2 JSON {field} must be text")))
}

pub(crate) fn json_u64(value: &Value, field: &str) -> Result<u64, ProtocolToolError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ProtocolToolError::new(format!("Catalog V2 JSON {field} must be unsigned")))
}

pub(crate) fn decode_lower_hex(value: &str) -> Result<Vec<u8>, ProtocolToolError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector hex must be even-length lower-case hexadecimal",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            Ok((high << 4) | low)
        })
        .collect()
}

pub(crate) fn encode_lower_hex(value: &[u8]) -> String {
    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
            encoded
        },
    )
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

pub(crate) fn decode_json_fixed<const LENGTH: usize>(
    value: &Value,
    field: &str,
) -> Result<[u8; LENGTH], ProtocolToolError> {
    decode_lower_hex(json_string(value, field)?)?
        .try_into()
        .map_err(|_| ProtocolToolError::new(format!("Catalog V2 JSON {field} length drifted")))
}

pub(crate) fn decode_exact_cddl(
    cddl: &str,
    rule: &str,
    encoded: &str,
    label: &str,
) -> Result<(Vec<u8>, CanonicalValue), ProtocolToolError> {
    let bytes = decode_lower_hex(encoded)?;
    let value = decode_exact_bytes(&bytes, label)?;
    cddl_cat::validate_cbor_bytes(rule, cddl, &bytes)
        .map_err(|error| ProtocolToolError::new(format!("CDDL rejected {label}: {error}")))?;
    Ok((bytes, value))
}

pub(crate) fn decode_exact_upload_cddl(
    cddl: &str,
    encoded: &str,
    label: &str,
) -> Result<(Vec<u8>, CanonicalValue), ProtocolToolError> {
    let bytes = decode_lower_hex(encoded)?;
    let value = decode_exact_upload_bytes(cddl, &bytes, label)?;
    Ok((bytes, value))
}

pub(crate) fn decode_exact_upload_bytes(
    cddl: &str,
    bytes: &[u8],
    label: &str,
) -> Result<CanonicalValue, ProtocolToolError> {
    let value = decode_exact_bytes_with_limit(bytes, label, MAX_ENVELOPE_BYTES)?;
    cddl_cat::validate_cbor_bytes("recovery-scope-catalog-upload-v2", cddl, bytes)
        .map_err(|error| ProtocolToolError::new(format!("CDDL rejected {label}: {error}")))?;
    Ok(value)
}

pub(crate) fn decode_exact_bytes(
    bytes: &[u8],
    label: &str,
) -> Result<CanonicalValue, ProtocolToolError> {
    let value = decode_deterministic_cbor(bytes).map_err(|error| {
        ProtocolToolError::new(format!(
            "{label} is not deterministic canonical CBOR: {error}"
        ))
    })?;
    let reencoded = encode_deterministic_cbor(&value)
        .map_err(|error| ProtocolToolError::new(format!("re-encode {label}: {error}")))?;
    if reencoded != bytes {
        return Err(ProtocolToolError::new(format!(
            "{label} changed under deterministic re-encoding"
        )));
    }
    Ok(value)
}

pub(crate) fn decode_exact_bytes_with_limit(
    bytes: &[u8],
    label: &str,
    limit: usize,
) -> Result<CanonicalValue, ProtocolToolError> {
    let value = decode_deterministic_cbor_with_limit(bytes, limit).map_err(|error| {
        ProtocolToolError::new(format!(
            "{label} is not deterministic canonical CBOR: {error}"
        ))
    })?;
    let reencoded = encode_deterministic_cbor_with_limit(&value, limit)
        .map_err(|error| ProtocolToolError::new(format!("re-encode {label}: {error}")))?;
    if reencoded != bytes {
        return Err(ProtocolToolError::new(format!(
            "{label} changed under deterministic re-encoding"
        )));
    }
    Ok(value)
}

pub(crate) fn numbered_fields<'a>(
    value: &'a CanonicalValue,
    expected: usize,
    label: &str,
) -> Result<Vec<&'a CanonicalValue>, ProtocolToolError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(ProtocolToolError::new(format!(
            "{label} must be a numbered map"
        )));
    };
    if entries.len() != expected {
        return Err(ProtocolToolError::new(format!(
            "{label} field count drifted"
        )));
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, (key, value))| {
            let expected =
                CanonicalValue::Unsigned(u64::try_from(index + 1).expect("bounded field index"));
            if key == &expected {
                Ok(value)
            } else {
                Err(ProtocolToolError::new(format!(
                    "{label} field keys drifted"
                )))
            }
        })
        .collect()
}

pub(crate) fn cbor_unsigned(value: &CanonicalValue, label: &str) -> Result<u64, ProtocolToolError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be unsigned")));
    };
    Ok(*value)
}

pub(crate) fn cbor_text<'a>(
    value: &'a CanonicalValue,
    label: &str,
) -> Result<&'a str, ProtocolToolError> {
    let CanonicalValue::Text(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be text")));
    };
    Ok(value)
}

pub(crate) fn cbor_bytes<'a>(
    value: &'a CanonicalValue,
    label: &str,
) -> Result<&'a [u8], ProtocolToolError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be bytes")));
    };
    Ok(value)
}

pub(crate) fn cbor_fixed<const LENGTH: usize>(
    value: &CanonicalValue,
    label: &str,
) -> Result<[u8; LENGTH], ProtocolToolError> {
    cbor_bytes(value, label)?
        .try_into()
        .map_err(|_| ProtocolToolError::new(format!("{label} must be exactly {LENGTH} bytes")))
}

pub(crate) fn cbor_array<'a>(
    value: &'a CanonicalValue,
    label: &str,
) -> Result<&'a [CanonicalValue], ProtocolToolError> {
    let CanonicalValue::Array(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be an array")));
    };
    Ok(value)
}

pub(crate) fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

pub(crate) fn verify_signature(
    public_key: [u8; 32],
    domain: &[u8],
    unsigned: &[u8],
    signature: [u8; 64],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let mut transcript = Vec::with_capacity(domain.len() + unsigned.len());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(unsigned);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ProtocolToolError::new(format!("{label} public key invalid")))?
        .verify_strict(&transcript, &Signature::from_bytes(&signature))
        .map_err(|_| ProtocolToolError::new(format!("{label} signature invalid")))
}

pub(crate) fn encoded_unsigned_prefix(
    value: &CanonicalValue,
    count: usize,
    label: &str,
) -> Result<Vec<u8>, ProtocolToolError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be a map")));
    };
    encode_deterministic_cbor(&CanonicalValue::Map(entries[..count].to_vec()))
        .map_err(|error| ProtocolToolError::new(format!("encode {label} unsigned: {error}")))
}

pub(crate) fn handoff_error(label: &str) -> ProtocolToolError {
    ProtocolToolError::new(format!("Catalog V2 C1b-B1 handoff {label}"))
}

pub(crate) fn require_handoff(condition: bool, label: &str) -> Result<(), ProtocolToolError> {
    if condition {
        Ok(())
    } else {
        Err(handoff_error(label))
    }
}
