use std::{collections::BTreeSet, fmt::Write as _};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::ProtocolToolError;

pub(super) fn object_at<'a>(
    document: &'a Value,
    pointer: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, ProtocolToolError> {
    document
        .pointer(pointer)
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new(format!("{label} must be an object")))
}

pub(super) fn string_at<'a>(
    document: &'a Value,
    pointer: &str,
    label: &str,
) -> Result<&'a str, ProtocolToolError> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolToolError::new(format!("{label} must be a string")))
}

pub(super) fn require_json(
    document: &Value,
    pointer: &str,
    expected: &Value,
    label: &str,
) -> Result<(), ProtocolToolError> {
    if document.pointer(pointer) != Some(expected) {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 {label} drift at {pointer}"
        )));
    }
    Ok(())
}

pub(super) fn require_exact_keys<'a>(
    object: &Map<String, Value>,
    expected: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<(), ProtocolToolError> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.into_iter().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 OpenAPI {label} key set drift: expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

pub(super) fn require_sha256(
    source: &str,
    expected: &str,
    label: &str,
) -> Result<(), ProtocolToolError> {
    let digest = Sha256::digest(source.as_bytes());
    let mut actual = String::with_capacity(64);
    for byte in digest {
        write!(&mut actual, "{byte:02x}").expect("writing to String cannot fail");
    }
    if actual != expected {
        return Err(ProtocolToolError::new(format!(
            "{label} SHA-256 drift: expected {expected}, found {actual}"
        )));
    }
    Ok(())
}
