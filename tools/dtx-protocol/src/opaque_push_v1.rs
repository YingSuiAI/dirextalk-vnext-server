use std::{fs, path::Path};

use dtx_wire::{CanonicalValue, decode_deterministic_cbor, encode_deterministic_cbor};
use serde_json::Value;

use crate::ProtocolToolError;

/// Validates the V43 opaque push registration CDDL, vector, and provider
/// payload boundary. This module intentionally has no runtime or persistence
/// dependencies.
pub fn validate(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_path = root.join("protocol/cddl/opaque-push/v1/opaque-push-v1.cddl");
    let cddl = fs::read_to_string(&cddl_path).map_err(|error| {
        ProtocolToolError::new(format!(
            "read opaque push CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse opaque push CDDL: {error}")))?;
    validate_openapi(root)?;

    let vector_path = root.join("protocol/test-vectors/opaque-push/v1/opaque-push-v1.json");
    let vector: Value =
        serde_json::from_str(&fs::read_to_string(&vector_path).map_err(|error| {
            ProtocolToolError::new(format!("read opaque push vector: {error}"))
        })?)
        .map_err(|error| ProtocolToolError::new(format!("parse opaque push vector: {error}")))?;

    exact_keys(
        &vector,
        &[
            "version",
            "baseline",
            "put_path",
            "delete_path",
            "provider",
            "put_content_type",
            "receipt_content_type",
            "device_session_header",
            "idempotency_header",
            "revision_header",
            "token_min_bytes",
            "token_max_bytes",
            "first_revision",
            "ttl_seconds",
            "request_canonical_cbor_hex",
            "receipt_active_canonical_cbor_hex",
            "receipt_revoked_canonical_cbor_hex",
            "internal_provider_payload_json",
            "error_responses",
        ],
        "opaque push vector",
    )?;
    if u64_field(&vector, "version")? != 1 || u64_field(&vector, "baseline")? != 43 {
        return Err(ProtocolToolError::new(
            "opaque push vector version/baseline drifted",
        ));
    }
    if string_field(&vector, "put_path")? != "/v1/devices/push-registrations/fcm"
        || string_field(&vector, "delete_path")? != "/v1/devices/push-registrations/fcm"
        || string_field(&vector, "provider")? != "fcm"
    {
        return Err(ProtocolToolError::new(
            "opaque push endpoint/provider drifted",
        ));
    }
    if u64_field(&vector, "token_min_bytes")? != 1
        || u64_field(&vector, "token_max_bytes")? != 4096
        || u64_field(&vector, "first_revision")? != 0
        || u64_field(&vector, "ttl_seconds")? != 60
    {
        return Err(ProtocolToolError::new("opaque push bounds drifted"));
    }

    validate_cbor_hex(
        &cddl,
        "opaque-push-register-v1",
        string_field(&vector, "request_canonical_cbor_hex")?,
        &[1, 2],
    )?;
    validate_cbor_hex(
        &cddl,
        "opaque-push-receipt-v1",
        string_field(&vector, "receipt_active_canonical_cbor_hex")?,
        &[1, 2, 3, 4],
    )?;
    validate_cbor_hex(
        &cddl,
        "opaque-push-receipt-v1",
        string_field(&vector, "receipt_revoked_canonical_cbor_hex")?,
        &[1, 2, 3, 4],
    )?;
    validate_payload(string_field(&vector, "internal_provider_payload_json")?)?;

    let errors = vector
        .get("error_responses")
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new("opaque push error_responses must be an array"))?;
    if errors.len() != 7 {
        return Err(ProtocolToolError::new(
            "opaque push error response set drifted",
        ));
    }
    for error in errors {
        exact_keys(error, &["status", "code", "retryable"], "opaque push error")?;
        if !error
            .get("status")
            .and_then(Value::as_u64)
            .is_some_and(|s| matches!(s, 400 | 401 | 409 | 410 | 415 | 422 | 503))
            || error.get("code").and_then(Value::as_str).is_none()
            || error.get("retryable").and_then(Value::as_bool).is_none()
        {
            return Err(ProtocolToolError::new(
                "opaque push error entry is malformed",
            ));
        }
    }
    Ok(())
}

fn validate_openapi(root: &Path) -> Result<(), ProtocolToolError> {
    let path = root.join("protocol/openapi/opaque-push/v1/openapi.yaml");
    let source = fs::read_to_string(&path)
        .map_err(|error| ProtocolToolError::new(format!("read opaque push OpenAPI: {error}")))?;
    let document: Value = yaml_serde::from_str(&source)
        .map_err(|error| ProtocolToolError::new(format!("parse opaque push OpenAPI: {error}")))?;
    if document.get("openapi").and_then(Value::as_str) != Some("3.1.0") {
        return Err(ProtocolToolError::new(
            "opaque push OpenAPI must declare 3.1.0",
        ));
    }
    let paths = document
        .pointer("/paths")
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new("opaque push OpenAPI paths missing"))?;
    if paths.len() != 1 || !paths.contains_key("/v1/devices/push-registrations/fcm") {
        return Err(ProtocolToolError::new("opaque push path set drifted"));
    }
    let endpoint = &paths["/v1/devices/push-registrations/fcm"];
    for method in ["put", "delete"] {
        let operation = endpoint.get(method).ok_or_else(|| {
            ProtocolToolError::new(format!("opaque push {method} operation missing"))
        })?;
        let parameters = operation
            .get("parameters")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ProtocolToolError::new(format!("opaque push {method} parameters missing"))
            })?;
        let names = parameters
            .iter()
            .filter_map(|parameter| parameter.get("$ref").and_then(Value::as_str))
            .collect::<Vec<_>>();
        if names
            != [
                "#/components/parameters/DeviceSession",
                "#/components/parameters/IdempotencyKey",
                "#/components/parameters/IfMatch",
            ]
        {
            return Err(ProtocolToolError::new(format!(
                "opaque push {method} parameter binding drifted"
            )));
        }
        let expected_statuses: &[&str] = if method == "put" {
            &[
                "201", "200", "400", "401", "409", "410", "415", "422", "503",
            ]
        } else {
            &["200", "400", "401", "409", "410", "422", "503"]
        };
        let response_keys = operation
            .get("responses")
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolToolError::new("opaque push responses missing"))?
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if response_keys.len() != expected_statuses.len()
            || expected_statuses
                .iter()
                .any(|status| !response_keys.contains(status))
        {
            return Err(ProtocolToolError::new(format!(
                "opaque push {method} status set drifted"
            )));
        }
    }
    let parameters = document
        .pointer("/components/parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new("opaque push parameters missing"))?;
    for name in ["DeviceSession", "IdempotencyKey", "IfMatch"] {
        let parameter = parameters.get(name).ok_or_else(|| {
            ProtocolToolError::new(format!("opaque push parameter {name} missing"))
        })?;
        if parameter.get("required").and_then(Value::as_bool) != Some(true) {
            return Err(ProtocolToolError::new(format!(
                "opaque push parameter {name} must be required"
            )));
        }
    }
    let device_schema = parameters["DeviceSession"].pointer("/schema");
    if device_schema
        .and_then(|schema| schema.get("pattern"))
        .and_then(Value::as_str)
        != Some(
            r"^DTX-Device-Session [0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$",
        )
    {
        return Err(ProtocolToolError::new(
            "opaque push device session pattern drifted",
        ));
    }
    if document
        .pointer("/components/headers/RequestId/schema/pattern")
        .and_then(Value::as_str)
        != Some(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    {
        return Err(ProtocolToolError::new(
            "opaque push request-id pattern drifted",
        ));
    }
    Ok(())
}

fn validate_payload(payload: &str) -> Result<(), ProtocolToolError> {
    let parsed: Value = serde_json::from_str(payload).map_err(|error| {
        ProtocolToolError::new(format!("provider payload is not JSON: {error}"))
    })?;
    if serde_json::to_string(&parsed)
        .map_err(|error| ProtocolToolError::new(format!("serialize provider payload: {error}")))?
        != payload
    {
        return Err(ProtocolToolError::new(
            "provider payload must use exact compact UTF-8 JSON",
        ));
    }
    exact_keys(
        &parsed,
        &["version", "wake_delivery_id"],
        "provider payload",
    )?;
    if parsed.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(ProtocolToolError::new("provider payload version must be 1"));
    }
    let wake = parsed
        .get("wake_delivery_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProtocolToolError::new("provider payload wake_delivery_id must be a string")
        })?;
    if !is_canonical_uuid_v7(wake) {
        return Err(ProtocolToolError::new(
            "provider payload wake_delivery_id must be canonical lowercase UUIDv7",
        ));
    }
    Ok(())
}

fn is_canonical_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 || ![8, 13, 18, 23].iter().all(|index| bytes[*index] == b'-') {
        return false;
    }
    if bytes.iter().enumerate().any(|(index, byte)| {
        [8, 13, 18, 23].contains(&index) == false
            && (!byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    }) {
        return false;
    }
    bytes[14] == b'7' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

fn validate_cbor_hex(
    cddl: &str,
    rule: &str,
    hex: &str,
    expected_keys: &[u64],
) -> Result<(), ProtocolToolError> {
    let bytes = decode_hex(hex)?;
    cddl_cat::validate_cbor_bytes(rule, cddl, &bytes)
        .map_err(|error| ProtocolToolError::new(format!("{rule} rejected vector: {error}")))?;
    let value = decode_deterministic_cbor(&bytes).map_err(|error| {
        ProtocolToolError::new(format!("{rule} is not canonical CBOR: {error}"))
    })?;
    let CanonicalValue::Map(entries) = &value else {
        return Err(ProtocolToolError::new(format!("{rule} must be a map")));
    };
    let keys = entries
        .iter()
        .map(|(key, _)| match key {
            CanonicalValue::Unsigned(value) => Ok(*value),
            _ => Err(ProtocolToolError::new(format!(
                "{rule} has non-integer key"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys != expected_keys {
        return Err(ProtocolToolError::new(format!(
            "{rule} has unknown or reordered fields"
        )));
    }
    if encode_deterministic_cbor(&value)
        .map_err(|error| ProtocolToolError::new(format!("encode {rule}: {error}")))?
        != bytes
    {
        return Err(ProtocolToolError::new(format!(
            "{rule} is not byte-canonical"
        )));
    }
    Ok(())
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ProtocolToolError> {
    if input.len() % 2 != 0 {
        return Err(ProtocolToolError::new(
            "opaque push vector hex has odd length",
        ));
    }
    (0..input.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&input[index..index + 2], 16)
                .map_err(|_| ProtocolToolError::new("opaque push vector contains invalid hex"))
        })
        .collect()
}

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), ProtocolToolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolToolError::new(format!("{label} must be an object")))?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(ProtocolToolError::new(format!(
            "{label} has unknown or missing fields"
        )));
    }
    Ok(())
}

fn string_field<'a>(vector: &'a Value, key: &str) -> Result<&'a str, ProtocolToolError> {
    vector
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolToolError::new(format!("opaque push field {key} must be a string")))
}

fn u64_field(vector: &Value, key: &str) -> Result<u64, ProtocolToolError> {
    vector
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| ProtocolToolError::new(format!("opaque push field {key} must be uint")))
}

#[cfg(test)]
mod tests {
    use super::validate_payload;

    #[test]
    fn provider_payload_rejects_scope_and_message_leakage() {
        let error = validate_payload(
            r#"{"version":1,"wake_delivery_id":"018f1f2e-7abc-7def-8abc-0123456789ab","conversation_id":"leak"}"#,
        )
        .expect_err("forbidden payload field must fail closed");
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn provider_payload_requires_uuidv7() {
        assert!(
            validate_payload(
                r#"{"version":1,"wake_delivery_id":"018f1f2e-7abc-6def-8abc-0123456789ab"}"#,
            )
            .is_err()
        );
    }
}
