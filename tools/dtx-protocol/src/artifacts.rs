use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

use crate::{
    ErrorRegistry, EventDefinition, EventField, EventRegistry, ProtocolToolError,
    load_error_registry, load_event_registry,
};

const SAFE_UINT_MAX: u64 = 9_007_199_254_740_991;

/// Parses every source schema and validates committed CBOR golden vectors.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for missing, malformed, or inconsistent
/// CDDL, `OpenAPI`, Protobuf, Buf, registry, or vector artifacts.
pub fn validate_artifacts(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_root = root.join("protocol/cddl/v1");
    let common = read(&cddl_root.join("common.cddl"))?;
    let cddl_files = collect_files(&cddl_root, Some("cddl"))?;
    if cddl_files.is_empty() {
        return Err(ProtocolToolError::new("v1 CDDL directory is empty"));
    }
    for path in &cddl_files {
        let source = read(path)?;
        let complete = if path.file_name().and_then(|value| value.to_str()) == Some("common.cddl") {
            source
        } else {
            format!("{common}\n{source}")
        };
        cddl_cat::parse_cddl(&complete).map_err(|error| {
            ProtocolToolError::new(format!("parse CDDL {}: {error}", path.display()))
        })?;
    }

    let event_cddl = format!(
        "{common}\n{}",
        read(&cddl_root.join("event-envelope.cddl"))?
    );
    let api_error_cddl = format!("{common}\n{}", read(&cddl_root.join("api-error.cddl"))?);
    let plan_cddl = format!(
        "{common}\n{}",
        read(&cddl_root.join("plan-hash-fixture.cddl"))?
    );
    let event_page_cddl = format!("{common}\n{}", read(&cddl_root.join("event-page.cddl"))?);

    let vector_root = root.join("protocol/test-vectors/v1");
    let event = read_json(&vector_root.join("event-envelope.json"))?;
    validate_vector_version(&event, "event-envelope")?;
    validate_uuid_fields(
        &event,
        &[
            "/event_id",
            "/tenant_id",
            "/aggregate_id",
            "/payload/installation_id",
        ],
    )?;
    validate_cddl_hex(
        "event-envelope-agent-installation-v1",
        &event_cddl,
        json_string(&event, "hash_only_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "event-envelope-agent-installation-v1",
        &event_cddl,
        json_string(&event, "signed_cbor_hex")?,
    )?;
    let signed_envelope = decode_hex(json_string(&event, "signed_cbor_hex")?)?;
    let event_page = encode_event_page_fixture(&signed_envelope, "next-cursor")?;
    cddl_cat::validate_cbor_bytes("event-page-v1", &event_page_cddl, &event_page)
        .map_err(|error| ProtocolToolError::new(format!("CDDL rejected event-page-v1: {error}")))?;

    let api_error = read_json(&vector_root.join("api-errors.json"))?;
    validate_vector_version(&api_error, "api-errors")?;
    validate_uuid_fields(&api_error, &["/error/request_id"])?;
    validate_cddl_hex(
        "api-error-v1",
        &api_error_cddl,
        json_string(&api_error, "canonical_cbor_hex")?,
    )?;

    let plan = read_json(&vector_root.join("plan-hash.json"))?;
    validate_vector_version(&plan, "plan-hash")?;
    validate_uuid_fields(&plan, &["/body/job_id"])?;
    validate_cddl_hex(
        "job-plan-hash-fixture-v1",
        &plan_cddl,
        json_string(&plan, "canonical_cbor_hex")?,
    )?;

    let public_ids = read_json(&vector_root.join("public-ids.json"))?;
    validate_vector_version(&public_ids, "public-ids")?;

    let identity_log_cddl = read(&root.join("protocol/cddl/identity-log/v1/identity-log-v1.cddl"))?;
    cddl_cat::parse_cddl(&identity_log_cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse identity-log v1 CDDL: {error}")))?;
    let identity_log =
        read_json(&root.join("protocol/test-vectors/identity-log/v1/identity-log-v1.json"))?;
    validate_vector_version(&identity_log, "identity-log-v1")?;
    validate_cddl_hex(
        "identity-log-event-v1",
        &identity_log_cddl,
        json_string(&identity_log, "canonical_cbor_hex")?,
    )?;

    let events = load_event_registry(&root.join("protocol/events/registry.yaml"))?;
    let errors = load_error_registry(&root.join("protocol/errors/registry.yaml"))?;
    validate_openapi(root, &events, &errors)?;
    validate_protobuf(root)?;
    Ok(())
}

fn validate_openapi(
    root: &Path,
    events: &EventRegistry,
    errors: &ErrorRegistry,
) -> Result<(), ProtocolToolError> {
    let openapi_root = root.join("protocol/openapi/v1");
    let paths = collect_files(&openapi_root, Some("yaml"))?;
    if paths.is_empty() {
        return Err(ProtocolToolError::new("v1 OpenAPI directory is empty"));
    }
    for path in &paths {
        let source = read(path)?;
        let spec = oas3::from_yaml(&source).map_err(|error| {
            ProtocolToolError::new(format!("parse OpenAPI {}: {error}", path.display()))
        })?;
        if spec.openapi != "3.1.0" {
            return Err(ProtocolToolError::new(format!(
                "OpenAPI contract {} must declare 3.1.0",
                path.display()
            )));
        }
    }

    let source = read(&openapi_root.join("openapi.yaml"))?;
    let document: Value = yaml_serde::from_str(&source)
        .map_err(|error| ProtocolToolError::new(format!("parse OpenAPI YAML tree: {error}")))?;
    validate_openapi_registry_contract(&document, events, errors)
}

fn validate_openapi_registry_contract(
    document: &Value,
    events: &EventRegistry,
    errors: &ErrorRegistry,
) -> Result<(), ProtocolToolError> {
    let schemas = object_at(document, "/components/schemas")?;
    validate_common_openapi_bounds(document)?;
    validate_api_error_schema(document, errors)?;
    validate_event_page_openapi_contract(document)?;

    let union = object_at(document, "/components/schemas/EventEnvelopeV1")?;
    let actual_union = refs_at(union, "oneOf")?;
    let expected_union = events.events.iter().map(envelope_ref).collect::<Vec<_>>();
    if actual_union != expected_union {
        return Err(ProtocolToolError::new(
            "EventEnvelopeV1 oneOf must list every registry event in registry order",
        ));
    }
    let mapping = object_at(
        document,
        "/components/schemas/EventEnvelopeV1/discriminator/mapping",
    )?;
    if mapping.len() != events.events.len() {
        return Err(ProtocolToolError::new(
            "EventEnvelopeV1 discriminator must match the event registry exactly",
        ));
    }

    for event in &events.events {
        let expected_envelope_ref = envelope_ref(event);
        if mapping.get(&event.event_type).and_then(Value::as_str)
            != Some(expected_envelope_ref.as_str())
        {
            return Err(ProtocolToolError::new(format!(
                "OpenAPI discriminator drift for {}",
                event.event_type
            )));
        }
        validate_payload_schema(schemas, event)?;
        validate_envelope_binding(schemas, event)?;
    }
    Ok(())
}

fn validate_event_page_openapi_contract(document: &Value) -> Result<(), ProtocolToolError> {
    for (pointer, expected) in [
        (
            "/paths/~1v1~1agent-jobs~1{job_id}~1events/get/responses/200/content/application~1json/schema/$ref",
            json!("#/components/schemas/EventPageV1"),
        ),
        (
            "/paths/~1v1~1agent-jobs~1{job_id}~1events/get/responses/200/content/application~1cbor/schema/$ref",
            json!("#/components/schemas/EventPageCborV1"),
        ),
        (
            "/paths/~1v1~1agent-jobs~1{job_id}~1events/get/responses/200/content/application~1cbor/x-dirextalk-max-body-bytes",
            json!(1_048_576),
        ),
        (
            "/paths/~1v1~1agent-jobs~1{job_id}~1events/get/parameters/1/schema/x-dirextalk-max-utf8-bytes",
            json!(512),
        ),
        (
            "/components/schemas/EventPageV1/x-dirextalk-unknown-event-policy",
            json!("reject_without_advancing_cursor"),
        ),
        (
            "/components/schemas/EventPageV1/properties/events/items/$ref",
            json!("#/components/schemas/EventEnvelopeV1"),
        ),
        (
            "/components/schemas/EventPageV1/properties/next_cursor/x-dirextalk-max-utf8-bytes",
            json!(512),
        ),
        (
            "/components/schemas/EventPageCborV1/contentMediaType",
            json!("application/cbor"),
        ),
        (
            "/components/schemas/EventPageCborV1/x-dirextalk-cddl-rule",
            json!("event-page-v1"),
        ),
        (
            "/components/schemas/EventPageCborV1/x-dirextalk-unknown-event-policy",
            json!("preserve_exact_bytes_then_admit"),
        ),
    ] {
        expect_value(document, pointer, &expected)?;
    }
    Ok(())
}

fn validate_common_openapi_bounds(document: &Value) -> Result<(), ProtocolToolError> {
    for (pointer, expected) in [
        (
            "/components/schemas/UuidV7/pattern",
            json!("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
        ),
        (
            "/components/schemas/StableCode/pattern",
            json!("^[a-z][a-z0-9]*(?:_[a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:_[a-z0-9]+)*)*$"),
        ),
        ("/components/schemas/BoundedString/minLength", json!(1)),
        ("/components/schemas/BoundedString/maxLength", json!(1024)),
        (
            "/components/schemas/BoundedString/pattern",
            json!("^[^\\u0000-\\u001F\\u007F-\\u009F]+$"),
        ),
        (
            "/components/schemas/BoundedString/x-dirextalk-max-utf8-bytes",
            json!(1024),
        ),
        (
            "/components/schemas/BoundedString/x-dirextalk-disallow-control-characters",
            json!(true),
        ),
        ("/components/schemas/SafeUint/minimum", json!(0)),
        ("/components/schemas/SafeUint/maximum", json!(SAFE_UINT_MAX)),
        ("/components/schemas/PositiveSafeUint/minimum", json!(1)),
        (
            "/components/schemas/PositiveSafeUint/maximum",
            json!(SAFE_UINT_MAX),
        ),
        ("/components/schemas/Uint32/minimum", json!(0)),
        ("/components/schemas/Uint32/maximum", json!(u32::MAX)),
        (
            "/components/schemas/EventEnvelopeCoreV1/properties/aggregate_revision/$ref",
            json!("#/components/schemas/PositiveSafeUint"),
        ),
        (
            "/components/schemas/EventEnvelopeCoreV1/properties/stream_sequence/$ref",
            json!("#/components/schemas/PositiveSafeUint"),
        ),
    ] {
        expect_value(document, pointer, &expected)?;
    }
    Ok(())
}

fn validate_api_error_schema(
    document: &Value,
    errors: &ErrorRegistry,
) -> Result<(), ProtocolToolError> {
    let known = document
        .pointer("/components/schemas/ApiErrorCode/x-dirextalk-known-values")
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new("ApiErrorCode known values must be an array"))?;
    let actual = known.iter().filter_map(Value::as_str).collect::<Vec<_>>();
    let expected = errors
        .errors
        .iter()
        .map(|error| error.code.as_str())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(ProtocolToolError::new(
            "OpenAPI ApiErrorCode values must match the error registry",
        ));
    }

    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/message/minLength",
        &json!(1),
    )?;
    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/message/maxLength",
        &json!(512),
    )?;
    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/message/x-dirextalk-max-utf8-bytes",
        &json!(512),
    )?;
    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/message/pattern",
        &json!("^[^\\u0000-\\u001F\\u007F-\\u009F]+$"),
    )?;
    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/message/x-dirextalk-disallow-control-characters",
        &json!(true),
    )?;
    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/details/maxProperties",
        &json!(16),
    )?;
    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/details/propertyNames/minLength",
        &json!(1),
    )?;
    expect_value(
        document,
        "/components/schemas/ApiErrorV1/properties/details/propertyNames/maxLength",
        &json!(64),
    )?;
    validate_api_error_detail_variants(document)
}

fn validate_api_error_detail_variants(document: &Value) -> Result<(), ProtocolToolError> {
    let detail_variants = document
        .pointer("/components/schemas/ApiErrorDetailValue/oneOf")
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new("ApiErrorDetailValue oneOf is missing"))?;
    let expected_detail_variants = json!([
        {
            "type": "string",
            "maxLength": 256,
            "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]*$",
            "x-dirextalk-max-utf8-bytes": 256,
            "x-dirextalk-disallow-control-characters": true,
        },
        {
            "type": "integer",
            "format": "int64",
            "minimum": -9_007_199_254_740_991_i64,
            "maximum": SAFE_UINT_MAX,
        },
        {"type": "boolean"},
        {
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "items": {
                "type": "string",
                "maxLength": 256,
                "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]*$",
                "x-dirextalk-max-utf8-bytes": 256,
                "x-dirextalk-disallow-control-characters": true,
            },
        },
        {
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "items": {
                "type": "integer",
                "format": "int64",
                "minimum": -9_007_199_254_740_991_i64,
                "maximum": SAFE_UINT_MAX,
            },
        },
    ]);
    if Value::Array(detail_variants.clone()) != expected_detail_variants {
        return Err(ProtocolToolError::new(
            "ApiErrorDetailValue bounds drifted from the public error contract",
        ));
    }
    Ok(())
}

fn validate_payload_schema(
    schemas: &serde_json::Map<String, Value>,
    event: &EventDefinition,
) -> Result<(), ProtocolToolError> {
    let payload = schemas.get(&event.rust_name).ok_or_else(|| {
        ProtocolToolError::new(format!(
            "missing OpenAPI payload schema {}",
            event.rust_name
        ))
    })?;
    if payload.get("type").and_then(Value::as_str) != Some("object")
        || payload.get("additionalProperties").and_then(Value::as_bool) != Some(false)
    {
        return Err(ProtocolToolError::new(format!(
            "payload schema {} must be a closed object",
            event.rust_name
        )));
    }
    let required = string_array(payload, "required")?;
    let expected_names = event
        .fields
        .iter()
        .map(|field| field.name.clone())
        .collect::<Vec<_>>();
    if required != expected_names {
        return Err(ProtocolToolError::new(format!(
            "payload required fields drift for {}",
            event.event_type
        )));
    }
    let properties = payload
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new("payload properties must be an object"))?;
    if properties.len() != event.fields.len() {
        return Err(ProtocolToolError::new(format!(
            "payload property count drift for {}",
            event.event_type
        )));
    }
    for field in &event.fields {
        let actual = properties.get(&field.name).ok_or_else(|| {
            ProtocolToolError::new(format!(
                "missing OpenAPI field {}.{}",
                event.event_type, field.name
            ))
        })?;
        let expected = expected_field_schema(field)?;
        if actual != &expected {
            return Err(ProtocolToolError::new(format!(
                "OpenAPI type/bounds drift for {}.{}",
                event.event_type, field.name
            )));
        }
    }
    Ok(())
}

fn validate_envelope_binding(
    schemas: &serde_json::Map<String, Value>,
    event: &EventDefinition,
) -> Result<(), ProtocolToolError> {
    let envelope_name = format!("EventEnvelope{}", event.rust_name);
    let binding_name = format!("EventBinding{}", event.rust_name);
    let envelope = schemas
        .get(&envelope_name)
        .ok_or_else(|| ProtocolToolError::new(format!("missing {envelope_name}")))?;
    let all_of = envelope
        .get("allOf")
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new(format!("{envelope_name}.allOf is missing")))?;
    let expected_all_of = vec![
        json!({"$ref": "#/components/schemas/EventEnvelopeCoreV1"}),
        json!({"$ref": format!("#/components/schemas/{binding_name}")}),
    ];
    if all_of != &expected_all_of {
        return Err(ProtocolToolError::new(format!(
            "envelope composition drift for {}",
            event.event_type
        )));
    }

    let binding = schemas
        .get(&binding_name)
        .ok_or_else(|| ProtocolToolError::new(format!("missing {binding_name}")))?;
    let required = string_array(binding, "required")?;
    let expected_required = [
        "aggregate_type",
        "schema_version",
        "event_type",
        "required_reader_capability",
        "payload",
    ];
    if required.iter().map(String::as_str).collect::<Vec<_>>() != expected_required {
        return Err(ProtocolToolError::new(format!(
            "binding required fields drift for {}",
            event.event_type
        )));
    }
    let properties = binding
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new(format!("{binding_name}.properties is missing")))?;
    let capability = event
        .required_reader_capability
        .as_ref()
        .map_or_else(|| json!({"type": "null"}), |value| json!({"const": value}));
    let expected = json!({
        "aggregate_type": {"const": event.aggregate},
        "schema_version": {"const": event.schema_version},
        "event_type": {"const": event.event_type},
        "required_reader_capability": capability,
        "payload": {"$ref": format!("#/components/schemas/{}", event.rust_name)},
    });
    if Value::Object(properties.clone()) != expected {
        return Err(ProtocolToolError::new(format!(
            "event type/payload binding drift for {}",
            event.event_type
        )));
    }
    Ok(())
}

fn expected_field_schema(field: &EventField) -> Result<Value, ProtocolToolError> {
    let reference = |name: &str| json!({"$ref": format!("#/components/schemas/{name}")});
    let optional = |name: &str| json!({"oneOf": [reference(name), {"type": "null"}]});
    let value = match field.field_type.as_str() {
        "aggregate_id"
        | "approval_id"
        | "binding_id"
        | "boot_id"
        | "connector_id"
        | "consent_id"
        | "conversation_id"
        | "device_id"
        | "directory_registration_id"
        | "host_id"
        | "indexer_id"
        | "installation_id"
        | "job_evidence_id"
        | "job_id"
        | "job_resource_id"
        | "job_step_id"
        | "managed_service_id"
        | "run_id"
        | "service_operation_id" => reference("UuidV7"),
        "api_error_code" => reference("ApiErrorCode"),
        "bool" => json!({"type": "boolean"}),
        "bounded_string" => reference("BoundedString"),
        "job_evidence_id_list" => json!({
            "type": "array",
            "maxItems": 4096,
            "items": reference("UuidV7"),
        }),
        "optional_api_error_code" => optional("ApiErrorCode"),
        "optional_connector_id" => optional("UuidV7"),
        "optional_sha256_digest" => optional("Sha256Digest"),
        "optional_stable_code" => optional("StableCode"),
        "optional_utc_millis" => optional("UtcMillis"),
        "public_subject_id" => reference("PublicSubjectId"),
        "sha256_digest" => reference("Sha256Digest"),
        "stable_code" => reference("StableCode"),
        "u32" => reference("Uint32"),
        "u64" => reference("SafeUint"),
        "utc_millis" => reference("UtcMillis"),
        unsupported => {
            return Err(ProtocolToolError::new(format!(
                "no OpenAPI mapping for registry field type {unsupported}"
            )));
        }
    };
    Ok(value)
}

fn validate_protobuf(root: &Path) -> Result<(), ProtocolToolError> {
    let proto_root = root.join("protocol/proto");
    let protos = collect_files(&proto_root, Some("proto"))?;
    if protos.is_empty() {
        return Err(ProtocolToolError::new(
            "protocol/proto contains no .proto files",
        ));
    }
    // Full additive Agent Control artifacts intentionally retain the same
    // package and service identity. Compile each version directory as its own
    // source unit while compiling the rest of the protocol tree together.
    let agent_control_root = proto_root.join("dirextalk/agent_control");
    let mut compilation_units: BTreeMap<PathBuf, Vec<&PathBuf>> = BTreeMap::new();
    for proto in &protos {
        let unit = proto
            .strip_prefix(&agent_control_root)
            .ok()
            .and_then(|relative| relative.components().next())
            .map_or_else(
                || PathBuf::from("shared"),
                |version| PathBuf::from("agent_control").join(version.as_os_str()),
            );
        compilation_units.entry(unit).or_default().push(proto);
    }
    let mut descriptor_names = BTreeSet::new();
    for unit in compilation_units.values() {
        let descriptors = protox::compile(unit.iter().copied(), [&proto_root])
            .map_err(|error| ProtocolToolError::new(format!("compile Protobuf: {error}")))?;
        descriptor_names.extend(
            descriptors
                .file
                .iter()
                .filter_map(|descriptor| descriptor.name.as_deref().map(str::to_owned)),
        );
    }
    for proto in &protos {
        let relative = normalize_relative(
            proto
                .strip_prefix(&proto_root)
                .map_err(|_| ProtocolToolError::new("Protobuf path escaped protocol/proto"))?,
        )?;
        if !descriptor_names.contains(&relative) {
            return Err(ProtocolToolError::new(format!(
                "Protobuf descriptor omitted {relative}"
            )));
        }
    }

    let buf_files = collect_named_files(&proto_root, "buf.yaml")?;
    if buf_files.is_empty() {
        return Err(ProtocolToolError::new("protocol/proto is missing buf.yaml"));
    }
    for path in buf_files {
        let buf: Value = yaml_serde::from_str(&read(&path)?).map_err(|error| {
            ProtocolToolError::new(format!("parse {}: {error}", path.display()))
        })?;
        if buf.get("version").and_then(Value::as_str) != Some("v2") {
            return Err(ProtocolToolError::new(format!(
                "{} must use Buf version v2",
                path.display()
            )));
        }
    }

    let common = read(&proto_root.join("dirextalk/v1/common.proto"))?;
    for semantic_bound in [
        "9007199254740991",
        "At most 16 values",
        "1..512 UTF-8 bytes",
        "1..9007199254740991",
    ] {
        if !common.contains(semantic_bound) {
            return Err(ProtocolToolError::new(format!(
                "Protobuf semantic bounds are missing marker {semantic_bound}"
            )));
        }
    }
    Ok(())
}

fn validate_uuid_fields(value: &Value, pointers: &[&str]) -> Result<(), ProtocolToolError> {
    for pointer in pointers {
        let encoded = value
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProtocolToolError::new(format!("UUID vector field {pointer} missing"))
            })?;
        validate_uuid_v7(encoded).map_err(|error| {
            ProtocolToolError::new(format!("UUID vector field {pointer} is invalid: {error}"))
        })?;
    }
    Ok(())
}

fn validate_uuid_v7(value: &str) -> Result<(), ProtocolToolError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 8 | 13 | 18 | 23) && !is_lower_hex(*byte))
        || bytes[14] != b'7'
        || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
    {
        return Err(ProtocolToolError::new(
            "expected canonical lowercase hyphenated UUIDv7",
        ));
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn validate_cddl_hex(rule: &str, cddl: &str, encoded: &str) -> Result<(), ProtocolToolError> {
    let bytes = decode_hex(encoded)?;
    cddl_cat::validate_cbor_bytes(rule, cddl, &bytes)
        .map_err(|error| ProtocolToolError::new(format!("CDDL rejected {rule}: {error}")))
}

fn encode_event_page_fixture(
    canonical_envelope: &[u8],
    cursor: &str,
) -> Result<Vec<u8>, ProtocolToolError> {
    let envelope_length = u64::try_from(canonical_envelope.len())
        .map_err(|_| ProtocolToolError::new("event envelope is too large"))?;
    let cursor_length = u64::try_from(cursor.len())
        .map_err(|_| ProtocolToolError::new("event cursor is too large"))?;
    let mut encoded = Vec::with_capacity(canonical_envelope.len() + cursor.len() + 16);
    encoded.extend([0xa2, 0x01, 0x81]);
    encode_cbor_length(&mut encoded, 2, envelope_length);
    encoded.extend_from_slice(canonical_envelope);
    encoded.push(0x02);
    encode_cbor_length(&mut encoded, 3, cursor_length);
    encoded.extend_from_slice(cursor.as_bytes());
    Ok(encoded)
}

fn encode_cbor_length(output: &mut Vec<u8>, major: u8, length: u64) {
    let prefix = major << 5;
    match length {
        0..=23 => output.push(prefix | u8::try_from(length).expect("length is at most 23")),
        24..=0xff => {
            output.push(prefix | 0x18);
            output.push(u8::try_from(length).expect("length is at most u8::MAX"));
        }
        0x100..=0xffff => {
            output.push(prefix | 0x19);
            output.extend_from_slice(
                &u16::try_from(length)
                    .expect("length is at most u16::MAX")
                    .to_be_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 0x1a);
            output.extend_from_slice(
                &u32::try_from(length)
                    .expect("length is at most u32::MAX")
                    .to_be_bytes(),
            );
        }
        _ => {
            output.push(prefix | 0x1b);
            output.extend_from_slice(&length.to_be_bytes());
        }
    }
}

fn validate_vector_version(vector: &Value, name: &str) -> Result<(), ProtocolToolError> {
    if vector.get("version").and_then(Value::as_u64) == Some(1) {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "{name} vector version must be 1"
        )))
    }
}

fn envelope_ref(event: &EventDefinition) -> String {
    format!("#/components/schemas/EventEnvelope{}", event.rust_name)
}

fn refs_at(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, ProtocolToolError> {
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new(format!("{key} must be an array")))?
        .iter()
        .map(|entry| {
            entry
                .get("$ref")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| ProtocolToolError::new(format!("{key} entry must contain $ref")))
        })
        .collect()
}

fn string_array(value: &Value, key: &str) -> Result<Vec<String>, ProtocolToolError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new(format!("{key} must be an array")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| ProtocolToolError::new(format!("{key} entry must be a string")))
        })
        .collect()
}

fn object_at<'a>(
    value: &'a Value,
    pointer: &str,
) -> Result<&'a serde_json::Map<String, Value>, ProtocolToolError> {
    value
        .pointer(pointer)
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new(format!("{pointer} must be an object")))
}

fn expect_value(value: &Value, pointer: &str, expected: &Value) -> Result<(), ProtocolToolError> {
    if value.pointer(pointer) == Some(expected) {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "OpenAPI bound drift at {pointer}"
        )))
    }
}

fn json_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProtocolToolError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolToolError::new(format!("vector field {key} must be a string")))
}

fn read_json(path: &Path) -> Result<Value, ProtocolToolError> {
    serde_json::from_str(&read(path)?)
        .map_err(|error| ProtocolToolError::new(format!("parse {}: {error}", path.display())))
}

fn read(path: &Path) -> Result<String, ProtocolToolError> {
    fs::read_to_string(path)
        .map_err(|error| ProtocolToolError::new(format!("read {}: {error}", path.display())))
}

fn collect_files(root: &Path, extension: Option<&str>) -> Result<Vec<PathBuf>, ProtocolToolError> {
    let mut files = Vec::new();
    collect_files_inner(root, extension, None, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_named_files(root: &Path, name: &str) -> Result<Vec<PathBuf>, ProtocolToolError> {
    let mut files = Vec::new();
    collect_files_inner(root, None, Some(name), &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(
    root: &Path,
    extension: Option<&str>,
    name: Option<&str>,
    output: &mut Vec<PathBuf>,
) -> Result<(), ProtocolToolError> {
    let entries = fs::read_dir(root).map_err(|error| {
        ProtocolToolError::new(format!("read directory {}: {error}", root.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ProtocolToolError::new(format!("read directory entry {}: {error}", root.display()))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            ProtocolToolError::new(format!(
                "read file type {}: {error}",
                entry.path().display()
            ))
        })?;
        if file_type.is_symlink() {
            return Err(ProtocolToolError::new(format!(
                "protocol artifact cannot be a symlink: {}",
                entry.path().display()
            )));
        }
        if file_type.is_dir() {
            collect_files_inner(&entry.path(), extension, name, output)?;
        } else if file_type.is_file()
            && extension.is_none_or(|expected| {
                entry.path().extension().and_then(|value| value.to_str()) == Some(expected)
            })
            && name.is_none_or(|expected| entry.file_name() == expected)
        {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn normalize_relative(path: &Path) -> Result<String, ProtocolToolError> {
    let parts = path
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| ProtocolToolError::new("protocol path must be UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parts.join("/"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ProtocolToolError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolToolError::new(
            "golden CBOR must use lowercase even-length hex",
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| ProtocolToolError::new("invalid golden CBOR hex"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn common_cddl() -> String {
        read(&root().join("protocol/cddl/v1/common.cddl")).unwrap()
    }

    fn validate(rule: &str, cddl: &str, bytes: &[u8]) -> bool {
        cddl_cat::validate_cbor_bytes(rule, cddl, bytes).is_ok()
    }

    fn text(length: usize) -> Vec<u8> {
        let mut encoded = if length <= 23 {
            vec![0x60 | u8::try_from(length).unwrap()]
        } else {
            let length = u16::try_from(length).unwrap();
            let [high, low] = length.to_be_bytes();
            vec![0x79, high, low]
        };
        encoded.extend(std::iter::repeat_n(b'a', length));
        encoded
    }

    fn unsigned(value: u64) -> Vec<u8> {
        let mut encoded = vec![0x1b];
        encoded.extend_from_slice(&value.to_be_bytes());
        encoded
    }

    fn negative(value: i64) -> Vec<u8> {
        assert!(value < 0);
        let argument = u64::try_from(-1_i128 - i128::from(value)).unwrap();
        let mut encoded = vec![0x3b];
        encoded.extend_from_slice(&argument.to_be_bytes());
        encoded
    }

    fn array_with_empty_text(count: u8) -> Vec<u8> {
        let mut encoded = vec![0x80 | count];
        encoded.extend(std::iter::repeat_n(0x60, usize::from(count)));
        encoded
    }

    fn details_map(count: u8) -> Vec<u8> {
        let mut encoded = vec![0xa0 | count];
        for index in 0..count {
            encoded.extend([0x61, b'a' + index, 0xf4]);
        }
        encoded
    }

    #[test]
    fn uuid_v7_semantics_reject_wrong_version_variant_case_and_shape() {
        validate_uuid_v7("0190f2a5-7b1c-7abc-8def-0123456789ab").unwrap();
        for invalid in [
            "0190f2a5-7b1c-6abc-8def-0123456789ab",
            "0190f2a5-7b1c-7abc-7def-0123456789ab",
            "0190F2A5-7b1c-7abc-8def-0123456789ab",
            "0190f2a57b1c7abc8def0123456789ab",
        ] {
            assert!(validate_uuid_v7(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn cddl_accepts_public_bounds_and_rejects_max_plus_one() {
        let common = common_cddl();
        assert!(validate("api-error-message", &common, &text(512)));
        assert!(!validate("api-error-message", &common, &text(513)));
        assert!(validate("api-error-detail-text", &common, &text(256)));
        assert!(!validate("api-error-detail-text", &common, &text(257)));
        assert!(validate("safe-uint", &common, &unsigned(SAFE_UINT_MAX)));
        assert!(!validate(
            "safe-uint",
            &common,
            &unsigned(SAFE_UINT_MAX + 1)
        ));
        assert!(validate(
            "safe-int",
            &common,
            &negative(-9_007_199_254_740_991)
        ));
        assert!(!validate(
            "safe-int",
            &common,
            &negative(-9_007_199_254_740_992)
        ));
        assert!(validate("positive-safe-uint", &common, &[0x01]));
        assert!(!validate("positive-safe-uint", &common, &[0x00]));
    }

    #[test]
    fn cddl_caps_api_error_lists_and_maps_at_sixteen() {
        let cddl = format!(
            "{}\n{}",
            common_cddl(),
            read(&root().join("protocol/cddl/v1/api-error.cddl")).unwrap()
        );
        assert!(validate(
            "api-error-detail",
            &cddl,
            &array_with_empty_text(16)
        ));
        assert!(!validate(
            "api-error-detail",
            &cddl,
            &array_with_empty_text(17)
        ));
        assert!(!validate(
            "api-error-detail",
            &cddl,
            &array_with_empty_text(0)
        ));
        assert!(validate("api-error-details", &cddl, &details_map(16)));
        assert!(!validate("api-error-details", &cddl, &details_map(17)));
    }

    #[test]
    fn openapi_registry_validation_detects_payload_type_drift() {
        let root = root();
        let source = read(&root.join("protocol/openapi/v1/openapi.yaml")).unwrap();
        let mut document: Value = yaml_serde::from_str(&source).unwrap();
        *document
            .pointer_mut("/components/schemas/JobChangedV1/properties/plan_revision/$ref")
            .unwrap() = json!("#/components/schemas/PositiveSafeUint");
        let events = load_event_registry(&root.join("protocol/events/registry.yaml")).unwrap();
        let errors = load_error_registry(&root.join("protocol/errors/registry.yaml")).unwrap();
        assert!(validate_openapi_registry_contract(&document, &events, &errors).is_err());
    }

    #[test]
    fn openapi_declares_runtime_text_and_event_page_byte_bounds() {
        let source = read(&root().join("protocol/openapi/v1/openapi.yaml")).unwrap();
        let document: Value = yaml_serde::from_str(&source).unwrap();

        for (pointer, expected) in [
            (
                "/components/schemas/StableCode/pattern",
                json!("^[a-z][a-z0-9]*(?:_[a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:_[a-z0-9]+)*)*$"),
            ),
            (
                "/components/schemas/BoundedString/x-dirextalk-max-utf8-bytes",
                json!(1024),
            ),
            (
                "/components/schemas/BoundedString/x-dirextalk-disallow-control-characters",
                json!(true),
            ),
            (
                "/components/schemas/BoundedString/pattern",
                json!("^[^\\u0000-\\u001F\\u007F-\\u009F]+$"),
            ),
            (
                "/components/schemas/ApiErrorV1/properties/message/x-dirextalk-max-utf8-bytes",
                json!(512),
            ),
            (
                "/components/schemas/ApiErrorDetailValue/oneOf/0/x-dirextalk-max-utf8-bytes",
                json!(256),
            ),
            (
                "/paths/~1v1~1agent-jobs~1{job_id}~1events/get/responses/200/content/application~1cbor/x-dirextalk-max-body-bytes",
                json!(1_048_576),
            ),
        ] {
            expect_value(&document, pointer, &expected).unwrap();
        }
    }

    #[test]
    fn cddl_event_page_preserves_nonempty_exact_envelope_bytes_and_cursor() {
        let cddl = format!(
            "{}\n{}",
            common_cddl(),
            read(&root().join("protocol/cddl/v1/event-page.cddl")).unwrap()
        );
        let valid = encode_event_page_fixture(&[0xa1, 0x01, 0x01], "cursor").unwrap();
        assert!(validate("event-page-v1", &cddl, &valid));

        let empty_envelope = encode_event_page_fixture(&[], "cursor").unwrap();
        assert!(!validate("event-page-v1", &cddl, &empty_envelope));
        let empty_cursor = encode_event_page_fixture(&[0xa1, 0x01, 0x01], "").unwrap();
        assert!(!validate("event-page-v1", &cddl, &empty_cursor));
    }

    #[test]
    fn protobuf_validation_compiles_nested_proto_files() {
        let unique = format!(
            "dtx-protocol-proto-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let proto_root = root.join("protocol/proto");
        let common = proto_root.join("dirextalk/v1/common.proto");
        let nested = proto_root.join("dirextalk/v1/nested.proto");
        fs::create_dir_all(common.parent().unwrap()).unwrap();
        fs::write(proto_root.join("buf.yaml"), "version: v2\n").unwrap();
        fs::write(
            &common,
            r#"syntax = "proto3";
package dirextalk.v1;
// 9007199254740991
// At most 16 values
// 1..512 UTF-8 bytes
// 1..9007199254740991
message Common {}
"#,
        )
        .unwrap();
        fs::write(&nested, "this is not protobuf\n").unwrap();
        assert!(validate_protobuf(&root).is_err());

        fs::write(
            &nested,
            "syntax = \"proto3\";\npackage dirextalk.v1;\nmessage Nested {}\n",
        )
        .unwrap();
        validate_protobuf(&root).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
}
