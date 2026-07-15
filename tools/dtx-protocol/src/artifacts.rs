use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, UtcMillis, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ErrorRegistry, EventDefinition, EventField, EventRegistry, ProtocolToolError,
    load_error_registry, load_event_registry,
};

const SAFE_UINT_MAX: u64 = 9_007_199_254_740_991;
const PRIVATE_EVENT_MAX_ENCODED_BYTES: usize = 66_383;
const PRIVATE_EVENT_MLS_GROUP_ID_DOMAIN: &[u8] = b"dirextalk.mls-group-id.conversation.v1\0";
const PRIVATE_EVENT_MLS_CIPHERTEXT_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.private-event-mls-ciphertext.v1\0";
const PRIVATE_EVENT_MAX_MLS_CIPHERTEXT_BYTES: usize = 262_144;
const CONTACT_CARD_QR_PREFIX: &str = "dtxc1:";
const CONTACT_CARD_MAX_DECODED_CBOR_BYTES: usize = 4_096;
const CONTACT_CARD_MAX_UNPADDED_BASE64URL_CHARS: usize =
    unpadded_base64url_character_count(CONTACT_CARD_MAX_DECODED_CBOR_BYTES);
const CONTACT_CARD_MAX_QR_PAYLOAD_CHARS: usize =
    CONTACT_CARD_QR_PREFIX.len() + CONTACT_CARD_MAX_UNPADDED_BASE64URL_CHARS;

/// Parses every source schema and validates committed CBOR golden vectors.
///
/// # Errors
///
/// Returns [`ProtocolToolError`] for missing, malformed, or inconsistent
/// CDDL, `OpenAPI`, Protobuf, Buf, registry, or vector artifacts.
#[allow(clippy::too_many_lines)] // Central artifact routing remains explicit at the protocol gate.
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

    validate_identity_log_v1_1(root)?;
    validate_identity_log_page_v1(root)?;
    validate_contact_card_v1(root)?;
    validate_identity_bootstrap_v1(root)?;
    validate_identity_session_v1(root)?;
    validate_identity_enrollment_v1(root)?;
    validate_key_package_v1(root)?;
    validate_mailbox_v1(root)?;
    validate_public_descriptor_v1(root)?;
    validate_public_descriptor_v1_1(root)?;
    validate_public_descriptor_v1_2(root)?;
    validate_public_feed_v1(root)?;
    validate_membership_federation_v1(root)?;
    validate_private_messaging_artifacts(root)?;

    let events = load_event_registry(&root.join("protocol/events/registry.yaml"))?;
    let errors = load_error_registry(&root.join("protocol/errors/registry.yaml"))?;
    validate_openapi(root, &events, &errors)?;
    validate_protobuf(root)?;
    Ok(())
}

fn validate_public_feed_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_path = root.join("protocol/cddl/public-feed/v1/public-feed-v1.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse public feed V1 CDDL: {error}")))?;
    let source = read(&root.join("protocol/openapi/public-feed/v1/openapi.yaml"))?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse public feed V1 OpenAPI: {error}"))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "public feed V1 OpenAPI must declare 3.1.0",
        ));
    }
    let vector = read_json(&root.join("protocol/test-vectors/public-feed/v1/public-feed-v1.json"))?;
    validate_vector_version(&vector, "public-feed-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(24) {
        return Err(ProtocolToolError::new(
            "public feed V1 vector baseline must be 24",
        ));
    }
    for field in ["channel_post_cbor_hex", "agent_post_cbor_hex"] {
        validate_cddl_hex("public-feed-event-v1", &cddl, json_string(&vector, field)?)?;
    }
    Ok(())
}

fn validate_private_messaging_artifacts(root: &Path) -> Result<(), ProtocolToolError> {
    validate_private_event_v1(root)?;
    validate_mls_sequencer_v1(root)?;
    validate_mls_sequencer_v2(root)
}

fn validate_mls_sequencer_v2(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_path = root.join("protocol/cddl/mls-sequencer/v2/mls-sequencer-v2.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse MLS Sequencer v2 CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;
    let openapi_path = root.join("protocol/openapi/mls-sequencer/v2/openapi.yaml");
    let source = read(&openapi_path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse MLS Sequencer v2 OpenAPI {}: {error}",
            openapi_path.display()
        ))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "MLS Sequencer v2 OpenAPI must declare 3.1.0",
        ));
    }
    let vector =
        read_json(&root.join("protocol/test-vectors/mls-sequencer/v2/mls-sequencer-v2.json"))?;
    if vector.get("version").and_then(Value::as_u64) != Some(2)
        || vector.get("baseline").and_then(Value::as_u64) != Some(22)
    {
        return Err(ProtocolToolError::new(
            "MLS Sequencer v2 vector version/baseline must be 2/22",
        ));
    }
    for domain in [
        "candidate_proof_digest_domain_utf8_hex",
        "candidate_proof_signature_domain_utf8_hex",
        "controller_consent_digest_domain_utf8_hex",
        "controller_consent_signature_domain_utf8_hex",
        "idempotency_key_hash_domain_utf8_hex",
        "inherited_confirmation_signature_domain_utf8_hex",
    ] {
        if json_string(&vector, domain)?.is_empty() {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer v2 missing {domain}"
            )));
        }
    }
    Ok(())
}

fn validate_mls_sequencer_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_path = root.join("protocol/cddl/mls-sequencer/v1/mls-sequencer-v1.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse MLS Sequencer v1 CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;
    let openapi_path = root.join("protocol/openapi/mls-sequencer/v1/openapi.yaml");
    let source = read(&openapi_path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse MLS Sequencer v1 OpenAPI {}: {error}",
            openapi_path.display()
        ))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "MLS Sequencer OpenAPI must declare 3.1.0",
        ));
    }
    let vector =
        read_json(&root.join("protocol/test-vectors/mls-sequencer/v1/mls-sequencer-v1.json"))?;
    validate_vector_version(&vector, "mls-sequencer-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(21) {
        return Err(ProtocolToolError::new(
            "MLS Sequencer vector baseline must be 21",
        ));
    }
    if json_string(&vector, "genesis_head_hex")? != "0".repeat(64) {
        return Err(ProtocolToolError::new(
            "MLS Sequencer genesis head must be 32 zero bytes",
        ));
    }
    if vector
        .get("max_opaque_commit_bytes")
        .and_then(Value::as_u64)
        != Some(1_048_576)
    {
        return Err(ProtocolToolError::new(
            "MLS Sequencer maximum opaque Commit must be 1048576",
        ));
    }
    Ok(())
}

fn validate_private_event_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_path = root.join("protocol/cddl/private-event/v1/private-event-v1.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse private application event v1 CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;

    let vector =
        read_json(&root.join("protocol/test-vectors/private-event/v1/private-event-v1.json"))?;
    require_exact_object_keys(
        &vector,
        &[
            "version",
            "baseline",
            "max_canonical_cbor_bytes",
            "mls_group_id_derivation",
            "mls_authenticated_event_digest",
            "events",
        ],
        "private-event-v1 vector",
    )?;
    validate_vector_version(&vector, "private-event-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(20) {
        return Err(ProtocolToolError::new(
            "private-event-v1 vector baseline must be 20",
        ));
    }
    if vector
        .get("max_canonical_cbor_bytes")
        .and_then(Value::as_u64)
        != Some(PRIVATE_EVENT_MAX_ENCODED_BYTES as u64)
    {
        return Err(ProtocolToolError::new(
            "private-event-v1 max canonical CBOR bytes must be 66383",
        ));
    }
    validate_private_event_mls_group_id_derivation(&vector)?;
    validate_private_event_mls_ciphertext_digest(&vector)?;
    let events = vector
        .get("events")
        .and_then(Value::as_array)
        .filter(|events| events.len() == 3)
        .ok_or_else(|| {
            ProtocolToolError::new(
                "private-event-v1 vector must contain exactly text, agent_request, and agent_response",
            )
        })?;
    let mut kinds = BTreeSet::new();
    for event in events {
        let kind = validate_private_event_vector_entry(event, &cddl)?;
        if !kinds.insert(kind) {
            return Err(ProtocolToolError::new(
                "private-event-v1 vector event kinds must be unique",
            ));
        }
    }
    if kinds != BTreeSet::from([1, 2, 3]) {
        return Err(ProtocolToolError::new(
            "private-event-v1 vector must cover kinds 1, 2, and 3",
        ));
    }
    Ok(())
}

fn validate_private_event_mls_ciphertext_digest(vector: &Value) -> Result<(), ProtocolToolError> {
    let digest = vector
        .get("mls_authenticated_event_digest")
        .ok_or_else(|| {
            ProtocolToolError::new("private-event-v1 MLS-authenticated event digest is missing")
        })?;
    require_exact_object_keys(
        digest,
        &[
            "domain_utf8_hex",
            "event_id",
            "event_uuid_raw16_hex",
            "max_ciphertext_bytes",
            "mls_wire_ciphertext_hex",
            "ciphertext_len",
            "digest_hex",
        ],
        "private-event-v1 MLS-authenticated event digest",
    )?;
    let domain = decode_hex(json_string(digest, "domain_utf8_hex")?)?;
    if domain != PRIVATE_EVENT_MLS_CIPHERTEXT_DIGEST_DOMAIN {
        return Err(ProtocolToolError::new(
            "private-event-v1 MLS ciphertext digest domain drifted",
        ));
    }
    if digest.get("max_ciphertext_bytes").and_then(Value::as_u64)
        != Some(PRIVATE_EVENT_MAX_MLS_CIPHERTEXT_BYTES as u64)
    {
        return Err(ProtocolToolError::new(
            "private-event-v1 MLS ciphertext maximum must match mailbox ciphertext maximum",
        ));
    }
    let event_id = json_string(digest, "event_id")?;
    let raw = decode_uuid_v7_raw16(event_id)?;
    if decode_lower_hex_fixed::<16>(json_string(digest, "event_uuid_raw16_hex")?)? != raw {
        return Err(ProtocolToolError::new(
            "private-event-v1 digest event UUID raw16 vector drifted",
        ));
    }
    let ciphertext = decode_hex(json_string(digest, "mls_wire_ciphertext_hex")?)?;
    if digest.get("ciphertext_len").and_then(Value::as_u64) != u64::try_from(ciphertext.len()).ok()
    {
        return Err(ProtocolToolError::new(
            "private-event-v1 MLS ciphertext length vector drifted",
        ));
    }
    let expected = mls_authenticated_private_event_digest(event_id, &ciphertext)?;
    if decode_lower_hex_fixed::<32>(json_string(digest, "digest_hex")?)? != expected {
        return Err(ProtocolToolError::new(
            "private-event-v1 MLS-authenticated event digest vector drifted",
        ));
    }
    let event_is_frozen = vector
        .get("events")
        .and_then(Value::as_array)
        .is_some_and(|events| {
            events
                .iter()
                .any(|event| event.get("event_id").and_then(Value::as_str) == Some(event_id))
        });
    if !event_is_frozen {
        return Err(ProtocolToolError::new(
            "private-event-v1 digest event_id must reference a frozen event vector",
        ));
    }
    Ok(())
}

fn mls_authenticated_private_event_digest(
    event_id: &str,
    ciphertext: &[u8],
) -> Result<[u8; 32], ProtocolToolError> {
    let event_id = decode_uuid_v7_raw16(event_id)?;
    if ciphertext.is_empty() || ciphertext.len() > PRIVATE_EVENT_MAX_MLS_CIPHERTEXT_BYTES {
        return Err(ProtocolToolError::new(
            "private-event-v1 MLS ciphertext must contain 1..262144 bytes",
        ));
    }
    let ciphertext_len = u64::try_from(ciphertext.len())
        .expect("private event MLS ciphertext length is bounded by 262144");
    Ok(Sha256::new()
        .chain_update(PRIVATE_EVENT_MLS_CIPHERTEXT_DIGEST_DOMAIN)
        .chain_update(event_id)
        .chain_update(ciphertext_len.to_be_bytes())
        .chain_update(ciphertext)
        .finalize()
        .into())
}

fn validate_private_event_mls_group_id_derivation(vector: &Value) -> Result<(), ProtocolToolError> {
    let derivation = vector.get("mls_group_id_derivation").ok_or_else(|| {
        ProtocolToolError::new("private-event-v1 MLS group derivation is missing")
    })?;
    require_exact_object_keys(
        derivation,
        &[
            "domain_utf8_hex",
            "conversation_id",
            "conversation_uuid_raw16_hex",
            "mls_group_id_hex",
        ],
        "private-event-v1 MLS group derivation",
    )?;
    let domain = decode_hex(json_string(derivation, "domain_utf8_hex")?)?;
    if domain != PRIVATE_EVENT_MLS_GROUP_ID_DOMAIN {
        return Err(ProtocolToolError::new(
            "private-event-v1 MLS group derivation domain drifted",
        ));
    }
    let conversation_id = json_string(derivation, "conversation_id")?;
    let raw = decode_uuid_v7_raw16(conversation_id)?;
    if decode_lower_hex_fixed::<16>(json_string(derivation, "conversation_uuid_raw16_hex")?)? != raw
    {
        return Err(ProtocolToolError::new(
            "private-event-v1 conversation UUID raw16 vector drifted",
        ));
    }
    let expected: [u8; 32] = Sha256::new()
        .chain_update(PRIVATE_EVENT_MLS_GROUP_ID_DOMAIN)
        .chain_update(raw)
        .finalize()
        .into();
    if decode_lower_hex_fixed::<32>(json_string(derivation, "mls_group_id_hex")?)? != expected {
        return Err(ProtocolToolError::new(
            "private-event-v1 MLS group ID vector drifted",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One entry audit keeps JSON semantics and exact CBOR inseparable.
fn validate_private_event_vector_entry(
    event: &Value,
    cddl: &str,
) -> Result<u64, ProtocolToolError> {
    require_exact_object_keys(
        event,
        &[
            "label",
            "event_id",
            "conversation_id",
            "author_identity_id",
            "author_device_id",
            "created_at_ms",
            "kind",
            "parent_event_ids",
            "body_utf8_hex",
            "run_id",
            "canonical_cbor_hex",
        ],
        "private-event-v1 entry",
    )?;
    let label = json_string(event, "label")?;
    let event_id = json_string(event, "event_id")?;
    let conversation_id = json_string(event, "conversation_id")?;
    let author_identity_id = json_string(event, "author_identity_id")?;
    let author_device_id = json_string(event, "author_device_id")?;
    for (value, name) in [
        (event_id, "event_id"),
        (conversation_id, "conversation_id"),
        (author_device_id, "author_device_id"),
    ] {
        validate_uuid_v7(value).map_err(|error| {
            ProtocolToolError::new(format!(
                "private-event-v1 {label} {name} is invalid: {error}"
            ))
        })?;
    }
    validate_identity_id(author_identity_id, "private-event-v1 author_identity_id")?;
    let created_at_ms = event
        .get("created_at_ms")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            ProtocolToolError::new("private-event-v1 created_at_ms must be an integer")
        })?;
    let created_at = UtcMillis::new(created_at_ms).map_err(|_| {
        ProtocolToolError::new("private-event-v1 created_at_ms must be a valid UtcMillis")
    })?;
    let kind = event
        .get("kind")
        .and_then(Value::as_u64)
        .filter(|kind| (1..=3).contains(kind))
        .ok_or_else(|| ProtocolToolError::new("private-event-v1 kind must be 1, 2, or 3"))?;
    let parent_values = event
        .get("parent_event_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProtocolToolError::new("private-event-v1 parent_event_ids must be an array")
        })?;
    if parent_values.len() > 16 {
        return Err(ProtocolToolError::new(
            "private-event-v1 parent_event_ids cannot exceed 16 entries",
        ));
    }
    let mut parent_ids = Vec::with_capacity(parent_values.len());
    let mut unique_parents = BTreeSet::new();
    for parent in parent_values {
        let parent = parent.as_str().ok_or_else(|| {
            ProtocolToolError::new("private-event-v1 parent_event_id must be text")
        })?;
        validate_uuid_v7(parent)?;
        if parent == event_id {
            return Err(ProtocolToolError::new(
                "private-event-v1 parent_event_ids cannot contain event_id",
            ));
        }
        if !unique_parents.insert(parent) {
            return Err(ProtocolToolError::new(
                "private-event-v1 parent_event_ids must be unique",
            ));
        }
        parent_ids.push(CanonicalValue::Text(parent.to_owned()));
    }
    let body_bytes = decode_hex(json_string(event, "body_utf8_hex")?)?;
    if body_bytes.len() > 65_536 {
        return Err(ProtocolToolError::new(
            "private-event-v1 body exceeds 65536 UTF-8 bytes",
        ));
    }
    let body = String::from_utf8(body_bytes)
        .map_err(|_| ProtocolToolError::new("private-event-v1 body_utf8_hex is not valid UTF-8"))?;
    let run_id = match event.get("run_id") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => {
            validate_uuid_v7(value)?;
            Some(value.as_str())
        }
        _ => {
            return Err(ProtocolToolError::new(
                "private-event-v1 run_id must be UUIDv7 text or null",
            ));
        }
    };
    if (kind == 1 && run_id.is_some()) || (kind == 3 && run_id.is_none()) {
        return Err(ProtocolToolError::new(
            "private-event-v1 kind/run_id combination is invalid",
        ));
    }

    let canonical = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(event_id.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(conversation_id.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(author_identity_id.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(author_device_id.to_owned()),
        ),
        (CanonicalValue::Unsigned(6), created_at.to_canonical_value()),
        (CanonicalValue::Unsigned(7), CanonicalValue::Unsigned(kind)),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Array(parent_ids),
        ),
        (CanonicalValue::Unsigned(9), CanonicalValue::Text(body)),
        (
            CanonicalValue::Unsigned(10),
            run_id.map_or(CanonicalValue::Null, |value| {
                CanonicalValue::Text(value.to_owned())
            }),
        ),
    ]);
    let actual = encode_deterministic_cbor(&canonical).map_err(|error| {
        ProtocolToolError::new(format!("encode private-event-v1 {label}: {error}"))
    })?;
    let expected_hex = json_string(event, "canonical_cbor_hex")?;
    if lowercase_hex(&actual) != expected_hex {
        return Err(ProtocolToolError::new(format!(
            "private-event-v1 {label} canonical CBOR drift: actual {}",
            lowercase_hex(&actual)
        )));
    }
    validate_private_event_bytes(cddl, &actual).map_err(|error| {
        ProtocolToolError::new(format!("private-event-v1 {label} is invalid: {error}"))
    })?;
    Ok(kind)
}

#[allow(clippy::too_many_lines)] // All ten strict decoder fields are audited in one ordered pass.
fn validate_private_event_bytes(cddl: &str, bytes: &[u8]) -> Result<(), ProtocolToolError> {
    if bytes.len() > PRIVATE_EVENT_MAX_ENCODED_BYTES {
        return Err(ProtocolToolError::new(
            "private application event exceeds 66383 canonical CBOR bytes",
        ));
    }
    let value = decode_deterministic_cbor(bytes).map_err(|error| {
        ProtocolToolError::new(format!(
            "private application event is not canonical: {error}"
        ))
    })?;
    let CanonicalValue::Map(entries) = value else {
        return Err(ProtocolToolError::new(
            "private application event must be a map",
        ));
    };
    if entries.len() != 10 {
        return Err(ProtocolToolError::new(
            "private application event must contain exactly fields 1 through 10",
        ));
    }
    let values = entries
        .iter()
        .enumerate()
        .map(|(index, (key, value))| {
            let expected = u64::try_from(index + 1).expect("field index is bounded");
            if key == &CanonicalValue::Unsigned(expected) {
                Ok(value)
            } else {
                Err(ProtocolToolError::new(
                    "private application event contains an unknown or missing field",
                ))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values[0] != &CanonicalValue::Unsigned(1) {
        return Err(ProtocolToolError::new(
            "private application event version must be 1",
        ));
    }
    for (value, label) in [
        (values[1], "event_id"),
        (values[2], "conversation_id"),
        (values[4], "author_device_id"),
    ] {
        let CanonicalValue::Text(value) = value else {
            return Err(ProtocolToolError::new(format!(
                "private application event {label} must be text"
            )));
        };
        validate_uuid_v7(value)?;
    }
    let CanonicalValue::Text(author_identity_id) = values[3] else {
        return Err(ProtocolToolError::new(
            "private application event author_identity_id must be text",
        ));
    };
    validate_identity_id(
        author_identity_id,
        "private application event author_identity_id",
    )?;
    decode_private_event_utc_millis(values[5])?;
    let CanonicalValue::Unsigned(kind @ 1..=3) = values[6] else {
        return Err(ProtocolToolError::new(
            "private application event kind must be 1, 2, or 3",
        ));
    };
    let CanonicalValue::Array(parents) = values[7] else {
        return Err(ProtocolToolError::new(
            "private application event parents must be an array",
        ));
    };
    if parents.len() > 16 {
        return Err(ProtocolToolError::new(
            "private application event parents cannot exceed 16 entries",
        ));
    }
    let mut unique = BTreeSet::new();
    for parent in parents {
        let CanonicalValue::Text(parent) = parent else {
            return Err(ProtocolToolError::new(
                "private application event parent must be text",
            ));
        };
        validate_uuid_v7(parent)?;
        let CanonicalValue::Text(event_id) = values[1] else {
            unreachable!("event_id was validated as text")
        };
        if parent == event_id {
            return Err(ProtocolToolError::new(
                "private application event parents cannot contain event_id",
            ));
        }
        if !unique.insert(parent) {
            return Err(ProtocolToolError::new(
                "private application event parents must be unique",
            ));
        }
    }
    let CanonicalValue::Text(body) = values[8] else {
        return Err(ProtocolToolError::new(
            "private application event body must be UTF-8 text",
        ));
    };
    if body.len() > 65_536 {
        return Err(ProtocolToolError::new(
            "private application event body exceeds 65536 UTF-8 bytes",
        ));
    }
    let run_id = match values[9] {
        CanonicalValue::Null => None,
        CanonicalValue::Text(value) => {
            validate_uuid_v7(value)?;
            Some(value)
        }
        _ => {
            return Err(ProtocolToolError::new(
                "private application event run_id must be UUIDv7 text or null",
            ));
        }
    };
    if (*kind == 1 && run_id.is_some()) || (*kind == 3 && run_id.is_none()) {
        return Err(ProtocolToolError::new(
            "private application event kind/run_id combination is invalid",
        ));
    }
    cddl_cat::validate_cbor_bytes("private-application-event-v1", cddl, bytes).map_err(|error| {
        ProtocolToolError::new(format!("private application event CDDL rejected: {error}"))
    })
}

fn decode_private_event_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, ProtocolToolError> {
    let raw = match value {
        CanonicalValue::Unsigned(value) => i64::try_from(*value).map_err(|_| {
            ProtocolToolError::new("private application event created_at_ms exceeds i64")
        })?,
        CanonicalValue::Negative(value) => *value,
        _ => {
            return Err(ProtocolToolError::new(
                "private application event created_at_ms must be an integer",
            ));
        }
    };
    UtcMillis::new(raw).map_err(|_| {
        ProtocolToolError::new("private application event created_at_ms must be a valid UtcMillis")
    })
}

fn validate_membership_federation_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_path =
        root.join("protocol/cddl/membership-federation/v1/membership-federation-v1.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse membership-federation v1 CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;

    let vector = read_json(
        &root.join("protocol/test-vectors/membership-federation/v1/membership-federation-v1.json"),
    )?;
    validate_vector_version(&vector, "membership-federation-v1")?;
    for (field, expected) in [
        (
            "action_binding_hash_domain",
            "dirextalk.membership-action-binding.v2\0",
        ),
        (
            "action_signature_domain",
            "dirextalk.membership-action-signature.v2\0",
        ),
        (
            "receipt_query_binding_hash_domain",
            "dirextalk.membership-receipt-query-binding.v2\0",
        ),
        (
            "receipt_query_signature_domain",
            "dirextalk.membership-receipt-query-signature.v2\0",
        ),
    ] {
        if json_string(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "membership-federation-v1 {field} drift"
            )));
        }
    }
    let origin = json_string(&vector, "identity_origin")?;
    if !origin.starts_with("https://") || origin.ends_with('/') || origin.contains(['?', '#']) {
        return Err(ProtocolToolError::new(
            "membership-federation-v1 identity_origin must be a canonical HTTPS origin without a trailing slash",
        ));
    }

    validate_membership_federation_proof_vector(&vector, &cddl)?;

    let openapi_path = root.join("protocol/openapi/membership-federation/v1/openapi.yaml");
    let openapi_source = read(&openapi_path)?;
    let openapi = oas3::from_yaml(&openapi_source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse membership-federation OpenAPI {}: {error}",
            openapi_path.display()
        ))
    })?;
    if openapi.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "membership-federation OpenAPI must declare 3.1.0",
        ));
    }
    Ok(())
}

fn validate_membership_federation_proof_vector(
    vector: &Value,
    cddl: &str,
) -> Result<(), ProtocolToolError> {
    const BINDING_DOMAIN: &[u8] = b"dirextalk.membership-receipt-query-binding.v2\0";
    const SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-receipt-query-signature.v2\0";

    validate_cddl_hex(
        "federated-receipt-query-binding-v2",
        cddl,
        json_string(vector, "receipt_query_binding_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "federated-receipt-query-proof-v2",
        cddl,
        json_string(vector, "receipt_query_proof_canonical_cbor_hex")?,
    )?;

    let binding = decode_hex(json_string(
        vector,
        "receipt_query_binding_canonical_cbor_hex",
    )?)?;
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update(&binding);
    let digest: [u8; 32] = hasher.finalize().into();
    if lowercase_hex(&digest) != json_string(vector, "receipt_query_binding_digest_hex")? {
        return Err(ProtocolToolError::new(
            "membership-federation-v1 receipt query binding digest drift",
        ));
    }
    let mut signature_input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + digest.len());
    signature_input.extend_from_slice(SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&digest);
    if lowercase_hex(&signature_input) != json_string(vector, "receipt_query_signature_input_hex")?
    {
        return Err(ProtocolToolError::new(
            "membership-federation-v1 receipt query signature input drift",
        ));
    }

    let exact_proof = decode_hex(json_string(
        vector,
        "receipt_query_proof_canonical_cbor_hex",
    )?)?;
    let encoded_proof =
        Base64UrlUnpadded::decode_vec(json_string(vector, "receipt_query_proof_base64url")?)
            .map_err(|_| {
                ProtocolToolError::new(
                    "membership-federation-v1 receipt query proof must be unpadded base64url",
                )
            })?;
    if encoded_proof != exact_proof {
        return Err(ProtocolToolError::new(
            "membership-federation-v1 base64url and canonical CBOR proof differ",
        ));
    }

    let public_key =
        decode_lower_hex_fixed::<32>(json_string(vector, "device_signing_public_key_hex")?)?;
    let signature =
        decode_lower_hex_fixed::<64>(json_string(vector, "receipt_query_signature_hex")?)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        ProtocolToolError::new("membership-federation-v1 device signing public key is not Ed25519")
    })?;
    verifying_key
        .verify_strict(&signature_input, &Signature::from_bytes(&signature))
        .map_err(|_| {
            ProtocolToolError::new(
                "membership-federation-v1 receipt query signature does not verify",
            )
        })?;

    Ok(())
}

fn validate_public_descriptor_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/public-descriptor/v1/public-descriptor-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse public-descriptor v1 CDDL: {error}"))
    })?;
    let vector = read_json(
        &root.join("protocol/test-vectors/public-descriptor/v1/public-descriptor-v1.json"),
    )?;
    validate_vector_version(&vector, "public-descriptor-v1")?;
    if json_string(&vector, "wire_version")? != "1.0" {
        return Err(ProtocolToolError::new(
            "public-descriptor-v1 vector wire_version must be 1.0",
        ));
    }
    let descriptors = vector
        .get("descriptors")
        .and_then(Value::as_array)
        .filter(|descriptors| !descriptors.is_empty())
        .ok_or_else(|| {
            ProtocolToolError::new(
                "public-descriptor-v1 vector descriptors must be a nonempty array",
            )
        })?;
    for descriptor in descriptors {
        let name = json_string(descriptor, "descriptor")?;
        let entry_hash = json_string(descriptor, "entry_hash")?;
        if !entry_hash.starts_with("sha256:") {
            return Err(ProtocolToolError::new(format!(
                "public-descriptor-v1 descriptor {name} entry_hash must use sha256"
            )));
        }
        validate_cddl_hex(
            "public-descriptor-v1",
            &cddl,
            json_string(descriptor, "canonical_cbor_hex")?,
        )?;
    }
    Ok(())
}

fn validate_public_descriptor_v1_1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl =
        read(&root.join("protocol/cddl/public-descriptor/v1_1/public-descriptor-v1-1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse public-descriptor v1.1 CDDL: {error}"))
    })?;
    let vector = read_json(
        &root.join("protocol/test-vectors/public-descriptor/v1_1/public-descriptor-v1-1.json"),
    )?;
    validate_vector_version(&vector, "public-descriptor-v1.1")?;
    if json_string(&vector, "wire_version")? != "1.1" {
        return Err(ProtocolToolError::new(
            "public-descriptor-v1.1 vector wire_version must be 1.1",
        ));
    }
    if json_string(&vector, "feed_path_template")?
        != "/.well-known/dirextalk/public/v1/{subject_id}"
    {
        return Err(ProtocolToolError::new(
            "public-descriptor-v1.1 vector feed_path_template must use the fixed subject path",
        ));
    }
    let descriptors = vector
        .get("descriptors")
        .and_then(Value::as_array)
        .filter(|descriptors| !descriptors.is_empty())
        .ok_or_else(|| {
            ProtocolToolError::new(
                "public-descriptor-v1.1 vector descriptors must be a nonempty array",
            )
        })?;
    for descriptor in descriptors {
        let name = json_string(descriptor, "descriptor")?;
        let subject_id = json_string(descriptor, "subject_id")?;
        let entry_hash = json_string(descriptor, "entry_hash")?;
        if !entry_hash.starts_with("sha256:") {
            return Err(ProtocolToolError::new(format!(
                "public-descriptor-v1.1 descriptor {name} entry_hash must use sha256"
            )));
        }
        validate_cddl_hex(
            "public-descriptor-v1-1",
            &cddl,
            json_string(descriptor, "canonical_cbor_hex")?,
        )?;
        let tombstone = descriptor
            .get("tombstone")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                ProtocolToolError::new(format!(
                    "public-descriptor-v1.1 descriptor {name} tombstone must be a boolean"
                ))
            })?;
        if tombstone {
            if descriptor.get("feed_origin").is_some()
                || descriptor.get("public_feed_url").is_some()
            {
                return Err(ProtocolToolError::new(format!(
                    "public-descriptor-v1.1 tombstone {name} must not carry a feed origin or URL"
                )));
            }
        } else {
            let origin = json_string(descriptor, "feed_origin")?;
            let public_feed_url = json_string(descriptor, "public_feed_url")?;
            let expected_url = format!(
                "{}{}{}",
                origin.trim_end_matches('/'),
                "/.well-known/dirextalk/public/v1/",
                subject_id
            );
            if public_feed_url != expected_url {
                return Err(ProtocolToolError::new(format!(
                    "public-descriptor-v1.1 descriptor {name} public_feed_url must derive from its origin and subject"
                )));
            }
        }
    }
    Ok(())
}

fn validate_public_descriptor_v1_2(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl =
        read(&root.join("protocol/cddl/public-descriptor/v1_2/public-descriptor-v1-2.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse public-descriptor v1.2 CDDL: {error}"))
    })?;
    let vector = read_json(
        &root.join("protocol/test-vectors/public-descriptor/v1_2/public-descriptor-v1-2.json"),
    )?;
    validate_vector_version(&vector, "public-descriptor-v1.2")?;
    if json_string(&vector, "wire_version")? != "1.2" {
        return Err(ProtocolToolError::new(
            "public-descriptor-v1.2 vector wire_version must be 1.2",
        ));
    }
    if json_string(&vector, "feed_path_template")?
        != "/.well-known/dirextalk/public/v1/{subject_id}"
    {
        return Err(ProtocolToolError::new(
            "public-descriptor-v1.2 vector feed_path_template must use the fixed subject path",
        ));
    }
    validate_public_descriptor_v1_2_invalid_origins(&vector)?;
    let descriptors = vector
        .get("descriptors")
        .and_then(Value::as_array)
        .filter(|descriptors| !descriptors.is_empty())
        .ok_or_else(|| {
            ProtocolToolError::new(
                "public-descriptor-v1.2 vector descriptors must be a nonempty array",
            )
        })?;
    let mut names = BTreeSet::new();
    for descriptor in descriptors {
        let name = json_string(descriptor, "descriptor")?;
        if !names.insert(name.to_owned()) {
            return Err(ProtocolToolError::new(format!(
                "public-descriptor-v1.2 vector has duplicate descriptor {name}"
            )));
        }
        let subject_id = json_string(descriptor, "subject_id")?;
        let entry_hash = json_string(descriptor, "entry_hash")?;
        if !entry_hash.starts_with("sha256:") {
            return Err(ProtocolToolError::new(format!(
                "public-descriptor-v1.2 descriptor {name} entry_hash must use sha256"
            )));
        }
        validate_cddl_hex(
            "public-descriptor-v1-2",
            &cddl,
            json_string(descriptor, "canonical_cbor_hex")?,
        )?;
        let tombstone = descriptor
            .get("tombstone")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                ProtocolToolError::new(format!(
                    "public-descriptor-v1.2 descriptor {name} tombstone must be a boolean"
                ))
            })?;
        if tombstone {
            if descriptor.get("feed_origin").is_some()
                || descriptor.get("public_feed_url").is_some()
            {
                return Err(ProtocolToolError::new(format!(
                    "public-descriptor-v1.2 tombstone {name} must not carry a feed origin or URL"
                )));
            }
        } else {
            let origin = json_string(descriptor, "feed_origin")?;
            let public_feed_url = json_string(descriptor, "public_feed_url")?;
            let expected_url = format!(
                "{}{}{}",
                origin.trim_end_matches('/'),
                "/.well-known/dirextalk/public/v1/",
                subject_id
            );
            if public_feed_url != expected_url {
                return Err(ProtocolToolError::new(format!(
                    "public-descriptor-v1.2 descriptor {name} public_feed_url must derive from its origin and subject"
                )));
            }
        }
    }
    for required in [
        "channel_genesis",
        "channel_tombstone",
        "agent_genesis",
        "agent_tombstone",
    ] {
        if !names.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "public-descriptor-v1.2 vector must include {required}"
            )));
        }
    }
    Ok(())
}

fn validate_public_descriptor_v1_2_invalid_origins(
    vector: &Value,
) -> Result<(), ProtocolToolError> {
    let invalid_origins = vector
        .get("invalid_feed_origins")
        .and_then(Value::as_array)
        .filter(|origins| !origins.is_empty())
        .ok_or_else(|| {
            ProtocolToolError::new(
                "public-descriptor-v1.2 vector invalid_feed_origins must be a nonempty array",
            )
        })?;
    if invalid_origins
        .iter()
        .any(|origin| origin.as_str().is_none())
    {
        Err(ProtocolToolError::new(
            "public-descriptor-v1.2 vector invalid_feed_origins must contain strings",
        ))
    } else {
        Ok(())
    }
}

fn validate_identity_log_v1_1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/identity-log/v1_1/identity-log-v1-1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse identity-log v1.1 CDDL: {error}"))
    })?;
    let vector =
        read_json(&root.join("protocol/test-vectors/identity-log/v1_1/identity-log-v1_1.json"))?;
    validate_vector_version(&vector, "identity-log-v1.1")?;
    if json_string(&vector, "wire_version")? != "1.1" {
        return Err(ProtocolToolError::new(
            "identity-log-v1.1 vector wire_version must be 1.1",
        ));
    }
    let events = vector
        .get("events")
        .and_then(Value::as_array)
        .filter(|events| !events.is_empty())
        .ok_or_else(|| {
            ProtocolToolError::new("identity-log-v1.1 vector events must be a nonempty array")
        })?;
    for event in events {
        let event_name = json_string(event, "event")?;
        let entry_hash = json_string(event, "entry_hash")?;
        if !entry_hash.starts_with("sha256:") {
            return Err(ProtocolToolError::new(format!(
                "identity-log-v1.1 event {event_name} entry_hash must use sha256"
            )));
        }
        validate_cddl_hex(
            "identity-log-event-v1-1",
            &cddl,
            json_string(event, "canonical_cbor_hex")?,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one auditable validator keeps every frozen V15 identity-log page constraint together"
)]
fn validate_identity_log_page_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/identity-log-page/v1/identity-log-page-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse identity-log-page v1 CDDL: {error}"))
    })?;
    let vector = read_json(
        &root.join("protocol/test-vectors/identity-log-page/v1/identity-log-page-v1.json"),
    )?;
    validate_vector_version(&vector, "identity-log-page-v1")?;
    require_exact_object_keys(
        &vector,
        &[
            "version",
            "path_template",
            "content_type",
            "max_page_bytes",
            "max_events",
            "identity_id",
            "advertised_head_sequence",
            "advertised_head_hash",
            "requested_after_sequence",
            "next_after_sequence",
            "has_more",
            "event_fixture",
            "canonical_cbor_hex",
            "error_responses",
        ],
        "identity-log-page-v1 vector",
    )?;
    for (field, expected) in [
        ("path_template", "/v1/identities/{identity_id}/log"),
        (
            "content_type",
            "application/vnd.dirextalk.identity-log-page.v1+cbor",
        ),
        ("event_fixture", "identity-log/v1_1/genesis"),
    ] {
        if json_string(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "identity-log-page-v1 vector {field} drifted"
            )));
        }
    }
    for (field, expected) in [
        ("max_page_bytes", 2_097_152_i64),
        ("max_events", 64_i64),
        ("advertised_head_sequence", 1_i64),
        ("requested_after_sequence", 0_i64),
        ("next_after_sequence", 1_i64),
    ] {
        if json_i64(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "identity-log-page-v1 vector {field} drifted"
            )));
        }
    }
    if vector.get("has_more").and_then(Value::as_bool) != Some(false) {
        return Err(ProtocolToolError::new(
            "identity-log-page-v1 terminal fixture must not have more pages",
        ));
    }
    validate_identity_id(
        json_string(&vector, "identity_id")?,
        "identity-log-page-v1 identity",
    )?;
    let advertised_head_hash = json_string(&vector, "advertised_head_hash")?
        .strip_prefix("sha256:")
        .ok_or_else(|| ProtocolToolError::new("identity-log-page-v1 head hash must use sha256"))?;
    let _ = decode_lower_hex_fixed::<32>(advertised_head_hash)?;
    validate_cddl_hex(
        "identity-log-page-v1",
        &cddl,
        json_string(&vector, "canonical_cbor_hex")?,
    )?;
    for (status, code, retryable) in [
        (400, "IDENTITY_LOG_PAGE_INVALID", false),
        (404, "IDENTITY_LOG_NOT_FOUND", false),
        (409, "IDENTITY_LOG_CURSOR_AHEAD", false),
        (410, "IDENTITY_LOG_INACTIVE", false),
        (503, "IDENTITY_SERVICE_UNAVAILABLE", true),
    ] {
        if !has_error_response(&vector, status, code, retryable)? {
            return Err(ProtocolToolError::new(format!(
                "identity-log-page-v1 vector must retain {status} {code}"
            )));
        }
    }

    let path = root.join("protocol/openapi/identity-log-page/v1/openapi.yaml");
    let source = read(&path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse identity-log-page OpenAPI {}: {error}",
            path.display()
        ))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "identity-log-page OpenAPI contract must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse identity-log-page OpenAPI YAML tree: {error}"
        ))
    })?;
    for (pointer, expected) in [
        (
            "/paths/~1v1~1identities~1{identity_id}~1log/get/operationId",
            json!("getIdentityLogPage"),
        ),
        (
            "/paths/~1v1~1identities~1{identity_id}~1log/get/responses/200/$ref",
            json!("#/components/responses/IdentityLogPage"),
        ),
        (
            "/components/responses/IdentityLogPage/content/application~1vnd.dirextalk.identity-log-page.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1identities~1{identity_id}~1log/get/responses/409/$ref",
            json!("#/components/responses/IdentityLogCursorAhead"),
        ),
        ("/components/parameters/PageLimit/schema/maximum", json!(64)),
    ] {
        expect_value(&document, pointer, &expected)?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one auditable validator keeps every frozen V16 contact-card constraint together"
)]
fn validate_contact_card_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/contact-card/v1/contact-card-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse contact-card v1 CDDL: {error}")))?;
    let vector =
        read_json(&root.join("protocol/test-vectors/contact-card/v1/contact-card-v1.json"))?;
    validate_vector_version(&vector, "contact-card-v1")?;
    require_exact_object_keys(
        &vector,
        &[
            "version",
            "qr_prefix",
            "max_decoded_cbor_bytes",
            "identity_id",
            "canonical_https_origin",
            "canonical_cbor_hex",
            "qr_payload",
            "invalid_https_origins",
        ],
        "contact-card-v1 vector",
    )?;
    if json_string(&vector, "qr_prefix")? != CONTACT_CARD_QR_PREFIX {
        return Err(ProtocolToolError::new(
            "contact-card-v1 QR prefix must be dtxc1:",
        ));
    }
    if json_i64(&vector, "max_decoded_cbor_bytes")?
        != i64::try_from(CONTACT_CARD_MAX_DECODED_CBOR_BYTES)
            .expect("contact card maximum fits i64")
    {
        return Err(ProtocolToolError::new(
            "contact-card-v1 decoded CBOR maximum drifted",
        ));
    }

    let identity_id = json_string(&vector, "identity_id")?;
    validate_identity_id(identity_id, "contact-card-v1 identity")?;
    let origin = json_string(&vector, "canonical_https_origin")?;
    validate_contact_card_https_origin(origin)?;
    let invalid_origins = vector
        .get("invalid_https_origins")
        .and_then(Value::as_array)
        .filter(|origins| !origins.is_empty())
        .ok_or_else(|| {
            ProtocolToolError::new(
                "contact-card-v1 vector invalid_https_origins must be a nonempty array",
            )
        })?;
    for invalid_origin in invalid_origins {
        let invalid_origin = invalid_origin.as_str().ok_or_else(|| {
            ProtocolToolError::new(
                "contact-card-v1 vector invalid_https_origins must contain strings",
            )
        })?;
        if validate_contact_card_https_origin(invalid_origin).is_ok() {
            return Err(ProtocolToolError::new(format!(
                "contact-card-v1 invalid origin was accepted: {invalid_origin}"
            )));
        }
    }

    let expected_cbor = encode_contact_card(identity_id, origin)?;
    if expected_cbor.len() > CONTACT_CARD_MAX_DECODED_CBOR_BYTES {
        return Err(ProtocolToolError::new(
            "contact-card-v1 fixture exceeds the decoded CBOR limit",
        ));
    }
    validate_exact_cddl_bytes(
        "contact-card-v1",
        &cddl,
        json_string(&vector, "canonical_cbor_hex")?,
        &expected_cbor,
    )?;
    let qr_payload = json_string(&vector, "qr_payload")?;
    if qr_payload.len() > CONTACT_CARD_MAX_QR_PAYLOAD_CHARS {
        return Err(ProtocolToolError::new(
            "contact-card-v1 QR payload exceeds the pre-decode size limit",
        ));
    }
    let encoded_payload = qr_payload
        .strip_prefix(CONTACT_CARD_QR_PREFIX)
        .ok_or_else(|| ProtocolToolError::new("contact-card-v1 QR payload has the wrong prefix"))?;
    if encoded_payload.is_empty()
        || encoded_payload.len() > CONTACT_CARD_MAX_UNPADDED_BASE64URL_CHARS
        || encoded_payload.contains('=')
        || !encoded_payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProtocolToolError::new(
            "contact-card-v1 QR payload must be bounded unpadded base64url",
        ));
    }
    let decoded_payload = Base64UrlUnpadded::decode_vec(encoded_payload).map_err(|_| {
        ProtocolToolError::new("contact-card-v1 QR payload is not valid unpadded base64url")
    })?;
    if decoded_payload.len() > CONTACT_CARD_MAX_DECODED_CBOR_BYTES {
        return Err(ProtocolToolError::new(
            "contact-card-v1 QR payload exceeds the post-decode size limit",
        ));
    }
    if Base64UrlUnpadded::encode_string(&decoded_payload) != encoded_payload {
        return Err(ProtocolToolError::new(
            "contact-card-v1 QR payload must reject non-canonical base64url aliases",
        ));
    }
    if decoded_payload != expected_cbor {
        return Err(ProtocolToolError::new(
            "contact-card-v1 QR payload does not preserve canonical CBOR",
        ));
    }
    Ok(())
}

fn validate_identity_bootstrap_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/identity-http/v1/identity-bootstrap-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse identity-bootstrap v1 CDDL: {error}"))
    })?;
    let vector =
        read_json(&root.join("protocol/test-vectors/identity-http/v1/identity-bootstrap-v1.json"))?;
    validate_vector_version(&vector, "identity-bootstrap-v1")?;
    if json_string(&vector, "request_content_type")?
        != "application/vnd.dirextalk.identity-log.v1.1+cbor"
        || json_string(&vector, "response_content_type")?
            != "application/vnd.dirextalk.identity-append-receipt.v1+cbor"
    {
        return Err(ProtocolToolError::new(
            "identity-bootstrap-v1 vector media types drifted",
        ));
    }
    validate_cddl_hex(
        "identity-bootstrap-append-receipt-v1",
        &cddl,
        json_string(&vector, "receipt_canonical_cbor_hex")?,
    )?;

    let path = root.join("protocol/openapi/identity/v1/openapi.yaml");
    let source = read(&path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse OpenAPI {}: {error}", path.display()))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "identity bootstrap OpenAPI contract must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse identity bootstrap OpenAPI YAML tree: {error}"
        ))
    })?;
    for (pointer, expected) in [
        (
            "/paths/~1v1~1identity~1bootstrap/post/operationId",
            json!("bootstrapIdentity"),
        ),
        (
            "/paths/~1v1~1identity~1bootstrap/post/requestBody/content/application~1vnd.dirextalk.identity-log.v1.1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/components/parameters/IdempotencyKey/schema/pattern",
            json!("^[A-Za-z0-9_-]{16,128}$"),
        ),
        (
            "/components/parameters/IdempotencyKey/schema/minLength",
            json!(16),
        ),
        (
            "/components/parameters/IdempotencyKey/schema/maxLength",
            json!(128),
        ),
        (
            "/components/responses/IdentityBootstrapCommitted/content/application~1vnd.dirextalk.identity-append-receipt.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
    ] {
        expect_value(&document, pointer, &expected)?;
    }
    Ok(())
}

fn validate_identity_session_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/identity-session/v1/device-session-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse identity-session v1 CDDL: {error}"))
    })?;
    let vector =
        read_json(&root.join("protocol/test-vectors/identity-session/v1/device-session-v1.json"))?;
    validate_vector_version(&vector, "identity-session-v1")?;
    if json_string(&vector, "initial_enroll_path")? != "/v1/devices/initial-enroll"
        || json_string(&vector, "challenge_path")? != "/v1/devices/sessions/challenges"
        || json_string(&vector, "session_path")? != "/v1/devices/sessions"
        || json_string(&vector, "session_response_content_type")?
            != "application/vnd.dirextalk.device-session-receipt.v1+cbor"
    {
        return Err(ProtocolToolError::new(
            "identity-session-v1 vector transport paths or media type drifted",
        ));
    }
    for (field, expected) in [
        ("idempotency_key_min_bytes", 16_i64),
        ("idempotency_key_max_bytes", 128_i64),
        ("challenge_ttl_millis", 300_000_i64),
        ("challenge_min_interval_millis", 5_000_i64),
        ("session_ttl_millis", 900_000_i64),
    ] {
        if json_i64(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "identity-session-v1 vector {field} drifted"
            )));
        }
    }
    validate_cddl_hex(
        "device-session-receipt-v1",
        &cddl,
        json_string(&vector, "receipt_canonical_cbor_hex")?,
    )?;
    validate_identity_session_proof_vector(&cddl, &vector)?;
    if !has_error_response(&vector, 429, "DEVICE_SESSION_CHALLENGE_RATE_LIMITED", true)? {
        return Err(ProtocolToolError::new(
            "identity-session-v1 vector must retain the challenge rate-limit response",
        ));
    }

    let path = root.join("protocol/openapi/identity-session/v1/openapi.yaml");
    let source = read(&path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse OpenAPI {}: {error}", path.display()))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "identity session OpenAPI contract must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse identity session OpenAPI YAML tree: {error}"))
    })?;
    for (pointer, expected) in [
        (
            "/paths/~1v1~1devices~1initial-enroll/post/operationId",
            json!("initialEnrollDevice"),
        ),
        (
            "/paths/~1v1~1devices~1sessions~1challenges/post/operationId",
            json!("createDeviceSessionChallenge"),
        ),
        (
            "/paths/~1v1~1devices~1sessions/post/operationId",
            json!("completeDeviceSession"),
        ),
        (
            "/components/parameters/GenesisIfMatch/schema/pattern",
            json!("^\"sha256:[a-f0-9]{64}\"$"),
        ),
        (
            "/paths/~1v1~1devices~1sessions~1challenges/post/responses/429/$ref",
            json!("#/components/responses/DeviceSessionChallengeRateLimited"),
        ),
        (
            "/components/responses/DeviceSessionIssued/content/application~1vnd.dirextalk.device-session-receipt.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
    ] {
        expect_value(&document, pointer, &expected)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One versioned contract audit keeps CDDL, vectors, and OpenAPI coupled.
fn validate_identity_enrollment_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl =
        read(&root.join("protocol/cddl/identity-enrollment/v1/identity-enrollment-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse identity-enrollment v1 CDDL: {error}"))
    })?;
    let vector = read_json(
        &root.join("protocol/test-vectors/identity-enrollment/v1/identity-enrollment-v1.json"),
    )?;
    validate_vector_version(&vector, "identity-enrollment-v1")?;
    for (field, expected) in [
        ("challenge_path", "/v1/devices/enroll/challenges"),
        (
            "challenge_status_path_template",
            "/v1/devices/enroll/challenges/{challenge_id}",
        ),
        ("enroll_path", "/v1/devices/enroll"),
        (
            "candidate_content_type",
            "application/vnd.dirextalk.device-enrollment-candidate.v1+cbor",
        ),
        (
            "challenge_status_content_type",
            "application/vnd.dirextalk.device-enrollment-status.v1+cbor",
        ),
        (
            "completion_content_type",
            "application/vnd.dirextalk.device-enrollment.v1+cbor",
        ),
        (
            "append_receipt_content_type",
            "application/vnd.dirextalk.identity-append-receipt.v1+cbor",
        ),
        ("authorization_scheme", "DTX-Device-Session"),
    ] {
        if json_string(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "identity-enrollment-v1 vector {field} drifted"
            )));
        }
    }
    for (field, expected) in [
        ("idempotency_key_min_bytes", 16_i64),
        ("idempotency_key_max_bytes", 128_i64),
        ("enrollment_capability_bytes", 32_i64),
        ("challenge_ttl_millis", 300_000_i64),
    ] {
        if json_i64(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "identity-enrollment-v1 vector {field} drifted"
            )));
        }
    }
    for (state, value) in [
        ("pending", 1_i64),
        ("approved", 2),
        ("cancelled", 3),
        ("expired", 4),
    ] {
        if vector.pointer(&format!("/states/{state}")) != Some(&json!(value)) {
            return Err(ProtocolToolError::new(format!(
                "identity-enrollment-v1 vector state {state} drifted"
            )));
        }
    }
    if vector.pointer("/success_statuses/challenge") != Some(&json!([201, 200]))
        || vector.pointer("/success_statuses/approval") != Some(&json!([201, 200]))
        || vector.pointer("/success_statuses/cancel") != Some(&json!([200]))
    {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 vector success statuses drifted",
        ));
    }

    validate_uuid_fields(
        &vector,
        &[
            "/candidate/device_id",
            "/challenge/challenge_id",
            "/qr_payload/challenge_id",
            "/qr_payload/device_id",
        ],
    )?;
    let candidate = vector
        .get("candidate")
        .ok_or_else(|| ProtocolToolError::new("identity-enrollment-v1 candidate is missing"))?;
    require_exact_object_keys(
        candidate,
        &[
            "identity_id",
            "device_id",
            "device_signing_public_key",
            "device_encryption_public_key",
            "enrollment_capability",
            "canonical_cbor_hex",
        ],
        "identity-enrollment-v1 candidate",
    )?;
    let identity_id = json_string(candidate, "identity_id")?;
    validate_identity_id(identity_id, "identity-enrollment-v1 candidate identity")?;
    let device_id = json_string(candidate, "device_id")?;
    let device_signing_public_key =
        decode_base64url_fixed::<32>(json_string(candidate, "device_signing_public_key")?)?;
    let device_encryption_public_key =
        decode_base64url_fixed::<32>(json_string(candidate, "device_encryption_public_key")?)?;
    let enrollment_capability =
        decode_base64url_fixed::<32>(json_string(candidate, "enrollment_capability")?)?;
    validate_enrollment_material(
        device_signing_public_key,
        device_encryption_public_key,
        enrollment_capability,
    )?;
    let expected_candidate = encode_device_enrollment_candidate(
        identity_id,
        device_id,
        device_signing_public_key,
        device_encryption_public_key,
        enrollment_capability,
    )?;
    validate_exact_cddl_bytes(
        "device-enrollment-candidate-v1",
        &cddl,
        json_string(candidate, "canonical_cbor_hex")?,
        &expected_candidate,
    )?;

    let challenge = vector
        .get("challenge")
        .ok_or_else(|| ProtocolToolError::new("identity-enrollment-v1 challenge is missing"))?;
    require_exact_object_keys(
        challenge,
        &[
            "challenge_id",
            "expires_at_ms",
            "pending_status_canonical_cbor_hex",
        ],
        "identity-enrollment-v1 challenge",
    )?;
    let challenge_id = json_string(challenge, "challenge_id")?;
    let expires_at_ms = json_i64(challenge, "expires_at_ms")?;
    validate_enrollment_expiry(expires_at_ms)?;
    let expected_status =
        encode_device_enrollment_status(challenge_id, identity_id, device_id, 1, expires_at_ms)?;
    validate_exact_cddl_bytes(
        "device-enrollment-challenge-status-v1",
        &cddl,
        json_string(challenge, "pending_status_canonical_cbor_hex")?,
        &expected_status,
    )?;

    let qr_payload = vector
        .get("qr_payload")
        .ok_or_else(|| ProtocolToolError::new("identity-enrollment-v1 QR payload is missing"))?;
    require_exact_object_keys(
        qr_payload,
        &[
            "https_origin",
            "identity_id",
            "challenge_id",
            "device_id",
            "device_signing_public_key",
            "device_encryption_public_key",
            "enrollment_capability",
            "expires_at_ms",
            "canonical_cbor_hex",
        ],
        "identity-enrollment-v1 QR payload",
    )?;
    let qr_origin = json_string(qr_payload, "https_origin")?;
    validate_strict_https_origin(qr_origin)?;
    for (field, expected) in [
        ("identity_id", identity_id),
        ("challenge_id", challenge_id),
        ("device_id", device_id),
        (
            "device_signing_public_key",
            json_string(candidate, "device_signing_public_key")?,
        ),
        (
            "device_encryption_public_key",
            json_string(candidate, "device_encryption_public_key")?,
        ),
        (
            "enrollment_capability",
            json_string(candidate, "enrollment_capability")?,
        ),
    ] {
        if json_string(qr_payload, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "identity-enrollment-v1 QR payload {field} does not bind the challenge candidate"
            )));
        }
    }
    if json_i64(qr_payload, "expires_at_ms")? != expires_at_ms {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 QR payload expiry does not bind the challenge",
        ));
    }
    let expected_qr = encode_device_enrollment_qr(
        qr_origin,
        identity_id,
        challenge_id,
        device_id,
        device_signing_public_key,
        device_encryption_public_key,
        enrollment_capability,
        expires_at_ms,
    )?;
    validate_exact_cddl_bytes(
        "device-enrollment-qr-v1",
        &cddl,
        json_string(qr_payload, "canonical_cbor_hex")?,
        &expected_qr,
    )?;

    let completion = vector
        .get("completion")
        .ok_or_else(|| ProtocolToolError::new("identity-enrollment-v1 completion is missing"))?;
    require_exact_object_keys(
        completion,
        &[
            "if_match",
            "device_add_event_canonical_cbor_hex",
            "canonical_cbor_hex",
        ],
        "identity-enrollment-v1 completion",
    )?;
    validate_quoted_sha256_if_match(json_string(completion, "if_match")?)?;
    let device_add_bytes = decode_hex(json_string(
        completion,
        "device_add_event_canonical_cbor_hex",
    )?)?;
    let identity_log_cddl =
        read(&root.join("protocol/cddl/identity-log/v1_1/identity-log-v1-1.cddl"))?;
    cddl_cat::validate_cbor_bytes(
        "identity-log-device-add-event-v1-1",
        &identity_log_cddl,
        &device_add_bytes,
    )
    .map_err(|error| {
        ProtocolToolError::new(format!(
            "CDDL rejected identity-enrollment-v1 exact DeviceAdd event: {error}"
        ))
    })?;
    let expected_completion = encode_device_enrollment_completion(
        challenge_id,
        enrollment_capability,
        &device_add_bytes,
    )?;
    validate_exact_cddl_bytes(
        "device-enrollment-completion-v1",
        &cddl,
        json_string(completion, "canonical_cbor_hex")?,
        &expected_completion,
    )?;

    let receipt_cddl =
        read(&root.join("protocol/cddl/identity-http/v1/identity-bootstrap-v1.cddl"))?;
    validate_cddl_hex(
        "identity-bootstrap-append-receipt-v1",
        &receipt_cddl,
        json_string(&vector, "append_receipt_canonical_cbor_hex")?,
    )?;
    for (status, code, retryable) in [
        (401, "DEVICE_ENROLLMENT_CAPABILITY_INVALID", false),
        (401, "DEVICE_AUTHENTICATION_FAILED", false),
        (409, "DEVICE_ENROLLMENT_CHALLENGE_EXPIRED", false),
        (409, "DEVICE_ENROLLMENT_CHALLENGE_CANCELLED", false),
        (409, "DEVICE_ENROLLMENT_CHALLENGE_ALREADY_APPROVED", false),
        (409, "IDEMPOTENCY_CONFLICT", false),
        (422, "DEVICE_ENROLLMENT_INVALID", false),
        (503, "IDENTITY_SERVICE_UNAVAILABLE", true),
    ] {
        if !has_error_response(&vector, status, code, retryable)? {
            return Err(ProtocolToolError::new(format!(
                "identity-enrollment-v1 vector must retain {status} {code}"
            )));
        }
    }

    let path = root.join("protocol/openapi/identity-enrollment/v1/openapi.yaml");
    let source = read(&path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse OpenAPI {}: {error}", path.display()))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "identity enrollment OpenAPI contract must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse identity enrollment OpenAPI YAML tree: {error}"
        ))
    })?;
    for (pointer, expected) in [
        (
            "/paths/~1v1~1devices~1enroll~1challenges/post/operationId",
            json!("createDeviceEnrollmentChallenge"),
        ),
        (
            "/paths/~1v1~1devices~1enroll~1challenges~1{challenge_id}/get/operationId",
            json!("getDeviceEnrollmentChallenge"),
        ),
        (
            "/paths/~1v1~1devices~1enroll~1challenges~1{challenge_id}/delete/operationId",
            json!("cancelDeviceEnrollmentChallenge"),
        ),
        (
            "/paths/~1v1~1devices~1enroll/post/operationId",
            json!("approveDeviceEnrollment"),
        ),
        (
            "/paths/~1v1~1devices~1enroll~1challenges/post/requestBody/content/application~1vnd.dirextalk.device-enrollment-candidate.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1devices~1enroll/post/requestBody/content/application~1vnd.dirextalk.device-enrollment.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/components/parameters/EnrollmentCapability/name",
            json!("DTX-Enrollment-Capability"),
        ),
        (
            "/components/parameters/DeviceSessionAuthorization/schema/pattern",
            json!(
                "^DTX-Device-Session [0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.[A-Za-z0-9_-]{43}$"
            ),
        ),
        (
            "/components/parameters/IdentityHeadIfMatch/schema/pattern",
            json!("^\"sha256:[a-f0-9]{64}\"$"),
        ),
        (
            "/components/responses/EnrollmentChallengeStatus/content/application~1vnd.dirextalk.device-enrollment-status.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/components/responses/IdentityAppendCommitted/content/application~1vnd.dirextalk.identity-append-receipt.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
    ] {
        expect_value(&document, pointer, &expected)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One versioned contract audit keeps CDDL, vectors, and OpenAPI coupled.
fn validate_key_package_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/key-package/v1/key-package-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse key-package v1 CDDL: {error}")))?;
    let vector = read_json(&root.join("protocol/test-vectors/key-package/v1/key-package-v1.json"))?;
    validate_vector_version(&vector, "key-package-v1")?;
    for (field, expected) in [
        ("publish_path_template", "/v1/key-packages/{package_id}"),
        ("claim_path", "/v1/key-packages/claim"),
        (
            "publish_content_type",
            "application/vnd.dirextalk.key-package-publish.v1+cbor",
        ),
        (
            "publish_receipt_content_type",
            "application/vnd.dirextalk.key-package-publish-receipt.v1+cbor",
        ),
        (
            "claim_content_type",
            "application/vnd.dirextalk.key-package-claim.v1+cbor",
        ),
        (
            "claim_receipt_content_type",
            "application/vnd.dirextalk.key-package-claim-receipt.v1+cbor",
        ),
        ("authorization_scheme", "DTX-Device-Session"),
    ] {
        if json_string(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "key-package-v1 vector {field} drifted"
            )));
        }
    }
    for (field, expected) in [
        ("idempotency_key_min_bytes", 16_i64),
        ("idempotency_key_max_bytes", 128_i64),
        ("max_key_package_bytes", 65_536_i64),
    ] {
        if json_i64(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "key-package-v1 vector {field} drifted"
            )));
        }
    }
    for (field, expected) in [
        (
            "opaque_key_package_hash_domain",
            "dirextalk.key-package-bytes.v1\0",
        ),
        (
            "publish_binding_hash_domain",
            "dirextalk.key-package-publish-binding.v1\0",
        ),
        (
            "publish_signature_domain",
            "dirextalk.key-package-publish-signature.v1\0",
        ),
    ] {
        if json_string(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "key-package-v1 vector {field} drifted"
            )));
        }
    }
    if vector.pointer("/publish_success_statuses") != Some(&json!([201, 200]))
        || vector.pointer("/claim_success_statuses") != Some(&json!([201, 200]))
    {
        return Err(ProtocolToolError::new(
            "key-package-v1 success statuses drifted",
        ));
    }
    validate_identity_id(
        json_string(&vector, "identity_id")?,
        "key-package-v1 publisher identity",
    )?;
    validate_uuid_fields(&vector, &["/device_id", "/package_id"])?;
    if json_i64(&vector, "published_identity_head_sequence")? != 2 {
        return Err(ProtocolToolError::new(
            "key-package-v1 published identity head sequence drifted",
        ));
    }
    let _ =
        decode_lower_hex_fixed::<32>(json_string(&vector, "published_identity_head_hash_hex")?)?;
    let opaque_key_package = decode_hex(json_string(&vector, "opaque_key_package_hex")?)?;
    if opaque_key_package.is_empty() || opaque_key_package.len() > 65_536 {
        return Err(ProtocolToolError::new(
            "key-package-v1 opaque package must be bounded and nonempty",
        ));
    }
    let mut package_hasher = Sha256::new();
    package_hasher.update(b"dirextalk.key-package-bytes.v1\0");
    package_hasher.update(&opaque_key_package);
    if json_string(&vector, "key_package_digest_hex")? != lowercase_hex(&package_hasher.finalize())
    {
        return Err(ProtocolToolError::new(
            "key-package-v1 package digest does not bind opaque bytes",
        ));
    }
    let binding = decode_hex(json_string(&vector, "binding_canonical_cbor_hex")?)?;
    let mut binding_hasher = Sha256::new();
    binding_hasher.update(b"dirextalk.key-package-publish-binding.v1\0");
    binding_hasher.update(&binding);
    let mut signature_input = b"dirextalk.key-package-publish-signature.v1\0".to_vec();
    signature_input.extend_from_slice(&binding_hasher.finalize());
    if json_string(&vector, "publish_signature_input_hex")? != lowercase_hex(&signature_input) {
        return Err(ProtocolToolError::new(
            "key-package-v1 publish signature input does not bind the canonical binding",
        ));
    }
    validate_cddl_hex(
        "key-package-publish-binding-v1",
        &cddl,
        json_string(&vector, "binding_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "key-package-publish-v1",
        &cddl,
        json_string(&vector, "publish_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "key-package-claim-v1",
        &cddl,
        json_string(&vector, "claim_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "key-package-claim-receipt-v1",
        &cddl,
        json_string(&vector, "claim_receipt_canonical_cbor_hex")?,
    )?;
    for (status, code, retryable) in [
        (401, "DEVICE_AUTHENTICATION_FAILED", false),
        (404, "KEY_PACKAGE_UNAVAILABLE", false),
        (409, "KEY_PACKAGE_CONFLICT", false),
        (409, "IDEMPOTENCY_CONFLICT", false),
        (422, "KEY_PACKAGE_INVALID", false),
        (503, "IDENTITY_SERVICE_UNAVAILABLE", true),
    ] {
        if !has_error_response(&vector, status, code, retryable)? {
            return Err(ProtocolToolError::new(format!(
                "key-package-v1 vector must retain {status} {code}"
            )));
        }
    }

    let path = root.join("protocol/openapi/key-package/v1/openapi.yaml");
    let source = read(&path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse OpenAPI {}: {error}", path.display()))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "key-package OpenAPI contract must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse key-package OpenAPI YAML tree: {error}"))
    })?;
    for (pointer, expected) in [
        (
            "/paths/~1v1~1key-packages~1{package_id}/put/operationId",
            json!("publishKeyPackage"),
        ),
        (
            "/paths/~1v1~1key-packages~1claim/post/operationId",
            json!("claimKeyPackage"),
        ),
        (
            "/paths/~1v1~1key-packages~1{package_id}/put/requestBody/content/application~1vnd.dirextalk.key-package-publish.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1key-packages~1claim/post/requestBody/content/application~1vnd.dirextalk.key-package-claim.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1key-packages~1claim/post/responses/404/$ref",
            json!("#/components/responses/KeyPackageUnavailable"),
        ),
        (
            "/components/parameters/IdempotencyKey/schema/pattern",
            json!("^[A-Za-z0-9_-]{16,128}$"),
        ),
    ] {
        expect_value(&document, pointer, &expected)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One versioned contract audit keeps CDDL, vectors, and OpenAPI coupled.
fn validate_mailbox_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/mailbox/v1/mailbox-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse mailbox v1 CDDL: {error}")))?;
    let vector = read_json(&root.join("protocol/test-vectors/mailbox/v1/mailbox-v1.json"))?;
    validate_vector_version(&vector, "mailbox-v1")?;
    require_exact_object_keys(
        &vector,
        &[
            "version",
            "register_path_template",
            "envelope_path_template",
            "pull_path_template",
            "acks_path_template",
            "register_content_type",
            "register_receipt_content_type",
            "envelope_content_type",
            "envelope_receipt_content_type",
            "pull_content_type",
            "pull_receipt_content_type",
            "acks_content_type",
            "acks_receipt_content_type",
            "device_session_authorization_scheme",
            "mailbox_capability_authorization_scheme",
            "idempotency_key_min_bytes",
            "idempotency_key_max_bytes",
            "mailbox_capability_bytes",
            "max_opaque_ciphertext_bytes",
            "max_envelopes_per_page",
            "max_envelopes_per_ack",
            "max_ttl_ms",
            "write_capability_hash_domain",
            "owner_identity_id",
            "owner_device_id",
            "mailbox_id",
            "envelope_id",
            "write_capability_hash_hex",
            "opaque_ciphertext_hex",
            "register_expires_at_ms",
            "envelope_expires_at_ms",
            "delivery_sequence",
            "after_sequence",
            "pull_limit",
            "next_sequence",
            "acknowledged_envelope_ids",
            "register_canonical_cbor_hex",
            "register_receipt_canonical_cbor_hex",
            "envelope_canonical_cbor_hex",
            "envelope_receipt_canonical_cbor_hex",
            "pull_canonical_cbor_hex",
            "pull_receipt_canonical_cbor_hex",
            "acks_canonical_cbor_hex",
            "acks_receipt_canonical_cbor_hex",
            "error_responses",
        ],
        "mailbox-v1 vector",
    )?;

    for (field, expected) in [
        ("register_path_template", "/v1/mailboxes/{mailbox_id}"),
        (
            "envelope_path_template",
            "/v1/mailboxes/{mailbox_id}/envelopes/{envelope_id}",
        ),
        ("pull_path_template", "/v1/mailboxes/{mailbox_id}/pull"),
        ("acks_path_template", "/v1/mailboxes/{mailbox_id}/acks"),
        (
            "register_content_type",
            "application/vnd.dirextalk.mailbox-register.v1+cbor",
        ),
        (
            "register_receipt_content_type",
            "application/vnd.dirextalk.mailbox-register-receipt.v1+cbor",
        ),
        (
            "envelope_content_type",
            "application/vnd.dirextalk.mailbox-envelope.v1+cbor",
        ),
        (
            "envelope_receipt_content_type",
            "application/vnd.dirextalk.mailbox-envelope-receipt.v1+cbor",
        ),
        (
            "pull_content_type",
            "application/vnd.dirextalk.mailbox-pull.v1+cbor",
        ),
        (
            "pull_receipt_content_type",
            "application/vnd.dirextalk.mailbox-pull-receipt.v1+cbor",
        ),
        (
            "acks_content_type",
            "application/vnd.dirextalk.mailbox-acks.v1+cbor",
        ),
        (
            "acks_receipt_content_type",
            "application/vnd.dirextalk.mailbox-acks-receipt.v1+cbor",
        ),
        ("device_session_authorization_scheme", "DTX-Device-Session"),
        (
            "mailbox_capability_authorization_scheme",
            "DTX-Mailbox-Capability",
        ),
        (
            "write_capability_hash_domain",
            "dirextalk.mailbox-write-capability.v1\0",
        ),
    ] {
        if json_string(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "mailbox-v1 vector {field} drifted"
            )));
        }
    }
    for (field, expected) in [
        ("idempotency_key_min_bytes", 16_i64),
        ("idempotency_key_max_bytes", 128_i64),
        ("mailbox_capability_bytes", 32_i64),
        ("max_opaque_ciphertext_bytes", 262_144_i64),
        ("max_envelopes_per_page", 100_i64),
        ("max_envelopes_per_ack", 100_i64),
        ("max_ttl_ms", 604_800_000_i64),
        ("register_expires_at_ms", 600_000_i64),
        ("envelope_expires_at_ms", 600_001_i64),
        ("delivery_sequence", 1_i64),
        ("after_sequence", 0_i64),
        ("pull_limit", 100_i64),
        ("next_sequence", 1_i64),
    ] {
        if json_i64(&vector, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "mailbox-v1 vector {field} drifted"
            )));
        }
    }

    validate_identity_id(
        json_string(&vector, "owner_identity_id")?,
        "mailbox-v1 owner identity",
    )?;
    validate_uuid_fields(
        &vector,
        &[
            "/owner_device_id",
            "/mailbox_id",
            "/envelope_id",
            "/acknowledged_envelope_ids/0",
        ],
    )?;
    let acknowledged = vector
        .get("acknowledged_envelope_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProtocolToolError::new("mailbox-v1 acknowledged envelope IDs must be an array")
        })?;
    if acknowledged.len() != 1
        || acknowledged.first().and_then(Value::as_str)
            != Some(json_string(&vector, "envelope_id")?)
    {
        return Err(ProtocolToolError::new(
            "mailbox-v1 acknowledgement fixture must retain its envelope ID",
        ));
    }
    let _ = decode_lower_hex_fixed::<32>(json_string(&vector, "write_capability_hash_hex")?)?;
    let ciphertext = decode_hex(json_string(&vector, "opaque_ciphertext_hex")?)?;
    if ciphertext.is_empty() || ciphertext.len() > 262_144 {
        return Err(ProtocolToolError::new(
            "mailbox-v1 opaque ciphertext must be bounded and nonempty",
        ));
    }

    for (rule, field) in [
        ("mailbox-register-v1", "register_canonical_cbor_hex"),
        (
            "mailbox-register-receipt-v1",
            "register_receipt_canonical_cbor_hex",
        ),
        ("mailbox-envelope-v1", "envelope_canonical_cbor_hex"),
        (
            "mailbox-envelope-receipt-v1",
            "envelope_receipt_canonical_cbor_hex",
        ),
        ("mailbox-pull-v1", "pull_canonical_cbor_hex"),
        ("mailbox-pull-receipt-v1", "pull_receipt_canonical_cbor_hex"),
        ("mailbox-acks-v1", "acks_canonical_cbor_hex"),
        ("mailbox-acks-receipt-v1", "acks_receipt_canonical_cbor_hex"),
    ] {
        validate_cddl_hex(rule, &cddl, json_string(&vector, field)?)?;
    }
    let expected_errors = [
        (401, "DEVICE_AUTHENTICATION_FAILED", false),
        (404, "MAILBOX_UNAVAILABLE", false),
        (409, "MAILBOX_CONFLICT", false),
        (409, "IDEMPOTENCY_CONFLICT", false),
        (422, "MAILBOX_INVALID", false),
        (429, "MAILBOX_CAPACITY_EXCEEDED", true),
        (503, "MAILBOX_SERVICE_UNAVAILABLE", true),
    ];
    if vector
        .get("error_responses")
        .and_then(Value::as_array)
        .is_none_or(|responses| responses.len() != expected_errors.len())
    {
        return Err(ProtocolToolError::new(
            "mailbox-v1 vector error responses drifted",
        ));
    }
    for (status, code, retryable) in expected_errors {
        if !has_error_response(&vector, status, code, retryable)? {
            return Err(ProtocolToolError::new(format!(
                "mailbox-v1 vector must retain {status} {code}"
            )));
        }
    }

    let path = root.join("protocol/openapi/mailbox/v1/openapi.yaml");
    let source = read(&path)?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse OpenAPI {}: {error}", path.display()))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "mailbox OpenAPI contract must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse mailbox OpenAPI YAML tree: {error}"))
    })?;
    for (pointer, expected) in [
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}/put/operationId",
            json!("registerMailbox"),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}~1envelopes~1{envelope_id}/put/operationId",
            json!("appendMailboxEnvelope"),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}~1pull/post/operationId",
            json!("pullMailboxEnvelopes"),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}~1acks/post/operationId",
            json!("acknowledgeMailboxEnvelopes"),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}/put/requestBody/content/application~1vnd.dirextalk.mailbox-register.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}~1envelopes~1{envelope_id}/put/requestBody/content/application~1vnd.dirextalk.mailbox-envelope.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}~1pull/post/requestBody/content/application~1vnd.dirextalk.mailbox-pull.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}~1acks/post/requestBody/content/application~1vnd.dirextalk.mailbox-acks.v1+cbor/x-dirextalk-exact-cbor",
            json!(true),
        ),
        (
            "/paths/~1v1~1mailboxes~1{mailbox_id}~1envelopes~1{envelope_id}/put/responses/404/$ref",
            json!("#/components/responses/MailboxUnavailable"),
        ),
        (
            "/components/parameters/IdempotencyKey/schema/pattern",
            json!("^[A-Za-z0-9_-]{16,128}$"),
        ),
        (
            "/components/parameters/DeviceSessionAuthorization/schema/pattern",
            json!(
                "^DTX-Device-Session [0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\.[A-Za-z0-9_-]{43}$"
            ),
        ),
        (
            "/components/parameters/MailboxCapabilityAuthorization/schema/pattern",
            json!("^DTX-Mailbox-Capability [A-Za-z0-9_-]{43}$"),
        ),
        (
            "/components/schemas/ErrorEnvelopeV1/properties/error/properties/code/enum",
            json!([
                "DEVICE_AUTHENTICATION_FAILED",
                "MAILBOX_UNAVAILABLE",
                "MAILBOX_CONFLICT",
                "IDEMPOTENCY_CONFLICT",
                "MAILBOX_INVALID",
                "MAILBOX_CAPACITY_EXCEEDED",
                "MAILBOX_SERVICE_UNAVAILABLE"
            ]),
        ),
    ] {
        expect_value(&document, pointer, &expected)?;
    }
    Ok(())
}

fn validate_identity_session_proof_vector(
    cddl: &str,
    vector: &Value,
) -> Result<(), ProtocolToolError> {
    let proof = vector
        .get("proof")
        .ok_or_else(|| ProtocolToolError::new("identity-session-v1 proof vector is missing"))?;
    validate_uuid_fields(
        vector,
        &[
            "/proof/device_id",
            "/proof/challenge_id",
            "/proof/session_id",
        ],
    )?;
    let identity_id = json_string(proof, "identity_id")?;
    if identity_id.len() != 57 || !identity_id.starts_with("dtxi1") {
        return Err(ProtocolToolError::new(
            "identity-session-v1 proof identity must be canonical-looking",
        ));
    }
    let nonce = decode_base64url_fixed::<32>(json_string(proof, "challenge_nonce")?)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(ProtocolToolError::new(
            "identity-session-v1 proof nonce cannot be all zero",
        ));
    }
    let audience = json_string(proof, "audience")?;
    if !(1..=256).contains(&audience.len()) || !audience.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ProtocolToolError::new(
            "identity-session-v1 proof audience must be bounded ASCII",
        ));
    }
    let session_secret_hash = json_string(proof, "session_secret_hash")?
        .strip_prefix("sha256:")
        .ok_or_else(|| {
            ProtocolToolError::new("identity-session-v1 proof secret hash must use sha256")
        })?;
    let _ = decode_lower_hex_fixed::<32>(session_secret_hash)?;
    let session_expires_at = json_i64(proof, "session_expires_at_ms")?;
    if !(-62_135_596_800_000..=253_402_300_799_999).contains(&session_expires_at) {
        return Err(ProtocolToolError::new(
            "identity-session-v1 proof expiry is outside UTC bounds",
        ));
    }

    let canonical = decode_hex(json_string(proof, "canonical_cbor_hex")?)?;
    cddl_cat::validate_cbor_bytes("device-session-proof-v1", cddl, &canonical).map_err(
        |error| {
            ProtocolToolError::new(format!(
                "CDDL rejected device-session-proof-v1 golden vector: {error}"
            ))
        },
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"dirextalk.device-session-proof.v1\0");
    hasher.update(&canonical);
    let proof_hash = hasher.finalize();
    if json_string(proof, "proof_hash_hex")? != lowercase_hex(&proof_hash) {
        return Err(ProtocolToolError::new(
            "identity-session-v1 proof hash does not bind canonical CBOR",
        ));
    }
    let mut signature_input = b"dirextalk.device-session-signature.v1\0".to_vec();
    signature_input.extend_from_slice(&proof_hash);
    if json_string(proof, "signature_input_hex")? != lowercase_hex(&signature_input) {
        return Err(ProtocolToolError::new(
            "identity-session-v1 signature input does not bind proof hash",
        ));
    }
    let public_key = decode_prefixed_base64url_fixed::<32>(
        json_string(proof, "device_signing_public_key")?,
        "ed25519:",
    )?;
    let signature =
        decode_prefixed_base64url_fixed::<64>(json_string(proof, "signature")?, "ed25519:")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        ProtocolToolError::new("identity-session-v1 proof public key is not an Ed25519 key")
    })?;
    verifying_key
        .verify_strict(&signature_input, &Signature::from_bytes(&signature))
        .map_err(|_| ProtocolToolError::new("identity-session-v1 proof signature does not verify"))
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

fn decode_uuid_v7_raw16(value: &str) -> Result<[u8; 16], ProtocolToolError> {
    validate_uuid_v7(value)?;
    let compact = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(char::from)
        .collect::<String>();
    decode_lower_hex_fixed(&compact)
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

fn require_exact_object_keys(
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
            "{label} field set does not match the frozen contract"
        )))
    }
}

fn validate_identity_id(value: &str, label: &str) -> Result<(), ProtocolToolError> {
    let bytes = value.as_bytes();
    if bytes.len() == 57
        && bytes.starts_with(b"dtxi1")
        && bytes[5..]
            .iter()
            .all(|byte| matches!(*byte, b'a'..=b'z' | b'2'..=b'7'))
        // 52 base32 symbols encode the 256-bit digest plus four unused tail
        // bits. Canonical public IDs require those tail bits to be zero.
        && base32_lower_value(bytes[56]).is_some_and(|value| value.trailing_zeros() >= 4)
    {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "{label} must be a canonical self-certifying identity ID"
        )))
    }
}

const fn base32_lower_value(byte: u8) -> Option<u8> {
    match byte {
        b'a'..=b'z' => Some(byte - b'a'),
        b'2'..=b'7' => Some(byte - b'2' + 26),
        _ => None,
    }
}

fn validate_enrollment_material(
    device_signing_public_key: [u8; 32],
    device_encryption_public_key: [u8; 32],
    enrollment_capability: [u8; 32],
) -> Result<(), ProtocolToolError> {
    VerifyingKey::from_bytes(&device_signing_public_key).map_err(|_| {
        ProtocolToolError::new("identity-enrollment-v1 signing key is not an Ed25519 key")
    })?;
    if device_encryption_public_key.iter().all(|byte| *byte == 0) {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 encryption key cannot be all zero",
        ));
    }
    if device_signing_public_key == device_encryption_public_key {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 signing and encryption keys must be distinct",
        ));
    }
    if enrollment_capability.iter().all(|byte| *byte == 0) {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 capability cannot be all zero",
        ));
    }
    Ok(())
}

fn validate_enrollment_expiry(value: i64) -> Result<(), ProtocolToolError> {
    if (1..=253_402_300_799_999).contains(&value) {
        Ok(())
    } else {
        Err(ProtocolToolError::new(
            "identity-enrollment-v1 expiry must be a positive UTC millisecond value",
        ))
    }
}

fn validate_strict_https_origin(value: &str) -> Result<(), ProtocolToolError> {
    let authority = value.strip_prefix("https://").ok_or_else(|| {
        ProtocolToolError::new("identity-enrollment-v1 QR origin must use lowercase HTTPS")
    })?;
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 QR origin must be a strict HTTPS origin without userinfo or path",
        ));
    }
    Ok(())
}

fn validate_contact_card_https_origin(value: &str) -> Result<(), ProtocolToolError> {
    if value.len() > 512 || !value.is_ascii() {
        return Err(ProtocolToolError::new(
            "contact-card-v1 origin must be a bounded ASCII HTTPS root origin",
        ));
    }
    let authority = value
        .strip_prefix("https://")
        .and_then(|authority_and_root| authority_and_root.strip_suffix('/'))
        .ok_or_else(|| {
            ProtocolToolError::new(
                "contact-card-v1 origin must use lowercase HTTPS and an explicit root slash",
            )
        })?;
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', '\\', '%', '[', ']']) {
        return Err(ProtocolToolError::new(
            "contact-card-v1 origin must be one canonical HTTPS authority and root slash",
        ));
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if authority.matches(':').count() > 1
        || !valid_contact_card_dns_host(host)
        || port.is_some_and(|port| !valid_contact_card_port(port))
    {
        return Err(ProtocolToolError::new(
            "contact-card-v1 origin must use a canonical lowercase DNS authority",
        ));
    }
    Ok(())
}

fn valid_contact_card_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
        && host.bytes().any(|byte| byte.is_ascii_lowercase())
        && !looks_like_whatwg_ipv4_host(host)
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && !label.starts_with("xn--")
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_contact_card_port(port: &str) -> bool {
    !port.is_empty()
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port
            .parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed != 443)
}

fn looks_like_whatwg_ipv4_host(host: &str) -> bool {
    host.split('.')
        .next_back()
        .is_some_and(is_whatwg_ipv4_number)
}

fn is_whatwg_ipv4_number(part: &str) -> bool {
    !part.is_empty()
        && (part.bytes().all(|byte| byte.is_ascii_digit())
            || part.strip_prefix("0x").is_some_and(|hex| {
                hex.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }))
}

fn validate_quoted_sha256_if_match(value: &str) -> Result<(), ProtocolToolError> {
    let digest = value
        .strip_prefix("\"sha256:")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            ProtocolToolError::new(
                "identity-enrollment-v1 If-Match must be quoted lowercase sha256",
            )
        })?;
    let _ = decode_lower_hex_fixed::<32>(digest)?;
    Ok(())
}

fn validate_exact_cddl_bytes(
    rule: &str,
    cddl: &str,
    encoded: &str,
    expected: &[u8],
) -> Result<(), ProtocolToolError> {
    let actual = decode_hex(encoded)?;
    if actual != expected {
        return Err(ProtocolToolError::new(format!(
            "{rule} golden vector does not preserve its exact canonical fields"
        )));
    }
    cddl_cat::validate_cbor_bytes(rule, cddl, &actual)
        .map_err(|error| ProtocolToolError::new(format!("CDDL rejected {rule}: {error}")))
}

fn encode_device_enrollment_candidate(
    identity_id: &str,
    device_id: &str,
    device_signing_public_key: [u8; 32],
    device_encryption_public_key: [u8; 32],
    enrollment_capability: [u8; 32],
) -> Result<Vec<u8>, ProtocolToolError> {
    let mut encoded = Vec::new();
    encode_cbor_length(&mut encoded, 5, 6);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 2);
    append_cbor_text(&mut encoded, identity_id)?;
    append_cbor_unsigned(&mut encoded, 3);
    append_cbor_text(&mut encoded, device_id)?;
    append_cbor_unsigned(&mut encoded, 4);
    append_cbor_bytes(&mut encoded, &device_signing_public_key)?;
    append_cbor_unsigned(&mut encoded, 5);
    append_cbor_bytes(&mut encoded, &device_encryption_public_key)?;
    append_cbor_unsigned(&mut encoded, 6);
    append_cbor_bytes(&mut encoded, &enrollment_capability)?;
    Ok(encoded)
}

fn encode_contact_card(identity_id: &str, origin: &str) -> Result<Vec<u8>, ProtocolToolError> {
    validate_identity_id(identity_id, "contact-card-v1 identity")?;
    validate_contact_card_https_origin(origin)?;
    let mut encoded = Vec::new();
    encode_cbor_length(&mut encoded, 5, 3);
    append_cbor_unsigned(&mut encoded, 1);
    encode_cbor_length(&mut encoded, 5, 2);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 2);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 2);
    append_cbor_text(&mut encoded, identity_id)?;
    append_cbor_unsigned(&mut encoded, 3);
    append_cbor_text(&mut encoded, origin)?;
    Ok(encoded)
}

fn encode_device_enrollment_status(
    challenge_id: &str,
    identity_id: &str,
    device_id: &str,
    state: u8,
    expires_at_ms: i64,
) -> Result<Vec<u8>, ProtocolToolError> {
    if !(1..=4).contains(&state) {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 state must be a known frozen value",
        ));
    }
    validate_enrollment_expiry(expires_at_ms)?;
    let mut encoded = Vec::new();
    encode_cbor_length(&mut encoded, 5, 6);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 2);
    append_cbor_text(&mut encoded, challenge_id)?;
    append_cbor_unsigned(&mut encoded, 3);
    append_cbor_text(&mut encoded, identity_id)?;
    append_cbor_unsigned(&mut encoded, 4);
    append_cbor_text(&mut encoded, device_id)?;
    append_cbor_unsigned(&mut encoded, 5);
    append_cbor_unsigned(&mut encoded, u64::from(state));
    append_cbor_unsigned(&mut encoded, 6);
    append_cbor_unsigned(
        &mut encoded,
        u64::try_from(expires_at_ms)
            .map_err(|_| ProtocolToolError::new("identity-enrollment-v1 expiry is negative"))?,
    );
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
fn encode_device_enrollment_qr(
    origin: &str,
    identity_id: &str,
    challenge_id: &str,
    device_id: &str,
    device_signing_public_key: [u8; 32],
    device_encryption_public_key: [u8; 32],
    enrollment_capability: [u8; 32],
    expires_at_ms: i64,
) -> Result<Vec<u8>, ProtocolToolError> {
    validate_strict_https_origin(origin)?;
    validate_enrollment_expiry(expires_at_ms)?;
    let mut encoded = Vec::new();
    encode_cbor_length(&mut encoded, 5, 9);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 2);
    append_cbor_text(&mut encoded, origin)?;
    append_cbor_unsigned(&mut encoded, 3);
    append_cbor_text(&mut encoded, identity_id)?;
    append_cbor_unsigned(&mut encoded, 4);
    append_cbor_text(&mut encoded, challenge_id)?;
    append_cbor_unsigned(&mut encoded, 5);
    append_cbor_text(&mut encoded, device_id)?;
    append_cbor_unsigned(&mut encoded, 6);
    append_cbor_bytes(&mut encoded, &device_signing_public_key)?;
    append_cbor_unsigned(&mut encoded, 7);
    append_cbor_bytes(&mut encoded, &device_encryption_public_key)?;
    append_cbor_unsigned(&mut encoded, 8);
    append_cbor_bytes(&mut encoded, &enrollment_capability)?;
    append_cbor_unsigned(&mut encoded, 9);
    append_cbor_unsigned(
        &mut encoded,
        u64::try_from(expires_at_ms)
            .map_err(|_| ProtocolToolError::new("identity-enrollment-v1 expiry is negative"))?,
    );
    Ok(encoded)
}

fn encode_device_enrollment_completion(
    challenge_id: &str,
    enrollment_capability: [u8; 32],
    device_add_bytes: &[u8],
) -> Result<Vec<u8>, ProtocolToolError> {
    if device_add_bytes.is_empty() || device_add_bytes.len() > 1_048_576 {
        return Err(ProtocolToolError::new(
            "identity-enrollment-v1 exact DeviceAdd has an invalid length",
        ));
    }
    let mut encoded = Vec::new();
    encode_cbor_length(&mut encoded, 5, 4);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 1);
    append_cbor_unsigned(&mut encoded, 2);
    append_cbor_text(&mut encoded, challenge_id)?;
    append_cbor_unsigned(&mut encoded, 3);
    append_cbor_bytes(&mut encoded, &enrollment_capability)?;
    append_cbor_unsigned(&mut encoded, 4);
    append_cbor_bytes(&mut encoded, device_add_bytes)?;
    Ok(encoded)
}

fn append_cbor_unsigned(output: &mut Vec<u8>, value: u64) {
    encode_cbor_length(output, 0, value);
}

fn append_cbor_text(output: &mut Vec<u8>, value: &str) -> Result<(), ProtocolToolError> {
    let length = u64::try_from(value.len())
        .map_err(|_| ProtocolToolError::new("CBOR text length exceeds u64"))?;
    encode_cbor_length(output, 3, length);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_cbor_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolToolError> {
    let length = u64::try_from(value.len())
        .map_err(|_| ProtocolToolError::new("CBOR byte string length exceeds u64"))?;
    encode_cbor_length(output, 2, length);
    output.extend_from_slice(value);
    Ok(())
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

fn json_i64(value: &Value, key: &str) -> Result<i64, ProtocolToolError> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| ProtocolToolError::new(format!("vector field {key} must be an integer")))
}

fn has_error_response(
    vector: &Value,
    status: i64,
    code: &str,
    retryable: bool,
) -> Result<bool, ProtocolToolError> {
    let responses = vector
        .get("error_responses")
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new("error_responses must be an array"))?;
    Ok(responses.iter().any(|response| {
        response.get("status").and_then(Value::as_i64) == Some(status)
            && response.get("code").and_then(Value::as_str) == Some(code)
            && response.get("retryable").and_then(Value::as_bool) == Some(retryable)
    }))
}

fn decode_prefixed_base64url_fixed<const LENGTH: usize>(
    value: &str,
    prefix: &str,
) -> Result<[u8; LENGTH], ProtocolToolError> {
    let encoded = value
        .strip_prefix(prefix)
        .ok_or_else(|| ProtocolToolError::new(format!("golden value must use {prefix} prefix")))?;
    decode_base64url_fixed(encoded)
}

const fn unpadded_base64url_character_count(input_bytes: usize) -> usize {
    let complete_chunks = input_bytes / 3;
    let remainder = input_bytes % 3;
    complete_chunks * 4
        + match remainder {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

fn decode_base64url_fixed<const LENGTH: usize>(
    value: &str,
) -> Result<[u8; LENGTH], ProtocolToolError> {
    let mut decoded = [0_u8; LENGTH];
    let result = Base64UrlUnpadded::decode(value, &mut decoded)
        .map_err(|_| ProtocolToolError::new("golden value must be unpadded base64url"))?;
    if result.len() != LENGTH {
        return Err(ProtocolToolError::new(
            "golden base64url value has the wrong length",
        ));
    }
    Ok(decoded)
}

fn decode_lower_hex_fixed<const LENGTH: usize>(
    value: &str,
) -> Result<[u8; LENGTH], ProtocolToolError> {
    let decoded = decode_hex(value)?;
    decoded
        .try_into()
        .map_err(|_| ProtocolToolError::new("golden hexadecimal value has the wrong length"))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
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

    fn private_event_fixture(label: &str) -> (String, Vec<u8>) {
        let cddl =
            read(&root().join("protocol/cddl/private-event/v1/private-event-v1.cddl")).unwrap();
        let vector: Value = serde_json::from_str(include_str!(
            "../../../protocol/test-vectors/private-event/v1/private-event-v1.json"
        ))
        .unwrap();
        let event = vector["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["label"] == label)
            .unwrap();
        (
            cddl,
            decode_hex(event["canonical_cbor_hex"].as_str().unwrap()).unwrap(),
        )
    }

    #[test]
    fn private_event_decoder_rejects_unknown_noncanonical_and_invalid_semantics() {
        let (cddl, text) = private_event_fixture("text");
        validate_private_event_bytes(&cddl, &text).unwrap();

        let mut noncanonical = text.clone();
        noncanonical.splice(2..3, [0x18, 0x01]);
        assert!(validate_private_event_bytes(&cddl, &noncanonical).is_err());

        let mut unknown = text.clone();
        unknown[0] = 0xab;
        unknown.extend([0x0b, 0x00]);
        assert!(validate_private_event_bytes(&cddl, &unknown).is_err());

        let mut invalid_text_run = text;
        assert_eq!(invalid_text_run.pop(), Some(0xf6));
        invalid_text_run.extend([0x78, 0x24]);
        invalid_text_run.extend_from_slice(b"0190f2a5-7b1c-7abc-8def-0123456789b6");
        assert!(validate_private_event_bytes(&cddl, &invalid_text_run).is_err());

        let (_, mut duplicate_parent) = private_event_fixture("agent_response");
        let parent_marker = duplicate_parent
            .windows(4)
            .position(|window| window == [0x08, 0x81, 0x78, 0x24])
            .unwrap();
        duplicate_parent[parent_marker + 1] = 0x82;
        let parent_start = parent_marker + 2;
        let parent_end = parent_start + 38;
        let encoded_parent = duplicate_parent[parent_start..parent_end].to_vec();
        duplicate_parent.splice(parent_end..parent_end, encoded_parent);
        assert!(validate_private_event_bytes(&cddl, &duplicate_parent).is_err());

        let (_, mut self_parent) = private_event_fixture("agent_response");
        let parent_marker = self_parent
            .windows(4)
            .position(|window| window == [0x08, 0x81, 0x78, 0x24])
            .unwrap();
        let parent_payload_start = parent_marker + 4;
        self_parent[parent_payload_start..parent_payload_start + 36]
            .copy_from_slice(b"0190f2a5-7b1c-7abc-8def-0123456789b4");
        assert!(validate_private_event_bytes(&cddl, &self_parent).is_err());
    }

    #[test]
    fn private_event_decoder_enforces_identity_timestamp_and_exact_size_bounds() {
        let (cddl, text) = private_event_fixture("text");
        let timestamp_marker = text
            .windows(2)
            .position(|window| window == [0x06, 0x1b])
            .unwrap();

        let mut minimum_timestamp = text.clone();
        minimum_timestamp[timestamp_marker + 1] = 0x3b;
        minimum_timestamp[timestamp_marker + 2..timestamp_marker + 10]
            .copy_from_slice(&62_135_596_799_999_u64.to_be_bytes());
        validate_private_event_bytes(&cddl, &minimum_timestamp).unwrap();

        let mut below_minimum_timestamp = text.clone();
        below_minimum_timestamp[timestamp_marker + 1] = 0x3b;
        below_minimum_timestamp[timestamp_marker + 2..timestamp_marker + 10]
            .copy_from_slice(&62_135_596_800_000_u64.to_be_bytes());
        assert!(validate_private_event_bytes(&cddl, &below_minimum_timestamp).is_err());

        let mut maximum_timestamp = text.clone();
        maximum_timestamp[timestamp_marker + 2..timestamp_marker + 10]
            .copy_from_slice(&253_402_300_799_999_u64.to_be_bytes());
        validate_private_event_bytes(&cddl, &maximum_timestamp).unwrap();

        let mut above_maximum_timestamp = text.clone();
        above_maximum_timestamp[timestamp_marker + 2..timestamp_marker + 10]
            .copy_from_slice(&253_402_300_800_000_u64.to_be_bytes());
        assert!(validate_private_event_bytes(&cddl, &above_maximum_timestamp).is_err());

        let identity_marker = text
            .windows(3)
            .position(|window| window == [0x04, 0x78, 0x39])
            .unwrap();
        let identity_start = identity_marker + 1;

        let mut noncanonical_identity = text;
        noncanonical_identity[identity_start + 2] = b'x';
        assert!(validate_private_event_bytes(&cddl, &noncanonical_identity).is_err());

        let parents = (0..16)
            .map(|index| {
                CanonicalValue::Text(format!("0190f2a5-7b1c-7abc-8def-0123456789{index:02x}"))
            })
            .collect();
        let maximal = CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789b1".to_owned()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789b0".to_owned()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(
                    "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la".to_owned(),
                ),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789b2".to_owned()),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Unsigned(253_402_300_799_999),
            ),
            (CanonicalValue::Unsigned(7), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(8), CanonicalValue::Array(parents)),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Text("a".repeat(65_536)),
            ),
            (
                CanonicalValue::Unsigned(10),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789b6".to_owned()),
            ),
        ]);
        let maximal = encode_deterministic_cbor(&maximal).unwrap();
        assert_eq!(maximal.len(), PRIVATE_EVENT_MAX_ENCODED_BYTES);
        validate_private_event_bytes(&cddl, &maximal).unwrap();
        let mut maximum_plus_one = maximal;
        maximum_plus_one.push(0);
        assert_eq!(maximum_plus_one.len(), PRIVATE_EVENT_MAX_ENCODED_BYTES + 1);
        assert!(validate_private_event_bytes(&cddl, &maximum_plus_one).is_err());
    }

    #[test]
    fn private_event_mls_digest_binds_event_length_and_exact_ciphertext() {
        let event_id = "0190f2a5-7b1c-7abc-8def-0123456789b1";
        let ciphertext =
            decode_hex("d91000010203a0ff1020304050607080").expect("fixture ciphertext");
        assert_eq!(
            mls_authenticated_private_event_digest(event_id, &ciphertext).unwrap(),
            decode_lower_hex_fixed(
                "b4d82332aaf82d39decd8aa42f02e300df5ebe6265e66fce877195d069254da6"
            )
            .unwrap()
        );

        let other_event = "0190f2a5-7b1c-7abc-8def-0123456789b2";
        assert_ne!(
            mls_authenticated_private_event_digest(event_id, &ciphertext).unwrap(),
            mls_authenticated_private_event_digest(other_event, &ciphertext).unwrap()
        );
        let mut changed_ciphertext = ciphertext.clone();
        changed_ciphertext.push(0);
        assert_ne!(
            mls_authenticated_private_event_digest(event_id, &ciphertext).unwrap(),
            mls_authenticated_private_event_digest(event_id, &changed_ciphertext).unwrap()
        );
        assert!(mls_authenticated_private_event_digest(event_id, &[]).is_err());
        assert!(
            mls_authenticated_private_event_digest(
                event_id,
                &vec![0; PRIVATE_EVENT_MAX_MLS_CIPHERTEXT_BYTES + 1],
            )
            .is_err()
        );
    }

    #[test]
    fn contact_card_origin_only_accepts_canonical_dns_https_roots() {
        for valid in ["https://a.co/", "https://node.example:8443/"] {
            assert!(
                validate_contact_card_https_origin(valid).is_ok(),
                "rejected {valid}"
            );
        }
        for invalid in [
            "HTTPS://a.co/",
            "https://A.co/",
            "https://a.co",
            "https://a.co:443/",
            "https://a.co:0444/",
            "https://127.0.0.1/",
            "https://a.1/",
            "https://foo.0x7f/",
            "https://foo.0x/",
            "https://[::1]/",
            "https://xn--bcher-kva.example/",
            "https://a.co./",
        ] {
            assert!(
                validate_contact_card_https_origin(invalid).is_err(),
                "accepted {invalid}"
            );
        }
        assert_eq!(CONTACT_CARD_MAX_UNPADDED_BASE64URL_CHARS, 5_462);
        assert_eq!(CONTACT_CARD_MAX_QR_PAYLOAD_CHARS, 5_468);
    }

    #[test]
    fn identity_id_rejects_noncanonical_base32_tail_bits() {
        assert!(
            validate_identity_id(
                "dtxi155pujebuvamvkmouxx6okeiijjuzjxxw4ktjahrjy6z27frlobiq",
                "test identity"
            )
            .is_ok()
        );
        assert!(
            validate_identity_id(
                "dtxi155pujebuvamvkmouxx6okeiijjuzjxxw4ktjahrjy6z27frlobir",
                "test identity"
            )
            .is_err()
        );
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
