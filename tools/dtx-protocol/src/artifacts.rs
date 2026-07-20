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
const PRIVATE_AGENT_APPROVAL_BASELINE: u64 = 34;
const PRIVATE_AGENT_APPROVAL_MAX_REQUEST_TTL_MS: i64 = 300_000;
const PRIVATE_AGENT_APPROVAL_MAX_TITLE_SCALARS: usize = 120;
const PRIVATE_AGENT_APPROVAL_MAX_DETAIL_BYTES: usize = 4_096;
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
    validate_contact_delivery_v1(root)?;
    validate_identity_bootstrap_v1(root)?;
    validate_identity_session_v1(root)?;
    validate_identity_enrollment_v1(root)?;
    validate_key_package_v1(root)?;
    validate_mailbox_v1(root)?;
    validate_public_descriptor_v1(root)?;
    validate_public_descriptor_v1_1(root)?;
    validate_public_descriptor_v1_2(root)?;
    validate_public_feed_v1(root)?;
    validate_indexer_v1(root)?;
    validate_conditional_cache_v1(root)?;
    validate_public_search_pagination_v1(root)?;
    validate_membership_federation_v1(root)?;
    validate_group_membership_discovery_v1(root)?;
    validate_private_messaging_artifacts(root)?;
    validate_v30_peer_admission(root)?;
    validate_mls_sequencer_v4(root)?;
    validate_conversation_agent_grant_v1(root)?;
    validate_v36_additive_contracts(root)?;
    validate_realtime_sync_v1(root)?;
    validate_account_read_cursor_v1(root)?;
    validate_realtime_sync_v2(root)?;

    let events = load_event_registry(&root.join("protocol/events/registry.yaml"))?;
    let errors = load_error_registry(&root.join("protocol/errors/registry.yaml"))?;
    validate_openapi(root, &events, &errors)?;
    validate_protobuf(root)?;
    Ok(())
}

fn validate_realtime_sync_v2(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/realtime-sync/v2/realtime-sync-v2.cddl"))?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse Realtime Sync V2 CDDL: {error}")))?;
    let vector =
        read_json(&root.join("protocol/test-vectors/realtime-sync/v2/realtime-sync-v2.json"))?;
    if vector.get("version").and_then(Value::as_u64) != Some(2)
        || vector.get("baseline").and_then(Value::as_u64) != Some(39)
        || vector.get("subprotocol").and_then(Value::as_str) != Some("dirextalk.realtime-sync.v2")
    {
        return Err(ProtocolToolError::new(
            "Realtime Sync V2 vector version/baseline/subprotocol drift",
        ));
    }
    for (rule, field) in [
        ("hello-v2", "hello_canonical_cbor_hex"),
        ("scope-subscribe-v2", "scope_subscribe_canonical_cbor_hex"),
        (
            "invalidation-v2",
            "typed_identity_invalidation_canonical_cbor_hex",
        ),
        (
            "identity-mailbox-pull-v3",
            "identity_pull_v3_canonical_cbor_hex",
        ),
    ] {
        validate_cddl_hex(rule, &cddl, json_string(&vector, field)?)?;
    }
    for pointer in [
        "/privacy/scope_is_digest_only",
        "/privacy/scope_membership_is_memory_only",
        "/privacy/ephemeral_requires_active_subscription",
        "/privacy/expired_delivery_has_no_ciphertext",
    ] {
        if vector.pointer(pointer).and_then(Value::as_bool) != Some(true) {
            return Err(ProtocolToolError::new(format!(
                "Realtime Sync V2 privacy invariant {pointer} is not frozen true"
            )));
        }
    }
    Ok(())
}

fn validate_account_read_cursor_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl =
        read(&root.join("protocol/cddl/account-read-cursor/v1/account-read-cursor-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse Account Read Cursor V1 CDDL: {error}"))
    })?;
    let vector = read_json(
        &root.join("protocol/test-vectors/account-read-cursor/v1/account-read-cursor-v1.json"),
    )?;
    if vector.get("version").and_then(Value::as_u64) != Some(1)
        || vector.get("baseline").and_then(Value::as_u64) != Some(38)
    {
        return Err(ProtocolToolError::new(
            "Account Read Cursor V1 vector version/baseline drift",
        ));
    }
    for (rule, field) in [
        ("account-read-cursor-write-v1", "write_canonical_cbor_hex"),
        ("account-read-cursor-query-v1", "query_canonical_cbor_hex"),
    ] {
        validate_cddl_hex(rule, &cddl, json_string(&vector, field)?)?;
    }
    for pointer in [
        "/privacy/conversation_is_digest_only",
        "/privacy/cursor_is_opaque_ciphertext",
        "/privacy/server_has_no_plaintext_unread_graph",
    ] {
        if vector.pointer(pointer).and_then(Value::as_bool) != Some(true) {
            return Err(ProtocolToolError::new(format!(
                "Account Read Cursor V1 privacy invariant {pointer} is not frozen true"
            )));
        }
    }
    Ok(())
}

fn validate_realtime_sync_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/realtime-sync/v1/realtime-sync-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse Realtime Sync V1 CDDL: {error}")))?;
    let vector =
        read_json(&root.join("protocol/test-vectors/realtime-sync/v1/realtime-sync-v1.json"))?;
    if vector.get("version").and_then(Value::as_u64) != Some(1)
        || vector.get("baseline").and_then(Value::as_u64) != Some(37)
        || vector.get("subprotocol").and_then(Value::as_str) != Some("dirextalk.realtime-sync.v1")
    {
        return Err(ProtocolToolError::new(
            "Realtime Sync V1 vector version/baseline/subprotocol drift",
        ));
    }
    for (rule, field) in [
        ("hello-v1", "hello_canonical_cbor_hex"),
        (
            "catch-up-required-v1",
            "catch_up_required_canonical_cbor_hex",
        ),
        ("invalidation-v1", "invalidation_canonical_cbor_hex"),
        (
            "identity-mailbox-pull-v2",
            "identity_pull_v2_canonical_cbor_hex",
        ),
        (
            "identity-mailbox-ack-v2",
            "identity_ack_v2_canonical_cbor_hex",
        ),
    ] {
        validate_cddl_hex(rule, &cddl, json_string(&vector, field)?)?;
    }
    for pointer in [
        "/privacy/invalidation_subject_is_digest_only",
        "/privacy/mailbox_ciphertext_not_available_to_gateway",
        "/privacy/wake_hint_contains_no_plaintext",
    ] {
        if vector.pointer(pointer).and_then(Value::as_bool) != Some(true) {
            return Err(ProtocolToolError::new(format!(
                "Realtime Sync V1 privacy invariant {pointer} is not frozen true"
            )));
        }
    }
    let invalidation = decode_hex(json_string(&vector, "invalidation_canonical_cbor_hex")?)?;
    let decoded = decode_deterministic_cbor(&invalidation)
        .map_err(|_| ProtocolToolError::new("Realtime Sync V1 invalidation is not canonical"))?;
    let CanonicalValue::Map(fields) = decoded else {
        return Err(ProtocolToolError::new(
            "Realtime Sync V1 invalidation is not a map",
        ));
    };
    if fields
        .iter()
        .any(|(_, value)| matches!(value, CanonicalValue::Text(_)))
    {
        return Err(ProtocolToolError::new(
            "Realtime Sync V1 invalidation must not contain plaintext text fields",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one V36 gate keeps the public discussion, private V8, and group-query overlay byte exact"
)]
fn validate_v36_additive_contracts(root: &Path) -> Result<(), ProtocolToolError> {
    let discussion_cddl_path =
        root.join("protocol/cddl/public-discussion/v1/public-discussion-v1.cddl");
    let discussion_cddl = read(&discussion_cddl_path)?;
    cddl_cat::parse_cddl(&discussion_cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Public Discussion V1 CDDL {}: {error}",
            discussion_cddl_path.display()
        ))
    })?;
    let discussion_openapi_path = root.join("protocol/openapi/public-discussion/v1/openapi.yaml");
    let discussion_openapi = read(&discussion_openapi_path)?;
    let discussion_spec = oas3::from_yaml(&discussion_openapi).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Public Discussion V1 OpenAPI {}: {error}",
            discussion_openapi_path.display()
        ))
    })?;
    if discussion_spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "Public Discussion V1 OpenAPI must declare 3.1.0",
        ));
    }
    for required in [
        "sequence-2-or-later",
        "Idempotency-Key",
        "application/vnd.dirextalk.public-discussion-policy.v1+cbor",
        "application/vnd.dirextalk.public-comment.v1+cbor",
        "application/vnd.dirextalk.public-reaction.v1+cbor",
        "currently active device",
        "no-store",
    ] {
        if !discussion_openapi.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "Public Discussion V1 OpenAPI is missing {required}"
            )));
        }
    }

    let discussion_vector = read_json(
        &root.join("protocol/test-vectors/public-discussion/v1/public-discussion-v1.json"),
    )?;
    validate_vector_version(&discussion_vector, "public-discussion-v1")?;
    if discussion_vector.get("baseline").and_then(Value::as_u64) != Some(36) {
        return Err(ProtocolToolError::new(
            "Public Discussion V1 vector baseline must be 36",
        ));
    }
    for (rule, pointer) in [
        ("public-discussion-policy-v1", "/policy/canonical_cbor_hex"),
        ("public-comment-v1", "/comment/canonical_cbor_hex"),
        (
            "public-comment-receipt-v1",
            "/comment_receipt/canonical_cbor_hex",
        ),
        ("public-comment-page-v1", "/comment_page_canonical_cbor_hex"),
        ("public-reaction-v1", "/reaction/canonical_cbor_hex"),
        (
            "public-reaction-receipt-v1",
            "/reaction_receipt_canonical_cbor_hex",
        ),
        (
            "public-reaction-projection-v1",
            "/reaction_projection_canonical_cbor_hex",
        ),
    ] {
        let encoded = discussion_vector
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProtocolToolError::new(format!(
                    "Public Discussion V1 vector field {pointer} must be a string"
                ))
            })?;
        validate_cddl_hex(rule, &discussion_cddl, encoded)?;
    }
    let cursor = discussion_vector
        .pointer("/comment_cursor/base64url")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolToolError::new("Public Discussion V1 cursor is missing"))?;
    let cursor_bytes = Base64UrlUnpadded::decode_vec(cursor)
        .map_err(|_| ProtocolToolError::new("Public Discussion V1 cursor is not base64url"))?;
    if Base64UrlUnpadded::encode_string(&cursor_bytes) != cursor {
        return Err(ProtocolToolError::new(
            "Public Discussion V1 cursor must use unpadded canonical base64url",
        ));
    }
    cddl_cat::validate_cbor_bytes("public-comment-cursor-v1", &discussion_cddl, &cursor_bytes)
        .map_err(|error| {
            ProtocolToolError::new(format!(
                "CDDL rejected Public Discussion V1 cursor: {error}"
            ))
        })?;
    for (domain, exact_pointer, digest_pointer, label) in [
        (
            b"dirextalk.public-discussion-policy-entry.v1\0".as_slice(),
            "/policy/canonical_cbor_hex",
            "/policy/policy_digest_hex",
            "Public Discussion V1 policy",
        ),
        (
            b"dirextalk.public-comment-event-entry.v1\0".as_slice(),
            "/comment/canonical_cbor_hex",
            "/comment/event_hash_hex",
            "Public Discussion V1 comment",
        ),
        (
            b"dirextalk.public-reaction-event-entry.v1\0".as_slice(),
            "/reaction/canonical_cbor_hex",
            "/reaction/event_digest_hex",
            "Public Discussion V1 reaction",
        ),
    ] {
        let exact = discussion_vector
            .pointer(exact_pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| ProtocolToolError::new(format!("missing {exact_pointer}")))?;
        let digest = discussion_vector
            .pointer(digest_pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| ProtocolToolError::new(format!("missing {digest_pointer}")))?;
        ensure_domain_digest(domain, exact, digest, label)?;
    }

    let private_cddl_path =
        root.join("protocol/cddl/private-event/v8/private-group-reaction-v8.cddl");
    let private_cddl = read(&private_cddl_path)?;
    cddl_cat::parse_cddl(&private_cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse private group reaction V8 CDDL {}: {error}",
            private_cddl_path.display()
        ))
    })?;
    let private_vector = read_json(
        &root.join("protocol/test-vectors/private-event/v8/private-group-reaction-v8.json"),
    )?;
    if private_vector.get("baseline").and_then(Value::as_u64) != Some(36)
        || private_vector.get("version").and_then(Value::as_u64) != Some(8)
        || private_vector.get("kind").and_then(Value::as_u64) != Some(8)
    {
        return Err(ProtocolToolError::new(
            "private group reaction V8 vector baseline/version/kind drift",
        ));
    }
    let private_hex = json_string(&private_vector, "canonical_cbor_hex")?;
    validate_cddl_hex("private-group-reaction-v8", &private_cddl, private_hex)?;
    let private_bytes = decode_hex(private_hex)?;
    if lowercase_hex(&Sha256::digest(&private_bytes))
        != json_string(&private_vector, "canonical_cbor_sha256")?
    {
        return Err(ProtocolToolError::new(
            "private group reaction V8 canonical CBOR digest drift",
        ));
    }
    let bound_head =
        decode_lower_hex_fixed::<32>(json_string(&private_vector, "bound_mls_head_hex")?)?;
    if bound_head.iter().all(|byte| *byte == 0) {
        return Err(ProtocolToolError::new(
            "private group reaction V8 MLS head must be non-zero",
        ));
    }

    let query_cddl_path =
        root.join("protocol/cddl/group-query-proof/v1/group-query-proof-overlay-v1.cddl");
    let query_cddl = read(&query_cddl_path)?;
    cddl_cat::parse_cddl(&query_cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Group Query Proof V1 overlay CDDL {}: {error}",
            query_cddl_path.display()
        ))
    })?;
    let query_openapi_path = root.join("protocol/openapi/group-query-proof/v1/openapi.yaml");
    let query_openapi = read(&query_openapi_path)?;
    let query_spec = oas3::from_yaml(&query_openapi).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Group Query Proof V1 overlay OpenAPI {}: {error}",
            query_openapi_path.display()
        ))
    })?;
    if query_spec.openapi != "3.1.0"
        || !query_openapi.contains("DTX-Group-Query-Proof")
        || !query_openapi.contains("Action 1")
        || !query_openapi.contains("action 2")
    {
        return Err(ProtocolToolError::new(
            "Group Query Proof V1 overlay header/action fence drift",
        ));
    }
    let query_vector = read_json(
        &root.join("protocol/test-vectors/group-query-proof/v1/group-query-proof-overlay-v1.json"),
    )?;
    if query_vector.get("baseline").and_then(Value::as_u64) != Some(36)
        || query_vector.get("version").and_then(Value::as_u64) != Some(1)
        || json_string(&query_vector, "canonical_header")? != "DTX-Group-Query-Proof"
    {
        return Err(ProtocolToolError::new(
            "Group Query Proof V1 overlay vector header/baseline drift",
        ));
    }
    let proofs = query_vector
        .get("proofs")
        .and_then(Value::as_array)
        .filter(|proofs| proofs.len() == 2)
        .ok_or_else(|| {
            ProtocolToolError::new("Group Query Proof V1 vector must contain two actions")
        })?;
    for (index, proof) in proofs.iter().enumerate() {
        let expected_action = (index + 1) as u64;
        if proof.get("action").and_then(Value::as_u64) != Some(expected_action) {
            return Err(ProtocolToolError::new(
                "Group Query Proof V1 actions must be exactly 1 then 2",
            ));
        }
        let encoded = json_string(proof, "canonical_cbor_hex")?;
        validate_cddl_hex("group-query-proof-v1", &query_cddl, encoded)?;
        let exact = decode_hex(encoded)?;
        let header = json_string(proof, "header_base64url")?;
        if Base64UrlUnpadded::encode_string(&exact) != header {
            return Err(ProtocolToolError::new(
                "Group Query Proof V1 header does not encode exact proof bytes",
            ));
        }
        let decoded = decode_deterministic_cbor(&exact).map_err(|error| {
            ProtocolToolError::new(format!("decode Group Query Proof V1: {error}"))
        })?;
        let CanonicalValue::Map(fields) = decoded else {
            return Err(ProtocolToolError::new("Group Query Proof V1 must be a map"));
        };
        let binding = fields
            .iter()
            .find_map(|(key, value)| (key == &CanonicalValue::Unsigned(2)).then_some(value))
            .ok_or_else(|| ProtocolToolError::new("Group Query Proof V1 binding is missing"))?;
        let CanonicalValue::Map(binding_fields) = binding else {
            return Err(ProtocolToolError::new(
                "Group Query Proof V1 binding must be a map",
            ));
        };
        if !binding_fields.iter().any(|(key, value)| {
            key == &CanonicalValue::Unsigned(2)
                && value == &CanonicalValue::Unsigned(expected_action)
        }) {
            return Err(ProtocolToolError::new(
                "Group Query Proof V1 encoded action does not match its label",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_v30_peer_admission(root: &Path) -> Result<(), ProtocolToolError> {
    let conversation_cddl =
        read(&root.join("protocol/cddl/conversation-admission/v1/conversation-admission-v1.cddl"))?;
    let membership_cddl = read(&root.join("protocol/cddl/membership/v2/membership-v2.cddl"))?;
    let federation_cddl =
        read(&root.join("protocol/cddl/membership-federation/v2/membership-federation-v2.cddl"))?;
    let mls_cddl = read(&root.join("protocol/cddl/mls-sequencer/v3/mls-sequencer-v3.cddl"))?;
    for (name, cddl) in [
        ("conversation-admission V1", &conversation_cddl),
        ("membership V2", &membership_cddl),
        ("membership-federation V2", &federation_cddl),
        ("MLS Sequencer V3", &mls_cddl),
    ] {
        cddl_cat::parse_cddl(cddl)
            .map_err(|error| ProtocolToolError::new(format!("parse {name} CDDL: {error}")))?;
    }
    for relative in [
        "protocol/openapi/membership/v2/openapi.yaml",
        "protocol/openapi/membership-federation/v2/openapi.yaml",
        "protocol/openapi/mls-sequencer/v3/openapi.yaml",
    ] {
        let source = read(&root.join(relative))?;
        let spec = oas3::from_yaml(&source)
            .map_err(|error| ProtocolToolError::new(format!("parse {relative}: {error}")))?;
        if spec.openapi != "3.1.0" {
            return Err(ProtocolToolError::new(format!(
                "{relative} must declare OpenAPI 3.1.0"
            )));
        }
    }

    let conversation = read_json(
        &root
            .join("protocol/test-vectors/conversation-admission/v1/conversation-admission-v1.json"),
    )?;
    require_v30_vector(&conversation, 1, "conversation-admission-v1")?;
    for (field, expected) in [
        ("outer_prefix_hex", "44545850413100"),
        ("hpke_info", "dirextalk.peer-admission-hpke.v1\0"),
        (
            "offer_signature_domain",
            "dirextalk.peer-admission-offer-signature.v1\0",
        ),
        (
            "welcome_signature_domain",
            "dirextalk.peer-admission-welcome-signature.v1\0",
        ),
    ] {
        if json_string(&conversation, field)? != expected {
            return Err(ProtocolToolError::new(format!(
                "conversation-admission-v1 {field} drift"
            )));
        }
    }
    validate_uuid_fields(&conversation, &["/envelope_id"])?;
    validate_cddl_hex(
        "peer-admission-hpke-aad-v1",
        &conversation_cddl,
        json_string(&conversation, "aad_canonical_cbor_hex")?,
    )?;
    let envelope = decode_hex(json_string(&conversation, "prefixed_envelope_hex")?)?;
    let prefix = decode_hex(json_string(&conversation, "outer_prefix_hex")?)?;
    if envelope.len() > 262_144 || !envelope.starts_with(&prefix) {
        return Err(ProtocolToolError::new(
            "conversation-admission-v1 envelope prefix/size drift",
        ));
    }
    cddl_cat::validate_cbor_bytes(
        "peer-admission-envelope-v1",
        &conversation_cddl,
        &envelope[prefix.len()..],
    )
    .map_err(|error| ProtocolToolError::new(format!("CDDL rejected V30 envelope: {error}")))?;
    validate_cddl_hex(
        "peer-admission-offer-v1",
        &conversation_cddl,
        json_string(&conversation, "offer_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "peer-admission-welcome-v1",
        &conversation_cddl,
        json_string(&conversation, "welcome_canonical_cbor_hex")?,
    )?;
    let owner_key =
        decode_lower_hex_fixed::<32>(json_string(&conversation, "owner_public_key_hex")?)?;
    verify_signed_map_vector(
        json_string(&conversation, "offer_canonical_cbor_hex")?,
        21,
        b"dirextalk.peer-admission-offer-signature.v1\0",
        owner_key,
        decode_lower_hex_fixed::<64>(json_string(&conversation, "offer_signature_hex")?)?,
    )?;
    verify_signed_map_vector(
        json_string(&conversation, "welcome_canonical_cbor_hex")?,
        20,
        b"dirextalk.peer-admission-welcome-signature.v1\0",
        owner_key,
        decode_lower_hex_fixed::<64>(json_string(&conversation, "welcome_signature_hex")?)?,
    )?;

    let membership =
        read_json(&root.join("protocol/test-vectors/membership/v2/membership-v2.json"))?;
    require_v30_vector(&membership, 2, "membership-v2")?;
    for (rule, field) in [
        (
            "join-request-signable-v2",
            "join_signable_canonical_cbor_hex",
        ),
        ("join-request-command-v2", "join_command_canonical_cbor_hex"),
        (
            "membership-command-digest-transcript-v2",
            "membership_command_digest_transcript_canonical_cbor_hex",
        ),
        ("pending-join-page-v2", "pending_page_canonical_cbor_hex"),
    ] {
        validate_cddl_hex(rule, &membership_cddl, json_string(&membership, field)?)?;
    }
    ensure_domain_digest(
        b"dirextalk.membership-command-request.v2\0",
        json_string(
            &membership,
            "membership_command_digest_transcript_canonical_cbor_hex",
        )?,
        json_string(&membership, "membership_command_digest_hex")?,
        "membership V2 request",
    )?;
    let _ = decode_lower_hex_fixed::<32>(json_string(
        &membership,
        "candidate_key_package_digest_hex",
    )?)?;

    let federation = read_json(
        &root.join("protocol/test-vectors/membership-federation/v2/membership-federation-v2.json"),
    )?;
    require_v30_vector(&federation, 2, "membership-federation-v2")?;
    validate_cddl_hex(
        "federated-device-action-binding-v2",
        &federation_cddl,
        json_string(&federation, "binding_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "federated-device-action-proof-v2",
        &federation_cddl,
        json_string(&federation, "proof_canonical_cbor_hex")?,
    )?;
    ensure_domain_digest(
        b"dirextalk.membership-action-binding.v2\0",
        json_string(&federation, "binding_canonical_cbor_hex")?,
        json_string(&federation, "binding_digest_hex")?,
        "federated membership V2 binding",
    )?;
    verify_domain_digest_signature(
        decode_lower_hex_fixed::<32>(json_string(&federation, "candidate_public_key_hex")?)?,
        b"dirextalk.membership-action-signature.v2\0",
        decode_lower_hex_fixed::<32>(json_string(&federation, "binding_digest_hex")?)?,
        decode_lower_hex_fixed::<64>(json_string(&federation, "signature_hex")?)?,
        "federated membership V2",
    )?;

    let mls =
        read_json(&root.join("protocol/test-vectors/mls-sequencer/v3/mls-sequencer-v3.json"))?;
    require_v30_vector(&mls, 3, "mls-sequencer-v3")?;
    for (rule, field) in [
        ("mls-commit-request-v3", "request_canonical_cbor_hex"),
        (
            "mls-request-digest-transcript-v3",
            "request_digest_transcript_canonical_cbor_hex",
        ),
        ("mls-commit-receipt-v3", "receipt_inner_canonical_cbor_hex"),
        (
            "signed-mls-commit-receipt-v3",
            "signed_receipt_canonical_cbor_hex",
        ),
        (
            "mls-device-join-confirmation-v3",
            "confirmation_canonical_cbor_hex",
        ),
        (
            "mls-confirmation-binding-v3",
            "confirmation_binding_canonical_cbor_hex",
        ),
        (
            "mls-confirmation-proof-v3",
            "confirmation_proof_canonical_cbor_hex",
        ),
    ] {
        validate_cddl_hex(rule, &mls_cddl, json_string(&mls, field)?)?;
    }
    for (domain, exact_field, digest_field, label) in [
        (
            b"dirextalk.mls-commit-request.v3\0".as_slice(),
            "request_digest_transcript_canonical_cbor_hex",
            "request_digest_hex",
            "MLS V3 request",
        ),
        (
            b"dirextalk.mls-commit-receipt.v3\0".as_slice(),
            "receipt_inner_canonical_cbor_hex",
            "receipt_digest_hex",
            "MLS V3 receipt",
        ),
        (
            b"dirextalk.mls-confirmation-body.v3\0".as_slice(),
            "confirmation_canonical_cbor_hex",
            "confirmation_body_digest_hex",
            "MLS V3 confirmation body",
        ),
        (
            b"dirextalk.mls-confirmation-binding.v3\0".as_slice(),
            "confirmation_binding_canonical_cbor_hex",
            "confirmation_binding_digest_hex",
            "MLS V3 confirmation binding",
        ),
    ] {
        ensure_domain_digest(
            domain,
            json_string(&mls, exact_field)?,
            json_string(&mls, digest_field)?,
            label,
        )?;
    }
    verify_domain_digest_signature(
        decode_lower_hex_fixed::<32>(json_string(&mls, "owner_public_key_hex")?)?,
        b"dirextalk.mls-commit-receipt-signature.v3\0",
        decode_lower_hex_fixed::<32>(json_string(&mls, "receipt_digest_hex")?)?,
        decode_lower_hex_fixed::<64>(json_string(&mls, "receipt_signature_hex")?)?,
        "MLS V3 receipt",
    )?;
    verify_domain_digest_signature(
        decode_lower_hex_fixed::<32>(json_string(&mls, "candidate_public_key_hex")?)?,
        b"dirextalk.mls-confirmation-proof-signature.v3\0",
        decode_lower_hex_fixed::<32>(json_string(&mls, "confirmation_binding_digest_hex")?)?,
        decode_lower_hex_fixed::<64>(json_string(&mls, "confirmation_proof_signature_hex")?)?,
        "MLS V3 confirmation proof",
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one frozen V32 audit keeps the removal request, receipt, signature, and feed linked"
)]
fn validate_mls_sequencer_v4(root: &Path) -> Result<(), ProtocolToolError> {
    const COMMIT_MEDIA_TYPE: &str = "application/vnd.dirextalk.mls-commit.v4+cbor";
    const RECEIPT_MEDIA_TYPE: &str = "application/vnd.dirextalk.mls-commit-receipt.v4+cbor";
    const FEED_MEDIA_TYPE: &str = "application/vnd.dirextalk.mls-commit-feed.v2+cbor";
    const REQUEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-request.v4\0";
    const COMMIT_DOMAIN: &[u8] = b"dirextalk.mls-opaque-commit.v1\0";
    const HEAD_DOMAIN: &[u8] = b"dirextalk.mls-sequencer-head.v1\0";
    const RECEIPT_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt.v4\0";
    const SIGNATURE_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt-signature.v4\0";

    let cddl_path = root.join("protocol/cddl/mls-sequencer/v4/mls-sequencer-v4.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse MLS Sequencer V4 CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;

    let openapi_path = root.join("protocol/openapi/mls-sequencer/v4/openapi.yaml");
    let openapi = read(&openapi_path)?;
    let spec = oas3::from_yaml(&openapi).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse MLS Sequencer V4 OpenAPI {}: {error}",
            openapi_path.display()
        ))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V4 OpenAPI must declare 3.1.0",
        ));
    }
    for required in [
        COMMIT_MEDIA_TYPE,
        RECEIPT_MEDIA_TYPE,
        FEED_MEDIA_TYPE,
        "Owner-only",
        "removed at epoch N may fetch through N",
    ] {
        if !openapi.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V4 OpenAPI is missing {required}"
            )));
        }
    }

    let vector =
        read_json(&root.join("protocol/test-vectors/mls-sequencer/v4/mls-sequencer-v4.json"))?;
    if vector.get("version").and_then(Value::as_u64) != Some(4)
        || vector.get("baseline").and_then(Value::as_u64) != Some(32)
    {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V4 vector version/baseline must be 4/32",
        ));
    }
    for (field, expected) in [
        ("commit_content_type", COMMIT_MEDIA_TYPE.as_bytes()),
        ("receipt_content_type", RECEIPT_MEDIA_TYPE.as_bytes()),
        ("feed_content_type", FEED_MEDIA_TYPE.as_bytes()),
        ("request_digest_domain", REQUEST_DOMAIN),
        ("commit_digest_domain", COMMIT_DOMAIN),
        ("head_digest_domain", HEAD_DOMAIN),
        ("receipt_digest_domain", RECEIPT_DOMAIN),
        ("receipt_signature_domain", SIGNATURE_DOMAIN),
    ] {
        if json_string(&vector, field)?.as_bytes() != expected {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V4 {field} drift"
            )));
        }
    }
    validate_uuid_fields(
        &vector,
        &[
            "/submission_id",
            "/conversation_id",
            "/owner_device_id",
            "/target_device_id",
        ],
    )?;
    validate_identity_id(
        json_string(&vector, "owner_identity_id")?,
        "MLS V4 Owner identity",
    )?;
    validate_identity_id(
        json_string(&vector, "target_identity_id")?,
        "MLS V4 target identity",
    )?;
    for (rule, field) in [
        ("mls-commit-request-v4", "request_canonical_cbor_hex"),
        (
            "mls-request-digest-transcript-v4",
            "request_digest_transcript_canonical_cbor_hex",
        ),
        ("mls-commit-receipt-v4", "receipt_inner_canonical_cbor_hex"),
        (
            "signed-mls-commit-receipt-v4",
            "signed_receipt_canonical_cbor_hex",
        ),
        ("mls-commit-feed-v2", "feed_canonical_cbor_hex"),
    ] {
        validate_cddl_hex(rule, &cddl, json_string(&vector, field)?)?;
    }
    for (domain, exact_field, digest_field, label) in [
        (
            REQUEST_DOMAIN,
            "request_digest_transcript_canonical_cbor_hex",
            "request_digest_hex",
            "MLS V4 request",
        ),
        (
            HEAD_DOMAIN,
            "head_digest_transcript_canonical_cbor_hex",
            "result_head_digest_hex",
            "MLS V4 head",
        ),
        (
            RECEIPT_DOMAIN,
            "receipt_inner_canonical_cbor_hex",
            "receipt_digest_hex",
            "MLS V4 receipt",
        ),
    ] {
        ensure_domain_digest(
            domain,
            json_string(&vector, exact_field)?,
            json_string(&vector, digest_field)?,
            label,
        )?;
    }
    let commit_bytes = decode_hex(json_string(&vector, "commit_bytes_hex")?)?;
    let mut commit_hasher = Sha256::new();
    commit_hasher.update(COMMIT_DOMAIN);
    commit_hasher.update(&commit_bytes);
    let commit_digest: [u8; 32] = commit_hasher.finalize().into();
    if lowercase_hex(&commit_digest) != json_string(&vector, "commit_digest_hex")? {
        return Err(ProtocolToolError::new("MLS V4 opaque commit digest drift"));
    }
    verify_domain_digest_signature(
        decode_lower_hex_fixed::<32>(json_string(&vector, "signing_public_key_hex")?)?,
        SIGNATURE_DOMAIN,
        decode_lower_hex_fixed::<32>(json_string(&vector, "receipt_digest_hex")?)?,
        decode_lower_hex_fixed::<64>(json_string(&vector, "receipt_signature_hex")?)?,
        "MLS V4 receipt",
    )?;

    let receipt = decode_deterministic_cbor(&decode_hex(json_string(
        &vector,
        "receipt_inner_canonical_cbor_hex",
    )?)?)
    .map_err(|error| ProtocolToolError::new(format!("decode MLS V4 receipt: {error}")))?;
    let receipt_digest = decode_lower_hex_fixed::<32>(json_string(&vector, "receipt_digest_hex")?)?;
    let signing_key =
        decode_lower_hex_fixed::<32>(json_string(&vector, "signing_public_key_hex")?)?;
    let signature = decode_lower_hex_fixed::<64>(json_string(&vector, "receipt_signature_hex")?)?;
    let expected_signed = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), receipt),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Bytes(receipt_digest.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(signing_key.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(signature.to_vec()),
        ),
    ]);
    let signed_bytes = decode_hex(json_string(&vector, "signed_receipt_canonical_cbor_hex")?)?;
    if decode_deterministic_cbor(&signed_bytes)
        .map_err(|error| ProtocolToolError::new(format!("decode MLS V4 signed receipt: {error}")))?
        != expected_signed
    {
        return Err(ProtocolToolError::new(
            "MLS V4 signed receipt linkage drift",
        ));
    }
    let parent_epoch = vector
        .get("parent_epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProtocolToolError::new("MLS V4 parent_epoch must be unsigned"))?;
    let expected_feed = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Unsigned(parent_epoch),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Array(vec![CanonicalValue::Array(vec![
                CanonicalValue::Bytes(signed_bytes),
                CanonicalValue::Bytes(commit_bytes),
            ])]),
        ),
    ]);
    if decode_deterministic_cbor(&decode_hex(json_string(
        &vector,
        "feed_canonical_cbor_hex",
    )?)?)
    .map_err(|error| ProtocolToolError::new(format!("decode MLS V4 feed: {error}")))?
        != expected_feed
    {
        return Err(ProtocolToolError::new("MLS V4 feed linkage drift"));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one frozen V31 audit keeps CDDL, OpenAPI, signed requests, and receipts coupled"
)]
fn validate_conversation_agent_grant_v1(root: &Path) -> Result<(), ProtocolToolError> {
    const REQUEST_MEDIA_TYPE: &str = "application/vnd.dirextalk.conversation-agent-grant.v1+cbor";
    const RECEIPT_MEDIA_TYPE: &str =
        "application/vnd.dirextalk.conversation-agent-grant-receipt.v1+cbor";
    const BINDING_DOMAIN: &[u8] = b"dirextalk.conversation-agent-grant-binding.v1\0";
    const SIGNATURE_DOMAIN: &[u8] = b"dirextalk.conversation-agent-grant-signature.v1\0";
    const REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.conversation-agent-grant-request.v1\0";
    const RECEIPT_DIGEST_DOMAIN: &[u8] = b"dirextalk.conversation-agent-grant-receipt.v1\0";

    let cddl = read(
        &root.join("protocol/cddl/conversation-agent-grant/v1/conversation-agent-grant-v1.cddl"),
    )?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse conversation agent grant V1 CDDL: {error}"))
    })?;

    let openapi_path = root.join("protocol/openapi/conversation-agent-grant/v1/openapi.yaml");
    let openapi = read(&openapi_path)?;
    let spec = oas3::from_yaml(&openapi).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse conversation agent grant V1 OpenAPI {}: {error}",
            openapi_path.display()
        ))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "conversation agent grant V1 OpenAPI must declare 3.1.0",
        ));
    }
    let openapi_value: Value = yaml_serde::from_str(&openapi).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse conversation agent grant V1 OpenAPI value: {error}"
        ))
    })?;
    for (pointer, expected) in [
        (
            "/paths/~1v1~1conversations~1{conversation_id}~1agent-grants~1{installation_id}/put/operationId",
            json!("grantPrivateConversationAgent"),
        ),
        (
            "/paths/~1v1~1conversations~1{conversation_id}~1agent-grants~1{installation_id}/delete/operationId",
            json!("revokePrivateConversationAgent"),
        ),
        (
            "/components/parameters/GrantFence/schema/pattern",
            json!("^\"g(?:0|[1-9][0-9]{0,15})\"$"),
        ),
        (
            "/components/responses/GrantReceiptCreated/headers/Cache-Control/schema/const",
            json!("no-store"),
        ),
        (
            "/components/responses/GrantReceiptReplay/headers/Cache-Control/schema/const",
            json!("no-store"),
        ),
    ] {
        expect_value(&openapi_value, pointer, &expected)?;
    }
    for pointer in [
        "/paths/~1v1~1conversations~1{conversation_id}~1agent-grants~1{installation_id}/put/requestBody/content/application~1vnd.dirextalk.conversation-agent-grant.v1+cbor/schema/$ref",
        "/paths/~1v1~1conversations~1{conversation_id}~1agent-grants~1{installation_id}/delete/requestBody/content/application~1vnd.dirextalk.conversation-agent-grant.v1+cbor/schema/$ref",
    ] {
        expect_value(
            &openapi_value,
            pointer,
            &json!("#/components/schemas/ExactCanonicalCbor"),
        )?;
    }

    let vector = read_json(&root.join(
        "protocol/test-vectors/conversation-agent-grant/v1/conversation-agent-grant-v1.json",
    ))?;
    validate_vector_version(&vector, "conversation-agent-grant-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(31) {
        return Err(ProtocolToolError::new(
            "conversation agent grant V1 vector baseline must be 31",
        ));
    }
    for (pointer, expected) in [
        ("/media_types/request", json!(REQUEST_MEDIA_TYPE)),
        ("/media_types/receipt", json!(RECEIPT_MEDIA_TYPE)),
        (
            "/binding_hash_domain",
            json!("dirextalk.conversation-agent-grant-binding.v1\0"),
        ),
        (
            "/signature_domain",
            json!("dirextalk.conversation-agent-grant-signature.v1\0"),
        ),
        (
            "/request_digest_domain",
            json!("dirextalk.conversation-agent-grant-request.v1\0"),
        ),
        (
            "/receipt_digest_domain",
            json!("dirextalk.conversation-agent-grant-receipt.v1\0"),
        ),
        ("/limits/maximum_proof_lifetime_ms", json!(600_000)),
        (
            "/limits/maximum_grant_lifetime_ms",
            json!(7_776_000_000_u64),
        ),
        ("/fixed_profile/code", json!(1)),
        ("/fixed_profile/trigger_policy", json!("mention_only")),
        (
            "/fixed_profile/permissions",
            json!(["read_future_messages", "send_messages"]),
        ),
        ("/grant/if_match", json!("\"g0\"")),
        ("/revoke/if_match", json!("\"g1\"")),
    ] {
        expect_value(&vector, pointer, &expected)?;
    }
    validate_uuid_fields(
        &vector,
        &[
            "/tenant_id",
            "/conversation_id",
            "/installation_id",
            "/server_generated_grant_id",
            "/owner_device_id",
            "/grant/operation_id",
            "/revoke/operation_id",
        ],
    )?;
    validate_identity_id(
        json_string(&vector, "owner_identity_id")?,
        "conversation agent grant owner identity",
    )?;
    let signing_key =
        decode_lower_hex_fixed::<32>(json_string(&vector, "device_signing_public_key_hex")?)?;

    for (name, binding_rule, action) in [
        ("grant", "conversation-agent-grant-put-binding-v1", 1_u64),
        (
            "revoke",
            "conversation-agent-grant-delete-binding-v1",
            2_u64,
        ),
    ] {
        let operation = vector.get(name).ok_or_else(|| {
            ProtocolToolError::new(format!(
                "conversation agent grant vector has no {name} operation"
            ))
        })?;
        validate_conversation_agent_grant_operation(
            &cddl,
            operation,
            name,
            binding_rule,
            action,
            signing_key,
            BINDING_DOMAIN,
            SIGNATURE_DOMAIN,
            REQUEST_DIGEST_DOMAIN,
            RECEIPT_DIGEST_DOMAIN,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // One frozen vector operation keeps all four transcripts coupled.
fn validate_conversation_agent_grant_operation(
    cddl: &str,
    operation: &Value,
    name: &str,
    binding_rule: &str,
    action: u64,
    signing_key: [u8; 32],
    binding_domain: &[u8],
    signature_domain: &[u8],
    request_digest_domain: &[u8],
    receipt_digest_domain: &[u8],
) -> Result<(), ProtocolToolError> {
    let binding_hex = json_string(operation, "binding_canonical_cbor_hex")?;
    validate_cddl_hex(binding_rule, cddl, binding_hex)?;
    ensure_domain_digest(
        binding_domain,
        binding_hex,
        json_string(operation, "binding_digest_hex")?,
        &format!("conversation agent grant {name} binding"),
    )?;
    let binding = decode_hex(binding_hex)?;
    let binding_value = decode_deterministic_cbor(&binding).map_err(|error| {
        ProtocolToolError::new(format!(
            "decode conversation agent grant {name} binding: {error}"
        ))
    })?;
    let CanonicalValue::Map(binding_fields) = &binding_value else {
        return Err(ProtocolToolError::new(format!(
            "conversation agent grant {name} binding must be a map"
        )));
    };
    let Some((CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(actual_action))) =
        binding_fields.get(1)
    else {
        return Err(ProtocolToolError::new(format!(
            "conversation agent grant {name} binding action is missing"
        )));
    };
    if *actual_action != action {
        return Err(ProtocolToolError::new(format!(
            "conversation agent grant {name} binding action drift"
        )));
    }

    let binding_digest =
        decode_lower_hex_fixed::<32>(json_string(operation, "binding_digest_hex")?)?;
    let owner_signature =
        decode_lower_hex_fixed::<64>(json_string(operation, "owner_signature_hex")?)?;
    verify_domain_digest_signature(
        signing_key,
        signature_domain,
        binding_digest,
        owner_signature,
        &format!("conversation agent grant {name}"),
    )?;

    let request_hex = json_string(operation, "request_canonical_cbor_hex")?;
    validate_cddl_hex("conversation-agent-grant-request-v1", cddl, request_hex)?;
    ensure_domain_digest(
        request_digest_domain,
        request_hex,
        json_string(operation, "request_digest_hex")?,
        &format!("conversation agent grant {name} request"),
    )?;
    let request = decode_deterministic_cbor(&decode_hex(request_hex)?).map_err(|error| {
        ProtocolToolError::new(format!(
            "decode conversation agent grant {name} request: {error}"
        ))
    })?;
    let CanonicalValue::Map(request_fields) = request else {
        return Err(ProtocolToolError::new(format!(
            "conversation agent grant {name} request must be a map"
        )));
    };
    let expected_request_fields = [
        (CanonicalValue::Unsigned(1), binding_value),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Bytes(binding_digest.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(owner_signature.to_vec()),
        ),
    ];
    if request_fields != expected_request_fields {
        return Err(ProtocolToolError::new(format!(
            "conversation agent grant {name} request/binding linkage drift"
        )));
    }

    let receipt_hex = json_string(operation, "receipt_canonical_cbor_hex")?;
    validate_cddl_hex("conversation-agent-grant-receipt-v1", cddl, receipt_hex)?;
    ensure_domain_digest(
        receipt_digest_domain,
        receipt_hex,
        json_string(operation, "receipt_digest_hex")?,
        &format!("conversation agent grant {name} receipt"),
    )
}

fn require_v30_vector(vector: &Value, version: u64, name: &str) -> Result<(), ProtocolToolError> {
    if vector.get("version").and_then(Value::as_u64) == Some(version)
        && vector.get("baseline").and_then(Value::as_u64) == Some(30)
    {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "{name} version/baseline must be {version}/30"
        )))
    }
}

fn ensure_domain_digest(
    domain: &[u8],
    exact_hex: &str,
    expected_hex: &str,
    label: &str,
) -> Result<(), ProtocolToolError> {
    let exact = decode_hex(exact_hex)?;
    decode_deterministic_cbor(&exact)
        .map_err(|error| ProtocolToolError::new(format!("decode {label}: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(exact);
    let actual: [u8; 32] = hasher.finalize().into();
    if lowercase_hex(&actual) == expected_hex {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!("{label} digest drift")))
    }
}

fn verify_domain_digest_signature(
    public_key: [u8; 32],
    domain: &[u8],
    digest: [u8; 32],
    signature: [u8; 64],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let mut input = Vec::with_capacity(domain.len() + digest.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&digest);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ProtocolToolError::new(format!("{label} public key invalid")))?
        .verify_strict(&input, &Signature::from_bytes(&signature))
        .map_err(|_| ProtocolToolError::new(format!("{label} signature invalid")))
}

fn verify_signed_map_vector(
    signed_hex: &str,
    signature_key: u64,
    domain: &[u8],
    public_key: [u8; 32],
    expected_signature: [u8; 64],
) -> Result<(), ProtocolToolError> {
    let exact = decode_hex(signed_hex)?;
    let value = decode_deterministic_cbor(&exact)
        .map_err(|error| ProtocolToolError::new(format!("decode signed V30 map: {error}")))?;
    let CanonicalValue::Map(mut fields) = value else {
        return Err(ProtocolToolError::new("signed V30 vector must be a map"));
    };
    let Some((CanonicalValue::Unsigned(key), CanonicalValue::Bytes(signature))) = fields.pop()
    else {
        return Err(ProtocolToolError::new(
            "signed V30 vector must end with a byte signature",
        ));
    };
    if key != signature_key || signature.as_slice() != expected_signature {
        return Err(ProtocolToolError::new("signed V30 vector signature drift"));
    }
    let unsigned = encode_deterministic_cbor(&CanonicalValue::Map(fields))
        .map_err(|_| ProtocolToolError::new("encode unsigned V30 vector"))?;
    let mut input = Vec::with_capacity(domain.len() + unsigned.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&unsigned);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ProtocolToolError::new("V30 owner public key invalid"))?
        .verify_strict(&input, &Signature::from_bytes(&expected_signature))
        .map_err(|_| ProtocolToolError::new("V30 owner signature invalid"))
}

fn validate_contact_delivery_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/contact-delivery/v1/contact-delivery-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse contact delivery V1 CDDL: {error}"))
    })?;

    let openapi = read(&root.join("protocol/openapi/contact-delivery/v1/openapi.yaml"))?;
    oas3::from_yaml(&openapi).map_err(|error| {
        ProtocolToolError::new(format!("parse contact delivery V1 OpenAPI: {error}"))
    })?;

    let vector = read_json(
        &root.join("protocol/test-vectors/contact-delivery/v1/contact-request-aad-v1.json"),
    )?;
    validate_vector_version(&vector, "contact-delivery-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(27) {
        return Err(ProtocolToolError::new(
            "contact delivery V1 vector baseline must be 27",
        ));
    }
    validate_uuid_fields(&vector, &["/request_id", "/invite_id", "/target_device_id"])?;

    let aad = decode_hex(json_string(&vector, "request_aad_cbor_hex")?)?;
    decode_deterministic_cbor(&aad).map_err(|error| {
        ProtocolToolError::new(format!("decode contact request AAD vector: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"dirextalk.contact-request-sealed-aad.v1\0");
    hasher.update(&aad);
    let actual = hasher.finalize();
    let expected = decode_hex(json_string(&vector, "request_aad_digest_hex")?)?;
    if actual.as_slice() != expected.as_slice() {
        return Err(ProtocolToolError::new(
            "contact request AAD vector digest does not match its canonical CBOR",
        ));
    }
    if decode_hex(json_string(&vector, "receipt_capability_hash_hex")?)?.len() != 32 {
        return Err(ProtocolToolError::new(
            "contact receipt capability hash vector must be 32 bytes",
        ));
    }
    Ok(())
}

fn validate_conditional_cache_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let source = read(&root.join("protocol/openapi/conditional-cache/v1/openapi.yaml"))?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!("parse conditional cache V1 OpenAPI: {error}"))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "conditional cache V1 OpenAPI must declare 3.1.0",
        ));
    }
    for required in ["If-None-Match", "'304'", "ETag", "must-revalidate"] {
        if !source.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "conditional cache V1 OpenAPI is missing {required}"
            )));
        }
    }
    let vector = read_json(&root.join("protocol/test-vectors/conditional-cache/v1/etag-v1.json"))?;
    validate_vector_version(&vector, "conditional-cache-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(26) {
        return Err(ProtocolToolError::new(
            "conditional cache V1 vector baseline must be 26",
        ));
    }
    let body = decode_hex(json_string(&vector, "body_hex")?)?;
    let digest: [u8; 32] = Sha256::digest(body).into();
    let advertised = json_string(&vector, "strong_etag")?
        .strip_prefix("\"dtx-")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| ProtocolToolError::new("conditional cache V1 ETag shape is invalid"))?;
    if decode_lower_hex_fixed::<32>(advertised)? != digest {
        return Err(ProtocolToolError::new(
            "conditional cache V1 strong ETag digest mismatch",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the versioned CDDL, OpenAPI, and vector audit atomic.
fn validate_public_search_pagination_v1(root: &Path) -> Result<(), ProtocolToolError> {
    const BINDING_DOMAIN: &[u8] = b"dirextalk.public-search-cursor.v1\0";
    let cddl = read(
        &root.join("protocol/cddl/public-search-pagination/v1/public-search-pagination-v1.cddl"),
    )?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!("parse public search pagination V1 CDDL: {error}"))
    })?;
    let source = read(&root.join("protocol/openapi/public-search-pagination/v1/openapi.yaml"))?;
    let spec = oas3::from_yaml(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse public search pagination V1 OpenAPI: {error}"
        ))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "public search pagination V1 OpenAPI must declare 3.1.0",
        ));
    }
    for required in [
        "X-DTX-Next-Cursor",
        "subject_id ascending",
        "maximum: 50",
        "maxLength: 512",
        "fail closed with 400",
        "credential-bearing reads use no-store",
    ] {
        if !source.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "public search pagination V1 OpenAPI is missing {required}"
            )));
        }
    }

    let vector = read_json(&root.join(
        "protocol/test-vectors/public-search-pagination/v1/public-search-pagination-v1.json",
    ))?;
    validate_vector_version(&vector, "public-search-pagination-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(33) {
        return Err(ProtocolToolError::new(
            "public search pagination V1 vector baseline must be 33",
        ));
    }
    validate_uuid_fields(&vector, &["/tenant_id", "/indexer_id"])?;
    if json_string(&vector, "cursor_binding_domain")? != "dirextalk.public-search-cursor.v1\0" {
        return Err(ProtocolToolError::new(
            "public search pagination V1 cursor binding domain drift",
        ));
    }
    validate_cddl_hex(
        "public-search-cursor-scope-v1",
        &cddl,
        json_string(&vector, "scope_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "public-search-cursor-v1",
        &cddl,
        json_string(&vector, "cursor_canonical_cbor_hex")?,
    )?;
    ensure_domain_digest(
        BINDING_DOMAIN,
        json_string(&vector, "scope_canonical_cbor_hex")?,
        json_string(&vector, "binding_digest_hex")?,
        "public search cursor scope",
    )?;
    let cursor = decode_hex(json_string(&vector, "cursor_canonical_cbor_hex")?)?;
    let encoded = json_string(&vector, "cursor_base64url")?;
    let decoded = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|_| ProtocolToolError::new("public search cursor is not unpadded base64url"))?;
    if decoded != cursor || Base64UrlUnpadded::encode_string(&decoded) != encoded {
        return Err(ProtocolToolError::new(
            "public search cursor base64url differs from canonical CBOR",
        ));
    }
    if vector.get("max_offset").and_then(Value::as_u64) != Some(10_000)
        || vector.get("default_limit").and_then(Value::as_u64) != Some(50)
        || vector.get("max_limit").and_then(Value::as_u64) != Some(50)
        || json_string(&vector, "next_cursor_header")? != "X-DTX-Next-Cursor"
    {
        return Err(ProtocolToolError::new(
            "public search pagination V1 bounds/header drift",
        ));
    }
    let stable_order = vector
        .get("stable_order")
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new("public search stable order vector missing"))?;
    let expected = [
        "exact_subject_desc",
        "ts_rank_desc",
        "similarity_desc",
        "subject_id_asc",
    ];
    if stable_order
        .iter()
        .map(Value::as_str)
        .ne(expected.into_iter().map(Some))
    {
        return Err(ProtocolToolError::new(
            "public search stable order vector drift",
        ));
    }
    Ok(())
}

fn validate_indexer_v1(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read(&root.join("protocol/cddl/indexer/v1/indexer-v1.cddl"))?;
    cddl_cat::parse_cddl(&cddl)
        .map_err(|error| ProtocolToolError::new(format!("parse Indexer V1 CDDL: {error}")))?;
    let source = read(&root.join("protocol/openapi/indexer/v1/openapi.yaml"))?;
    let spec = oas3::from_yaml(&source)
        .map_err(|error| ProtocolToolError::new(format!("parse Indexer V1 OpenAPI: {error}")))?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "Indexer V1 OpenAPI must declare 3.1.0",
        ));
    }
    let vector = read_json(&root.join("protocol/test-vectors/indexer/v1/indexer-v1.json"))?;
    validate_vector_version(&vector, "indexer-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(25) {
        return Err(ProtocolToolError::new(
            "Indexer V1 vector baseline must be 25",
        ));
    }
    validate_uuid_fields(&vector, &["/registration_id", "/indexer_id"])?;
    validate_cddl_hex(
        "index-registration-request-v1",
        &cddl,
        json_string(&vector, "registration_request_cbor_hex")?,
    )?;
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
    validate_private_agent_approval_v6_v7(root)?;
    validate_mls_sequencer_v1(root)?;
    validate_mls_sequencer_v2(root)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateAgentApprovalShape {
    Request {
        version: u64,
        runtime: u64,
        action: u64,
    },
    Decision {
        version: u64,
        decision: u64,
    },
}

#[allow(clippy::too_many_lines)] // The V34 gate keeps every frozen JSON ordinal and vector family together.
fn validate_private_agent_approval_v6_v7(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl_path =
        root.join("protocol/cddl/private-event/v6_v7/private-agent-approval-v6-v7.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse private Agent approval V6/V7 CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;

    let vector = read_json(
        &root.join("protocol/test-vectors/private-event/v6_v7/private-agent-approval-v6-v7.json"),
    )?;
    require_exact_object_keys(
        &vector,
        &[
            "baseline",
            "wire_versions",
            "ordinals",
            "max_canonical_cbor_bytes",
            "max_request_ttl_ms",
            "max_title_unicode_scalars",
            "max_detail_utf8_bytes",
            "events",
            "invalid_events",
        ],
        "private Agent approval V6/V7 vector",
    )?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(PRIVATE_AGENT_APPROVAL_BASELINE)
        || vector
            .get("max_canonical_cbor_bytes")
            .and_then(Value::as_u64)
            != Some(PRIVATE_EVENT_MAX_ENCODED_BYTES as u64)
        || vector.get("max_request_ttl_ms").and_then(Value::as_i64)
            != Some(PRIVATE_AGENT_APPROVAL_MAX_REQUEST_TTL_MS)
        || vector
            .get("max_title_unicode_scalars")
            .and_then(Value::as_u64)
            != Some(PRIVATE_AGENT_APPROVAL_MAX_TITLE_SCALARS as u64)
        || vector.get("max_detail_utf8_bytes").and_then(Value::as_u64)
            != Some(PRIVATE_AGENT_APPROVAL_MAX_DETAIL_BYTES as u64)
    {
        return Err(ProtocolToolError::new(
            "private Agent approval V6/V7 baseline or bounds drifted",
        ));
    }

    require_exact_u64_object(
        vector.get("wire_versions").ok_or_else(|| {
            ProtocolToolError::new("private Agent approval wire_versions are missing")
        })?,
        &[("existing_approval", 6), ("hermes_request", 7)],
        "private Agent approval wire_versions",
    )?;
    let ordinals = vector
        .get("ordinals")
        .ok_or_else(|| ProtocolToolError::new("private Agent approval ordinals are missing"))?;
    require_exact_object_keys(
        ordinals,
        &[
            "event_kinds",
            "runtimes",
            "payload_kinds",
            "action_kinds",
            "decisions",
        ],
        "private Agent approval ordinals",
    )?;
    require_exact_u64_object(
        ordinals.get("event_kinds").ok_or_else(|| {
            ProtocolToolError::new("private Agent approval event kind ordinals are missing")
        })?,
        &[("request", 6), ("decision", 7)],
        "private Agent approval event kind ordinals",
    )?;
    require_exact_u64_object(
        ordinals.get("runtimes").ok_or_else(|| {
            ProtocolToolError::new("private Agent approval runtime ordinals are missing")
        })?,
        &[("codex", 1), ("openclaw", 2), ("hermes", 3)],
        "private Agent approval runtime ordinals",
    )?;
    require_exact_u64_object(
        ordinals.get("payload_kinds").ok_or_else(|| {
            ProtocolToolError::new("private Agent approval payload ordinals are missing")
        })?,
        &[("request", 1), ("decision", 2)],
        "private Agent approval payload ordinals",
    )?;
    require_exact_u64_object(
        ordinals.get("action_kinds").ok_or_else(|| {
            ProtocolToolError::new("private Agent approval action ordinals are missing")
        })?,
        &[
            ("command", 1),
            ("file_change", 2),
            ("mcp_tool_call", 3),
            ("other", 4),
        ],
        "private Agent approval action ordinals",
    )?;
    require_exact_u64_object(
        ordinals.get("decisions").ok_or_else(|| {
            ProtocolToolError::new("private Agent approval decision ordinals are missing")
        })?,
        &[("allow_once", 1), ("deny", 2)],
        "private Agent approval decision ordinals",
    )?;

    let events = vector
        .get("events")
        .and_then(Value::as_array)
        .filter(|events| events.len() == 4)
        .ok_or_else(|| {
            ProtocolToolError::new(
                "private Agent approval V6/V7 vector must contain exactly four valid events",
            )
        })?;
    let mut labels = BTreeSet::new();
    for event in events {
        let label = json_string(event, "label")?;
        if !labels.insert(label) {
            return Err(ProtocolToolError::new(
                "private Agent approval valid event labels must be unique",
            ));
        }
        validate_private_agent_approval_vector_entry(event, &cddl)?;
    }
    if labels
        != BTreeSet::from([
            "v6_codex_command",
            "v6_openclaw_file_change",
            "v6_allow_once_decision_for_hermes",
            "v7_hermes_other",
        ])
    {
        return Err(ProtocolToolError::new(
            "private Agent approval valid event labels drifted",
        ));
    }
    validate_private_agent_approval_hermes_decision_linkage(events)?;

    let invalid_events = vector
        .get("invalid_events")
        .and_then(Value::as_array)
        .filter(|events| events.len() == 4)
        .ok_or_else(|| {
            ProtocolToolError::new(
                "private Agent approval V6/V7 vector must contain exactly four invalid relabelings",
            )
        })?;
    let mut invalid_labels = BTreeSet::new();
    for event in invalid_events {
        require_exact_object_keys(
            event,
            &["label", "canonical_cbor_hex"],
            "private Agent approval invalid event",
        )?;
        let label = json_string(event, "label")?;
        if !invalid_labels.insert(label) {
            return Err(ProtocolToolError::new(
                "private Agent approval invalid event labels must be unique",
            ));
        }
        validate_private_agent_approval_invalid_event(event, &cddl)?;
    }
    if invalid_labels
        != BTreeSet::from([
            "v6_hermes_request",
            "v7_codex_request",
            "v7_openclaw_request",
            "v7_decision",
        ])
    {
        return Err(ProtocolToolError::new(
            "private Agent approval invalid event labels drifted",
        ));
    }
    Ok(())
}

fn require_exact_u64_object(
    value: &Value,
    expected: &[(&str, u64)],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let expected_keys = expected.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    require_exact_object_keys(value, &expected_keys, label)?;
    if expected.iter().all(|(key, expected_value)| {
        value.get(*key).and_then(Value::as_u64) == Some(*expected_value)
    }) {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "{label} values do not match the frozen contract"
        )))
    }
}

fn validate_private_agent_approval_hermes_decision_linkage(
    events: &[Value],
) -> Result<(), ProtocolToolError> {
    let request = events
        .iter()
        .find(|event| event.get("label").and_then(Value::as_str) == Some("v7_hermes_other"))
        .ok_or_else(|| {
            ProtocolToolError::new("private Agent approval Hermes request is missing")
        })?;
    let decision = events
        .iter()
        .find(|event| {
            event.get("label").and_then(Value::as_str) == Some("v6_allow_once_decision_for_hermes")
        })
        .ok_or_else(|| {
            ProtocolToolError::new("private Agent approval Hermes decision is missing")
        })?;
    for field in ["conversation_id", "run_id"] {
        if json_string(decision, field)? != json_string(request, field)? {
            return Err(ProtocolToolError::new(format!(
                "private Agent approval Hermes decision {field} must match its request"
            )));
        }
    }
    if json_string(decision, "parent_event_id")? != json_string(request, "event_id")? {
        return Err(ProtocolToolError::new(
            "private Agent approval Hermes decision must parent its V7 request",
        ));
    }
    let request_payload = request.get("payload").ok_or_else(|| {
        ProtocolToolError::new("private Agent approval Hermes payload is missing")
    })?;
    let decision_payload = decision.get("payload").ok_or_else(|| {
        ProtocolToolError::new("private Agent approval Hermes decision payload is missing")
    })?;
    if json_string(decision_payload, "request_digest_hex")?
        != json_string(request_payload, "request_digest_hex")?
    {
        return Err(ProtocolToolError::new(
            "private Agent approval Hermes decision digest must match its request",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // JSON semantics and the exact eleven-field CBOR are one vector boundary.
fn validate_private_agent_approval_vector_entry(
    event: &Value,
    cddl: &str,
) -> Result<(), ProtocolToolError> {
    require_exact_object_keys(
        event,
        &[
            "label",
            "version",
            "event_id",
            "conversation_id",
            "author_identity_id",
            "author_device_id",
            "created_at_ms",
            "kind",
            "parent_event_id",
            "run_id",
            "payload",
            "canonical_cbor_hex",
        ],
        "private Agent approval valid event",
    )?;
    let label = json_string(event, "label")?;
    let version = private_agent_approval_json_u64(event, "version", label)?;
    if !matches!(version, 6 | 7) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} version must be 6 or 7"
        )));
    }
    let event_id = json_string(event, "event_id")?;
    let conversation_id = json_string(event, "conversation_id")?;
    let author_identity_id = json_string(event, "author_identity_id")?;
    let author_device_id = json_string(event, "author_device_id")?;
    let parent_event_id = json_string(event, "parent_event_id")?;
    let run_id = json_string(event, "run_id")?;
    for (value, field) in [
        (event_id, "event_id"),
        (conversation_id, "conversation_id"),
        (author_device_id, "author_device_id"),
        (parent_event_id, "parent_event_id"),
        (run_id, "run_id"),
    ] {
        validate_uuid_v7(value).map_err(|error| {
            ProtocolToolError::new(format!(
                "private Agent approval {label} {field} is invalid: {error}"
            ))
        })?;
    }
    if parent_event_id == event_id {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} parent cannot equal event_id"
        )));
    }
    validate_identity_id(
        author_identity_id,
        &format!("private Agent approval {label} author_identity_id"),
    )?;
    let created_at_ms = json_i64(event, "created_at_ms")?;
    let created_at = UtcMillis::new(created_at_ms).map_err(|_| {
        ProtocolToolError::new(format!(
            "private Agent approval {label} created_at_ms must be valid UTC milliseconds"
        ))
    })?;
    let kind = private_agent_approval_json_u64(event, "kind", label)?;
    if !matches!(kind, 6 | 7) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} kind must be request=6 or decision=7"
        )));
    }
    let payload = event.get("payload").ok_or_else(|| {
        ProtocolToolError::new(format!("private Agent approval {label} payload is missing"))
    })?;
    let (payload, shape) =
        build_private_agent_approval_payload(payload, version, kind, created_at_ms, label)?;
    if !private_agent_approval_shape_is_allowed(shape) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} version/runtime combination is forbidden"
        )));
    }
    if private_agent_approval_expected_valid_shape(label) != Some(shape) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} no longer proves its frozen ordinal combination"
        )));
    }

    let canonical = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(version),
        ),
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
            CanonicalValue::Array(vec![CanonicalValue::Text(parent_event_id.to_owned())]),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(String::new()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(run_id.to_owned()),
        ),
        (CanonicalValue::Unsigned(11), payload),
    ]);
    let rebuilt = encode_deterministic_cbor(&canonical).map_err(|error| {
        ProtocolToolError::new(format!(
            "encode private Agent approval {label} canonical CBOR: {error}"
        ))
    })?;
    if rebuilt.len() > PRIVATE_EVENT_MAX_ENCODED_BYTES {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} exceeds 66383 canonical CBOR bytes"
        )));
    }
    let golden = decode_hex(json_string(event, "canonical_cbor_hex")?)?;
    if rebuilt != golden {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} canonical CBOR drift: actual {}",
            lowercase_hex(&rebuilt)
        )));
    }
    let decoded = decode_strict_private_agent_approval_cbor(&golden, label)?;
    if decoded != canonical || validate_relaxed_private_agent_approval_event(&decoded)? != shape {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} canonical field linkage drifted"
        )));
    }
    cddl_cat::validate_cbor_bytes("private-agent-approval-event-v6-v7", cddl, &golden).map_err(
        |error| {
            ProtocolToolError::new(format!(
                "private Agent approval {label} CDDL union rejected: {error}"
            ))
        },
    )
}

fn private_agent_approval_json_u64(
    value: &Value,
    key: &str,
    label: &str,
) -> Result<u64, ProtocolToolError> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| {
        ProtocolToolError::new(format!(
            "private Agent approval {label} {key} must be an unsigned integer"
        ))
    })
}

fn build_private_agent_approval_payload(
    payload: &Value,
    version: u64,
    kind: u64,
    created_at_ms: i64,
    label: &str,
) -> Result<(CanonicalValue, PrivateAgentApprovalShape), ProtocolToolError> {
    match kind {
        6 => build_private_agent_approval_request_payload(payload, version, created_at_ms, label),
        7 => build_private_agent_approval_decision_payload(payload, version, label),
        _ => Err(ProtocolToolError::new(
            "private Agent approval event kind must be 6 or 7",
        )),
    }
}

fn build_private_agent_approval_request_payload(
    payload: &Value,
    version: u64,
    created_at_ms: i64,
    label: &str,
) -> Result<(CanonicalValue, PrivateAgentApprovalShape), ProtocolToolError> {
    require_exact_object_keys(
        payload,
        &[
            "payload_kind",
            "runtime",
            "action_kind",
            "title_utf8_hex",
            "detail_utf8_hex",
            "request_digest_hex",
            "expires_at_ms",
        ],
        &format!("private Agent approval {label} request payload"),
    )?;
    if private_agent_approval_json_u64(payload, "payload_kind", label)? != 1 {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} request payload kind must be 1"
        )));
    }
    let runtime = private_agent_approval_json_u64(payload, "runtime", label)?;
    if !(1..=3).contains(&runtime) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} runtime must be 1, 2, or 3"
        )));
    }
    let action = private_agent_approval_json_u64(payload, "action_kind", label)?;
    if !(1..=4).contains(&action) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} action kind must be 1 through 4"
        )));
    }
    let title = decode_private_agent_approval_utf8_hex(payload, "title_utf8_hex", label)?;
    validate_private_agent_approval_title(&title)?;
    let detail = decode_private_agent_approval_utf8_hex(payload, "detail_utf8_hex", label)?;
    validate_private_agent_approval_detail(&detail)?;
    let digest = decode_lower_hex_fixed::<32>(json_string(payload, "request_digest_hex")?)?;
    validate_private_agent_approval_digest(&digest)?;
    let expires_at_ms = json_i64(payload, "expires_at_ms")?;
    let expires_at = UtcMillis::new(expires_at_ms).map_err(|_| {
        ProtocolToolError::new(format!(
            "private Agent approval {label} expires_at_ms must be valid UTC milliseconds"
        ))
    })?;
    validate_private_agent_approval_ttl(created_at_ms, expires_at_ms)?;
    Ok((
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(runtime),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Unsigned(action),
            ),
            (CanonicalValue::Unsigned(4), CanonicalValue::Text(title)),
            (CanonicalValue::Unsigned(5), CanonicalValue::Text(detail)),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Bytes(digest.to_vec()),
            ),
            (CanonicalValue::Unsigned(7), expires_at.to_canonical_value()),
        ]),
        PrivateAgentApprovalShape::Request {
            version,
            runtime,
            action,
        },
    ))
}

fn build_private_agent_approval_decision_payload(
    payload: &Value,
    version: u64,
    label: &str,
) -> Result<(CanonicalValue, PrivateAgentApprovalShape), ProtocolToolError> {
    require_exact_object_keys(
        payload,
        &["payload_kind", "request_digest_hex", "decision"],
        &format!("private Agent approval {label} decision payload"),
    )?;
    if private_agent_approval_json_u64(payload, "payload_kind", label)? != 2 {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} decision payload kind must be 2"
        )));
    }
    let digest = decode_lower_hex_fixed::<32>(json_string(payload, "request_digest_hex")?)?;
    validate_private_agent_approval_digest(&digest)?;
    let decision = private_agent_approval_json_u64(payload, "decision", label)?;
    if !(1..=2).contains(&decision) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} decision must be 1 or 2"
        )));
    }
    Ok((
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(digest.to_vec()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Unsigned(decision),
            ),
        ]),
        PrivateAgentApprovalShape::Decision { version, decision },
    ))
}

fn decode_private_agent_approval_utf8_hex(
    value: &Value,
    field: &str,
    label: &str,
) -> Result<String, ProtocolToolError> {
    String::from_utf8(decode_hex(json_string(value, field)?)?).map_err(|_| {
        ProtocolToolError::new(format!(
            "private Agent approval {label} {field} must contain valid UTF-8"
        ))
    })
}

fn private_agent_approval_expected_valid_shape(label: &str) -> Option<PrivateAgentApprovalShape> {
    match label {
        "v6_codex_command" => Some(PrivateAgentApprovalShape::Request {
            version: 6,
            runtime: 1,
            action: 1,
        }),
        "v6_openclaw_file_change" => Some(PrivateAgentApprovalShape::Request {
            version: 6,
            runtime: 2,
            action: 2,
        }),
        "v6_allow_once_decision_for_hermes" => Some(PrivateAgentApprovalShape::Decision {
            version: 6,
            decision: 1,
        }),
        "v7_hermes_other" => Some(PrivateAgentApprovalShape::Request {
            version: 7,
            runtime: 3,
            action: 4,
        }),
        _ => None,
    }
}

const fn private_agent_approval_shape_is_allowed(shape: PrivateAgentApprovalShape) -> bool {
    matches!(
        shape,
        PrivateAgentApprovalShape::Request {
            version: 6,
            runtime: 1 | 2,
            ..
        } | PrivateAgentApprovalShape::Request {
            version: 7,
            runtime: 3,
            ..
        } | PrivateAgentApprovalShape::Decision { version: 6, .. }
    )
}

fn validate_private_agent_approval_invalid_event(
    event: &Value,
    cddl: &str,
) -> Result<(), ProtocolToolError> {
    let label = json_string(event, "label")?;
    let bytes = decode_hex(json_string(event, "canonical_cbor_hex")?)?;
    let decoded = decode_strict_private_agent_approval_cbor(&bytes, label)?;
    let shape = validate_relaxed_private_agent_approval_event(&decoded)?;
    if private_agent_approval_shape_is_allowed(shape) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval invalid vector {label} is an allowed version combination"
        )));
    }
    if private_agent_approval_expected_invalid_shape(label) != Some(shape) {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval invalid vector {label} is not its exact forbidden relabeling"
        )));
    }
    if cddl_cat::validate_cbor_bytes("private-agent-approval-event-v6-v7", cddl, &bytes).is_ok() {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval CDDL union accepted forbidden relabeling {label}"
        )));
    }
    Ok(())
}

fn private_agent_approval_expected_invalid_shape(label: &str) -> Option<PrivateAgentApprovalShape> {
    match label {
        "v6_hermes_request" => Some(PrivateAgentApprovalShape::Request {
            version: 6,
            runtime: 3,
            action: 1,
        }),
        "v7_codex_request" => Some(PrivateAgentApprovalShape::Request {
            version: 7,
            runtime: 1,
            action: 1,
        }),
        "v7_openclaw_request" => Some(PrivateAgentApprovalShape::Request {
            version: 7,
            runtime: 2,
            action: 1,
        }),
        "v7_decision" => Some(PrivateAgentApprovalShape::Decision {
            version: 7,
            decision: 1,
        }),
        _ => None,
    }
}

fn decode_strict_private_agent_approval_cbor(
    bytes: &[u8],
    label: &str,
) -> Result<CanonicalValue, ProtocolToolError> {
    if bytes.len() > PRIVATE_EVENT_MAX_ENCODED_BYTES {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} exceeds 66383 canonical CBOR bytes"
        )));
    }
    let decoded = decode_deterministic_cbor(bytes).map_err(|error| {
        ProtocolToolError::new(format!(
            "private Agent approval {label} is not strict canonical CBOR: {error}"
        ))
    })?;
    let reencoded = encode_deterministic_cbor(&decoded).map_err(|error| {
        ProtocolToolError::new(format!("re-encode private Agent approval {label}: {error}"))
    })?;
    if reencoded != bytes {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval {label} changed under canonical re-encoding"
        )));
    }
    Ok(decoded)
}

#[allow(clippy::too_many_lines)] // The relaxed decoder proves forbidden vectors differ only by version/runtime pairing.
fn validate_relaxed_private_agent_approval_event(
    value: &CanonicalValue,
) -> Result<PrivateAgentApprovalShape, ProtocolToolError> {
    let fields = private_agent_approval_map_fields(value, 11, "event")?;
    let version = private_agent_approval_unsigned(fields[0], "event version")?;
    if !matches!(version, 6 | 7) {
        return Err(ProtocolToolError::new(
            "private Agent approval event version must be 6 or 7",
        ));
    }
    let event_id = private_agent_approval_text(fields[1], "event_id")?;
    let conversation_id = private_agent_approval_text(fields[2], "conversation_id")?;
    let author_identity_id = private_agent_approval_text(fields[3], "author_identity_id")?;
    let author_device_id = private_agent_approval_text(fields[4], "author_device_id")?;
    for (value, field) in [
        (event_id, "event_id"),
        (conversation_id, "conversation_id"),
        (author_device_id, "author_device_id"),
    ] {
        validate_uuid_v7(value).map_err(|error| {
            ProtocolToolError::new(format!(
                "private Agent approval decoded {field} is invalid: {error}"
            ))
        })?;
    }
    validate_identity_id(
        author_identity_id,
        "private Agent approval decoded author_identity_id",
    )?;
    let created_at_ms = private_agent_approval_utc(fields[5], "created_at_ms")?.get();
    let kind = private_agent_approval_unsigned(fields[6], "event kind")?;
    if !matches!(kind, 6 | 7) {
        return Err(ProtocolToolError::new(
            "private Agent approval decoded kind must be 6 or 7",
        ));
    }
    let CanonicalValue::Array(parents) = fields[7] else {
        return Err(ProtocolToolError::new(
            "private Agent approval decoded parents must be an array",
        ));
    };
    if parents.len() != 1 {
        return Err(ProtocolToolError::new(
            "private Agent approval decoded event must have exactly one parent",
        ));
    }
    let parent = private_agent_approval_text(&parents[0], "parent_event_id")?;
    validate_uuid_v7(parent)?;
    if parent == event_id {
        return Err(ProtocolToolError::new(
            "private Agent approval decoded parent cannot equal event_id",
        ));
    }
    if fields[8] != &CanonicalValue::Text(String::new()) {
        return Err(ProtocolToolError::new(
            "private Agent approval decoded body must be empty text",
        ));
    }
    let run_id = private_agent_approval_text(fields[9], "run_id")?;
    validate_uuid_v7(run_id)?;

    match kind {
        6 => {
            let payload = private_agent_approval_map_fields(fields[10], 7, "request payload")?;
            if private_agent_approval_unsigned(payload[0], "request payload kind")? != 1 {
                return Err(ProtocolToolError::new(
                    "private Agent approval decoded request payload kind must be 1",
                ));
            }
            let runtime = private_agent_approval_unsigned(payload[1], "runtime")?;
            if !(1..=3).contains(&runtime) {
                return Err(ProtocolToolError::new(
                    "private Agent approval decoded runtime must be 1, 2, or 3",
                ));
            }
            let action = private_agent_approval_unsigned(payload[2], "action kind")?;
            if !(1..=4).contains(&action) {
                return Err(ProtocolToolError::new(
                    "private Agent approval decoded action kind must be 1 through 4",
                ));
            }
            validate_private_agent_approval_title(private_agent_approval_text(
                payload[3],
                "request title",
            )?)?;
            validate_private_agent_approval_detail(private_agent_approval_text(
                payload[4],
                "request detail",
            )?)?;
            validate_private_agent_approval_digest(private_agent_approval_bytes(
                payload[5],
                "request digest",
            )?)?;
            let expires_at_ms = private_agent_approval_utc(payload[6], "expires_at_ms")?.get();
            validate_private_agent_approval_ttl(created_at_ms, expires_at_ms)?;
            Ok(PrivateAgentApprovalShape::Request {
                version,
                runtime,
                action,
            })
        }
        7 => {
            let payload = private_agent_approval_map_fields(fields[10], 3, "decision payload")?;
            if private_agent_approval_unsigned(payload[0], "decision payload kind")? != 2 {
                return Err(ProtocolToolError::new(
                    "private Agent approval decoded decision payload kind must be 2",
                ));
            }
            validate_private_agent_approval_digest(private_agent_approval_bytes(
                payload[1],
                "request digest",
            )?)?;
            let decision = private_agent_approval_unsigned(payload[2], "decision")?;
            if !(1..=2).contains(&decision) {
                return Err(ProtocolToolError::new(
                    "private Agent approval decoded decision must be 1 or 2",
                ));
            }
            Ok(PrivateAgentApprovalShape::Decision { version, decision })
        }
        _ => unreachable!("approval kind was constrained above"),
    }
}

fn private_agent_approval_map_fields<'a>(
    value: &'a CanonicalValue,
    expected_len: usize,
    label: &str,
) -> Result<Vec<&'a CanonicalValue>, ProtocolToolError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval decoded {label} must be a map"
        )));
    };
    if entries.len() != expected_len {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval decoded {label} field set drifted"
        )));
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, (key, value))| {
            let expected = u64::try_from(index + 1).expect("approval field count is bounded");
            if key == &CanonicalValue::Unsigned(expected) {
                Ok(value)
            } else {
                Err(ProtocolToolError::new(format!(
                    "private Agent approval decoded {label} has an unknown or missing field"
                )))
            }
        })
        .collect()
}

fn private_agent_approval_unsigned(
    value: &CanonicalValue,
    label: &str,
) -> Result<u64, ProtocolToolError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval decoded {label} must be unsigned"
        )));
    };
    Ok(*value)
}

fn private_agent_approval_text<'a>(
    value: &'a CanonicalValue,
    label: &str,
) -> Result<&'a str, ProtocolToolError> {
    let CanonicalValue::Text(value) = value else {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval decoded {label} must be text"
        )));
    };
    Ok(value)
}

fn private_agent_approval_bytes<'a>(
    value: &'a CanonicalValue,
    label: &str,
) -> Result<&'a [u8], ProtocolToolError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(ProtocolToolError::new(format!(
            "private Agent approval decoded {label} must be bytes"
        )));
    };
    Ok(value)
}

fn private_agent_approval_utc(
    value: &CanonicalValue,
    label: &str,
) -> Result<UtcMillis, ProtocolToolError> {
    let raw = match value {
        CanonicalValue::Unsigned(value) => i64::try_from(*value).map_err(|_| {
            ProtocolToolError::new(format!(
                "private Agent approval decoded {label} exceeds i64"
            ))
        })?,
        CanonicalValue::Negative(value) => *value,
        _ => {
            return Err(ProtocolToolError::new(format!(
                "private Agent approval decoded {label} must be an integer"
            )));
        }
    };
    UtcMillis::new(raw).map_err(|_| {
        ProtocolToolError::new(format!(
            "private Agent approval decoded {label} must be valid UTC milliseconds"
        ))
    })
}

fn validate_private_agent_approval_title(value: &str) -> Result<(), ProtocolToolError> {
    let scalar_count = value.chars().count();
    if !(1..=PRIVATE_AGENT_APPROVAL_MAX_TITLE_SCALARS).contains(&scalar_count)
        || value
            .chars()
            .any(|character| character.is_control() || is_bidi_control(character))
    {
        return Err(ProtocolToolError::new(
            "private Agent approval title must contain 1..120 safe Unicode scalars",
        ));
    }
    Ok(())
}

fn validate_private_agent_approval_detail(value: &str) -> Result<(), ProtocolToolError> {
    if value.len() > PRIVATE_AGENT_APPROVAL_MAX_DETAIL_BYTES
        || value.chars().any(|character| {
            (character.is_control() && !matches!(character, '\n' | '\t'))
                || is_bidi_control(character)
        })
    {
        return Err(ProtocolToolError::new(
            "private Agent approval detail must be at most 4096 safe UTF-8 bytes",
        ));
    }
    Ok(())
}

const fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn validate_private_agent_approval_digest(value: &[u8]) -> Result<(), ProtocolToolError> {
    if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
        return Err(ProtocolToolError::new(
            "private Agent approval request digest must be 32 nonzero bytes",
        ));
    }
    Ok(())
}

fn validate_private_agent_approval_ttl(
    created_at_ms: i64,
    expires_at_ms: i64,
) -> Result<(), ProtocolToolError> {
    let ttl = expires_at_ms
        .checked_sub(created_at_ms)
        .ok_or_else(|| ProtocolToolError::new("private Agent approval request TTL overflowed"))?;
    if (1..=PRIVATE_AGENT_APPROVAL_MAX_REQUEST_TTL_MS).contains(&ttl) {
        Ok(())
    } else {
        Err(ProtocolToolError::new(
            "private Agent approval request TTL must be 1..=300000 milliseconds",
        ))
    }
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

fn validate_group_membership_discovery_v1(root: &Path) -> Result<(), ProtocolToolError> {
    const BINDING_DOMAIN: &[u8] = b"dirextalk.group-query-binding.v1\0";
    const SIGNATURE_DOMAIN: &[u8] = b"dirextalk.group-query-signature.v1\0";

    let cddl_path =
        root.join("protocol/cddl/group-membership-discovery/v1/group-membership-discovery-v1.cddl");
    let cddl = read(&cddl_path)?;
    cddl_cat::parse_cddl(&cddl).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse group-membership-discovery V1 CDDL {}: {error}",
            cddl_path.display()
        ))
    })?;
    let vector = read_json(
        &root.join("protocol/test-vectors/group-membership-discovery/v1/group-query-v1.json"),
    )?;
    validate_vector_version(&vector, "group-membership-discovery-v1")?;
    if vector.get("baseline").and_then(Value::as_u64) != Some(29)
        || json_string(&vector, "binding_hash_domain")? != "dirextalk.group-query-binding.v1\0"
        || json_string(&vector, "signature_domain")? != "dirextalk.group-query-signature.v1\0"
    {
        return Err(ProtocolToolError::new(
            "group membership discovery V1 baseline or domains drift",
        ));
    }
    let target = json_string(&vector, "canonical_target")?;
    if !target.ends_with("/join-requests?after=&limit=32") || target.contains('%') {
        return Err(ProtocolToolError::new(
            "group membership discovery canonical target drift",
        ));
    }
    validate_uuid_fields(&vector, &["/scope_id", "/actor_device_id"])?;
    validate_cddl_hex(
        "group-query-binding-v1",
        &cddl,
        json_string(&vector, "binding_canonical_cbor_hex")?,
    )?;
    validate_cddl_hex(
        "group-query-proof-v1",
        &cddl,
        json_string(&vector, "proof_canonical_cbor_hex")?,
    )?;

    let binding = decode_hex(json_string(&vector, "binding_canonical_cbor_hex")?)?;
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update(&binding);
    let digest: [u8; 32] = hasher.finalize().into();
    if lowercase_hex(&digest) != json_string(&vector, "binding_digest_hex")? {
        return Err(ProtocolToolError::new(
            "group membership discovery binding digest drift",
        ));
    }
    let mut signature_input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + digest.len());
    signature_input.extend_from_slice(SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&digest);
    if lowercase_hex(&signature_input) != json_string(&vector, "signature_input_hex")? {
        return Err(ProtocolToolError::new(
            "group membership discovery signature input drift",
        ));
    }
    let proof = decode_hex(json_string(&vector, "proof_canonical_cbor_hex")?)?;
    let encoded_proof = Base64UrlUnpadded::decode_vec(json_string(&vector, "proof_base64url")?)
        .map_err(|_| ProtocolToolError::new("group query proof is not unpadded base64url"))?;
    if proof != encoded_proof {
        return Err(ProtocolToolError::new(
            "group query proof base64url differs from canonical CBOR",
        ));
    }
    let public_key =
        decode_lower_hex_fixed::<32>(json_string(&vector, "device_signing_public_key_hex")?)?;
    let signature = decode_lower_hex_fixed::<64>(json_string(&vector, "signature_hex")?)?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ProtocolToolError::new("group query public key is not Ed25519"))?
        .verify_strict(&signature_input, &Signature::from_bytes(&signature))
        .map_err(|_| ProtocolToolError::new("group query signature does not verify"))?;

    let openapi_path = root.join("protocol/openapi/group-membership-discovery/v1/openapi.yaml");
    let openapi = oas3::from_yaml(&read(&openapi_path)?).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse group-membership-discovery OpenAPI {}: {error}",
            openapi_path.display()
        ))
    })?;
    if openapi.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "group-membership-discovery OpenAPI must declare 3.1.0",
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
    fn private_agent_approval_text_semantics_reject_layout_and_bidi_spoofing() {
        assert!(validate_private_agent_approval_title(&"𐀀".repeat(120)).is_ok());
        assert!(validate_private_agent_approval_title(&"𐀀".repeat(121)).is_err());
        assert!(validate_private_agent_approval_detail("line one\n\tline two").is_ok());
        for unsafe_character in ['\u{2028}', '\u{2029}', '\u{202e}', '\u{2066}'] {
            assert!(
                validate_private_agent_approval_title(&format!("unsafe{unsafe_character}"))
                    .is_err()
            );
            assert!(
                validate_private_agent_approval_detail(&format!("unsafe{unsafe_character}"))
                    .is_err()
            );
        }
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
