use super::{
    BTreeSet, CatalogPositiveFacts, CatalogServerProjection, Deserializable, Digest, KemTrait,
    ProtocolToolError, Serializable, ServerVisibleHandoffFacts, Sha256, Value, X25519HkdfSha256,
    cbor_fixed, cbor_text, cbor_unsigned, decode_exact_bytes, decode_exact_cddl, decode_json_fixed,
    decode_lower_hex, expect_b2b_target_error, handoff_error, json, json_field, json_string,
    json_u64, numbered_fields, parse_origin_authenticated_verifier_oracle,
    parse_server_visible_handoff_input, require_handoff, require_json_keys,
    validate_b2b_authentic_crypto_handoff, validate_b2b_preparation_artifact,
    validate_candidate_handoff, validate_server_visible_handoff, vector_with_handoff,
};
pub(crate) fn validate_b2b_verifier_rotation(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "verifier_rotation", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "rotated_origin_authenticated_oracle",
            "server_visible_exact_bytes_sha256_hex",
        ],
        "Catalog V2 B2b verifier rotation",
    )?;
    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let mut serialized = serde_json::to_vec(json_field(
        handoff,
        "origin_authenticated_identity_log",
        "Catalog V2 handoff",
    )?)
    .map_err(|error| handoff_error(&format!("serialize B2b identity oracle: {error}")))?;
    for exact in [
        base.preparation_exact.as_slice(),
        base.device_add_exact.as_slice(),
        base.public_aad_exact.as_slice(),
        base.envelope_exact.as_slice(),
        base.provider_response_exact.as_slice(),
        base.preparation_receipt_exact.as_slice(),
        base.provider_response_receipt_exact.as_slice(),
    ] {
        serialized.extend_from_slice(exact);
    }
    for exact in &base.status_exact {
        serialized.extend_from_slice(exact);
    }
    require_handoff(
        decode_json_fixed::<32>(family, "server_visible_exact_bytes_sha256_hex")?
            == Sha256::digest(&serialized).as_slice(),
        "B2b verifier rotation server-projection hash drifted",
    )?;
    let mut rotated = vector.clone();
    rotated
        .as_object_mut()
        .ok_or_else(|| handoff_error("B2b rotated vector root is not an object"))?
        .insert(
            "origin_authenticated_completion_verifier_descriptors".to_owned(),
            json_field(
                family,
                "rotated_origin_authenticated_oracle",
                "Catalog V2 B2b verifier rotation",
            )?
            .clone(),
        );
    let rotated_oracle = parse_origin_authenticated_verifier_oracle(
        &rotated,
        cddl,
        catalog.context.validation_time,
    )?;
    let current_oracle =
        parse_origin_authenticated_verifier_oracle(vector, cddl, catalog.context.validation_time)?;
    require_handoff(
        rotated_oracle != current_oracle,
        "B2b rotated hidden verifier oracle equals the current oracle",
    )?;
    let input = parse_server_visible_handoff_input(&rotated)?;
    let rotated_server = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
    require_handoff(
        rotated_server == *base
            && rotated_server.preparation_receipt_exact == base.preparation_receipt_exact
            && rotated_server.provider_response_receipt_exact
                == base.provider_response_receipt_exact
            && rotated_server.status_exact == base.status_exact,
        "B2b hidden verifier rotation changed server-visible response, receipt, status, or projection bytes",
    )?;
    expect_b2b_target_error(
        validate_candidate_handoff(&rotated, cddl, &rotated_server, catalog),
        "hidden verifier rotation",
        "candidate-only verifier binding does not match the current signed origin-authenticated descriptor",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the paired preparation/provider trace gate keeps authentic artifacts adjacent to their state-machine assertions"
)]
pub(crate) fn validate_b2b_state_idempotency(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    type Kem = X25519HkdfSha256;

    let family = json_field(b2b, "state_idempotency_traces", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "preparation",
            "preparation_reject_before_write_order",
            "provider_response",
            "provider_response_reject_before_write_order",
        ],
        "Catalog V2 B2b state/idempotency traces",
    )?;
    validate_b2b_reject_order(
        json_field(
            family,
            "preparation_reject_before_write_order",
            "B2b preparation order",
        )?,
        &[
            "media_and_size",
            "exact_canonical_cbor",
            "capabilities",
            "path_and_static_binding",
            "idempotency_claim_lookup",
            "body_signature_and_digest",
            "committed_exact_replay",
            "mutable_currentness",
            "final_cas",
        ],
        "preparation",
    )?;
    validate_b2b_reject_order(
        json_field(
            family,
            "provider_response_reject_before_write_order",
            "B2b response order",
        )?,
        &[
            "media_and_size",
            "exact_canonical_cbor",
            "response_capability_and_provider_session",
            "path_and_static_binding",
            "idempotency_claim_lookup",
            "body_dual_signatures_and_digests",
            "committed_exact_replay",
            "mutable_currentness",
            "final_cas",
        ],
        "provider response",
    )?;

    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_inputs = json_field(base_handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let base_preparation = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(base_handoff, "preparation", "Catalog V2 handoff")?,
        decode_json_fixed(base_inputs, "response_capability_hex")?,
        json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
    )?;
    require_handoff(
        base_preparation.exact == base.preparation_exact
            && base_preparation.digest == base.preparation_digest,
        "B2b base preparation proof drifted from the accepted handoff",
    )?;

    let preparation = json_field(family, "preparation", "B2b state traces")?;
    require_json_keys(
        preparation,
        &[
            "candidate_one_enrollment_capability_hex",
            "candidate_two",
            "different_key_duplicate_target",
            "same_key_different_body",
            "trace",
        ],
        "B2b preparation state traces",
    )?;
    let candidate_two_json = json_field(preparation, "candidate_two", "B2b preparation traces")?;
    require_json_keys(
        candidate_two_json,
        &[
            "enrollment_capability_hex",
            "preparation",
            "preparation_idempotency_key_ascii",
            "receipt",
            "replay_receipt_cbor_hex",
            "replay_writes",
            "response_capability_hex",
            "status_available",
            "x25519_recipient_private_key_hex",
        ],
        "B2b second candidate preparation",
    )?;
    let candidate_two_capability =
        decode_json_fixed(candidate_two_json, "response_capability_hex")?;
    let candidate_one_enrollment_capability =
        decode_json_fixed::<32>(preparation, "candidate_one_enrollment_capability_hex")?;
    let candidate_one_response_capability =
        decode_json_fixed::<32>(base_inputs, "response_capability_hex")?;
    let candidate_two_enrollment_capability =
        decode_json_fixed::<32>(candidate_two_json, "enrollment_capability_hex")?;
    require_handoff(
        BTreeSet::from([
            candidate_one_enrollment_capability,
            candidate_one_response_capability,
            candidate_two_enrollment_capability,
            candidate_two_capability,
        ])
        .len()
            == 4,
        "B2b candidate preparations do not use four disjoint enrollment/response capabilities",
    )?;
    let candidate_two_idempotency =
        json_string(candidate_two_json, "preparation_idempotency_key_ascii")?.as_bytes();
    let candidate_two = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(candidate_two_json, "preparation", "B2b second candidate")?,
        candidate_two_capability,
        candidate_two_idempotency,
    )?;
    let candidate_two_private =
        decode_json_fixed::<32>(candidate_two_json, "x25519_recipient_private_key_hex")?;
    let candidate_two_private = <Kem as KemTrait>::PrivateKey::from_bytes(&candidate_two_private)
        .map_err(|error| {
        handoff_error(&format!("B2b second candidate key invalid: {error}"))
    })?;
    require_handoff(
        Kem::sk_to_pk(&candidate_two_private).to_bytes().as_slice()
            == candidate_two.recipient_public_key
            && candidate_two.signed_head_digest == base_preparation.signed_head_digest
            && candidate_two.request_id != base_preparation.request_id
            && candidate_two.candidate_device_id != base_preparation.candidate_device_id
            && candidate_two.signing_public_key != base_preparation.signing_public_key
            && candidate_two.recipient_public_key != base_preparation.recipient_public_key
            && candidate_two.response_capability_digest
                != base_preparation.response_capability_digest
            && candidate_two.idempotency_digest != base_preparation.idempotency_digest,
        "B2b two authenticated candidate preparations are not disjoint while sharing one signed Catalog head",
    )?;
    let candidate_two_receipt_json = json_field(
        candidate_two_json,
        "receipt",
        "B2b second candidate preparation",
    )?;
    require_json_keys(
        candidate_two_receipt_json,
        &["accepted_at", "cbor_hex", "request_digest_hex"],
        "B2b second candidate receipt",
    )?;
    let (candidate_two_receipt_exact, candidate_two_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-receipt-v2",
        json_string(candidate_two_receipt_json, "cbor_hex")?,
        "B2b second candidate receipt",
    )?;
    let candidate_two_receipt = numbered_fields(
        &candidate_two_receipt_value,
        4,
        "B2b second candidate receipt",
    )?;
    require_handoff(
        cbor_text(
            candidate_two_receipt[1],
            "B2b second candidate receipt request",
        )? == candidate_two.request_id
            && cbor_fixed::<32>(
                candidate_two_receipt[2],
                "B2b second candidate receipt digest",
            )? == candidate_two.digest
            && decode_json_fixed::<32>(candidate_two_receipt_json, "request_digest_hex")?
                == candidate_two.digest
            && decode_lower_hex(json_string(candidate_two_json, "replay_receipt_cbor_hex")?)?
                == candidate_two_receipt_exact
            && json_u64(candidate_two_json, "replay_writes")? == 0
            && b2b_json_bool(candidate_two_json, "status_available")?,
        "B2b second request exact replay did not return its original receipt with no writes and status available",
    )?;

    let same_key = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(
            preparation,
            "same_key_different_body",
            "B2b preparation traces",
        )?,
        decode_json_fixed(base_inputs, "response_capability_hex")?,
        json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
    )?;
    require_handoff(
        same_key.idempotency_digest == base_preparation.idempotency_digest
            && same_key.exact != base_preparation.exact
            && same_key.request_id == base_preparation.request_id
            && same_key.candidate_device_id == base_preparation.candidate_device_id,
        "B2b same-key/different-preparation body is not an authentic scoped conflict",
    )?;
    let different_key_json = json_field(
        preparation,
        "different_key_duplicate_target",
        "B2b preparation traces",
    )?;
    require_json_keys(
        different_key_json,
        &["preparation", "preparation_idempotency_key_ascii"],
        "B2b preparation duplicate target",
    )?;
    let different_key = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(different_key_json, "preparation", "B2b duplicate target")?,
        decode_json_fixed(base_inputs, "response_capability_hex")?,
        json_string(different_key_json, "preparation_idempotency_key_ascii")?.as_bytes(),
    )?;
    require_handoff(
        different_key.idempotency_digest != base_preparation.idempotency_digest
            && different_key.request_id == base_preparation.request_id
            && different_key.candidate_device_id == base_preparation.candidate_device_id,
        "B2b different-key preparation does not target the already admitted request",
    )?;
    validate_b2b_admission_trace(
        json_field(preparation, "trace", "B2b preparation traces")?,
        "preparation",
        &base.preparation_receipt_exact,
    )?;

    let provider = json_field(family, "provider_response", "B2b state traces")?;
    require_json_keys(
        provider,
        &[
            "different_key_duplicate_target",
            "same_key_different_body",
            "trace",
        ],
        "B2b provider-response state traces",
    )?;
    let same_response_handoff = json_field(
        provider,
        "same_key_different_body",
        "B2b provider-response traces",
    )?;
    let same_response_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        same_response_handoff,
        "B2b same-key different provider response",
    )?;
    let same_response_vector = vector_with_handoff(vector, same_response_handoff)?;
    let same_response_input = parse_server_visible_handoff_input(&same_response_vector)?;
    let same_response_server =
        validate_server_visible_handoff(cddl, catalog_projection, &same_response_input)?;
    validate_candidate_handoff(&same_response_vector, cddl, &same_response_server, catalog)?;
    let different_response_handoff = json_field(
        provider,
        "different_key_duplicate_target",
        "B2b provider-response traces",
    )?;
    let different_response_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        different_response_handoff,
        "B2b different-key duplicate provider response",
    )?;
    let different_response_vector = vector_with_handoff(vector, different_response_handoff)?;
    let different_response_input = parse_server_visible_handoff_input(&different_response_vector)?;
    let different_response_server =
        validate_server_visible_handoff(cddl, catalog_projection, &different_response_input)?;
    validate_candidate_handoff(
        &different_response_vector,
        cddl,
        &different_response_server,
        catalog,
    )?;
    let base_response_value =
        decode_exact_bytes(&base.provider_response_exact, "B2b base response")?;
    let base_response_fields = numbered_fields(&base_response_value, 26, "B2b base response")?;
    let same_response_value = decode_exact_bytes(
        &same_response_crypto.provider_response_exact,
        "B2b same response",
    )?;
    let same_response_fields = numbered_fields(&same_response_value, 26, "B2b same response")?;
    let different_response_value = decode_exact_bytes(
        &different_response_crypto.provider_response_exact,
        "B2b different response",
    )?;
    let different_response_fields =
        numbered_fields(&different_response_value, 26, "B2b different response")?;
    require_handoff(
        same_response_crypto.preparation.exact == base.preparation_exact
            && different_response_crypto.preparation.exact == base.preparation_exact
            && same_response_crypto.provider_response_exact != base.provider_response_exact
            && different_response_crypto.provider_response_exact != base.provider_response_exact
            && cbor_fixed::<32>(same_response_fields[19], "B2b same response key")?
                == cbor_fixed::<32>(base_response_fields[19], "B2b base response key")?
            && cbor_fixed::<32>(different_response_fields[19], "B2b different response key")?
                != cbor_fixed::<32>(base_response_fields[19], "B2b base response key")?
            && same_response_crypto.provider_response_receipt_exact
                != base.provider_response_receipt_exact
            && different_response_crypto.provider_response_receipt_exact
                != base.provider_response_receipt_exact,
        "B2b provider-response idempotency fixtures are not authentic body/key conflicts",
    )?;
    validate_b2b_admission_trace(
        json_field(provider, "trace", "B2b provider-response traces")?,
        "provider response",
        &base.provider_response_receipt_exact,
    )
}

pub(crate) fn validate_b2b_reject_order(
    value: &Value,
    expected: &[&str],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let observed = value
        .as_array()
        .ok_or_else(|| handoff_error(&format!("B2b {label} order must be an array")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| handoff_error(&format!("B2b {label} order must contain strings")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    require_handoff(
        observed == expected,
        &format!("B2b {label} auth/static/body/idempotency/replay/currentness/CAS order drifted"),
    )
}

pub(crate) fn b2b_json_bool(value: &Value, field: &str) -> Result<bool, ProtocolToolError> {
    json_field(value, field, "Catalog V2 B2b trace")?
        .as_bool()
        .ok_or_else(|| handoff_error(&format!("B2b trace {field} must be Boolean")))
}

pub(crate) fn validate_b2b_admission_trace(
    value: &Value,
    label: &str,
    original_receipt: &[u8],
) -> Result<(), ProtocolToolError> {
    let entries = value
        .as_array()
        .ok_or_else(|| handoff_error(&format!("B2b {label} trace must be an array")))?;
    require_handoff(
        entries.len() == 5,
        &format!("B2b {label} trace must contain five ordered admissions"),
    )?;
    for (index, (event, outcome, writes, receipt_returned)) in [
        ("first_admission", "accepted", 1, true),
        ("same_key_same_body", "exact_replay", 0, true),
        ("same_key_different_body", "idempotency_conflict", 0, false),
        (
            "different_key_duplicate_target",
            "duplicate_target_conflict",
            0,
            false,
        ),
        ("final_cas", "first_admission_only", 1, true),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = &entries[index];
        let has_currentness = (1..=3).contains(&index);
        let keys = if index <= 1 && has_currentness {
            &[
                "event",
                "mutable_currentness_checked",
                "outcome",
                "receipt_cbor_hex",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        } else if index == 0 {
            &[
                "event",
                "outcome",
                "receipt_cbor_hex",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        } else if index == 4 {
            &[
                "cas_loser_writes",
                "event",
                "outcome",
                "partial_write",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        } else {
            &[
                "event",
                "mutable_currentness_checked",
                "outcome",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        };
        require_json_keys(entry, keys, &format!("B2b {label} trace entry"))?;
        require_handoff(
            json_string(entry, "event")? == event
                && json_string(entry, "outcome")? == outcome
                && json_u64(entry, "writes")? == writes
                && b2b_json_bool(entry, "receipt_returned")? == receipt_returned
                && b2b_json_bool(entry, "status_available")?
                && (!has_currentness || !b2b_json_bool(entry, "mutable_currentness_checked")?)
                && (index > 1
                    || decode_lower_hex(json_string(entry, "receipt_cbor_hex")?)?
                        == original_receipt)
                && (index != 4
                    || json_u64(entry, "cas_loser_writes")? == 0
                        && !b2b_json_bool(entry, "partial_write")?),
            &format!("B2b {label} {event} trace outcome/order/write/receipt/status drifted"),
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "five exact status encodings, terminal tie reduction, and immutable receipts form one GET contract"
)]
pub(crate) fn validate_b2b_get_states(
    vector: &Value,
    cddl: &str,
    base: &ServerVisibleHandoffFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "get_state_traces", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "http_status",
            "invalidation_reason_priority",
            "preparation_receipt_cbor_hex",
            "provider_response_receipt_cbor_hex",
            "read_only_no_writes",
            "receipts_remain_immutable",
            "state_changed_at",
            "states",
            "tie_priority",
            "valid_response_capability_hex",
        ],
        "Catalog V2 B2b GET-state traces",
    )?;
    let base_inputs = json_field(
        json_field(vector, "handoff", "Catalog V2 vector")?,
        "test_only_inputs",
        "Catalog V2 handoff",
    )?;
    require_handoff(
        json_u64(family, "http_status")? == 200
            && b2b_json_bool(family, "read_only_no_writes")?
            && b2b_json_bool(family, "receipts_remain_immutable")?
            && decode_json_fixed::<32>(family, "valid_response_capability_hex")?
                == decode_json_fixed::<32>(base_inputs, "response_capability_hex")?,
        "B2b GET must require the valid response capability and return HTTP 200 without writes",
    )?;
    let states = json_field(family, "states", "B2b GET-state traces")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b GET states must be an array"))?;
    let state_names = states
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| handoff_error("B2b GET state name must be text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    require_handoff(
        state_names == ["pending", "ready", "expired", "cancelled", "invalidated"],
        "B2b GET five-state closure drifted",
    )?;
    let changed = json_field(family, "state_changed_at", "B2b GET-state traces")?;
    require_json_keys(
        changed,
        &["cancelled", "expired", "invalidated", "pending", "ready"],
        "B2b GET stable timestamps",
    )?;
    for (index, name) in state_names.iter().enumerate() {
        let value = decode_exact_bytes(&base.status_exact[index], &format!("B2b {name} status"))?;
        cddl_cat::validate_cbor_bytes(
            match *name {
                "pending" => "recovery-scope-catalog-status-pending-v2",
                "ready" => "recovery-scope-catalog-status-ready-v2",
                "expired" => "recovery-scope-catalog-status-expired-v2",
                "cancelled" => "recovery-scope-catalog-status-cancelled-v2",
                "invalidated" => "recovery-scope-catalog-status-invalidated-v2",
                _ => unreachable!("closed B2b GET states"),
            },
            cddl,
            &base.status_exact[index],
        )
        .map_err(|error| handoff_error(&format!("B2b {name} status CDDL failed: {error}")))?;
        let fields = numbered_fields(&value, 6, &format!("B2b {name} status"))?;
        require_handoff(
            cbor_text(fields[1], "B2b GET request")? == base.request_id
                && cbor_unsigned(fields[5], "B2b GET stable timestamp")?
                    == json_u64(changed, name)?,
            &format!("B2b {name} GET timestamp/request changed across reads"),
        )?;
    }
    let tie_priority = json_field(family, "tie_priority", "B2b GET-state traces")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b GET tie priority must be an array"))?;
    require_handoff(
        tie_priority == &[json!("cancelled"), json!("invalidated"), json!("expired")],
        "B2b equal-time terminal priority must be cancelled > invalidated > expired",
    )?;
    let selected = [("expired", 3_u8), ("invalidated", 2), ("cancelled", 1)]
        .into_iter()
        .min_by_key(|(_, priority)| *priority)
        .map(|(name, _)| name);
    require_handoff(
        selected == Some("cancelled"),
        "B2b equal-time state reducer did not select cancelled",
    )?;
    let invalidation = json_field(
        family,
        "invalidation_reason_priority",
        "B2b GET-state traces",
    )?
    .as_array()
    .ok_or_else(|| handoff_error("B2b invalidation priority must be an array"))?;
    let expected = [
        "identity_head_or_h_plus_2",
        "catalog_id_generation_or_head",
        "public_catalog_authority_or_head",
        "candidate_device_add_or_key",
        "provider_session_or_key",
        "independent_authority",
    ];
    require_handoff(
        invalidation
            .iter()
            .map(Value::as_str)
            .eq(expected.into_iter().map(Some)),
        "B2b invalidated reason order must use the lowest numeric priority",
    )?;
    require_handoff(
        decode_lower_hex(json_string(family, "preparation_receipt_cbor_hex")?)?
            == base.preparation_receipt_exact
            && decode_lower_hex(json_string(family, "provider_response_receipt_cbor_hex")?)?
                == base.provider_response_receipt_exact,
        "B2b GET rewrote an immutable mutation receipt",
    )
}
