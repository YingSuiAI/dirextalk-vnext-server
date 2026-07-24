use super::{
    BTreeSet, COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN, COMPLETION_EVIDENCE_POP_DOMAIN,
    CanonicalValue, CatalogPositiveFacts, CatalogServerProjection, MAX_CATALOG_LEAVES,
    MAX_CATALOG_UPLOAD_BODY_BYTES, MAX_PREPARATION_BODY_BYTES, MAX_PROOF_SIBLINGS,
    MAX_PROVIDER_PACKAGE_BYTES, MAX_SIGNED_CATALOG_HEAD_BYTES, MAX_STATUS_BODY_BYTES,
    ProtocolToolError, VERIFIER_BINDING_SIGNATURE_DOMAIN, Value, b2b_json_bool, cbor_fixed,
    cbor_unsigned, decode_exact_bytes, decode_exact_cddl, decode_json_fixed, decode_lower_hex,
    encode_deterministic_cbor, encoded_unsigned_prefix, expect_b2b_target_error, handoff_error,
    json, json_field, json_string, json_u64, numbered_fields, parse_server_visible_handoff_input,
    require_handoff, require_json_keys, validate_b2b_preparation_artifact,
    validate_server_visible_handoff, vector_with_handoff, verify_signature,
};
pub(crate) fn validate_b2b_issuer_times(
    cddl: &str,
    catalog: &CatalogPositiveFacts,
    time_family: &Value,
) -> Result<(), ProtocolToolError> {
    let cases = json_field(time_family, "issuer", "B2b time boundaries")?;
    require_json_keys(
        cases,
        &[
            "after_catalog_signed_binding_cbor_hex",
            "before_catalog_signed_binding_cbor_hex",
            "empty_signed_binding_cbor_hex",
            "exact_boundary_signed_binding_cbor_hex",
        ],
        "B2b issuer time cases",
    )?;
    let (_, base_binding_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-completion-verifier-binding-v1",
        json_string(cases, "exact_boundary_signed_binding_cbor_hex")?,
        "B2b base issuer time comparison",
    )?;
    let base_binding_fields =
        numbered_fields(&base_binding_value, 23, "B2b base issuer time comparison")?;
    for (field, expected_valid) in [
        ("exact_boundary_signed_binding_cbor_hex", true),
        ("before_catalog_signed_binding_cbor_hex", false),
        ("after_catalog_signed_binding_cbor_hex", false),
        ("empty_signed_binding_cbor_hex", false),
    ] {
        let (_, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-completion-verifier-binding-v1",
            json_string(cases, field)?,
            &format!("B2b issuer time {field}"),
        )?;
        let fields = numbered_fields(&value, 23, "B2b issuer time binding")?;
        let changed = fields
            .iter()
            .zip(&base_binding_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            changed
                .iter()
                .all(|index| [18, 19, 20, 21, 22].contains(index))
                && (changed.is_empty() || changed.iter().any(|index| [18, 19].contains(index))),
            &format!(
                "B2b issuer {field} changed bytes outside issuer times and three dependent signatures"
            ),
        )?;
        verify_signature(
            cbor_fixed(fields[17], "B2b issuer EPK")?,
            COMPLETION_EVIDENCE_POP_DOMAIN,
            &encoded_unsigned_prefix(&value, 20, "B2b issuer PoP")?,
            cbor_fixed(fields[20], "B2b issuer PoP signature")?,
            field,
        )?;
        verify_signature(
            cbor_fixed(fields[8], "B2b verifier key")?,
            COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
            &encoded_unsigned_prefix(&value, 21, "B2b origin authorization")?,
            cbor_fixed(fields[21], "B2b origin authorization signature")?,
            field,
        )?;
        verify_signature(
            catalog.context.authority_public_key,
            VERIFIER_BINDING_SIGNATURE_DOMAIN,
            &encoded_unsigned_prefix(&value, 22, "B2b Catalog countersignature")?,
            cbor_fixed(fields[22], "B2b Catalog countersignature")?,
            field,
        )?;
        let binding_issued = cbor_unsigned(fields[11], "B2b binding issued_at")?;
        let binding_expires = cbor_unsigned(fields[12], "B2b binding expires_at")?;
        let issuer_not_before = cbor_unsigned(fields[18], "B2b issuer not_before")?;
        let issuer_expires = cbor_unsigned(fields[19], "B2b issuer expires_at")?;
        let valid = issuer_not_before < issuer_expires
            && issuer_not_before >= binding_issued
            && issuer_expires <= binding_expires
            && issuer_not_before >= catalog.context.head_issued_at
            && issuer_expires <= catalog.context.head_expires_at;
        require_handoff(
            valid == expected_valid,
            &format!(
                "B2b triple-signed issuer time {field} did not reach only its target interval predicate"
            ),
        )?;
        if expected_valid {
            require_handoff(
                issuer_not_before == catalog.context.head_issued_at
                    && issuer_expires == catalog.context.head_expires_at,
                "B2b issuer exact authorization boundaries drifted",
            )?;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "strict decoding and closed server-visible JSON types are one pre-business privacy boundary"
)]
pub(crate) fn validate_b2b_decoder_privacy(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "decoder_privacy_closure", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "closed_server_visible_injections",
            "low_order_recipient_preparations",
            "noncanonical_preparation_cbor_hex",
            "size_count_index_sibling_status_boundaries",
            "trailing_preparation_cbor_hex",
        ],
        "Catalog V2 B2b decoder/privacy closure",
    )?;
    for field in [
        "noncanonical_preparation_cbor_hex",
        "trailing_preparation_cbor_hex",
    ] {
        expect_b2b_target_error(
            decode_exact_cddl(
                cddl,
                "recovery-scope-catalog-preparation-v2",
                json_string(family, field)?,
                field,
            ),
            field,
            "not deterministic canonical CBOR",
        )?;
    }

    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_inputs = json_field(base_handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let low_order = json_field(
        family,
        "low_order_recipient_preparations",
        "B2b decoder/privacy closure",
    )?;
    require_json_keys(
        low_order,
        &["all_zero", "u_coordinate_one"],
        "B2b low-order X25519 preparations",
    )?;
    for name in ["all_zero", "u_coordinate_one"] {
        expect_b2b_target_error(
            validate_b2b_preparation_artifact(
                cddl,
                catalog_projection,
                json_field(low_order, name, "B2b low-order X25519 preparations")?,
                decode_json_fixed(base_inputs, "response_capability_hex")?,
                json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
            ),
            &format!("{name} X25519 recipient"),
            "all-zero or low-order X25519 recipient key rejected",
        )?;
    }

    validate_b2b_shape_and_size_boundaries(cddl, family, base_handoff)?;
    let injections = json_field(
        family,
        "closed_server_visible_injections",
        "B2b decoder/privacy closure",
    )?
    .as_array()
    .ok_or_else(|| handoff_error("B2b closed-type injections must be an array"))?;
    require_handoff(
        injections.len() == 4,
        "B2b closed server-visible type portfolio must cover four private-field classes",
    )?;
    let mut observed = BTreeSet::new();
    for fixture in injections {
        require_json_keys(
            fixture,
            &["field", "target"],
            "B2b server-visible private-field injection",
        )?;
        let target = json_string(fixture, "target")?;
        let field = json_string(fixture, "field")?;
        require_handoff(
            observed.insert((target.to_owned(), field.to_owned())),
            "B2b server-visible injection portfolio contains a duplicate",
        )?;
        let mut handoff = base_handoff.clone();
        let pointer = match target {
            "preparation" => "/preparation",
            "provider_response" => "/provider_response",
            "public_aad" => "/public_aad",
            "statuses.ready" => "/statuses/ready",
            _ => {
                return Err(handoff_error(
                    "B2b closed-type injection target is not closed",
                ));
            }
        };
        handoff
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| handoff_error("B2b injection target is not an object"))?
            .insert(field.to_owned(), json!("forbidden-private-value"));
        let variant = vector_with_handoff(vector, &handoff)?;
        let input = parse_server_visible_handoff_input(&variant)?;
        expect_b2b_target_error(
            validate_server_visible_handoff(cddl, catalog_projection, &input),
            &format!("closed {target} private field {field}"),
            "exact JSON key set drifted",
        )?;
    }
    let expected = BTreeSet::from([
        (
            "preparation".to_owned(),
            "x25519_recipient_private_key_hex".to_owned(),
        ),
        (
            "provider_response".to_owned(),
            "plaintext_cbor_hex".to_owned(),
        ),
        (
            "public_aad".to_owned(),
            "verifier_public_key_hex".to_owned(),
        ),
        (
            "statuses.ready".to_owned(),
            "completion_evidence_issuer_epk_hex".to_owned(),
        ),
    ]);
    require_handoff(
        observed == expected,
        "B2b closed server-visible types did not cover every private material class",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "byte, count, index, sibling, status, and safe-integer max/max+1 checks form one shape portfolio"
)]
pub(crate) fn validate_b2b_shape_and_size_boundaries(
    cddl: &str,
    family: &Value,
    base_handoff: &Value,
) -> Result<(), ProtocolToolError> {
    let bounds = json_field(
        family,
        "size_count_index_sibling_status_boundaries",
        "B2b decoder/privacy closure",
    )?;
    require_json_keys(
        bounds,
        &[
            "max_catalog_upload_body_bytes",
            "max_leaf_count",
            "max_leaf_count_plus_one",
            "max_preparation_body_bytes",
            "max_proof_siblings",
            "max_proof_siblings_plus_one",
            "max_signed_catalog_head_bytes",
            "max_status_body_bytes",
            "safe_highwater_max",
            "safe_successor_max",
        ],
        "B2b shape and size boundaries",
    )?;
    require_handoff(
        json_u64(bounds, "max_catalog_upload_body_bytes")?
            == u64::try_from(MAX_CATALOG_UPLOAD_BODY_BYTES).expect("upload body bound fits")
            && json_u64(bounds, "max_leaf_count")?
                == u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits")
            && json_u64(bounds, "max_leaf_count_plus_one")?
                == u64::try_from(MAX_CATALOG_LEAVES + 1).expect("catalog max+1 fits")
            && json_u64(bounds, "max_preparation_body_bytes")?
                == u64::try_from(MAX_PREPARATION_BODY_BYTES).expect("preparation bound fits")
            && json_u64(bounds, "max_proof_siblings")?
                == u64::try_from(MAX_PROOF_SIBLINGS).expect("proof siblings fit")
            && json_u64(bounds, "max_proof_siblings_plus_one")?
                == u64::try_from(MAX_PROOF_SIBLINGS + 1).expect("proof max+1 fits")
            && json_u64(bounds, "max_signed_catalog_head_bytes")?
                == u64::try_from(MAX_SIGNED_CATALOG_HEAD_BYTES)
                    .expect("signed Catalog head bound fits")
            && json_u64(bounds, "max_status_body_bytes")?
                == u64::try_from(MAX_STATUS_BODY_BYTES).expect("status bound fits")
            && json_u64(bounds, "safe_highwater_max")? == 9_007_199_254_740_990
            && json_u64(bounds, "safe_successor_max")? == 9_007_199_254_740_991,
        "B2b shape/size boundary metadata drifted",
    )?;
    let encoded_bstr = |length: usize| {
        let length = u32::try_from(length).expect("B2b byte boundary fits u32");
        let mut encoded = Vec::with_capacity(length as usize + 5);
        encoded.push(0x5a);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.resize(length as usize + 5, 0);
        encoded
    };
    for (rule, maximum) in [
        (
            "exact-signed-catalog-head-v2",
            MAX_SIGNED_CATALOG_HEAD_BYTES,
        ),
        ("exact-provider-package-v2", MAX_PROVIDER_PACKAGE_BYTES),
        ("exact-ready-status-v2", MAX_STATUS_BODY_BYTES),
    ] {
        cddl_cat::validate_cbor_bytes(rule, cddl, &encoded_bstr(maximum)).map_err(|error| {
            handoff_error(&format!("B2b {rule} rejected its exact maximum: {error}"))
        })?;
        require_handoff(
            cddl_cat::validate_cbor_bytes(rule, cddl, &encoded_bstr(maximum + 1)).is_err(),
            &format!("B2b {rule} accepted max+1 bytes"),
        )?;
    }

    let proof = |count: u64, index: u64, siblings: usize| {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789a2".to_owned()),
            ),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(8)),
            (CanonicalValue::Unsigned(4), CanonicalValue::Unsigned(count)),
            (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(index)),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Array(
                    (0..siblings)
                        .map(|_| CanonicalValue::Bytes(vec![0; 32]))
                        .collect(),
                ),
            ),
        ])
    };
    for (label, value, accepted) in [
        ("count max", proof(1_023, 1_023, 0), true),
        ("count max+1", proof(1_024, 1_023, 0), false),
        ("index max", proof(1_023, 1_023, 0), true),
        ("index max+1", proof(1_023, 1_024, 0), false),
        ("siblings max", proof(1_023, 1, 10), true),
        ("siblings max+1", proof(1_023, 1, 11), false),
    ] {
        let exact = encode_deterministic_cbor(&value)
            .map_err(|error| handoff_error(&format!("encode B2b {label}: {error}")))?;
        require_handoff(
            cddl_cat::validate_cbor_bytes("catalog-merkle-proof-v2", cddl, &exact).is_ok()
                == accepted,
            &format!("B2b proof {label} boundary result drifted"),
        )?;
    }
    let base_preparation = decode_exact_bytes(
        &decode_lower_hex(json_string(
            json_field(base_handoff, "preparation", "B2b base handoff")?,
            "cbor_hex",
        )?)?,
        "B2b base preparation bound",
    )?;
    let CanonicalValue::Map(base_fields) = base_preparation else {
        return Err(handoff_error("B2b base preparation must be a map"));
    };
    for (label, highwater, accepted) in [
        ("safe highwater max", 9_007_199_254_740_990, true),
        ("safe highwater max+1", 9_007_199_254_740_991, false),
    ] {
        let mut fields = base_fields.clone();
        fields[9].1 = CanonicalValue::Unsigned(highwater);
        let exact = encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|error| handoff_error(&format!("encode B2b {label}: {error}")))?;
        require_handoff(
            cddl_cat::validate_cbor_bytes("recovery-scope-catalog-preparation-v2", cddl, &exact)
                .is_ok()
                == accepted,
            &format!("B2b {label} boundary result drifted"),
        )?;
    }
    let base_response = decode_exact_bytes(
        &decode_lower_hex(json_string(
            json_field(base_handoff, "provider_response", "B2b base handoff")?,
            "cbor_hex",
        )?)?,
        "B2b base response successor bound",
    )?;
    let CanonicalValue::Map(base_response_fields) = base_response else {
        return Err(handoff_error("B2b base provider response must be a map"));
    };
    for (label, successor, accepted) in [
        ("safe successor max", 9_007_199_254_740_991, true),
        ("safe successor max+1", 9_007_199_254_740_992, false),
    ] {
        let mut fields = base_response_fields.clone();
        fields[11].1 = CanonicalValue::Unsigned(successor);
        let exact = encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|error| handoff_error(&format!("encode B2b {label}: {error}")))?;
        require_handoff(
            cddl_cat::validate_cbor_bytes(
                "recovery-scope-catalog-provider-response-v2",
                cddl,
                &exact,
            )
            .is_ok()
                == accepted,
            &format!("B2b {label} boundary result drifted"),
        )?;
    }
    Ok(())
}

pub(crate) fn validate_b2b_limitations(b2b: &Value) -> Result<(), ProtocolToolError> {
    let limitations = json_field(b2b, "limitations", "Catalog V2 B2b")?;
    require_json_keys(
        limitations,
        &[
            "generic_counter_is_wire",
            "provider_session_is_wire",
            "represented_by",
        ],
        "Catalog V2 B2b limitations",
    )?;
    let represented = json_field(limitations, "represented_by", "B2b limitations")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b limitation representation must be an array"))?;
    require_handoff(
        !b2b_json_bool(limitations, "generic_counter_is_wire")?
            && !b2b_json_bool(limitations, "provider_session_is_wire")?
            && represented
                == &[
                    json!("identity_log_h_to_h_plus_1"),
                    json!("safe_highwater_max"),
                    json!("leaf_count_index_and_sibling_bounds"),
                ],
        "B2b must not invent a generic wire counter or provider-session field",
    )
}
