use super::{
    BTreeSet, COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN,
    COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN, CatalogPositiveFacts, CatalogServerProjection,
    HEAD_SIGNATURE_DOMAIN, IndependentAuthorityKind, ProtocolToolError, ServerVisibleHandoffFacts,
    Value, VerifyingKey, b2b_json_bool, cbor_fixed, cbor_text, cbor_unsigned, decode_exact_bytes,
    decode_exact_cddl, decode_json_fixed, decode_lower_hex, domain_digest, encoded_unsigned_prefix,
    expect_b2b_target_error, handoff_error, json, json_field, json_string, json_u64,
    numbered_fields, origin_has_device, parse_origin_authenticated_current_identity_snapshot,
    parse_origin_authenticated_verifier_oracle, parse_server_visible_handoff_input,
    require_handoff, require_json_keys, validate_b2b_authentic_crypto_handoff,
    validate_b2b_issuer_times, validate_b2b_preparation_artifact, validate_candidate_handoff,
    validate_independent_authority_currentness, validate_server_visible_handoff,
    vector_with_handoff, verify_signature,
};
#[allow(
    clippy::too_many_lines,
    reason = "H+2, provider session, and all three authority kinds share one lower-signature-first currentness gate"
)]
pub(crate) fn validate_b2b_currentness(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "currentness_drifts", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "authenticated_snapshot_rejections",
            "authority_kinds",
            "exact_first_admission",
            "h_plus_2_origin_authenticated_identity_log",
            "provider_session_drift",
        ],
        "Catalog V2 B2b currentness drifts",
    )?;
    let first = json_field(family, "exact_first_admission", "B2b currentness")?;
    require_json_keys(first, &["h", "h_plus_1", "writes"], "B2b first admission")?;
    require_handoff(
        json_u64(first, "h")? == base.identity_log.at_h.sequence
            && json_u64(first, "h_plus_1")? == base.identity_log.at_h.sequence + 1
            && json_u64(first, "h_plus_1")? == base.identity_log.at_h_plus_1.sequence
            && json_u64(first, "writes")? == 1,
        "B2b first admission is not the exact H to H+1 DeviceAdd CAS",
    )?;

    let mut h_plus_2_vector = vector.clone();
    *h_plus_2_vector
        .pointer_mut("/handoff/origin_authenticated_identity_log")
        .ok_or_else(|| handoff_error("B2b H+2 oracle mutation path missing"))? = json_field(
        family,
        "h_plus_2_origin_authenticated_identity_log",
        "B2b currentness",
    )?
    .clone();
    let h_plus_2_input = parse_server_visible_handoff_input(&h_plus_2_vector)?;
    expect_b2b_target_error(
        validate_server_visible_handoff(cddl, catalog_projection, &h_plus_2_input),
        "origin-authenticated H+2",
        "origin-authenticated H/H+1 oracle drifted",
    )?;

    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        base_handoff,
        "B2b base currentness transcript",
    )?;
    let response_value = decode_exact_bytes(
        &base_crypto.provider_response_exact,
        "B2b provider-session response",
    )?;
    let response = numbered_fields(&response_value, 26, "B2b provider-session response")?;
    let provider_descriptor = numbered_fields(response[14], 3, "B2b provider descriptor")?;
    let provider_session = json_field(family, "provider_session_drift", "B2b currentness")?;
    require_json_keys(
        provider_session,
        &[
            "authenticated_device_id",
            "authenticated_signing_public_key_hex",
        ],
        "B2b provider-session drift",
    )?;
    let authenticated_provider_key =
        decode_json_fixed::<32>(provider_session, "authenticated_signing_public_key_hex")?;
    VerifyingKey::from_bytes(&authenticated_provider_key).map_err(|error| {
        handoff_error(&format!(
            "B2b authenticated provider-session drift key is not Ed25519: {error}"
        ))
    })?;
    require_handoff(
        origin_has_device(
            &base.identity_log.at_h_plus_1,
            json_string(provider_session, "authenticated_device_id")?,
            authenticated_provider_key,
        ) && (cbor_text(provider_descriptor[1], "B2b response provider id")?
            != json_string(provider_session, "authenticated_device_id")?
            || cbor_fixed::<32>(provider_descriptor[2], "B2b response provider key")?
                != authenticated_provider_key),
        "B2b provider-session drift is not an authentic current session distinct from the signed response descriptor",
    )?;
    expect_b2b_target_error(
        require_handoff(
            cbor_text(provider_descriptor[1], "B2b response provider id")?
                == json_string(provider_session, "authenticated_device_id")?
                && cbor_fixed::<32>(provider_descriptor[2], "B2b response provider key")?
                    == authenticated_provider_key,
            "provider authenticated session does not equal the signed provider descriptor",
        ),
        "provider descriptor/session drift",
        "provider authenticated session does not equal the signed provider descriptor",
    )?;

    let authority_cases = json_field(family, "authority_kinds", "B2b currentness")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b authority currentness cases must be an array"))?;
    require_handoff(
        authority_cases.len() == 3,
        "B2b authority currentness must cover all three closed kinds",
    )?;
    let variants = json_field(vector, "handoff_authority_variants", "Catalog V2 vector")?;
    for (index, (name, handoff, expected_kind)) in [
        (
            "active_device",
            base_handoff,
            IndependentAuthorityKind::ActiveDevice,
        ),
        (
            "current_root",
            json_field(variants, "current_root", "B2b authority variants")?,
            IndependentAuthorityKind::CurrentRoot,
        ),
        (
            "current_recovery",
            json_field(variants, "current_recovery", "B2b authority variants")?,
            IndependentAuthorityKind::CurrentRecovery,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = &authority_cases[index];
        require_json_keys(
            fixture,
            &["current_identity_snapshot", "kind"],
            "B2b authority currentness fixture",
        )?;
        let crypto = validate_b2b_authentic_crypto_handoff(
            cddl,
            catalog_projection,
            handoff,
            &format!("B2b {name} currentness transcript"),
        )?;
        let value = decode_exact_bytes(
            &crypto.provider_response_exact,
            &format!("B2b {name} response"),
        )?;
        let fields = numbered_fields(&value, 26, &format!("B2b {name} response"))?;
        let candidate_device_id = cbor_text(fields[7], "B2b response candidate")?;
        let provider = numbered_fields(fields[14], 3, &format!("B2b {name} provider"))?;
        let provider_id = cbor_text(provider[1], "B2b response provider id")?;
        let provider_key = cbor_fixed::<32>(provider[2], "B2b response provider key")?;
        let authority = numbered_fields(fields[15], 3, &format!("B2b {name} authority"))?;
        let observed_kind = match cbor_unsigned(authority[0], "B2b authority kind")? {
            1 => IndependentAuthorityKind::ActiveDevice,
            2 => IndependentAuthorityKind::CurrentRoot,
            3 => IndependentAuthorityKind::CurrentRecovery,
            _ => return Err(handoff_error("B2b authority kind is not closed")),
        };
        let signed_key = cbor_fixed::<32>(authority[2], "B2b signed authority key")?;
        let current_snapshot = parse_origin_authenticated_current_identity_snapshot(
            json_field(
                fixture,
                "current_identity_snapshot",
                "B2b authority currentness fixture",
            )?,
            &format!("B2b {name} origin-authenticated current identity snapshot"),
        )?;
        require_handoff(
            json_string(fixture, "kind")? == name
                && observed_kind == expected_kind
                && current_snapshot.origin == base.identity_log.origin
                && current_snapshot.state.sequence == base.identity_log.at_h_plus_1.sequence + 1
                && current_snapshot.state.head_digest != base.identity_log.at_h_plus_1.head_digest
                && origin_has_device(&current_snapshot.state, provider_id, provider_key)
                && origin_has_device(
                    &current_snapshot.state,
                    candidate_device_id,
                    crypto.preparation.signing_public_key,
                ),
            &format!(
                "B2b {name} currentness fixture did not preserve a valid lower transcript and authenticated forward current snapshot"
            ),
        )?;
        let target_error = match expected_kind {
            IndependentAuthorityKind::ActiveDevice => {
                let authority_id = cbor_text(authority[1], "B2b authority device")?;
                require_handoff(
                    current_snapshot.state.active_devices.iter().any(|device| {
                        device.device_id == authority_id && device.signing_public_key != signed_key
                    }),
                    "B2b active-device current snapshot did not rotate the signed authority device key",
                )?;
                "active independent authority is not current and distinct in authenticated identity state"
            }
            IndependentAuthorityKind::CurrentRoot => {
                require_handoff(
                    current_snapshot.state.current_root_public_key != signed_key,
                    "B2b current-root snapshot did not rotate the signed root authority key",
                )?;
                "root independent authority id/key is not current in authenticated identity state"
            }
            IndependentAuthorityKind::CurrentRecovery => {
                require_handoff(
                    current_snapshot.state.current_recovery_public_key != signed_key,
                    "B2b current-recovery snapshot did not rotate the signed recovery authority key",
                )?;
                "recovery independent authority id/key is not current in authenticated identity state"
            }
        };
        expect_b2b_target_error(
            validate_independent_authority_currentness(
                &current_snapshot.state,
                candidate_device_id,
                provider_id,
                &authority,
            ),
            &format!("{name} authority currentness"),
            target_error,
        )?;
    }
    let snapshot_rejections = json_field(
        family,
        "authenticated_snapshot_rejections",
        "B2b currentness",
    )?;
    require_json_keys(
        snapshot_rejections,
        &[
            "arbitrary_untrusted_signer",
            "invalid_current_key",
            "invalid_head",
            "invalid_signature",
        ],
        "B2b authenticated-current-snapshot rejection closure",
    )?;
    for (name, expected) in [
        ("arbitrary_untrusted_signer", "origin trust anchor drifted"),
        ("invalid_current_key", "current root key is invalid"),
        ("invalid_head", "sequence/head is invalid"),
        ("invalid_signature", "signature invalid"),
    ] {
        expect_b2b_target_error(
            parse_origin_authenticated_current_identity_snapshot(
                json_field(snapshot_rejections, name, "B2b snapshot rejection closure")?,
                &format!("B2b {name} current identity snapshot"),
            ),
            &format!("{name} current identity snapshot"),
            expected,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "preparation and freshly re-sealed response boundaries are one outer handoff validity portfolio"
)]
pub(crate) fn validate_b2b_time_boundaries(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "time_boundaries", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &["catalog", "descriptor", "issuer", "preparation", "response"],
        "Catalog V2 B2b time boundaries",
    )?;
    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_inputs = json_field(base_handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let base_preparation_value = decode_exact_bytes(
        &base.preparation_exact,
        "B2b base preparation time comparison",
    )?;
    let base_preparation_fields = numbered_fields(
        &base_preparation_value,
        17,
        "B2b base preparation time comparison",
    )?;
    let base_package_exact = decode_lower_hex(json_string(
        json_field(base_handoff, "package", "B2b base handoff")?,
        "cbor_hex",
    )?)?;
    let base_package_value =
        decode_exact_bytes(&base_package_exact, "B2b base response-time package")?;
    let base_package_fields =
        numbered_fields(&base_package_value, 17, "B2b base response-time package")?;

    let preparation_cases = json_field(family, "preparation", "B2b time boundaries")?;
    require_json_keys(
        preparation_cases,
        &[
            "empty_interval",
            "expires_after_catalog",
            "expires_at_catalog_boundary",
            "issued_at_catalog_boundary",
            "issued_before_catalog",
        ],
        "B2b preparation time cases",
    )?;
    for (name, expected_valid) in [
        ("issued_at_catalog_boundary", true),
        ("expires_at_catalog_boundary", true),
        ("issued_before_catalog", false),
        ("expires_after_catalog", false),
        ("empty_interval", false),
    ] {
        let fixture = json_field(preparation_cases, name, "B2b preparation time cases")?;
        require_json_keys(
            fixture,
            &["expected_valid", "preparation"],
            "B2b preparation time fixture",
        )?;
        require_handoff(
            b2b_json_bool(fixture, "expected_valid")? == expected_valid,
            &format!("B2b preparation {name} expected-valid label drifted"),
        )?;
        let facts = validate_b2b_preparation_artifact(
            cddl,
            catalog_projection,
            json_field(fixture, "preparation", "B2b preparation time fixture")?,
            decode_json_fixed(base_inputs, "response_capability_hex")?,
            json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
        )?;
        let preparation_value =
            decode_exact_bytes(&facts.exact, &format!("B2b preparation time {name}"))?;
        let preparation_fields =
            numbered_fields(&preparation_value, 17, "B2b preparation time comparison")?;
        let changed = preparation_fields
            .iter()
            .zip(&base_preparation_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            !changed.is_empty()
                && changed.iter().all(|index| [14, 15, 16].contains(index))
                && changed.iter().any(|index| [14, 15].contains(index)),
            &format!(
                "B2b preparation {name} changed bytes outside validity times and the dependent signature"
            ),
        )?;
        let valid = facts.issued_at < facts.expires_at
            && facts.issued_at >= catalog_projection.head_issued_at
            && facts.expires_at <= catalog_projection.head_expires_at;
        require_handoff(
            valid == expected_valid,
            &format!(
                "B2b preparation {name} did not fail only after its valid signature/header proof"
            ),
        )?;
        if name == "issued_at_catalog_boundary" {
            require_handoff(
                facts.issued_at == catalog_projection.head_issued_at,
                "B2b preparation issued_at boundary is not exact",
            )?;
        }
        if name == "expires_at_catalog_boundary" {
            require_handoff(
                facts.expires_at == catalog_projection.head_expires_at,
                "B2b preparation expires_at boundary is not exact",
            )?;
        }
    }

    let response_cases = json_field(family, "response", "B2b time boundaries")?;
    require_json_keys(
        response_cases,
        &[
            "empty_interval",
            "expires_after_preparation",
            "expires_at_preparation_boundary",
            "issued_at_preparation_boundary",
            "issued_before_preparation",
        ],
        "B2b response time cases",
    )?;
    for (name, expected_valid) in [
        ("issued_at_preparation_boundary", true),
        ("expires_at_preparation_boundary", true),
        ("issued_before_preparation", false),
        ("expires_after_preparation", false),
        ("empty_interval", false),
    ] {
        let fixture = json_field(response_cases, name, "B2b response time cases")?;
        require_json_keys(
            fixture,
            &["expected_valid", "handoff"],
            "B2b response time fixture",
        )?;
        require_handoff(
            b2b_json_bool(fixture, "expected_valid")? == expected_valid,
            &format!("B2b response {name} expected-valid label drifted"),
        )?;
        let handoff = json_field(fixture, "handoff", "B2b response time fixture")?;
        let crypto = validate_b2b_authentic_crypto_handoff(
            cddl,
            catalog_projection,
            handoff,
            &format!("B2b response time {name}"),
        )?;
        let package_fields =
            numbered_fields(&crypto.package, 17, "B2b response-time package comparison")?;
        let package_changed = package_fields
            .iter()
            .zip(&base_package_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            crypto.provider_response_exact != base.provider_response_exact
                && crypto.envelope_exact != base.envelope_exact,
            &format!("B2b response time {name} was not freshly signed and re-sealed"),
        )?;
        require_handoff(
            !package_changed.is_empty()
                && package_changed.iter().all(|index| [15, 16].contains(index)),
            &format!(
                "B2b response time {name} changed decrypted package bytes outside its two validity fields"
            ),
        )?;
        let variant = vector_with_handoff(vector, handoff)?;
        let input = parse_server_visible_handoff_input(&variant)?;
        if expected_valid {
            let server = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
            validate_candidate_handoff(&variant, cddl, &server, catalog)?;
            let response_value = decode_exact_bytes(
                &crypto.provider_response_exact,
                &format!("B2b response {name}"),
            )?;
            let fields = numbered_fields(&response_value, 26, "B2b response boundary")?;
            if name == "issued_at_preparation_boundary" {
                require_handoff(
                    cbor_unsigned(fields[20], "B2b response issued_at")?
                        == crypto.preparation.issued_at,
                    "B2b response issued_at boundary is not exact",
                )?;
            } else {
                require_handoff(
                    cbor_unsigned(fields[21], "B2b response expires_at")?
                        == crypto.preparation.expires_at,
                    "B2b response expires_at boundary is not exact",
                )?;
            }
        } else {
            expect_b2b_target_error(
                validate_server_visible_handoff(cddl, catalog_projection, &input),
                &format!("response time {name}"),
                "provider response public coordinates or validity drifted",
            )?;
        }
    }

    validate_b2b_catalog_times(cddl, catalog_projection, family)?;
    validate_b2b_descriptor_times(vector, cddl, catalog, family)?;
    validate_b2b_issuer_times(cddl, catalog, family)
}

pub(crate) fn validate_b2b_catalog_times(
    cddl: &str,
    catalog: &CatalogServerProjection,
    time_family: &Value,
) -> Result<(), ProtocolToolError> {
    let cases = json_field(time_family, "catalog", "B2b time boundaries")?;
    let base_value = decode_exact_bytes(
        &catalog.signed_head_exact,
        "B2b base Catalog time comparison",
    )?;
    let base_fields = numbered_fields(&base_value, 16, "B2b base Catalog time comparison")?;
    require_json_keys(
        cases,
        &[
            "empty_interval",
            "validation_at_expires",
            "validation_at_issued",
            "validation_before_expires",
            "validation_before_issued",
        ],
        "B2b Catalog time cases",
    )?;
    for (name, expected_valid) in [
        ("validation_at_issued", true),
        ("validation_before_expires", true),
        ("validation_before_issued", false),
        ("validation_at_expires", false),
        ("empty_interval", false),
    ] {
        let fixture = json_field(cases, name, "B2b Catalog time cases")?;
        require_json_keys(
            fixture,
            &["expected_valid", "signed_head_cbor_hex", "validation_time"],
            "B2b Catalog time fixture",
        )?;
        let (_, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-head-v2",
            json_string(fixture, "signed_head_cbor_hex")?,
            &format!("B2b Catalog time {name}"),
        )?;
        let fields = numbered_fields(&value, 16, "B2b signed Catalog time head")?;
        let changed = fields
            .iter()
            .zip(&base_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            changed.iter().all(|index| [13, 14, 15].contains(index))
                && (!changed.contains(&15) || changed.iter().any(|index| [13, 14].contains(index))),
            &format!("B2b Catalog {name} changed bytes outside validity times and their signature"),
        )?;
        let unsigned = encoded_unsigned_prefix(&value, 15, "B2b signed Catalog time head")?;
        verify_signature(
            catalog.authority_public_key,
            HEAD_SIGNATURE_DOMAIN,
            &unsigned,
            cbor_fixed(fields[15], "B2b Catalog head signature")?,
            &format!("B2b Catalog time {name}"),
        )?;
        let issued_at = cbor_unsigned(fields[13], "B2b Catalog issued_at")?;
        let expires_at = cbor_unsigned(fields[14], "B2b Catalog expires_at")?;
        let validation_time = json_u64(fixture, "validation_time")?;
        let valid =
            issued_at < expires_at && validation_time >= issued_at && validation_time < expires_at;
        require_handoff(
            b2b_json_bool(fixture, "expected_valid")? == expected_valid && valid == expected_valid,
            &format!("B2b re-signed Catalog {name} did not reach only its target time predicate"),
        )?;
    }
    Ok(())
}

pub(crate) fn validate_b2b_descriptor_crypto(
    cddl: &str,
    descriptor: &Value,
    label: &str,
) -> Result<(u64, u64), ProtocolToolError> {
    require_json_keys(
        descriptor,
        &[
            "descriptor_digest_hex",
            "epoch",
            "expires_at",
            "issued_at",
            "key_id",
            "origin",
            "public_key_hex",
            "signature_hex",
            "signed_cbor_hex",
            "unsigned_cbor_hex",
        ],
        label,
    )?;
    let (exact, value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-completion-verifier-descriptor-v1",
        json_string(descriptor, "signed_cbor_hex")?,
        label,
    )?;
    let fields = numbered_fields(&value, 8, label)?;
    let unsigned = encoded_unsigned_prefix(&value, 7, label)?;
    let public_key = cbor_fixed(fields[3], label)?;
    let signature = cbor_fixed(fields[7], label)?;
    verify_signature(
        public_key,
        COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN,
        &unsigned,
        signature,
        label,
    )?;
    let issued_at = cbor_unsigned(fields[5], label)?;
    let expires_at = cbor_unsigned(fields[6], label)?;
    require_handoff(
        decode_lower_hex(json_string(descriptor, "unsigned_cbor_hex")?)? == unsigned
            && decode_json_fixed::<64>(descriptor, "signature_hex")? == signature
            && decode_json_fixed::<32>(descriptor, "descriptor_digest_hex")?
                == domain_digest(COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN, &exact)
            && decode_json_fixed::<32>(descriptor, "public_key_hex")? == public_key
            && json_u64(descriptor, "issued_at")? == issued_at
            && json_u64(descriptor, "expires_at")? == expires_at,
        &format!("{label} lower descriptor signature/digest assertions drifted"),
    )?;
    Ok((issued_at, expires_at))
}

pub(crate) fn validate_b2b_descriptor_times(
    vector: &Value,
    cddl: &str,
    catalog: &CatalogPositiveFacts,
    time_family: &Value,
) -> Result<(), ProtocolToolError> {
    let cases = json_field(time_family, "descriptor", "B2b time boundaries")?;
    require_json_keys(
        cases,
        &[
            "current_exact_boundaries",
            "expired_at_validation",
            "issued_after_validation",
            "validation_at_issued",
        ],
        "B2b descriptor time cases",
    )?;
    let base_descriptor = json_field(
        cases,
        "current_exact_boundaries",
        "B2b descriptor time cases",
    )?;
    let (_, base_descriptor_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-completion-verifier-descriptor-v1",
        json_string(base_descriptor, "signed_cbor_hex")?,
        "B2b base descriptor time comparison",
    )?;
    let base_descriptor_fields = numbered_fields(
        &base_descriptor_value,
        8,
        "B2b base descriptor time comparison",
    )?;
    for (name, expected_valid) in [
        ("current_exact_boundaries", true),
        ("validation_at_issued", true),
        ("expired_at_validation", false),
        ("issued_after_validation", false),
    ] {
        let descriptor = json_field(cases, name, "B2b descriptor time cases")?;
        let (issued_at, expires_at) =
            validate_b2b_descriptor_crypto(cddl, descriptor, &format!("B2b descriptor {name}"))?;
        let (_, descriptor_value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-completion-verifier-descriptor-v1",
            json_string(descriptor, "signed_cbor_hex")?,
            &format!("B2b descriptor {name} comparison"),
        )?;
        let descriptor_fields =
            numbered_fields(&descriptor_value, 8, "B2b descriptor time comparison")?;
        let changed = descriptor_fields
            .iter()
            .zip(&base_descriptor_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            changed.iter().all(|index| [5, 6, 7].contains(index))
                && (!changed.contains(&7) || changed.iter().any(|index| [5, 6].contains(index))),
            &format!(
                "B2b descriptor {name} changed bytes outside validity times and their signature"
            ),
        )?;
        let valid = issued_at < expires_at
            && catalog.context.validation_time >= issued_at
            && catalog.context.validation_time < expires_at;
        require_handoff(
            valid == expected_valid,
            &format!(
                "B2b signed descriptor {name} did not reach only its target currentness predicate"
            ),
        )?;
        let mut variant = vector.clone();
        let oracle = json!({
            "by_origin": {"https://recovery.example.test": descriptor.clone()},
            "classification": "trusted-origin-authenticated-completion-verifier-test-oracle-not-portable-wire-proof",
        });
        variant
            .as_object_mut()
            .ok_or_else(|| handoff_error("B2b descriptor vector root is not an object"))?
            .insert(
                "origin_authenticated_completion_verifier_descriptors".to_owned(),
                oracle,
            );
        let parsed = parse_origin_authenticated_verifier_oracle(
            &variant,
            cddl,
            catalog.context.validation_time,
        );
        if expected_valid {
            parsed?;
        } else {
            expect_b2b_target_error(parsed, name, "descriptor syntax or currentness drifted")?;
        }
    }
    Ok(())
}
