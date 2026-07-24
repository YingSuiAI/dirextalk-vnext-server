use super::{
    CanonicalValue, CatalogServerProjection, IDENTITY_DEVICE_ADD_DOMAIN, IDENTITY_LOG_WIRE_VERSION,
    IdentityLogEventPayloadV1, IdentityLogEventV1, MAX_DEVICE_ADD_BYTES, MAX_HPKE_CIPHERTEXT_BYTES,
    MAX_HPKE_ENCODED_ENVELOPE_BYTES, MAX_PREPARATION_BODY_BYTES, MAX_PROVIDER_RESPONSE_BODY_BYTES,
    MAX_STATUS_BODY_BYTES, OriginAuthenticatedIdentityLog, PREPARATION_DIGEST_DOMAIN,
    PREPARATION_IDEMPOTENCY_DOMAIN, PREPARATION_SIGNATURE_DOMAIN, PROVIDER_AAD_DOMAIN,
    PROVIDER_AUTHORITY_SIGNATURE_DOMAIN, PROVIDER_ENVELOPE_DOMAIN, PROVIDER_RESPONSE_DOMAIN,
    PROVIDER_SIGNATURE_DOMAIN, ProtocolToolError, RECIPIENT_KEY_DOMAIN, RESPONSE_CAPABILITY_DOMAIN,
    RESPONSE_IDEMPOTENCY_DOMAIN, ServerVisibleHandoffFacts, ServerVisibleHandoffInput, cbor_bytes,
    cbor_fixed, cbor_text, cbor_unsigned, decode_exact_cddl, decode_json_fixed, decode_lower_hex,
    domain_digest, encoded_unsigned_prefix, handoff_error, json_field, json_string, json_u64,
    numbered_fields, origin_has_device, origin_has_device_id, parse_origin_identity_state,
    require_handoff, require_json_keys, validate_exact_device_add_reduction,
    validate_independent_authority_currentness, validate_recipient_public_key_semantics,
    verify_signature,
};
#[allow(
    clippy::too_many_lines,
    reason = "the positive server-visible handoff projection is one closed admission and status contract"
)]
pub(crate) fn validate_server_visible_handoff(
    cddl: &str,
    catalog: &CatalogServerProjection,
    input: &ServerVisibleHandoffInput,
) -> Result<ServerVisibleHandoffFacts, ProtocolToolError> {
    let preparation_json = &input.preparation;
    require_json_keys(
        preparation_json,
        &[
            "candidate_device_id",
            "candidate_signing_public_key_hex",
            "cbor_hex",
            "digest_hex",
            "recipient_public_key_hex",
            "request_id",
            "signature_hex",
            "unsigned_cbor_hex",
        ],
        "Catalog V2 handoff preparation",
    )?;
    let (preparation_exact, preparation_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-v2",
        json_string(preparation_json, "cbor_hex")?,
        "Catalog V2 handoff preparation",
    )?;
    require_handoff(
        preparation_exact.len() <= MAX_PREPARATION_BODY_BYTES,
        "preparation exceeds its body bound",
    )?;
    let preparation = numbered_fields(&preparation_value, 17, "Catalog V2 handoff preparation")?;
    let preparation_unsigned =
        encoded_unsigned_prefix(&preparation_value, 16, "Catalog V2 handoff preparation")?;
    let request_id = cbor_text(preparation[1], "handoff preparation request_id")?.to_owned();
    let candidate_device_id =
        cbor_text(preparation[6], "handoff preparation candidate device")?.to_owned();
    let candidate_signing_public_key =
        cbor_fixed(preparation[7], "handoff preparation candidate signing key")?;
    let candidate_recipient_public_key =
        cbor_fixed(preparation[8], "handoff preparation recipient key")?;
    let preparation_digest = domain_digest(PREPARATION_DIGEST_DOMAIN, &preparation_exact);
    require_handoff(
        cbor_unsigned(preparation[0], "handoff preparation version")? == 2
            && cbor_text(preparation[2], "handoff preparation identity")? == catalog.identity_id
            && cbor_text(preparation[3], "handoff preparation catalog")? == catalog.catalog_id
            && cbor_unsigned(preparation[4], "handoff preparation generation")?
                == catalog.generation
            && cbor_fixed::<32>(preparation[5], "handoff preparation head digest")?
                == catalog.signed_head_digest
            && cbor_unsigned(preparation[9], "handoff preparation H")? == catalog.identity_sequence
            && cbor_fixed::<32>(preparation[10], "handoff preparation head at H")?
                == catalog.identity_head_digest,
        "preparation Catalog coordinates drifted",
    )?;
    let candidate_nonce = cbor_fixed::<32>(preparation[11], "handoff candidate nonce")?;
    require_handoff(
        candidate_nonce != [0; 32]
            && cbor_fixed::<32>(preparation[12], "handoff response capability digest")?
                == domain_digest(RESPONSE_CAPABILITY_DOMAIN, &input.response_capability)
            && cbor_fixed::<32>(preparation[13], "handoff preparation idempotency digest")?
                == domain_digest(
                    PREPARATION_IDEMPOTENCY_DOMAIN,
                    &input.preparation_idempotency_key,
                ),
        "preparation nonce or header digest drifted",
    )?;
    let preparation_issued = cbor_unsigned(preparation[14], "handoff preparation issued_at")?;
    let preparation_expires = cbor_unsigned(preparation[15], "handoff preparation expires_at")?;
    require_handoff(
        preparation_issued < preparation_expires
            && preparation_issued >= catalog.head_issued_at
            && preparation_expires <= catalog.head_expires_at,
        "preparation validity is not contained by the signed Catalog head",
    )?;
    let preparation_signature = cbor_fixed(preparation[16], "handoff preparation signature")?;
    verify_signature(
        candidate_signing_public_key,
        PREPARATION_SIGNATURE_DOMAIN,
        &preparation_unsigned,
        preparation_signature,
        "handoff preparation",
    )?;
    validate_recipient_public_key_semantics(candidate_recipient_public_key)?;
    require_handoff(
        decode_lower_hex(json_string(preparation_json, "unsigned_cbor_hex")?)?
            == preparation_unsigned
            && decode_json_fixed::<64>(preparation_json, "signature_hex")? == preparation_signature
            && decode_json_fixed::<32>(preparation_json, "digest_hex")? == preparation_digest
            && json_string(preparation_json, "request_id")? == request_id
            && json_string(preparation_json, "candidate_device_id")? == candidate_device_id
            && decode_json_fixed::<32>(preparation_json, "candidate_signing_public_key_hex")?
                == candidate_signing_public_key
            && decode_json_fixed::<32>(preparation_json, "recipient_public_key_hex")?
                == candidate_recipient_public_key
            && input.enrollment_candidate_recipient_public_key == candidate_recipient_public_key,
        "preparation JSON assertions do not match independently decoded bytes",
    )?;

    let oracle_json = &input.origin_authenticated_identity_log;
    require_json_keys(
        oracle_json,
        &["at_h", "at_h_plus_1", "classification", "origin"],
        "Catalog V2 handoff origin oracle",
    )?;
    require_handoff(
        json_string(oracle_json, "classification")?
            == "trusted-test-oracle-not-portable-wire-proof",
        "origin oracle classification drifted",
    )?;
    let identity_log = OriginAuthenticatedIdentityLog {
        origin: json_string(oracle_json, "origin")?.to_owned(),
        at_h: parse_origin_identity_state(
            json_field(oracle_json, "at_h", "Catalog V2 origin oracle")?,
            "Catalog V2 origin oracle at H",
        )?,
        at_h_plus_1: parse_origin_identity_state(
            json_field(oracle_json, "at_h_plus_1", "Catalog V2 origin oracle")?,
            "Catalog V2 origin oracle at H+1",
        )?,
    };
    require_handoff(
        identity_log.origin.starts_with("https://")
            && identity_log.at_h.sequence == catalog.identity_sequence
            && identity_log.at_h.head_digest == catalog.identity_head_digest
            && identity_log.at_h_plus_1.sequence == identity_log.at_h.sequence + 1
            && identity_log.at_h.current_root_public_key
                == identity_log.at_h_plus_1.current_root_public_key
            && identity_log.at_h.current_recovery_public_key
                == identity_log.at_h_plus_1.current_recovery_public_key,
        "origin-authenticated H/H+1 oracle drifted",
    )?;

    let device_add_json = &input.device_add;
    require_json_keys(
        device_add_json,
        &["cbor_hex", "digest_hex"],
        "Catalog V2 handoff DeviceAdd",
    )?;
    let device_add_exact = decode_lower_hex(json_string(device_add_json, "cbor_hex")?)?;
    require_handoff(
        device_add_exact.len() <= MAX_DEVICE_ADD_BYTES,
        "DeviceAdd exceeds its exact bound",
    )?;
    let device_add = IdentityLogEventV1::decode_and_verify(&device_add_exact)
        .map_err(|error| handoff_error(&format!("DeviceAdd V1.1 invalid: {error}")))?;
    let device_add_digest = domain_digest(IDENTITY_DEVICE_ADD_DOMAIN, &device_add_exact);
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = device_add.payload() else {
        return Err(handoff_error("identity event is not DeviceAdd"));
    };
    require_handoff(
        device_add.wire() == IDENTITY_LOG_WIRE_VERSION
            && device_add.identity_id().to_string() == catalog.identity_id
            && device_add.sequence().get() == identity_log.at_h_plus_1.sequence
            && device_add
                .previous_event_hash()
                .is_some_and(|digest| digest.as_bytes() == &identity_log.at_h.head_digest)
            && device_add.signer().as_bytes() == &identity_log.at_h.current_root_public_key
            && device_add
                .entry_hash()
                .is_ok_and(|digest| digest.as_bytes() == &identity_log.at_h_plus_1.head_digest)
            && certificate.identity_id() == device_add.identity_id()
            && certificate.device_id().to_string() == candidate_device_id
            && certificate.device_signing_key().as_bytes() == &candidate_signing_public_key
            && certificate.device_encryption_key().as_bytes() == &candidate_recipient_public_key
            && certificate.issuer_root_key().as_bytes()
                == &identity_log.at_h.current_root_public_key,
        "DeviceAdd transition or candidate key binding drifted",
    )?;
    require_handoff(
        !origin_has_device_id(&identity_log.at_h, &candidate_device_id)
            && origin_has_device(
                &identity_log.at_h_plus_1,
                &candidate_device_id,
                candidate_signing_public_key,
            )
            && decode_json_fixed::<32>(device_add_json, "digest_hex")? == device_add_digest,
        "DeviceAdd currentness or JSON digest assertion drifted",
    )?;
    validate_exact_device_add_reduction(
        &identity_log,
        &candidate_device_id,
        candidate_signing_public_key,
        candidate_recipient_public_key,
    )?;

    let response_json = &input.provider_response;
    require_json_keys(
        response_json,
        &[
            "authority_signature_hex",
            "cbor_hex",
            "digest_hex",
            "provider_signature_hex",
            "unsigned_cbor_hex",
        ],
        "Catalog V2 handoff provider response",
    )?;
    let (provider_response_exact, provider_response_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-v2",
        json_string(response_json, "cbor_hex")?,
        "Catalog V2 handoff provider response",
    )?;
    require_handoff(
        provider_response_exact.len() <= MAX_PROVIDER_RESPONSE_BODY_BYTES,
        "provider response exceeds its body bound",
    )?;
    let response = numbered_fields(
        &provider_response_value,
        26,
        "Catalog V2 handoff provider response",
    )?;
    let response_unsigned = encoded_unsigned_prefix(
        &provider_response_value,
        22,
        "Catalog V2 handoff provider response",
    )?;
    let provider_descriptor = numbered_fields(response[14], 3, "handoff provider descriptor")?;
    let authority_descriptor = numbered_fields(response[15], 3, "handoff authority descriptor")?;
    let provider_id = cbor_text(provider_descriptor[1], "handoff provider device")?;
    let provider_key = cbor_fixed(provider_descriptor[2], "handoff provider key")?;
    let (authority_kind, authority_key) = validate_independent_authority_currentness(
        &identity_log.at_h_plus_1,
        &candidate_device_id,
        provider_id,
        &authority_descriptor,
    )?;
    require_handoff(
        cbor_unsigned(provider_descriptor[0], "handoff provider version")? == 2
            && provider_id != candidate_device_id
            && provider_key != candidate_signing_public_key
            && authority_key != candidate_signing_public_key
            && authority_key != provider_key
            && origin_has_device(&identity_log.at_h_plus_1, provider_id, provider_key),
        "provider or independent authority key is not current and distinct",
    )?;
    let response_provider_signature = cbor_fixed(response[22], "provider response signature")?;
    let response_authority_signature = cbor_fixed(response[23], "provider authority signature")?;
    verify_signature(
        provider_key,
        PROVIDER_SIGNATURE_DOMAIN,
        &response_unsigned,
        response_provider_signature,
        "handoff provider response provider",
    )?;
    verify_signature(
        authority_key,
        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
        &response_unsigned,
        response_authority_signature,
        "handoff provider response authority",
    )?;
    let response_digest = domain_digest(PROVIDER_RESPONSE_DOMAIN, &provider_response_exact);
    let response_issued = cbor_unsigned(response[20], "handoff response issued_at")?;
    let response_expires = cbor_unsigned(response[21], "handoff response expires_at")?;
    require_handoff(
        cbor_unsigned(response[0], "handoff response version")? == 2
            && cbor_text(response[1], "handoff response request")? == request_id
            && cbor_fixed::<32>(response[2], "handoff response preparation digest")?
                == preparation_digest
            && cbor_text(response[3], "handoff response identity")? == catalog.identity_id
            && cbor_text(response[4], "handoff response catalog")? == catalog.catalog_id
            && cbor_unsigned(response[5], "handoff response generation")? == catalog.generation
            && cbor_fixed::<32>(response[6], "handoff response head digest")?
                == cbor_fixed::<32>(preparation[5], "preparation head digest")?
            && cbor_text(response[7], "handoff response candidate")? == candidate_device_id
            && cbor_fixed::<32>(response[8], "handoff recipient digest")?
                == domain_digest(RECIPIENT_KEY_DOMAIN, &candidate_recipient_public_key)
            && cbor_unsigned(response[9], "handoff response H")? == identity_log.at_h.sequence
            && cbor_fixed::<32>(response[10], "handoff response head at H")?
                == identity_log.at_h.head_digest
            && cbor_unsigned(response[11], "handoff response H+1")?
                == identity_log.at_h_plus_1.sequence
            && cbor_fixed::<32>(response[12], "handoff response head at H+1")?
                == identity_log.at_h_plus_1.head_digest
            && cbor_fixed::<32>(response[13], "handoff response DeviceAdd digest")?
                == device_add_digest
            && cbor_fixed::<32>(response[19], "handoff response idempotency digest")?
                == domain_digest(RESPONSE_IDEMPOTENCY_DOMAIN, &input.response_idempotency_key)
            && preparation_issued <= response_issued
            && response_issued < response_expires
            && response_expires <= preparation_expires,
        "provider response public coordinates or validity drifted",
    )?;
    require_handoff(
        decode_lower_hex(json_string(response_json, "unsigned_cbor_hex")?)? == response_unsigned
            && decode_json_fixed::<64>(response_json, "provider_signature_hex")?
                == response_provider_signature
            && decode_json_fixed::<64>(response_json, "authority_signature_hex")?
                == response_authority_signature
            && decode_json_fixed::<32>(response_json, "digest_hex")? == response_digest,
        "provider response JSON assertions drifted",
    )?;

    let aad_json = &input.public_aad;
    require_json_keys(
        aad_json,
        &["cbor_hex", "digest_hex"],
        "Catalog V2 handoff public AAD",
    )?;
    let (public_aad_exact, public_aad_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-public-aad-v2",
        json_string(aad_json, "cbor_hex")?,
        "Catalog V2 handoff public AAD",
    )?;
    let aad = numbered_fields(&public_aad_value, 20, "Catalog V2 handoff public AAD")?;
    let expected_aad = CanonicalValue::Map(
        response[..17]
            .iter()
            .chain(response[19..22].iter())
            .enumerate()
            .map(|(index, value)| {
                (
                    CanonicalValue::Unsigned(
                        u64::try_from(index + 1).expect("bounded AAD field index"),
                    ),
                    (*value).clone(),
                )
            })
            .collect(),
    );
    require_handoff(
        public_aad_value == expected_aad
            && cbor_fixed::<32>(aad[17], "handoff AAD idempotency digest")?
                == cbor_fixed::<32>(response[19], "handoff response idempotency digest")?,
        "raw public AAD is not exactly reconstructed from public response coordinates",
    )?;
    let aad_digest = domain_digest(PROVIDER_AAD_DOMAIN, &public_aad_exact);
    require_handoff(
        cbor_fixed::<32>(response[17], "handoff response AAD digest")? == aad_digest
            && decode_json_fixed::<32>(aad_json, "digest_hex")? == aad_digest,
        "public AAD digest assertion drifted",
    )?;

    let envelope_json = &input.hpke_envelope;
    require_json_keys(
        envelope_json,
        &["cbor_hex", "ciphertext_hex", "digest_hex", "enc_hex"],
        "Catalog V2 handoff HPKE envelope",
    )?;
    let (envelope_exact, envelope_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-hpke-envelope-v2",
        json_string(envelope_json, "cbor_hex")?,
        "Catalog V2 handoff HPKE envelope",
    )?;
    require_handoff(
        envelope_exact.len() <= MAX_HPKE_ENCODED_ENVELOPE_BYTES && envelope_value == *response[25],
        "nested HPKE envelope is not exact or exceeds its bound",
    )?;
    let envelope = numbered_fields(&envelope_value, 3, "Catalog V2 handoff HPKE envelope")?;
    let envelope_enc = cbor_fixed(envelope[1], "handoff HPKE enc")?;
    let envelope_ciphertext = cbor_bytes(envelope[2], "handoff HPKE ciphertext")?.to_vec();
    let envelope_digest = domain_digest(PROVIDER_ENVELOPE_DOMAIN, &envelope_exact);
    require_handoff(
        envelope_ciphertext.len() <= MAX_HPKE_CIPHERTEXT_BYTES
            && envelope_ciphertext.len() >= 17
            && cbor_unsigned(envelope[0], "handoff envelope version")? == 2
            && decode_json_fixed::<32>(envelope_json, "enc_hex")? == envelope_enc
            && decode_lower_hex(json_string(envelope_json, "ciphertext_hex")?)?
                == envelope_ciphertext
            && decode_json_fixed::<32>(envelope_json, "digest_hex")? == envelope_digest
            && cbor_fixed::<32>(response[18], "handoff response envelope digest")?
                == envelope_digest
            && cbor_bytes(response[24], "handoff response DeviceAdd")? == device_add_exact,
        "HPKE envelope or embedded DeviceAdd assertion drifted",
    )?;

    let receipts = &input.mutation_receipts;
    require_json_keys(
        receipts,
        &["preparation", "provider_response"],
        "Catalog V2 handoff receipts",
    )?;
    let preparation_receipt_json =
        json_field(receipts, "preparation", "Catalog V2 handoff receipts")?;
    require_json_keys(
        preparation_receipt_json,
        &["accepted_at", "cbor_hex", "request_digest_hex"],
        "Catalog V2 preparation receipt",
    )?;
    let (preparation_receipt_exact, preparation_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-receipt-v2",
        json_string(preparation_receipt_json, "cbor_hex")?,
        "Catalog V2 preparation receipt",
    )?;
    let preparation_receipt = numbered_fields(
        &preparation_receipt_value,
        4,
        "Catalog V2 preparation receipt",
    )?;
    let preparation_accepted =
        cbor_unsigned(preparation_receipt[3], "preparation receipt accepted_at")?;
    require_handoff(
        cbor_unsigned(preparation_receipt[0], "preparation receipt version")? == 2
            && cbor_text(preparation_receipt[1], "preparation receipt request")? == request_id
            && cbor_fixed::<32>(preparation_receipt[2], "preparation receipt digest")?
                == preparation_digest
            && decode_json_fixed::<32>(preparation_receipt_json, "request_digest_hex")?
                == preparation_digest
            && json_u64(preparation_receipt_json, "accepted_at")? == preparation_accepted,
        "immutable preparation receipt drifted",
    )?;
    let provider_receipt_json =
        json_field(receipts, "provider_response", "Catalog V2 handoff receipts")?;
    require_json_keys(
        provider_receipt_json,
        &["accepted_at", "cbor_hex", "response_digest_hex"],
        "Catalog V2 provider receipt",
    )?;
    let (provider_response_receipt_exact, provider_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-receipt-v2",
        json_string(provider_receipt_json, "cbor_hex")?,
        "Catalog V2 provider receipt",
    )?;
    let provider_receipt =
        numbered_fields(&provider_receipt_value, 4, "Catalog V2 provider receipt")?;
    let provider_accepted = cbor_unsigned(provider_receipt[3], "provider receipt accepted_at")?;
    require_handoff(
        cbor_unsigned(provider_receipt[0], "provider receipt version")? == 2
            && cbor_text(provider_receipt[1], "provider receipt request")? == request_id
            && cbor_fixed::<32>(provider_receipt[2], "provider receipt digest")? == response_digest
            && decode_json_fixed::<32>(provider_receipt_json, "response_digest_hex")?
                == response_digest
            && json_u64(provider_receipt_json, "accepted_at")? == provider_accepted,
        "immutable provider receipt drifted",
    )?;

    let statuses = &input.statuses;
    require_json_keys(
        statuses,
        &["cancelled", "expired", "invalidated", "pending", "ready"],
        "Catalog V2 handoff statuses",
    )?;
    let mut status_exact = Vec::with_capacity(5);
    for (name, rule, code, embedded, reason, changed_at) in [
        (
            "pending",
            "recovery-scope-catalog-status-pending-v2",
            1,
            false,
            None,
            preparation_accepted,
        ),
        (
            "ready",
            "recovery-scope-catalog-status-ready-v2",
            2,
            true,
            None,
            provider_accepted,
        ),
        (
            "expired",
            "recovery-scope-catalog-status-expired-v2",
            3,
            false,
            Some(1),
            response_expires,
        ),
        (
            "cancelled",
            "recovery-scope-catalog-status-cancelled-v2",
            4,
            false,
            Some(2),
            1_701_000_400_000,
        ),
        (
            "invalidated",
            "recovery-scope-catalog-status-invalidated-v2",
            5,
            false,
            Some(3),
            1_701_000_500_000,
        ),
    ] {
        let status_json = json_field(statuses, name, "Catalog V2 handoff statuses")?;
        let keys = if reason.is_some() {
            &["cbor_hex", "reason_code", "state_changed_at"][..]
        } else {
            &["cbor_hex", "state_changed_at"][..]
        };
        require_json_keys(status_json, keys, &format!("Catalog V2 {name} status"))?;
        let (exact, value) = decode_exact_cddl(
            cddl,
            rule,
            json_string(status_json, "cbor_hex")?,
            &format!("Catalog V2 {name} status"),
        )?;
        let fields = numbered_fields(&value, 6, &format!("Catalog V2 {name} status"))?;
        let embedded_matches = if embedded {
            fields[3] == &provider_response_value
        } else {
            fields[3] == &CanonicalValue::Null
        };
        let reason_matches = match reason {
            Some(expected) => {
                cbor_unsigned(fields[4], "handoff status reason")? == expected
                    && json_u64(status_json, "reason_code")? == expected
            }
            None => fields[4] == &CanonicalValue::Null,
        };
        require_handoff(
            cbor_unsigned(fields[0], "handoff status version")? == 2
                && cbor_text(fields[1], "handoff status request")? == request_id
                && cbor_unsigned(fields[2], "handoff status code")? == code
                && embedded_matches
                && reason_matches
                && cbor_unsigned(fields[5], "handoff status changed_at")? == changed_at
                && json_u64(status_json, "state_changed_at")? == changed_at
                && exact.len() <= MAX_STATUS_BODY_BYTES,
            &format!("{name} status drifted"),
        )?;
        status_exact.push(exact);
    }

    Ok(ServerVisibleHandoffFacts {
        request_id,
        candidate_device_id,
        candidate_signing_public_key,
        candidate_recipient_public_key,
        preparation_exact,
        preparation_digest,
        identity_log,
        device_add_exact,
        device_add_digest,
        public_aad_exact,
        envelope_exact,
        envelope_enc,
        envelope_ciphertext,
        provider_response_exact,
        provider_response_digest: response_digest,
        independent_authority_kind: authority_kind,
        independent_authority_key: authority_key,
        preparation_receipt_exact,
        provider_response_receipt_exact,
        status_exact: status_exact
            .try_into()
            .expect("five closed handoff status encodings"),
    })
}
