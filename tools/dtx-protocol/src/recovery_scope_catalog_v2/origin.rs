use super::{
    BTreeMap, CIPHERTEXT_DOMAIN, CanonicalValue, CatalogServerProjection, CatalogVectorContext,
    DEVICE_HISTORY_AUTHORITY_ID_DOMAIN, HEAD_DOMAIN, IndependentAuthorityKind,
    MAX_CIPHERTEXT_BYTES, ORIGIN_IDENTITY_SNAPSHOT_AUTHENTICATION_PUBLIC_KEY,
    ORIGIN_IDENTITY_SNAPSHOT_SIGNATURE_DOMAIN, OriginActiveDevice,
    OriginAuthenticatedCurrentIdentitySnapshot, OriginAuthenticatedIdentityLog,
    OriginIdentityState, ProtocolToolError, ServerVisibleHandoffInput, Value, VerifyingKey,
    cbor_array, cbor_bytes, cbor_fixed, cbor_text, cbor_unsigned, decode_exact_bytes,
    decode_exact_cddl, decode_exact_upload_cddl, decode_json_fixed, decode_lower_hex,
    domain_digest, encoded_unsigned_prefix, handoff_error, json_field, json_string, json_u64,
    numbered_fields, require_handoff, require_json_keys, valid_https_origin, valid_uuid_v7,
    validate_context_syntax, validate_head_value, validate_recipient_public_key_semantics,
    verify_signature,
};
#[allow(
    clippy::too_many_lines,
    reason = "the server projection must be derived exclusively from one exact signed head and ciphertext upload"
)]
pub(crate) fn validate_catalog_server_projection(
    vector: &Value,
    cddl: &str,
) -> Result<CatalogServerProjection, ProtocolToolError> {
    let catalog = json_field(vector, "catalog", "Catalog V2 vector")?;
    let (signed_head_exact, signed_head) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-head-v2",
        json_string(catalog, "head_signed_cbor_hex")?,
        "Catalog V2 server signed head",
    )?;
    let head = numbered_fields(&signed_head, 16, "Catalog V2 server signed head")?;
    let context = CatalogVectorContext {
        identity_id: cbor_text(head[2], "server head identity")?.to_owned(),
        catalog_id: cbor_text(head[1], "server head catalog")?.to_owned(),
        generation: cbor_unsigned(head[3], "server head generation")?,
        previous_head: cbor_fixed(head[4], "server head previous digest")?,
        identity_sequence: cbor_unsigned(head[8], "server head identity H")?,
        identity_head: cbor_fixed(head[9], "server head identity digest")?,
        authority_device_id: cbor_text(head[10], "server head authority device")?.to_owned(),
        authority_key_id: cbor_text(head[11], "server head authority key")?.to_owned(),
        authority_public_key: cbor_fixed(head[12], "server head authority public key")?,
        head_issued_at: cbor_unsigned(head[13], "server head issued_at")?,
        head_expires_at: cbor_unsigned(head[14], "server head expires_at")?,
        validation_time: json_u64(catalog, "validation_time")?,
    };
    validate_context_syntax(&context)?;
    let leaf_count = cbor_unsigned(head[5], "server head leaf count")?;
    let leaf_count_usize = usize::try_from(leaf_count)
        .map_err(|_| ProtocolToolError::new("Catalog V2 server leaf count does not fit usize"))?;
    let merkle_root = cbor_fixed(head[6], "server head Merkle root")?;
    let ciphertext_digest = cbor_fixed(head[7], "server head ciphertext digest")?;
    validate_head_value(
        &signed_head,
        &context,
        merkle_root,
        ciphertext_digest,
        leaf_count_usize,
    )?;
    if context.head_issued_at >= context.head_expires_at
        || context.validation_time < context.head_issued_at
        || context.validation_time >= context.head_expires_at
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server head validity invalid",
        ));
    }
    let signed_head_digest = domain_digest(HEAD_DOMAIN, &signed_head_exact);
    let ciphertext = decode_lower_hex(json_string(catalog, "ciphertext_hex")?)?;
    if ciphertext.is_empty()
        || ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || domain_digest(CIPHERTEXT_DOMAIN, &ciphertext) != ciphertext_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server ciphertext binding invalid",
        ));
    }
    let (_, upload) = decode_exact_upload_cddl(
        cddl,
        json_string(catalog, "upload_cbor_hex")?,
        "Catalog V2 server upload",
    )?;
    let upload_fields = numbered_fields(&upload, 2, "Catalog V2 server upload")?;
    if upload_fields[0] != &signed_head
        || cbor_bytes(upload_fields[1], "server upload ciphertext")? != ciphertext
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server upload/head/ciphertext mismatch",
        ));
    }
    let identity_head = json_field(catalog, "identity_head", "Catalog V2 catalog")?;
    require_json_keys(
        identity_head,
        &["digest_hex", "sequence"],
        "Catalog V2 server identity head",
    )?;
    if json_string(catalog, "identity_id")? != context.identity_id
        || json_string(catalog, "catalog_id")? != context.catalog_id
        || json_u64(catalog, "generation")? != context.generation
        || decode_json_fixed::<32>(catalog, "previous_head_digest_hex")? != context.previous_head
        || json_u64(identity_head, "sequence")? != context.identity_sequence
        || decode_json_fixed::<32>(identity_head, "digest_hex")? != context.identity_head
        || json_string(catalog, "authority_device_id")? != context.authority_device_id
        || json_string(catalog, "authority_key_id")? != context.authority_key_id
        || decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?
            != context.authority_public_key
        || json_u64(catalog, "head_issued_at")? != context.head_issued_at
        || json_u64(catalog, "head_expires_at")? != context.head_expires_at
        || decode_json_fixed::<32>(catalog, "merkle_root_hex")? != merkle_root
        || decode_json_fixed::<32>(catalog, "ciphertext_digest_hex")? != ciphertext_digest
        || decode_json_fixed::<32>(catalog, "head_digest_hex")? != signed_head_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server public assertion mismatch",
        ));
    }
    Ok(CatalogServerProjection {
        signed_head_exact,
        signed_head_digest,
        identity_id: context.identity_id,
        catalog_id: context.catalog_id,
        generation: context.generation,
        previous_head_digest: context.previous_head,
        leaf_count,
        merkle_root,
        identity_sequence: context.identity_sequence,
        identity_head_digest: context.identity_head,
        authority_device_id: context.authority_device_id,
        authority_key_id: context.authority_key_id,
        authority_public_key: context.authority_public_key,
        head_issued_at: context.head_issued_at,
        head_expires_at: context.head_expires_at,
        validation_time: context.validation_time,
        ciphertext,
        ciphertext_digest,
    })
}

pub(crate) fn parse_server_visible_handoff_input(
    vector: &Value,
) -> Result<ServerVisibleHandoffInput, ProtocolToolError> {
    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let inputs = json_field(handoff, "test_only_inputs", "Catalog V2 handoff")?;
    require_handoff(
        json_string(inputs, "classification")?
            == "public-deterministic-test-fixture-not-a-credential",
        "test-only input classification drifted",
    )?;
    Ok(ServerVisibleHandoffInput {
        preparation: json_field(handoff, "preparation", "Catalog V2 handoff")?.clone(),
        origin_authenticated_identity_log: json_field(
            handoff,
            "origin_authenticated_identity_log",
            "Catalog V2 handoff",
        )?
        .clone(),
        device_add: json_field(handoff, "device_add", "Catalog V2 handoff")?.clone(),
        provider_response: json_field(handoff, "provider_response", "Catalog V2 handoff")?.clone(),
        public_aad: json_field(handoff, "public_aad", "Catalog V2 handoff")?.clone(),
        hpke_envelope: json_field(handoff, "hpke_envelope", "Catalog V2 handoff")?.clone(),
        mutation_receipts: json_field(handoff, "mutation_receipts", "Catalog V2 handoff")?.clone(),
        statuses: json_field(handoff, "statuses", "Catalog V2 handoff")?.clone(),
        enrollment_candidate_recipient_public_key: decode_json_fixed(
            inputs,
            "enrollment_candidate_recipient_public_key_hex",
        )?,
        response_capability: decode_json_fixed(inputs, "response_capability_hex")?,
        preparation_idempotency_key: json_string(inputs, "preparation_idempotency_key_ascii")?
            .as_bytes()
            .to_vec(),
        response_idempotency_key: json_string(inputs, "response_idempotency_key_ascii")?
            .as_bytes()
            .to_vec(),
    })
}

pub(crate) fn parse_origin_active_devices(
    value: &Value,
    label: &str,
) -> Result<Vec<OriginActiveDevice>, ProtocolToolError> {
    value
        .as_array()
        .ok_or_else(|| handoff_error(&format!("{label} active_devices must be an array")))?
        .iter()
        .map(|device| {
            require_json_keys(
                device,
                &[
                    "device_id",
                    "encryption_public_key_hex",
                    "signing_public_key_hex",
                ],
                label,
            )?;
            Ok(OriginActiveDevice {
                device_id: json_string(device, "device_id")?.to_owned(),
                signing_public_key: decode_json_fixed(device, "signing_public_key_hex")?,
                encryption_public_key: decode_json_fixed(device, "encryption_public_key_hex")?,
            })
        })
        .collect()
}

pub(crate) fn parse_origin_identity_state(
    value: &Value,
    label: &str,
) -> Result<OriginIdentityState, ProtocolToolError> {
    require_json_keys(
        value,
        &[
            "active_devices",
            "current_recovery_public_key_hex",
            "current_root_public_key_hex",
            "head_digest_hex",
            "sequence",
        ],
        label,
    )?;
    Ok(OriginIdentityState {
        sequence: json_u64(value, "sequence")?,
        head_digest: decode_json_fixed(value, "head_digest_hex")?,
        current_root_public_key: decode_json_fixed(value, "current_root_public_key_hex")?,
        current_recovery_public_key: decode_json_fixed(value, "current_recovery_public_key_hex")?,
        active_devices: parse_origin_active_devices(
            json_field(value, "active_devices", label)?,
            label,
        )?,
    })
}

pub(crate) fn parse_origin_active_devices_cbor(
    value: &CanonicalValue,
    label: &str,
) -> Result<Vec<OriginActiveDevice>, ProtocolToolError> {
    cbor_array(value, label)?
        .iter()
        .map(|device| {
            let fields = numbered_fields(device, 3, label)?;
            Ok(OriginActiveDevice {
                device_id: cbor_text(fields[0], label)?.to_owned(),
                signing_public_key: cbor_fixed(fields[1], label)?,
                encryption_public_key: cbor_fixed(fields[2], label)?,
            })
        })
        .collect()
}

pub(crate) fn validate_origin_identity_state_semantics(
    state: &OriginIdentityState,
    label: &str,
) -> Result<(), ProtocolToolError> {
    require_handoff(
        state.sequence > 0 && state.head_digest != [0; 32],
        &format!("{label} sequence/head is invalid"),
    )?;
    let current_root = VerifyingKey::from_bytes(&state.current_root_public_key)
        .map_err(|_| handoff_error(&format!("{label} current root key is invalid")))?;
    require_handoff(
        !current_root.is_weak(),
        &format!("{label} current root key is invalid"),
    )?;
    let current_recovery = VerifyingKey::from_bytes(&state.current_recovery_public_key)
        .map_err(|_| handoff_error(&format!("{label} current recovery key is invalid")))?;
    require_handoff(
        !current_recovery.is_weak(),
        &format!("{label} current recovery key is invalid"),
    )?;
    let devices = indexed_active_devices(state, label)?;
    require_handoff(
        !devices.is_empty(),
        &format!("{label} has no active devices"),
    )?;
    for device in devices.values() {
        let signing_key = VerifyingKey::from_bytes(&device.signing_public_key)
            .map_err(|_| handoff_error(&format!("{label} active-device key is invalid")))?;
        require_handoff(
            !signing_key.is_weak(),
            &format!("{label} active-device key is invalid"),
        )?;
        validate_recipient_public_key_semantics(device.encryption_public_key)?;
    }
    Ok(())
}

pub(crate) fn parse_origin_authenticated_current_identity_snapshot(
    snapshot: &Value,
    label: &str,
) -> Result<OriginAuthenticatedCurrentIdentitySnapshot, ProtocolToolError> {
    require_json_keys(
        snapshot,
        &[
            "active_devices",
            "classification",
            "current_recovery_public_key_hex",
            "current_root_public_key_hex",
            "head_digest_hex",
            "origin",
            "origin_authentication_public_key_hex",
            "sequence",
            "signature_hex",
            "signed_cbor_hex",
            "unsigned_cbor_hex",
        ],
        label,
    )?;
    let signed_exact = decode_lower_hex(json_string(snapshot, "signed_cbor_hex")?)?;
    let signed_value = decode_exact_bytes(&signed_exact, label)?;
    let fields = numbered_fields(&signed_value, 10, label)?;
    let unsigned = encoded_unsigned_prefix(&signed_value, 9, label)?;
    let authentication_public_key = cbor_fixed::<32>(fields[8], label)?;
    let signature = cbor_fixed::<64>(fields[9], label)?;
    require_handoff(
        authentication_public_key == ORIGIN_IDENTITY_SNAPSHOT_AUTHENTICATION_PUBLIC_KEY,
        &format!("{label} origin trust anchor drifted"),
    )?;
    verify_signature(
        authentication_public_key,
        ORIGIN_IDENTITY_SNAPSHOT_SIGNATURE_DOMAIN,
        &unsigned,
        signature,
        label,
    )?;

    let classification = cbor_text(fields[1], label)?;
    let origin = cbor_text(fields[2], label)?.to_owned();
    let state = OriginIdentityState {
        sequence: cbor_unsigned(fields[3], label)?,
        head_digest: cbor_fixed(fields[4], label)?,
        current_root_public_key: cbor_fixed(fields[5], label)?,
        current_recovery_public_key: cbor_fixed(fields[6], label)?,
        active_devices: parse_origin_active_devices_cbor(fields[7], label)?,
    };
    validate_origin_identity_state_semantics(&state, label)?;
    let json_devices =
        parse_origin_active_devices(json_field(snapshot, "active_devices", label)?, label)?;
    require_handoff(
        cbor_unsigned(fields[0], label)? == 1
            && classification
                == "trusted-origin-authenticated-current-identity-snapshot-not-portable-wire-proof"
            && valid_https_origin(&origin)
            && json_string(snapshot, "classification")? == classification
            && json_string(snapshot, "origin")? == origin
            && json_u64(snapshot, "sequence")? == state.sequence
            && decode_json_fixed::<32>(snapshot, "head_digest_hex")? == state.head_digest
            && decode_json_fixed::<32>(snapshot, "current_root_public_key_hex")?
                == state.current_root_public_key
            && decode_json_fixed::<32>(snapshot, "current_recovery_public_key_hex")?
                == state.current_recovery_public_key
            && json_devices == state.active_devices
            && decode_json_fixed::<32>(snapshot, "origin_authentication_public_key_hex")?
                == authentication_public_key
            && decode_lower_hex(json_string(snapshot, "unsigned_cbor_hex")?)? == unsigned
            && decode_json_fixed::<64>(snapshot, "signature_hex")? == signature,
        &format!("{label} authenticated bytes/JSON/head assertions drifted"),
    )?;
    Ok(OriginAuthenticatedCurrentIdentitySnapshot { origin, state })
}

pub(crate) fn origin_has_device(
    state: &OriginIdentityState,
    device_id: &str,
    signing_key: [u8; 32],
) -> bool {
    state
        .active_devices
        .iter()
        .any(|device| device.device_id == device_id && device.signing_public_key == signing_key)
}

pub(crate) fn origin_has_device_id(state: &OriginIdentityState, device_id: &str) -> bool {
    state
        .active_devices
        .iter()
        .any(|device| device.device_id == device_id)
}

pub(crate) fn indexed_active_devices(
    state: &OriginIdentityState,
    label: &str,
) -> Result<BTreeMap<String, OriginActiveDevice>, ProtocolToolError> {
    let mut indexed = BTreeMap::new();
    for device in &state.active_devices {
        if !valid_uuid_v7(&device.device_id)
            || indexed
                .insert(device.device_id.clone(), device.clone())
                .is_some()
        {
            return Err(handoff_error(&format!(
                "{label} has an invalid or duplicate active device"
            )));
        }
    }
    Ok(indexed)
}

pub(crate) fn validate_exact_device_add_reduction(
    identity_log: &OriginAuthenticatedIdentityLog,
    candidate_device_id: &str,
    candidate_signing_public_key: [u8; 32],
    candidate_encryption_public_key: [u8; 32],
) -> Result<(), ProtocolToolError> {
    let mut expected = indexed_active_devices(&identity_log.at_h, "origin state at H")?;
    require_handoff(
        expected
            .insert(
                candidate_device_id.to_owned(),
                OriginActiveDevice {
                    device_id: candidate_device_id.to_owned(),
                    signing_public_key: candidate_signing_public_key,
                    encryption_public_key: candidate_encryption_public_key,
                },
            )
            .is_none(),
        "candidate device id already existed at H",
    )?;
    let observed = indexed_active_devices(&identity_log.at_h_plus_1, "origin state at H+1")?;
    require_handoff(
        observed == expected,
        "origin-authenticated H+1 is not exactly H plus the direct DeviceAdd candidate",
    )
}

pub(crate) fn validate_independent_authority_currentness(
    current_state: &OriginIdentityState,
    candidate_device_id: &str,
    provider_id: &str,
    authority_descriptor: &[&CanonicalValue],
) -> Result<(IndependentAuthorityKind, [u8; 32]), ProtocolToolError> {
    let authority_key = cbor_fixed(authority_descriptor[2], "handoff authority key")?;
    let authority_kind = match cbor_unsigned(authority_descriptor[0], "handoff authority kind")? {
        1 => {
            let authority_id = cbor_text(authority_descriptor[1], "handoff authority device")?;
            require_handoff(
                authority_id != candidate_device_id
                    && authority_id != provider_id
                    && origin_has_device(current_state, authority_id, authority_key),
                "active independent authority is not current and distinct in authenticated identity state",
            )?;
            IndependentAuthorityKind::ActiveDevice
        }
        2 => {
            require_handoff(
                cbor_fixed::<32>(authority_descriptor[1], "handoff root authority id")?
                    == domain_digest(DEVICE_HISTORY_AUTHORITY_ID_DOMAIN, &authority_key)
                    && authority_key == current_state.current_root_public_key,
                "root independent authority id/key is not current in authenticated identity state",
            )?;
            IndependentAuthorityKind::CurrentRoot
        }
        3 => {
            require_handoff(
                cbor_fixed::<32>(authority_descriptor[1], "handoff recovery authority id")?
                    == domain_digest(DEVICE_HISTORY_AUTHORITY_ID_DOMAIN, &authority_key)
                    && authority_key == current_state.current_recovery_public_key,
                "recovery independent authority id/key is not current in authenticated identity state",
            )?;
            IndependentAuthorityKind::CurrentRecovery
        }
        _ => return Err(handoff_error("independent authority kind is not closed")),
    };
    Ok((authority_kind, authority_key))
}
