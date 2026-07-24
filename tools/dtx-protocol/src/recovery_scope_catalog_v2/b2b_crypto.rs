use super::{
    BTreeSet, CanonicalValue, CatalogPositiveFacts, CatalogServerProjection, ChaCha20Poly1305,
    Deserializable, HPKE_INFO, HkdfSha256, KemTrait, MAX_PREPARATION_BODY_BYTES,
    MAX_PROVIDER_PACKAGE_BYTES, MAX_PROVIDER_RESPONSE_BODY_BYTES, MAX_STATUS_BODY_BYTES, OpModeR,
    PREPARATION_DIGEST_DOMAIN, PREPARATION_IDEMPOTENCY_DOMAIN, PREPARATION_SIGNATURE_DOMAIN,
    PROVIDER_AAD_DOMAIN, PROVIDER_AUTHORITY_SIGNATURE_DOMAIN, PROVIDER_ENVELOPE_DOMAIN,
    PROVIDER_PACKAGE_DOMAIN, PROVIDER_RESPONSE_DOMAIN, PROVIDER_SIGNATURE_DOMAIN,
    ProtocolToolError, RECIPIENT_KEY_DOMAIN, RESPONSE_CAPABILITY_DOMAIN,
    RESPONSE_IDEMPOTENCY_DOMAIN, Serializable, ServerVisibleHandoffFacts, Value,
    X25519_PUBLIC_VALIDATION_SCALAR, X25519HkdfSha256, cbor_fixed, cbor_text, cbor_unsigned,
    decode_exact_bytes, decode_exact_cddl, decode_handoff_envelope, decode_json_fixed,
    decode_lower_hex, domain_digest, encode_lower_hex, encoded_unsigned_prefix, handoff_error,
    json, json_field, json_string, json_u64, numbered_fields, parse_server_visible_handoff_input,
    require_handoff, require_json_keys, valid_uuid_v7, validate_candidate_handoff,
    validate_server_visible_handoff, vector_with_handoff, verify_signature,
};
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct B2bPreparationFacts {
    pub(super) exact: Vec<u8>,
    pub(super) digest: [u8; 32],
    pub(super) request_id: String,
    pub(super) candidate_device_id: String,
    pub(super) signing_public_key: [u8; 32],
    pub(super) recipient_public_key: [u8; 32],
    pub(super) signed_head_digest: [u8; 32],
    pub(super) response_capability_digest: [u8; 32],
    pub(super) idempotency_digest: [u8; 32],
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct B2bCryptoFacts {
    pub(super) preparation: B2bPreparationFacts,
    pub(super) package_exact: Vec<u8>,
    pub(super) package: CanonicalValue,
    pub(super) public_aad_exact: Vec<u8>,
    pub(super) envelope_exact: Vec<u8>,
    pub(super) provider_response_exact: Vec<u8>,
    pub(super) provider_response_digest: [u8; 32],
    pub(super) preparation_receipt_exact: Vec<u8>,
    pub(super) provider_response_receipt_exact: Vec<u8>,
    pub(super) status_exact: [Vec<u8>; 5],
}

pub(crate) fn expect_b2b_target_error<T>(
    result: Result<T, ProtocolToolError>,
    label: &str,
    expected: &str,
) -> Result<(), ProtocolToolError> {
    match result {
        Err(error) if error.to_string().contains(expected) => Ok(()),
        Err(error) => Err(handoff_error(&format!(
            "B2b {label} reached the wrong target check: {error}"
        ))),
        Ok(_) => Err(handoff_error(&format!("B2b {label} was accepted"))),
    }
}

pub(crate) fn require_b2b_handoff_shape(
    handoff: &Value,
    label: &str,
) -> Result<(), ProtocolToolError> {
    require_json_keys(
        handoff,
        &[
            "device_add",
            "hpke_envelope",
            "mutation_receipts",
            "origin_authenticated_identity_log",
            "package",
            "preparation",
            "provider_response",
            "public_aad",
            "statuses",
            "test_only_inputs",
        ],
        label,
    )
}

/// Applies the RFC 7748 contributory-behaviour check used by preparation
/// admission.  The validation scalar is public and deterministic: this is a
/// semantic public-key check, not a key-generation or credential path.
pub(crate) fn validate_recipient_public_key_semantics(
    recipient_public_key: [u8; 32],
) -> Result<(), ProtocolToolError> {
    type Kem = X25519HkdfSha256;

    let validation_private_key =
        <Kem as KemTrait>::PrivateKey::from_bytes(&X25519_PUBLIC_VALIDATION_SCALAR)
            .map_err(|_| handoff_error("fixed public X25519 validation scalar is invalid"))?;
    let candidate = <Kem as KemTrait>::EncappedKey::from_bytes(&recipient_public_key)
        .map_err(|_| handoff_error("all-zero or low-order X25519 recipient key rejected"))?;
    <Kem as KemTrait>::decap(&validation_private_key, None, &candidate)
        .map(|_| ())
        .map_err(|_| handoff_error("all-zero or low-order X25519 recipient key rejected"))
}

pub(crate) fn validate_b2b_preparation_artifact(
    cddl: &str,
    catalog: &CatalogServerProjection,
    artifact: &Value,
    response_capability: [u8; 32],
    idempotency_key: &[u8],
) -> Result<B2bPreparationFacts, ProtocolToolError> {
    require_json_keys(
        artifact,
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
        "Catalog V2 B2b preparation artifact",
    )?;
    let (exact, value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-v2",
        json_string(artifact, "cbor_hex")?,
        "Catalog V2 B2b preparation artifact",
    )?;
    require_handoff(
        exact.len() <= MAX_PREPARATION_BODY_BYTES,
        "B2b preparation exceeds its body bound",
    )?;
    let fields = numbered_fields(&value, 17, "Catalog V2 B2b preparation")?;
    let unsigned = encoded_unsigned_prefix(&value, 16, "Catalog V2 B2b preparation")?;
    let request_id = cbor_text(fields[1], "B2b preparation request")?.to_owned();
    let candidate_device_id = cbor_text(fields[6], "B2b preparation candidate")?.to_owned();
    let signing_public_key = cbor_fixed(fields[7], "B2b preparation signing key")?;
    let recipient_public_key = cbor_fixed(fields[8], "B2b preparation recipient key")?;
    let signed_head_digest = cbor_fixed(fields[5], "B2b preparation head digest")?;
    let response_capability_digest =
        cbor_fixed(fields[12], "B2b preparation response capability digest")?;
    let idempotency_digest = cbor_fixed(fields[13], "B2b preparation idempotency digest")?;
    let issued_at = cbor_unsigned(fields[14], "B2b preparation issued_at")?;
    let expires_at = cbor_unsigned(fields[15], "B2b preparation expires_at")?;
    let signature = cbor_fixed(fields[16], "B2b preparation signature")?;
    verify_signature(
        signing_public_key,
        PREPARATION_SIGNATURE_DOMAIN,
        &unsigned,
        signature,
        "B2b preparation",
    )?;
    validate_recipient_public_key_semantics(recipient_public_key)?;
    let preparation_digest = domain_digest(PREPARATION_DIGEST_DOMAIN, &exact);
    require_handoff(
        cbor_unsigned(fields[0], "B2b preparation version")? == 2
            && valid_uuid_v7(&request_id)
            && valid_uuid_v7(&candidate_device_id)
            && cbor_text(fields[2], "B2b preparation identity")? == catalog.identity_id
            && cbor_text(fields[3], "B2b preparation catalog")? == catalog.catalog_id
            && cbor_unsigned(fields[4], "B2b preparation generation")? == catalog.generation
            && signed_head_digest == catalog.signed_head_digest
            && cbor_unsigned(fields[9], "B2b preparation H")? == catalog.identity_sequence
            && cbor_fixed::<32>(fields[10], "B2b preparation head at H")?
                == catalog.identity_head_digest
            && cbor_fixed::<32>(fields[11], "B2b preparation nonce")? != [0; 32]
            && response_capability_digest
                == domain_digest(RESPONSE_CAPABILITY_DOMAIN, &response_capability)
            && idempotency_digest == domain_digest(PREPARATION_IDEMPOTENCY_DOMAIN, idempotency_key)
            && decode_lower_hex(json_string(artifact, "unsigned_cbor_hex")?)? == unsigned
            && decode_json_fixed::<64>(artifact, "signature_hex")? == signature
            && decode_json_fixed::<32>(artifact, "digest_hex")? == preparation_digest
            && json_string(artifact, "request_id")? == request_id
            && json_string(artifact, "candidate_device_id")? == candidate_device_id
            && decode_json_fixed::<32>(artifact, "candidate_signing_public_key_hex")?
                == signing_public_key
            && decode_json_fixed::<32>(artifact, "recipient_public_key_hex")?
                == recipient_public_key,
        "B2b preparation lower structural, coordinate, header-digest, signature, or JSON proof drifted",
    )?;
    Ok(B2bPreparationFacts {
        exact,
        digest: preparation_digest,
        request_id,
        candidate_device_id,
        signing_public_key,
        recipient_public_key,
        signed_head_digest,
        response_capability_digest,
        idempotency_digest,
        issued_at,
        expires_at,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "B2b negative fixtures must prove every lower crypto, receipt, and status layer before their target semantic"
)]
pub(crate) fn validate_b2b_authentic_crypto_handoff(
    cddl: &str,
    catalog: &CatalogServerProjection,
    handoff: &Value,
    label: &str,
) -> Result<B2bCryptoFacts, ProtocolToolError> {
    type Kem = X25519HkdfSha256;
    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;

    require_b2b_handoff_shape(handoff, label)?;
    let inputs = json_field(handoff, "test_only_inputs", label)?;
    require_json_keys(
        inputs,
        &[
            "classification",
            "enrollment_candidate_recipient_public_key_hex",
            "preparation_idempotency_key_ascii",
            "response_capability_hex",
            "response_idempotency_key_ascii",
            "x25519_recipient_private_key_hex",
        ],
        &format!("{label} test inputs"),
    )?;
    require_handoff(
        json_string(inputs, "classification")?
            == "public-deterministic-test-fixture-not-a-credential",
        &format!("{label} test-input classification drifted"),
    )?;
    let response_capability = decode_json_fixed(inputs, "response_capability_hex")?;
    let preparation_idempotency_key =
        json_string(inputs, "preparation_idempotency_key_ascii")?.as_bytes();
    let preparation = validate_b2b_preparation_artifact(
        cddl,
        catalog,
        json_field(handoff, "preparation", label)?,
        response_capability,
        preparation_idempotency_key,
    )?;
    require_handoff(
        decode_json_fixed::<32>(inputs, "enrollment_candidate_recipient_public_key_hex")?
            == preparation.recipient_public_key,
        &format!("{label} enrollment/preparation recipient binding drifted"),
    )?;

    let response_json = json_field(handoff, "provider_response", label)?;
    require_json_keys(
        response_json,
        &[
            "authority_signature_hex",
            "cbor_hex",
            "digest_hex",
            "provider_signature_hex",
            "unsigned_cbor_hex",
        ],
        &format!("{label} provider response"),
    )?;
    let (provider_response_exact, response_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-v2",
        json_string(response_json, "cbor_hex")?,
        &format!("{label} provider response"),
    )?;
    require_handoff(
        provider_response_exact.len() <= MAX_PROVIDER_RESPONSE_BODY_BYTES,
        &format!("{label} response exceeds its bound"),
    )?;
    let response = numbered_fields(&response_value, 26, &format!("{label} response"))?;
    let response_unsigned = encoded_unsigned_prefix(&response_value, 22, label)?;
    let provider_descriptor = numbered_fields(response[14], 3, label)?;
    let authority_descriptor = numbered_fields(response[15], 3, label)?;
    let provider_key = cbor_fixed(provider_descriptor[2], "B2b provider key")?;
    let authority_key = cbor_fixed(authority_descriptor[2], "B2b authority key")?;
    let provider_signature = cbor_fixed(response[22], "B2b provider signature")?;
    let authority_signature = cbor_fixed(response[23], "B2b authority signature")?;
    verify_signature(
        provider_key,
        PROVIDER_SIGNATURE_DOMAIN,
        &response_unsigned,
        provider_signature,
        label,
    )?;
    verify_signature(
        authority_key,
        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
        &response_unsigned,
        authority_signature,
        label,
    )?;
    let provider_response_digest =
        domain_digest(PROVIDER_RESPONSE_DOMAIN, &provider_response_exact);
    require_handoff(
        cbor_unsigned(provider_descriptor[0], "B2b provider version")? == 2
            && provider_key != preparation.signing_public_key
            && authority_key != preparation.signing_public_key
            && authority_key != provider_key
            && cbor_text(response[1], "B2b response request")? == preparation.request_id
            && cbor_fixed::<32>(response[2], "B2b response preparation digest")?
                == preparation.digest
            && cbor_text(response[3], "B2b response identity")? == catalog.identity_id
            && cbor_text(response[4], "B2b response catalog")? == catalog.catalog_id
            && cbor_unsigned(response[5], "B2b response generation")? == catalog.generation
            && cbor_fixed::<32>(response[6], "B2b response Catalog head")?
                == catalog.signed_head_digest
            && cbor_text(response[7], "B2b response candidate")? == preparation.candidate_device_id
            && cbor_fixed::<32>(response[8], "B2b response recipient digest")?
                == domain_digest(RECIPIENT_KEY_DOMAIN, &preparation.recipient_public_key)
            && cbor_fixed::<32>(response[19], "B2b response idempotency digest")?
                == domain_digest(
                    RESPONSE_IDEMPOTENCY_DOMAIN,
                    json_string(inputs, "response_idempotency_key_ascii")?.as_bytes(),
                )
            && decode_lower_hex(json_string(response_json, "unsigned_cbor_hex")?)?
                == response_unsigned
            && decode_json_fixed::<64>(response_json, "provider_signature_hex")?
                == provider_signature
            && decode_json_fixed::<64>(response_json, "authority_signature_hex")?
                == authority_signature
            && decode_json_fixed::<32>(response_json, "digest_hex")? == provider_response_digest,
        &format!("{label} response lower coordinates, signatures, or JSON proof drifted"),
    )?;

    let aad_json = json_field(handoff, "public_aad", label)?;
    require_json_keys(
        aad_json,
        &["cbor_hex", "digest_hex"],
        &format!("{label} AAD"),
    )?;
    let (public_aad_exact, aad_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-public-aad-v2",
        json_string(aad_json, "cbor_hex")?,
        &format!("{label} AAD"),
    )?;
    let expected_aad = CanonicalValue::Map(
        response[..17]
            .iter()
            .chain(response[19..22].iter())
            .enumerate()
            .map(|(index, value)| {
                (
                    CanonicalValue::Unsigned(
                        u64::try_from(index + 1).expect("bounded B2b AAD field"),
                    ),
                    (*value).clone(),
                )
            })
            .collect(),
    );
    let aad_digest = domain_digest(PROVIDER_AAD_DOMAIN, &public_aad_exact);
    require_handoff(
        aad_value == expected_aad
            && cbor_fixed::<32>(response[17], "B2b response AAD digest")? == aad_digest
            && decode_json_fixed::<32>(aad_json, "digest_hex")? == aad_digest,
        &format!("{label} raw canonical AAD proof drifted"),
    )?;

    let envelope_json = json_field(handoff, "hpke_envelope", label)?;
    require_json_keys(
        envelope_json,
        &["cbor_hex", "ciphertext_hex", "digest_hex", "enc_hex"],
        &format!("{label} envelope"),
    )?;
    let envelope = decode_handoff_envelope(
        cddl,
        json_string(envelope_json, "cbor_hex")?,
        &format!("{label} envelope"),
    )?;
    let envelope_value = decode_exact_bytes(&envelope.exact, label)?;
    let envelope_digest = domain_digest(PROVIDER_ENVELOPE_DOMAIN, &envelope.exact);
    require_handoff(
        envelope_value == *response[25]
            && decode_json_fixed::<32>(envelope_json, "enc_hex")? == envelope.enc
            && decode_lower_hex(json_string(envelope_json, "ciphertext_hex")?)?
                == envelope.ciphertext
            && decode_json_fixed::<32>(envelope_json, "digest_hex")? == envelope_digest
            && cbor_fixed::<32>(response[18], "B2b response envelope digest")? == envelope_digest,
        &format!("{label} exact envelope proof drifted"),
    )?;

    let recipient_private = decode_json_fixed::<32>(inputs, "x25519_recipient_private_key_hex")?;
    let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private)
        .map_err(|error| handoff_error(&format!("{label} recipient private invalid: {error}")))?;
    require_handoff(
        Kem::sk_to_pk(&private_key).to_bytes().as_slice() == preparation.recipient_public_key,
        &format!("{label} protected recipient secret does not derive the preparation key"),
    )?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|error| handoff_error(&format!("{label} HPKE enc invalid: {error}")))?;
    let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encapped,
        HPKE_INFO.as_bytes(),
    )
    .map_err(|error| handoff_error(&format!("{label} HPKE receiver setup failed: {error}")))?;
    let package_exact = receiver
        .open(&envelope.ciphertext, &public_aad_exact)
        .map_err(|error| handoff_error(&format!("{label} HPKE open failed: {error}")))?;
    require_handoff(
        package_exact.len() <= MAX_PROVIDER_PACKAGE_BYTES,
        &format!("{label} package exceeds its bound"),
    )?;
    let package = decode_exact_bytes(&package_exact, &format!("{label} package"))?;
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-provider-package-v2",
        cddl,
        &package_exact,
    )
    .map_err(|error| handoff_error(&format!("CDDL rejected {label} package: {error}")))?;
    let package_json = json_field(handoff, "package", label)?;
    require_json_keys(
        package_json,
        &["cbor_hex", "digest_hex"],
        &format!("{label} package assertions"),
    )?;
    let package_digest = domain_digest(PROVIDER_PACKAGE_DOMAIN, &package_exact);
    require_handoff(
        decode_lower_hex(json_string(package_json, "cbor_hex")?)? == package_exact
            && decode_json_fixed::<32>(package_json, "digest_hex")? == package_digest
            && cbor_fixed::<32>(response[16], "B2b response package digest")? == package_digest,
        &format!("{label} decrypted package digest proof drifted"),
    )?;

    let receipts = json_field(handoff, "mutation_receipts", label)?;
    require_json_keys(receipts, &["preparation", "provider_response"], label)?;
    let preparation_receipt_json = json_field(receipts, "preparation", label)?;
    require_json_keys(
        preparation_receipt_json,
        &["accepted_at", "cbor_hex", "request_digest_hex"],
        label,
    )?;
    let (preparation_receipt_exact, preparation_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-receipt-v2",
        json_string(preparation_receipt_json, "cbor_hex")?,
        label,
    )?;
    let preparation_receipt = numbered_fields(&preparation_receipt_value, 4, label)?;
    require_handoff(
        cbor_unsigned(preparation_receipt[0], label)? == 2
            && cbor_text(preparation_receipt[1], label)? == preparation.request_id
            && cbor_fixed::<32>(preparation_receipt[2], label)? == preparation.digest
            && decode_json_fixed::<32>(preparation_receipt_json, "request_digest_hex")?
                == preparation.digest
            && json_u64(preparation_receipt_json, "accepted_at")?
                == cbor_unsigned(preparation_receipt[3], label)?,
        &format!("{label} preparation receipt is not the exact immutable receipt"),
    )?;
    let provider_receipt_json = json_field(receipts, "provider_response", label)?;
    require_json_keys(
        provider_receipt_json,
        &["accepted_at", "cbor_hex", "response_digest_hex"],
        label,
    )?;
    let (provider_response_receipt_exact, provider_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-receipt-v2",
        json_string(provider_receipt_json, "cbor_hex")?,
        label,
    )?;
    let provider_receipt = numbered_fields(&provider_receipt_value, 4, label)?;
    require_handoff(
        cbor_unsigned(provider_receipt[0], label)? == 2
            && cbor_text(provider_receipt[1], label)? == preparation.request_id
            && cbor_fixed::<32>(provider_receipt[2], label)? == provider_response_digest
            && decode_json_fixed::<32>(provider_receipt_json, "response_digest_hex")?
                == provider_response_digest
            && json_u64(provider_receipt_json, "accepted_at")?
                == cbor_unsigned(provider_receipt[3], label)?,
        &format!("{label} provider receipt is not the exact immutable receipt"),
    )?;

    let statuses = json_field(handoff, "statuses", label)?;
    require_json_keys(
        statuses,
        &["cancelled", "expired", "invalidated", "pending", "ready"],
        label,
    )?;
    let mut status_exact = Vec::with_capacity(5);
    for (name, rule, code, reason, embeds_response) in [
        (
            "pending",
            "recovery-scope-catalog-status-pending-v2",
            1,
            None,
            false,
        ),
        (
            "ready",
            "recovery-scope-catalog-status-ready-v2",
            2,
            None,
            true,
        ),
        (
            "expired",
            "recovery-scope-catalog-status-expired-v2",
            3,
            Some(1),
            false,
        ),
        (
            "cancelled",
            "recovery-scope-catalog-status-cancelled-v2",
            4,
            Some(2),
            false,
        ),
        (
            "invalidated",
            "recovery-scope-catalog-status-invalidated-v2",
            5,
            Some(3),
            false,
        ),
    ] {
        let status_json = json_field(statuses, name, label)?;
        let keys = if reason.is_some() {
            &["cbor_hex", "reason_code", "state_changed_at"][..]
        } else {
            &["cbor_hex", "state_changed_at"][..]
        };
        require_json_keys(status_json, keys, label)?;
        let (exact, value) =
            decode_exact_cddl(cddl, rule, json_string(status_json, "cbor_hex")?, label)?;
        let status = numbered_fields(&value, 6, label)?;
        let response_matches = if embeds_response {
            status[3] == &response_value
        } else {
            status[3] == &CanonicalValue::Null
        };
        let reason_matches = if let Some(reason) = reason {
            cbor_unsigned(status[4], label)? == reason
                && json_u64(status_json, "reason_code")? == reason
        } else {
            status[4] == &CanonicalValue::Null
        };
        require_handoff(
            cbor_unsigned(status[0], label)? == 2
                && cbor_text(status[1], label)? == preparation.request_id
                && cbor_unsigned(status[2], label)? == code
                && response_matches
                && reason_matches
                && cbor_unsigned(status[5], label)? == json_u64(status_json, "state_changed_at")?
                && exact.len() <= MAX_STATUS_BODY_BYTES,
            &format!("{label} {name} status lower proof drifted"),
        )?;
        status_exact.push(exact);
    }
    Ok(B2bCryptoFacts {
        preparation,
        package_exact,
        package,
        public_aad_exact,
        envelope_exact: envelope.exact,
        provider_response_exact,
        provider_response_digest,
        preparation_receipt_exact,
        provider_response_receipt_exact,
        status_exact: status_exact.try_into().expect("five B2b status encodings"),
    })
}

pub(crate) fn validate_b2b_recipient_bindings(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "recipient_bindings", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "alternate_recipient_device_add_mismatch",
            "enrollment_oracle_mismatch_public_key_hex",
            "protected_secret_mismatch_private_key_hex",
        ],
        "Catalog V2 B2b recipient bindings",
    )?;
    let alternate = json_field(
        family,
        "alternate_recipient_device_add_mismatch",
        "Catalog V2 B2b recipient bindings",
    )?;
    let alternate_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        alternate,
        "B2b alternate recipient",
    )?;
    require_handoff(
        alternate_crypto.preparation.recipient_public_key != base.candidate_recipient_public_key
            && alternate_crypto.preparation.request_id == base.request_id
            && alternate_crypto.preparation.candidate_device_id == base.candidate_device_id
            && alternate_crypto.envelope_exact != base.envelope_exact
            && alternate_crypto.provider_response_exact != base.provider_response_exact,
        "B2b alternate recipient did not rebuild a distinct valid downstream crypto transcript",
    )?;
    let alternate_vector = vector_with_handoff(vector, alternate)?;
    let alternate_input = parse_server_visible_handoff_input(&alternate_vector)?;
    expect_b2b_target_error(
        validate_server_visible_handoff(cddl, catalog_projection, &alternate_input),
        "alternate recipient versus DeviceAdd",
        "DeviceAdd transition or candidate key binding drifted",
    )?;

    let mismatched_enrollment =
        decode_json_fixed::<32>(family, "enrollment_oracle_mismatch_public_key_hex")?;
    require_handoff(
        mismatched_enrollment == alternate_crypto.preparation.recipient_public_key
            && mismatched_enrollment != base.candidate_recipient_public_key,
        "B2b enrollment mismatch is not the independently valid alternate X25519 key",
    )?;
    let base_input = parse_server_visible_handoff_input(vector)?;
    let mut enrollment_input = base_input.clone();
    enrollment_input.enrollment_candidate_recipient_public_key = mismatched_enrollment;
    expect_b2b_target_error(
        validate_server_visible_handoff(cddl, catalog_projection, &enrollment_input),
        "preparation versus enrollment candidate",
        "preparation JSON assertions do not match independently decoded bytes",
    )?;

    let protected_secret =
        decode_json_fixed::<32>(family, "protected_secret_mismatch_private_key_hex")?;
    let mut protected_vector = vector.clone();
    *protected_vector
        .pointer_mut("/handoff/test_only_inputs/x25519_recipient_private_key_hex")
        .ok_or_else(|| handoff_error("B2b protected-secret mutation path missing"))? =
        json!(encode_lower_hex(&protected_secret));
    let server = validate_server_visible_handoff(cddl, catalog_projection, &base_input)?;
    require_handoff(
        server == *base,
        "B2b protected-secret case changed server-visible bytes",
    )?;
    expect_b2b_target_error(
        validate_candidate_handoff(&protected_vector, cddl, &server, catalog),
        "protected secret versus enrolled recipient",
        "candidate protected X25519 secret does not derive the enrolled recipient key",
    )
}

pub(crate) fn validate_b2b_sealed_package_mismatches(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "sealed_package_mismatches", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &["request_coordinate", "response_time", "signed_head"],
        "Catalog V2 B2b sealed-package mismatches",
    )?;
    let mut envelopes = BTreeSet::from([base.envelope_exact.clone()]);
    let mut responses = BTreeSet::from([base.provider_response_exact.clone()]);
    let base_package_exact = decode_lower_hex(json_string(
        json_field(
            json_field(vector, "handoff", "Catalog V2 vector")?,
            "package",
            "Catalog V2 handoff",
        )?,
        "cbor_hex",
    )?)?;
    let base_package = decode_exact_bytes(&base_package_exact, "B2b base package")?;
    let base_package_fields = numbered_fields(&base_package, 17, "B2b base package")?;
    for name in ["request_coordinate", "signed_head", "response_time"] {
        let handoff = json_field(family, name, "Catalog V2 B2b sealed-package mismatches")?;
        let crypto = validate_b2b_authentic_crypto_handoff(
            cddl,
            catalog_projection,
            handoff,
            &format!("B2b sealed-package {name}"),
        )?;
        let package_fields =
            numbered_fields(&crypto.package, 17, &format!("B2b sealed-package {name}"))?;
        let changed_fields = package_fields
            .iter()
            .zip(&base_package_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<Vec<_>>();
        let expected_changed_field = match name {
            "request_coordinate" => 1,
            "signed_head" => 3,
            "response_time" => 15,
            _ => unreachable!("closed B2b sealed-package mismatch family"),
        };
        require_handoff(
            crypto.preparation.exact == base.preparation_exact
                && crypto.public_aad_exact != base.public_aad_exact
                && crypto.package_exact != base_package_exact
                && changed_fields == [expected_changed_field]
                && envelopes.insert(crypto.envelope_exact.clone())
                && responses.insert(crypto.provider_response_exact.clone())
                && crypto.preparation_receipt_exact == base.preparation_receipt_exact
                && crypto.provider_response_receipt_exact != base.provider_response_receipt_exact
                && crypto.status_exact[0] == base.status_exact[0]
                && crypto.status_exact[1] != base.status_exact[1]
                && crypto.status_exact[2] == base.status_exact[2]
                && crypto.status_exact[3] == base.status_exact[3]
                && crypto.status_exact[4] == base.status_exact[4],
            &format!("B2b {name} did not rebuild every dependent outer crypto artifact"),
        )?;
        let variant = vector_with_handoff(vector, handoff)?;
        let input = parse_server_visible_handoff_input(&variant)?;
        let server = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
        expect_b2b_target_error(
            validate_candidate_handoff(&variant, cddl, &server, catalog),
            &format!("sealed-package {name}"),
            "decrypted package/head/plaintext/public-coordinate equality drifted",
        )?;
    }
    Ok(())
}
