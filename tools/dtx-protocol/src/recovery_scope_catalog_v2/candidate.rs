use super::{
    BTreeMap, BTreeSet, COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN,
    COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN, CanonicalValue, CatalogPositiveFacts,
    CatalogServerProjection, ChaCha20Poly1305, DecodedHandoffEnvelope, Deserializable, HPKE_INFO,
    HkdfSha256, IndependentAuthorityKind, KemTrait, MAX_HPKE_CIPHERTEXT_BYTES,
    MAX_HPKE_ENCODED_ENVELOPE_BYTES, MAX_PROVIDER_PACKAGE_BYTES, OpModeR,
    OriginAuthenticatedVerifierDescriptor, OriginAuthenticatedVerifierOracle,
    PREPARATION_ALTERNATE_SIGNATURE_DOMAIN, PREPARATION_SIGNATURE_DOMAIN, PROVIDER_AAD_DOMAIN,
    PROVIDER_ALTERNATE_SIGNATURE_DOMAIN, PROVIDER_AUTHORITY_ALTERNATE_SIGNATURE_DOMAIN,
    PROVIDER_AUTHORITY_SIGNATURE_DOMAIN, PROVIDER_PACKAGE_DOMAIN, PROVIDER_SIGNATURE_DOMAIN,
    PUBLIC_TEST_PSK, PUBLIC_TEST_PSK_ID, ProtocolToolError, Serializable,
    ServerVisibleHandoffFacts, Value, X25519HkdfSha256, cbor_bytes, cbor_fixed, cbor_text,
    cbor_unsigned, decode_exact_bytes, decode_exact_cddl, decode_json_fixed, decode_lower_hex,
    domain_digest, encode_deterministic_cbor, encode_lower_hex, encoded_unsigned_prefix,
    handoff_error, json, json_field, json_string, json_u64, numbered_fields,
    parse_server_visible_handoff_input, require_handoff, require_json_keys, valid_https_origin,
    valid_uuid_v7, validate_server_visible_handoff, verify_signature,
};
use hpke::PskBundle;
#[allow(
    clippy::too_many_lines,
    reason = "the trusted verifier fixture closes descriptor authenticity, exact bytes, and currentness in one parser"
)]
pub(crate) fn parse_origin_authenticated_verifier_oracle(
    vector: &Value,
    cddl: &str,
    validation_time: u64,
) -> Result<OriginAuthenticatedVerifierOracle, ProtocolToolError> {
    let oracle = json_field(
        vector,
        "origin_authenticated_completion_verifier_descriptors",
        "Catalog V2 vector",
    )?;
    require_json_keys(
        oracle,
        &["by_origin", "classification"],
        "Catalog V2 verifier oracle",
    )?;
    require_handoff(
        json_string(oracle, "classification")?
            == "trusted-origin-authenticated-completion-verifier-test-oracle-not-portable-wire-proof",
        "verifier oracle classification drifted",
    )?;
    let by_origin_json = json_field(oracle, "by_origin", "Catalog V2 verifier oracle")?
        .as_object()
        .ok_or_else(|| handoff_error("verifier oracle by_origin must be an object"))?;
    require_handoff(
        !by_origin_json.is_empty(),
        "verifier oracle must contain at least one origin-authenticated descriptor",
    )?;
    let mut by_origin = BTreeMap::new();
    for (origin_key, descriptor_json) in by_origin_json {
        require_json_keys(
            descriptor_json,
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
            "Catalog V2 origin-authenticated verifier descriptor",
        )?;
        let (signed_exact, descriptor_value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-completion-verifier-descriptor-v1",
            json_string(descriptor_json, "signed_cbor_hex")?,
            "Catalog V2 origin-authenticated completion-verifier descriptor",
        )?;
        let fields = numbered_fields(
            &descriptor_value,
            8,
            "Catalog V2 origin-authenticated completion-verifier descriptor",
        )?;
        let origin = cbor_text(fields[1], "completion-verifier descriptor origin")?.to_owned();
        let key_id = cbor_text(fields[2], "completion-verifier descriptor key id")?.to_owned();
        let public_key = cbor_fixed(fields[3], "completion-verifier descriptor public key")?;
        let epoch = cbor_unsigned(fields[4], "completion-verifier descriptor epoch")?;
        let issued_at = cbor_unsigned(fields[5], "completion-verifier descriptor issued_at")?;
        let expires_at = cbor_unsigned(fields[6], "completion-verifier descriptor expires_at")?;
        let unsigned =
            encoded_unsigned_prefix(&descriptor_value, 7, "completion-verifier descriptor")?;
        let signature = cbor_fixed::<64>(fields[7], "completion-verifier descriptor signature")?;
        verify_signature(
            public_key,
            COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN,
            &unsigned,
            signature,
            "Catalog V2 completion-verifier descriptor",
        )?;
        let descriptor_digest = domain_digest(COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN, &signed_exact);
        require_handoff(
            cbor_unsigned(fields[0], "completion-verifier descriptor version")? == 1
                && origin_key == &origin
                && valid_https_origin(&origin)
                && valid_uuid_v7(&key_id)
                && epoch > 0
                && issued_at < expires_at
                && validation_time >= issued_at
                && validation_time < expires_at
                && json_string(descriptor_json, "origin")? == origin
                && json_string(descriptor_json, "key_id")? == key_id
                && decode_json_fixed::<32>(descriptor_json, "public_key_hex")? == public_key
                && json_u64(descriptor_json, "epoch")? == epoch
                && json_u64(descriptor_json, "issued_at")? == issued_at
                && json_u64(descriptor_json, "expires_at")? == expires_at
                && decode_lower_hex(json_string(descriptor_json, "unsigned_cbor_hex")?)?
                    == unsigned
                && decode_json_fixed::<64>(descriptor_json, "signature_hex")? == signature
                && decode_json_fixed::<32>(descriptor_json, "descriptor_digest_hex")?
                    == descriptor_digest,
            "origin-authenticated verifier descriptor syntax or currentness drifted",
        )?;
        require_handoff(
            by_origin
                .insert(
                    origin.clone(),
                    OriginAuthenticatedVerifierDescriptor {
                        origin,
                        key_id,
                        public_key,
                        epoch,
                        descriptor_digest,
                        issued_at,
                        expires_at,
                        signed_exact,
                    },
                )
                .is_none(),
            "verifier oracle contains a duplicate canonical origin",
        )?;
    }
    Ok(OriginAuthenticatedVerifierOracle { by_origin })
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate-only decryption, exact package validation, and hidden verifier currentness form one privacy boundary"
)]
pub(crate) fn validate_candidate_handoff(
    vector: &Value,
    cddl: &str,
    server: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    type Kem = X25519HkdfSha256;
    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;

    let verifier_oracle =
        parse_origin_authenticated_verifier_oracle(vector, cddl, catalog.context.validation_time)?;

    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let inputs = json_field(handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let recipient_private = decode_json_fixed::<32>(inputs, "x25519_recipient_private_key_hex")?;
    let recipient_private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private)
        .map_err(|error| handoff_error(&format!("candidate private key invalid: {error}")))?;
    let derived_public = Kem::sk_to_pk(&recipient_private_key);
    require_handoff(
        derived_public.to_bytes().as_slice() == server.candidate_recipient_public_key,
        "candidate protected X25519 secret does not derive the enrolled recipient key",
    )?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&server.envelope_enc)
        .map_err(|error| handoff_error(&format!("HPKE enc invalid: {error}")))?;
    let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient_private_key,
        &encapped,
        HPKE_INFO.as_bytes(),
    )
    .map_err(|error| handoff_error(&format!("HPKE receiver setup failed: {error}")))?;
    let package_exact = receiver
        .open(&server.envelope_ciphertext, &server.public_aad_exact)
        .map_err(|error| handoff_error(&format!("HPKE open failed: {error}")))?;
    require_handoff(
        package_exact.len() <= MAX_PROVIDER_PACKAGE_BYTES,
        "decrypted provider package exceeds its bound",
    )?;
    let package_value = decode_exact_bytes(&package_exact, "Catalog V2 decrypted package")?;
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-provider-package-v2",
        cddl,
        &package_exact,
    )
    .map_err(|error| handoff_error(&format!("CDDL rejected decrypted package: {error}")))?;
    let package = numbered_fields(&package_value, 17, "Catalog V2 decrypted package")?;
    let response_value = decode_exact_bytes(
        &server.provider_response_exact,
        "Catalog V2 candidate provider response",
    )?;
    let response = numbered_fields(
        &response_value,
        26,
        "Catalog V2 candidate provider response",
    )?;
    let signed_head_exact = encode_deterministic_cbor(&catalog.signed_head)
        .map_err(|error| handoff_error(&format!("signed head encode failed: {error}")))?;
    require_handoff(
        cbor_unsigned(package[0], "candidate package version")? == 2
            && cbor_text(package[1], "candidate package request")? == server.request_id
            && cbor_fixed::<32>(package[2], "candidate package preparation digest")?
                == server.preparation_digest
            && cbor_bytes(package[3], "candidate package signed head")? == signed_head_exact
            && cbor_bytes(package[4], "candidate package Catalog plaintext")?
                == catalog.plaintext_exact
            && cbor_text(package[5], "candidate package identity")? == catalog.context.identity_id
            && cbor_text(package[6], "candidate package catalog")? == catalog.context.catalog_id
            && cbor_unsigned(package[7], "candidate package generation")?
                == catalog.context.generation
            && cbor_text(package[8], "candidate package candidate")? == server.candidate_device_id
            && cbor_fixed::<32>(package[9], "candidate package recipient key")?
                == server.candidate_recipient_public_key
            && cbor_unsigned(package[10], "candidate package H")?
                == server.identity_log.at_h.sequence
            && cbor_fixed::<32>(package[11], "candidate package head at H")?
                == server.identity_log.at_h.head_digest
            && cbor_unsigned(package[12], "candidate package H+1")?
                == server.identity_log.at_h_plus_1.sequence
            && cbor_fixed::<32>(package[13], "candidate package head at H+1")?
                == server.identity_log.at_h_plus_1.head_digest
            && cbor_fixed::<32>(package[14], "candidate package DeviceAdd digest")?
                == server.device_add_digest
            && cbor_unsigned(package[15], "candidate package issued_at")?
                == cbor_unsigned(response[20], "candidate response issued_at")?
            && cbor_unsigned(package[16], "candidate package expires_at")?
                == cbor_unsigned(response[21], "candidate response expires_at")?
            && domain_digest(PROVIDER_PACKAGE_DOMAIN, &package_exact)
                == cbor_fixed::<32>(response[16], "candidate response package digest")?,
        "decrypted package/head/plaintext/public-coordinate equality drifted",
    )?;

    let package_json = json_field(handoff, "package", "Catalog V2 handoff")?;
    require_json_keys(
        package_json,
        &["cbor_hex", "digest_hex"],
        "Catalog V2 handoff package",
    )?;
    require_handoff(
        decode_lower_hex(json_string(package_json, "cbor_hex")?)? == package_exact
            && decode_json_fixed::<32>(package_json, "digest_hex")?
                == domain_digest(PROVIDER_PACKAGE_DOMAIN, &package_exact),
        "decrypted package JSON assertions drifted",
    )?;

    let mut visible_keys = BTreeSet::from([
        server.candidate_signing_public_key,
        server.candidate_recipient_public_key,
        catalog.context.authority_public_key,
        server.identity_log.at_h.current_root_public_key,
        server.identity_log.at_h.current_recovery_public_key,
        server.identity_log.at_h_plus_1.current_root_public_key,
        server.identity_log.at_h_plus_1.current_recovery_public_key,
    ]);
    for state in [&server.identity_log.at_h, &server.identity_log.at_h_plus_1] {
        for device in &state.active_devices {
            visible_keys.insert(device.signing_public_key);
            visible_keys.insert(device.encryption_public_key);
        }
    }
    let mut issuer_keys = BTreeSet::new();
    for opening in &catalog.openings {
        let opening_fields = numbered_fields(&opening.value, 3, "candidate Catalog opening")?;
        let binding = numbered_fields(opening_fields[1], 23, "candidate Catalog verifier binding")?;
        let origin = cbor_text(binding[6], "candidate verifier origin")?;
        let descriptor = verifier_oracle.by_origin.get(origin).ok_or_else(|| {
            handoff_error("candidate verifier origin is absent from the trusted oracle")
        })?;
        let issuer_authorization_not_before =
            cbor_unsigned(binding[18], "candidate evidence authorization not_before")?;
        let issuer_authorization_expires_at =
            cbor_unsigned(binding[19], "candidate evidence authorization expires_at")?;
        require_handoff(
            descriptor.origin == origin
                && cbor_text(binding[7], "candidate verifier key id")? == descriptor.key_id
                && cbor_fixed::<32>(binding[8], "candidate verifier public key")?
                    == descriptor.public_key
                && cbor_unsigned(binding[9], "candidate verifier epoch")? == descriptor.epoch
                && cbor_fixed::<32>(binding[10], "candidate verifier descriptor digest")?
                    == descriptor.descriptor_digest
                && issuer_authorization_not_before >= descriptor.issued_at
                && issuer_authorization_expires_at <= descriptor.expires_at
                && !descriptor.signed_exact.is_empty(),
            "candidate-only verifier binding does not match the current signed origin-authenticated descriptor",
        )?;
        require_handoff(
            !visible_keys.contains(&opening.evidence.issuer_epk)
                && issuer_keys.insert(opening.evidence.issuer_epk),
            "candidate-only completion evidence issuer EPK was reused or collides with a visible key",
        )?;
        visible_keys.insert(opening.evidence.issuer_epk);
    }
    Ok(())
}

pub(crate) fn vector_with_handoff(
    vector: &Value,
    handoff: &Value,
) -> Result<Value, ProtocolToolError> {
    let mut variant = vector.clone();
    variant
        .as_object_mut()
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 vector root must be an object"))?
        .insert("handoff".to_owned(), handoff.clone());
    Ok(variant)
}

pub(crate) fn validate_handoff_authority_variants(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let variants = json_field(
        vector,
        "handoff_authority_variants",
        "Catalog V2 B2a authority variants",
    )?;
    require_json_keys(
        variants,
        &["current_recovery", "current_root"],
        "Catalog V2 B2a authority variants",
    )?;
    require_handoff(
        base.independent_authority_kind == IndependentAuthorityKind::ActiveDevice,
        "B2a base handoff must use the independent active-device authority",
    )?;

    let mut distinct_responses = BTreeSet::new();
    let mut distinct_envelopes = BTreeSet::new();
    distinct_responses.insert(base.provider_response_exact.clone());
    distinct_envelopes.insert(base.envelope_exact.clone());
    for (name, expected_kind) in [
        ("current_root", IndependentAuthorityKind::CurrentRoot),
        (
            "current_recovery",
            IndependentAuthorityKind::CurrentRecovery,
        ),
    ] {
        let handoff = json_field(variants, name, "Catalog V2 B2a authority variants")?;
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
            &format!("Catalog V2 B2a {name} handoff"),
        )?;
        let variant_vector = vector_with_handoff(vector, handoff)?;
        let input = parse_server_visible_handoff_input(&variant_vector)?;
        let facts = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
        require_handoff(
            facts.independent_authority_kind == expected_kind
                && facts.preparation_exact == base.preparation_exact
                && facts.device_add_exact == base.device_add_exact
                && facts.public_aad_exact != base.public_aad_exact
                && facts.envelope_exact != base.envelope_exact
                && facts.provider_response_exact != base.provider_response_exact
                && facts.provider_response_receipt_exact != base.provider_response_receipt_exact
                && facts.status_exact[1] != base.status_exact[1]
                && distinct_responses.insert(facts.provider_response_exact.clone())
                && distinct_envelopes.insert(facts.envelope_exact.clone()),
            &format!("B2a {name} is not a full, fresh authority-specific handoff construction"),
        )?;
        let expected_key = match expected_kind {
            IndependentAuthorityKind::CurrentRoot => {
                facts.identity_log.at_h_plus_1.current_root_public_key
            }
            IndependentAuthorityKind::CurrentRecovery => {
                facts.identity_log.at_h_plus_1.current_recovery_public_key
            }
            IndependentAuthorityKind::ActiveDevice => unreachable!("closed B2a variant table"),
        };
        require_handoff(
            facts.independent_authority_key == expected_key,
            &format!("B2a {name} did not use the current identity authority key"),
        )?;
        validate_candidate_handoff(&variant_vector, cddl, &facts, catalog)?;
    }
    Ok(())
}

pub(crate) fn decode_handoff_envelope(
    cddl: &str,
    encoded: &str,
    label: &str,
) -> Result<DecodedHandoffEnvelope, ProtocolToolError> {
    let (exact, value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-hpke-envelope-v2",
        encoded,
        label,
    )?;
    let fields = numbered_fields(&value, 3, label)?;
    require_handoff(
        exact.len() <= MAX_HPKE_ENCODED_ENVELOPE_BYTES && cbor_unsigned(fields[0], label)? == 2,
        &format!("{label} envelope version or size drifted"),
    )?;
    let enc = cbor_fixed(fields[1], label)?;
    let ciphertext = cbor_bytes(fields[2], label)?.to_vec();
    require_handoff(
        (17..=MAX_HPKE_CIPHERTEXT_BYTES).contains(&ciphertext.len()),
        &format!("{label} ciphertext size drifted"),
    )?;
    Ok(DecodedHandoffEnvelope {
        exact,
        enc,
        ciphertext,
    })
}

pub(crate) fn open_handoff_hpke_fixture(
    cddl: &str,
    encoded_envelope: &str,
    recipient_private: [u8; 32],
    info: &[u8],
    aad: &[u8],
    psk: bool,
    label: &str,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolToolError> {
    type Kem = X25519HkdfSha256;
    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;

    let envelope = decode_handoff_envelope(cddl, encoded_envelope, label)?;
    let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private)
        .map_err(|error| handoff_error(&format!("{label} private key invalid: {error}")))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|error| handoff_error(&format!("{label} enc invalid: {error}")))?;
    let mode = if psk {
        OpModeR::Psk(
            PskBundle::new(&PUBLIC_TEST_PSK, PUBLIC_TEST_PSK_ID)
                .map_err(|error| handoff_error(&format!("{label} PSK invalid: {error}")))?,
        )
    } else {
        OpModeR::Base
    };
    let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(&mode, &private_key, &encapped, info)
        .map_err(|error| handoff_error(&format!("{label} receiver setup failed: {error}")))?;
    let plaintext = receiver
        .open(&envelope.ciphertext, aad)
        .map_err(|error| handoff_error(&format!("{label} open failed: {error}")))?;
    Ok((envelope.exact, plaintext))
}

#[allow(
    clippy::too_many_lines,
    reason = "the alternate HPKE portfolio proves each complete transcript before the production rejection"
)]
pub(crate) fn validate_handoff_hpke_alternates(
    vector: &Value,
    cddl: &str,
    base: &ServerVisibleHandoffFacts,
) -> Result<(), ProtocolToolError> {
    let alternates = json_field(
        vector,
        "handoff_alternate_constructions",
        "Catalog V2 B2a alternate constructions",
    )?;
    require_json_keys(
        alternates,
        &[
            "classification",
            "hpke",
            "preparation_signatures",
            "provider_response_signatures",
        ],
        "Catalog V2 B2a alternate constructions",
    )?;
    require_handoff(
        json_string(alternates, "classification")?
            == "public-deterministic-negative-crypto-fixtures-not-credentials",
        "B2a alternate construction classification drifted",
    )?;
    let hpke = json_field(alternates, "hpke", "Catalog V2 B2a alternates")?;
    require_json_keys(
        hpke,
        &[
            "alternate_canonical_cbor_aad",
            "digest_as_aad",
            "domain_prefixed_aad",
            "hex_aad",
            "json_aad",
            "missing_nul_info",
            "psk_mode",
        ],
        "Catalog V2 B2a HPKE alternates",
    )?;

    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let inputs = json_field(handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let recipient_private = decode_json_fixed(inputs, "x25519_recipient_private_key_hex")?;
    let package_json = json_field(handoff, "package", "Catalog V2 handoff")?;
    let package_exact = decode_lower_hex(json_string(package_json, "cbor_hex")?)?;
    let aad_value = decode_exact_bytes(&base.public_aad_exact, "Catalog V2 B2a base AAD")?;
    let CanonicalValue::Map(aad_entries) = aad_value else {
        return Err(handoff_error("B2a base public AAD must be a map"));
    };
    let alternate_canonical_aad = encode_deterministic_cbor(&CanonicalValue::Array(
        aad_entries.into_iter().map(|(_, value)| value).collect(),
    ))
    .map_err(|error| handoff_error(&format!("B2a alternate AAD encode failed: {error}")))?;
    let mut domain_prefixed_aad = PROVIDER_AAD_DOMAIN.to_vec();
    domain_prefixed_aad.extend_from_slice(&base.public_aad_exact);
    let json_aad = serde_json::to_vec(&json!({
        "public_aad_cbor_hex": encode_lower_hex(&base.public_aad_exact),
    }))
    .map_err(|error| handoff_error(&format!("B2a JSON AAD encode failed: {error}")))?;
    let cases = vec![
        (
            "alternate_canonical_cbor_aad",
            alternate_canonical_aad,
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        (
            "digest_as_aad",
            domain_digest(PROVIDER_AAD_DOMAIN, &base.public_aad_exact).to_vec(),
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        (
            "domain_prefixed_aad",
            domain_prefixed_aad,
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        (
            "hex_aad",
            encode_lower_hex(&base.public_aad_exact).into_bytes(),
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        ("json_aad", json_aad, HPKE_INFO.as_bytes().to_vec(), false),
        (
            "missing_nul_info",
            base.public_aad_exact.clone(),
            HPKE_INFO.as_bytes()[..HPKE_INFO.len() - 1].to_vec(),
            false,
        ),
        (
            "psk_mode",
            base.public_aad_exact.clone(),
            HPKE_INFO.as_bytes().to_vec(),
            true,
        ),
    ];
    let mut distinct_envelopes = BTreeSet::new();
    distinct_envelopes.insert(base.envelope_exact.clone());
    for (name, aad, info, psk) in cases {
        let artifact = json_field(hpke, name, "Catalog V2 B2a HPKE alternates")?;
        if psk {
            require_json_keys(
                artifact,
                &[
                    "envelope_cbor_hex",
                    "public_test_psk_hex",
                    "public_test_psk_id_hex",
                ],
                "Catalog V2 B2a PSK alternate",
            )?;
            require_handoff(
                decode_json_fixed::<32>(artifact, "public_test_psk_hex")? == PUBLIC_TEST_PSK
                    && decode_lower_hex(json_string(artifact, "public_test_psk_id_hex")?)?
                        == PUBLIC_TEST_PSK_ID,
                "B2a public test PSK assertions drifted",
            )?;
        } else {
            require_json_keys(
                artifact,
                &["envelope_cbor_hex"],
                &format!("Catalog V2 B2a {name} alternate"),
            )?;
        }
        let encoded = json_string(artifact, "envelope_cbor_hex")?;

        // First prove the alternate construction under its own complete
        // transcript and mode. Only then exercise the production transcript.
        let (exact, plaintext) = open_handoff_hpke_fixture(
            cddl,
            encoded,
            recipient_private,
            &info,
            &aad,
            psk,
            &format!("B2a {name} alternate"),
        )?;
        require_handoff(
            plaintext == package_exact && distinct_envelopes.insert(exact),
            &format!("B2a {name} is not a unique valid alternate HPKE construction"),
        )?;
        require_handoff(
            open_handoff_hpke_fixture(
                cddl,
                encoded,
                recipient_private,
                HPKE_INFO.as_bytes(),
                &base.public_aad_exact,
                false,
                &format!("B2a {name} production attempt"),
            )
            .is_err(),
            &format!("B2a {name} alternate was accepted by production HPKE inputs"),
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "alternate preparation and dual-signature constructions are one closed cryptographic rejection portfolio"
)]
pub(crate) fn validate_handoff_signature_alternates(
    vector: &Value,
    cddl: &str,
    base: &ServerVisibleHandoffFacts,
) -> Result<(), ProtocolToolError> {
    let alternates = json_field(
        vector,
        "handoff_alternate_constructions",
        "Catalog V2 B2a alternate constructions",
    )?;
    let preparation_alternates = json_field(
        alternates,
        "preparation_signatures",
        "Catalog V2 B2a signature alternates",
    )?;
    require_json_keys(
        preparation_alternates,
        &[
            "missing_nul_domain",
            "substituted_candidate_key",
            "wrong_domain",
        ],
        "Catalog V2 B2a preparation signature alternates",
    )?;
    let base_preparation =
        decode_exact_bytes(&base.preparation_exact, "Catalog V2 B2a base preparation")?;
    let base_preparation_unsigned =
        encoded_unsigned_prefix(&base_preparation, 16, "Catalog V2 B2a base preparation")?;
    let mut preparation_encodings = BTreeSet::new();
    preparation_encodings.insert(base.preparation_exact.clone());
    for (name, domain, substituted) in [
        (
            "missing_nul_domain",
            &PREPARATION_SIGNATURE_DOMAIN[..PREPARATION_SIGNATURE_DOMAIN.len() - 1],
            false,
        ),
        (
            "wrong_domain",
            PREPARATION_ALTERNATE_SIGNATURE_DOMAIN,
            false,
        ),
        (
            "substituted_candidate_key",
            PREPARATION_SIGNATURE_DOMAIN,
            true,
        ),
    ] {
        let artifact = json_field(
            preparation_alternates,
            name,
            "Catalog V2 B2a preparation signature alternates",
        )?;
        if substituted {
            require_json_keys(
                artifact,
                &["cbor_hex", "substituted_public_key_hex"],
                "Catalog V2 B2a substituted preparation key",
            )?;
        } else {
            require_json_keys(
                artifact,
                &["cbor_hex"],
                &format!("Catalog V2 B2a {name} preparation signature"),
            )?;
        }
        let (exact, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-preparation-v2",
            json_string(artifact, "cbor_hex")?,
            &format!("Catalog V2 B2a {name} preparation"),
        )?;
        let fields = numbered_fields(&value, 17, "Catalog V2 B2a alternate preparation")?;
        let unsigned = encoded_unsigned_prefix(&value, 16, "Catalog V2 B2a alternate preparation")?;
        require_handoff(
            unsigned == base_preparation_unsigned && preparation_encodings.insert(exact),
            &format!("B2a {name} preparation did not preserve the exact unsigned bytes"),
        )?;
        let signature = cbor_fixed(fields[16], "B2a alternate preparation signature")?;
        let own_key = if substituted {
            let key = decode_json_fixed(artifact, "substituted_public_key_hex")?;
            require_handoff(
                key != base.candidate_signing_public_key,
                "B2a substituted candidate key equals the production key",
            )?;
            key
        } else {
            base.candidate_signing_public_key
        };

        // Prove the alternate key/domain transcript, then reject it with the
        // production candidate key and exact NUL-terminated domain.
        verify_signature(own_key, domain, &unsigned, signature, name)?;
        require_handoff(
            verify_signature(
                base.candidate_signing_public_key,
                PREPARATION_SIGNATURE_DOMAIN,
                &unsigned,
                signature,
                name,
            )
            .is_err(),
            &format!("B2a {name} preparation signature passed production verification"),
        )?;
    }

    let response_alternates = json_field(
        alternates,
        "provider_response_signatures",
        "Catalog V2 B2a signature alternates",
    )?;
    require_json_keys(
        response_alternates,
        &["substituted_keys", "swapped_keys", "wrong_domains"],
        "Catalog V2 B2a provider response signature alternates",
    )?;
    let base_response = decode_exact_bytes(
        &base.provider_response_exact,
        "Catalog V2 B2a base provider response",
    )?;
    let base_response_fields = numbered_fields(&base_response, 26, "B2a base response")?;
    let base_response_unsigned =
        encoded_unsigned_prefix(&base_response, 22, "Catalog V2 B2a base response")?;
    let provider_descriptor = numbered_fields(base_response_fields[14], 3, "B2a provider")?;
    let provider_key = cbor_fixed(provider_descriptor[2], "B2a provider key")?;
    let authority_key = base.independent_authority_key;
    let mut response_encodings = BTreeSet::new();
    response_encodings.insert(base.provider_response_exact.clone());
    for name in ["wrong_domains", "swapped_keys", "substituted_keys"] {
        let artifact = json_field(
            response_alternates,
            name,
            "Catalog V2 B2a provider response signature alternates",
        )?;
        if name == "substituted_keys" {
            require_json_keys(
                artifact,
                &[
                    "cbor_hex",
                    "substituted_authority_public_key_hex",
                    "substituted_provider_public_key_hex",
                ],
                "Catalog V2 B2a substituted response keys",
            )?;
        } else {
            require_json_keys(
                artifact,
                &["cbor_hex"],
                &format!("Catalog V2 B2a {name} response signatures"),
            )?;
        }
        let (exact, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-provider-response-v2",
            json_string(artifact, "cbor_hex")?,
            &format!("Catalog V2 B2a {name} provider response"),
        )?;
        let fields = numbered_fields(&value, 26, "B2a alternate provider response")?;
        let unsigned = encoded_unsigned_prefix(&value, 22, "B2a alternate provider response")?;
        require_handoff(
            unsigned == base_response_unsigned
                && fields[24] == base_response_fields[24]
                && fields[25] == base_response_fields[25]
                && response_encodings.insert(exact),
            &format!("B2a {name} response changed bytes outside its two signatures"),
        )?;
        let provider_signature = cbor_fixed(fields[22], "B2a alternate provider signature")?;
        let authority_signature = cbor_fixed(fields[23], "B2a alternate authority signature")?;
        let (own_provider_key, own_provider_domain, own_authority_key, own_authority_domain) =
            match name {
                "wrong_domains" => (
                    provider_key,
                    PROVIDER_ALTERNATE_SIGNATURE_DOMAIN,
                    authority_key,
                    PROVIDER_AUTHORITY_ALTERNATE_SIGNATURE_DOMAIN,
                ),
                "swapped_keys" => (
                    authority_key,
                    PROVIDER_SIGNATURE_DOMAIN,
                    provider_key,
                    PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
                ),
                "substituted_keys" => {
                    let substituted_provider =
                        decode_json_fixed(artifact, "substituted_provider_public_key_hex")?;
                    let substituted_authority =
                        decode_json_fixed(artifact, "substituted_authority_public_key_hex")?;
                    require_handoff(
                        substituted_provider != provider_key
                            && substituted_provider != authority_key
                            && substituted_authority != provider_key
                            && substituted_authority != authority_key
                            && substituted_provider != substituted_authority,
                        "B2a substituted response keys are not independent",
                    )?;
                    (
                        substituted_provider,
                        PROVIDER_SIGNATURE_DOMAIN,
                        substituted_authority,
                        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
                    )
                }
                _ => unreachable!("closed B2a response alternate table"),
            };

        // Prove both alternate signatures first, then require both exact
        // production signer/domain checks to fail.
        verify_signature(
            own_provider_key,
            own_provider_domain,
            &unsigned,
            provider_signature,
            name,
        )?;
        verify_signature(
            own_authority_key,
            own_authority_domain,
            &unsigned,
            authority_signature,
            name,
        )?;
        require_handoff(
            verify_signature(
                provider_key,
                PROVIDER_SIGNATURE_DOMAIN,
                &unsigned,
                provider_signature,
                name,
            )
            .is_err()
                && verify_signature(
                    authority_key,
                    PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
                    &unsigned,
                    authority_signature,
                    name,
                )
                .is_err(),
            &format!("B2a {name} response signatures passed production verification"),
        )?;
    }
    Ok(())
}
