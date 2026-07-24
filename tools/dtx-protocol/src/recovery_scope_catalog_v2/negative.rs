use super::{
    COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN,
    COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN, COMPLETION_EVIDENCE_POP_DOMAIN,
    CanonicalValue, CatalogPositiveFacts, HEAD_SIGNATURE_DOMAIN, MAX_ENVELOPE_BYTES,
    PRIVATE_BODY_DOMAIN_WITHOUT_NUL, ProtocolToolError, RECOVERY_SCOPE_DOMAIN,
    VERIFIER_BINDING_DOMAIN, VERIFIER_BINDING_SIGNATURE_DOMAIN,
    VERIFIER_BINDING_SIGNATURE_DOMAIN_WITHOUT_NUL, Value, cbor_fixed, cbor_text,
    decode_exact_bytes, decode_exact_bytes_with_limit, decode_exact_cddl, decode_exact_upload_cddl,
    decode_json_fixed, decode_lower_hex, domain_digest, encode_deterministic_cbor,
    encoded_unsigned_prefix, json_field, json_string, json_u64, numbered_fields, require_json_keys,
    validate_binding_value, validate_commitment_value, validate_context_syntax,
    validate_global_issuer_epk_uniqueness, validate_head_value, validate_opening_value,
    validate_plaintext_value, validate_private_body_value, validate_proof_value,
    validate_upload_value, verify_signature,
};
#[allow(
    clippy::too_many_lines,
    reason = "the completion-evidence adversarial portfolio freezes one cryptographic and privacy boundary"
)]
pub(crate) fn validate_completion_evidence_negative_vector_family(
    vector: &Value,
    cddl: &str,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let negative = json_field(vector, "negative_completion_evidence", "Catalog V2 vector")?;
    require_json_keys(
        negative,
        &[
            "catalog_countersignature_omitted_binding",
            "catalog_countersignature_substituted_binding",
            "full_binding_digest_cross_binding_leaf",
            "issuer_authorization_after_catalog_binding",
            "issuer_authorization_before_catalog_binding",
            "issuer_authorization_digest_cross_binding_leaf",
            "issuer_authorization_empty_binding",
            "issuer_authorization_window_cross_binding_leaf",
            "issuer_authorization_window_per_leaf_drift_plaintext",
            "issuer_epk_catalog_authority_collision_binding",
            "issuer_epk_cross_binding_leaf",
            "issuer_epk_reused_across_catalogs",
            "issuer_epk_substitution_breaks_origin_authorization_binding",
            "issuer_origin_authorization_missing_nul_domain_binding",
            "issuer_origin_authorization_wrong_descriptor_key_binding",
            "issuer_origin_authorization_wrong_signature_binding",
            "issuer_pop_missing_nul_domain_binding",
            "issuer_pop_substituted_epk_binding",
            "issuer_pop_wrong_signature_binding",
            "projection_attempt_upload",
            "reused_issuer_epk_plaintext",
            "wrong_algorithm_binding",
            "wrong_purpose_binding",
        ],
        "Catalog V2 completion-evidence negative family",
    )?;

    for (field, rule) in [
        (
            "wrong_algorithm_binding",
            "recovery-scope-catalog-completion-verifier-binding-v1",
        ),
        (
            "wrong_purpose_binding",
            "recovery-scope-catalog-completion-verifier-binding-v1",
        ),
        (
            "catalog_countersignature_omitted_binding",
            "recovery-scope-catalog-completion-verifier-binding-v1",
        ),
        (
            "projection_attempt_upload",
            "recovery-scope-catalog-upload-v2",
        ),
    ] {
        let bytes = decode_lower_hex(json_string(negative, field)?)?;
        decode_exact_bytes(&bytes, field)?;
        if cddl_cat::validate_cbor_bytes(rule, cddl, &bytes).is_ok() {
            return Err(ProtocolToolError::new(format!(
                "Catalog V2 completion-evidence structural negative {field} passed CDDL"
            )));
        }
    }

    for (field, expected) in [
        (
            "issuer_authorization_empty_binding",
            "issuer authorization validity is empty",
        ),
        (
            "issuer_authorization_before_catalog_binding",
            "issuer authorization validity escapes binding or catalog",
        ),
        (
            "issuer_authorization_after_catalog_binding",
            "issuer authorization validity escapes binding or catalog",
        ),
        ("issuer_pop_wrong_signature_binding", "signature invalid"),
        ("issuer_pop_missing_nul_domain_binding", "signature invalid"),
        ("issuer_pop_substituted_epk_binding", "signature invalid"),
        (
            "issuer_epk_substitution_breaks_origin_authorization_binding",
            "signature invalid",
        ),
        (
            "issuer_epk_catalog_authority_collision_binding",
            "issuer EPK violates key separation",
        ),
        (
            "issuer_origin_authorization_wrong_signature_binding",
            "signature invalid",
        ),
        (
            "issuer_origin_authorization_missing_nul_domain_binding",
            "signature invalid",
        ),
        (
            "issuer_origin_authorization_wrong_descriptor_key_binding",
            "signature invalid",
        ),
        (
            "catalog_countersignature_substituted_binding",
            "signature invalid",
        ),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-completion-verifier-binding-v1",
        )?;
        expect_negative_error(
            validate_binding_value(
                &value,
                &facts.context,
                &facts.verifier,
                1,
                facts.openings[0].private_digest,
            )
            .map(|_| ()),
            field,
            expected,
        )?;
    }

    for field in [
        "issuer_authorization_digest_cross_binding_leaf",
        "full_binding_digest_cross_binding_leaf",
        "issuer_epk_cross_binding_leaf",
        "issuer_authorization_window_cross_binding_leaf",
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-leaf-commitment-v2",
        )?;
        expect_negative_error(
            validate_commitment_value(
                &value,
                &facts.context,
                1,
                facts.openings[0].private_digest,
                facts.openings[0].binding_digest,
                &facts.openings[0].evidence,
            )
            .map(|_| ()),
            field,
            "commitment binding mismatch",
        )?;
    }

    let (_, reused) = decode_negative_cddl(
        negative,
        cddl,
        "reused_issuer_epk_plaintext",
        "recovery-scope-catalog-plaintext-v2",
    )?;
    expect_negative_error(
        validate_plaintext_value(&reused, &facts.context, &facts.verifier).map(|_| ()),
        "reused_issuer_epk_plaintext",
        "issuer EPK reused across retained Catalog V2 bindings or generations",
    )?;

    let (_, drifted_window) = decode_negative_cddl(
        negative,
        cddl,
        "issuer_authorization_window_per_leaf_drift_plaintext",
        "recovery-scope-catalog-plaintext-v2",
    )?;
    expect_negative_error(
        validate_plaintext_value(&drifted_window, &facts.context, &facts.verifier).map(|_| ()),
        "issuer_authorization_window_per_leaf_drift_plaintext",
        "catalog-wide issuer authorization window drifted across leaves",
    )?;

    let cross_catalog = json_field(
        negative,
        "issuer_epk_reused_across_catalogs",
        "Catalog V2 completion-evidence negative family",
    )?;
    require_json_keys(
        cross_catalog,
        &["catalog_id", "generation", "opening_cbor_hex"],
        "Catalog V2 cross-catalog issuer-EPK reuse fixture",
    )?;
    let cross_catalog_id = json_string(cross_catalog, "catalog_id")?;
    let cross_generation = json_u64(cross_catalog, "generation")?;
    if cross_catalog_id == facts.context.catalog_id || cross_generation == facts.context.generation
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 cross-catalog issuer-EPK reuse fixture did not change both catalog coordinates",
        ));
    }
    let (_, cross_opening) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-opening-v2",
        json_string(cross_catalog, "opening_cbor_hex")?,
        "Catalog V2 cross-catalog issuer-EPK reuse opening",
    )?;
    let mut cross_context = facts.context.clone();
    cross_catalog_id.clone_into(&mut cross_context.catalog_id);
    cross_context.generation = cross_generation;
    validate_context_syntax(&cross_context)?;
    let cross_facts = validate_opening_value(&cross_opening, &cross_context, &facts.verifier, 1)?;
    if cross_facts.evidence.issuer_epk != facts.openings[0].evidence.issuer_epk {
        return Err(ProtocolToolError::new(
            "Catalog V2 cross-catalog issuer-EPK reuse fixture did not reuse the positive issuer EPK",
        ));
    }
    expect_negative_error(
        validate_global_issuer_epk_uniqueness(
            facts
                .openings
                .iter()
                .map(|opening| opening.evidence.issuer_epk)
                .chain(std::iter::once(cross_facts.evidence.issuer_epk)),
        ),
        "issuer_epk_reused_across_catalogs",
        "issuer EPK reused across retained Catalog V2 bindings or generations",
    )
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_negative_vector_family(
    vector: &Value,
    cddl: &str,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let negative = json_field(vector, "negative_cbor", "Catalog V2 vector")?;
    require_json_keys(
        negative,
        &[
            "binding_expired_at_use",
            "binding_outside_head_validity",
            "duplicate_plaintext",
            "head_leakage",
            "invalid_binding_validity",
            "missing_nonce_private_body",
            "missing_nul_binding_signature",
            "mixed_opening",
            "noncanonical_cbor",
            "nonconsecutive_plaintext",
            "path_catalog_mismatch_head",
            "plaintext_as_ciphertext_upload",
            "private_body_as_ciphertext_upload",
            "proof_extra_siblings",
            "proof_index_above_count",
            "proof_index_zero",
            "proof_odd_final_supplied_sibling",
            "proof_reordered_siblings",
            "proof_short_siblings",
            "proof_wrong_catalog",
            "proof_wrong_count",
            "proof_wrong_generation",
            "proof_wrong_sibling",
            "proof_wrong_side",
            "proof_wrong_version",
            "reused_nonce_plaintext",
            "self_consistent_wrong_domain_opening",
            "stale_private_digest_opening",
            "stale_receipt_digest_private_body",
            "stale_scope_digest_private_body",
            "substituted_authority_device_binding",
            "substituted_authority_key_binding",
            "substituted_binding_expires_at",
            "substituted_binding_issued_at",
            "substituted_catalog_private_body",
            "substituted_generation_private_body",
            "substituted_index_private_body",
            "substituted_verifier_descriptor_binding",
            "substituted_verifier_epoch_binding",
            "substituted_verifier_key_id_binding",
            "substituted_verifier_origin_binding",
            "substituted_verifier_public_key_binding",
            "unsorted_plaintext",
            "upload_leakage",
            "valid_signature_authority_id_mismatch_binding",
            "valid_signature_coordinate_mismatch_binding",
            "valid_signature_descriptor_mismatch_binding",
            "valid_signature_private_mismatch_binding",
            "wrong_authority_signer_binding",
            "wrong_binding_digest_commitment",
            "wrong_ciphertext_digest_head",
            "wrong_ciphertext_upload",
            "wrong_head_signature",
            "wrong_identity_head_digest",
            "wrong_identity_height_head",
            "wrong_leaf_count_head",
            "wrong_merkle_root_head",
            "wrong_private_digest_commitment",
            "wrong_scope_digest_encoding_private_body",
            "zero_nonce_private_body",
        ],
        "Catalog V2 negative family",
    )?;

    let noncanonical = decode_lower_hex(json_string(negative, "noncanonical_cbor")?)?;
    if decode_exact_bytes(&noncanonical, "noncanonical negative").is_ok() {
        return Err(ProtocolToolError::new(
            "Catalog V2 noncanonical negative was accepted",
        ));
    }
    for (field, rule) in [
        (
            "missing_nonce_private_body",
            "recovery-scope-catalog-private-body-v2",
        ),
        ("head_leakage", "recovery-scope-catalog-head-v2"),
        ("proof_index_zero", "catalog-merkle-proof-v2"),
        ("proof_wrong_version", "catalog-merkle-proof-v2"),
    ] {
        let bytes = decode_lower_hex(json_string(negative, field)?)?;
        decode_exact_bytes(&bytes, field)?;
        if cddl_cat::validate_cbor_bytes(rule, cddl, &bytes).is_ok() {
            return Err(ProtocolToolError::new(format!(
                "Catalog V2 structural negative {field} passed CDDL"
            )));
        }
    }
    let upload_leakage = decode_lower_hex(json_string(negative, "upload_leakage")?)?;
    decode_exact_bytes_with_limit(&upload_leakage, "upload_leakage", MAX_ENVELOPE_BYTES)?;
    if cddl_cat::validate_cbor_bytes("recovery-scope-catalog-upload-v2", cddl, &upload_leakage)
        .is_ok()
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 structural negative upload_leakage passed CDDL",
        ));
    }
    validate_independent_negative_constructions(vector, negative, cddl)?;
    for (field, expected) in [
        ("zero_nonce_private_body", "hiding nonce"),
        (
            "stale_receipt_digest_private_body",
            "membership-receipt digest",
        ),
        ("stale_scope_digest_private_body", "recovery-scope digest"),
        (
            "wrong_scope_digest_encoding_private_body",
            "recovery-scope digest",
        ),
        ("substituted_catalog_private_body", "coordinate mismatch"),
        ("substituted_generation_private_body", "coordinate mismatch"),
        ("substituted_index_private_body", "coordinate mismatch"),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-private-body-v2",
        )?;
        expect_negative_error(
            validate_private_body_value(&value, &facts.context, 1).map(|_| ()),
            field,
            expected,
        )?;
    }
    validate_negative_signature_fixtures(vector, negative)?;
    for (field, expected) in [
        ("substituted_verifier_origin_binding", "descriptor tuple"),
        ("substituted_verifier_key_id_binding", "descriptor tuple"),
        (
            "substituted_verifier_public_key_binding",
            "descriptor tuple",
        ),
        ("substituted_verifier_epoch_binding", "descriptor tuple"),
        (
            "substituted_verifier_descriptor_binding",
            "descriptor tuple",
        ),
        ("substituted_binding_issued_at", "signature invalid"),
        ("substituted_binding_expires_at", "escapes head"),
        ("substituted_authority_device_binding", "authority mismatch"),
        ("substituted_authority_key_binding", "authority mismatch"),
        ("wrong_authority_signer_binding", "signature invalid"),
        ("invalid_binding_validity", "inner validity"),
        ("binding_outside_head_validity", "escapes head"),
        ("binding_expired_at_use", "expired at use"),
        (
            "valid_signature_authority_id_mismatch_binding",
            "authority mismatch",
        ),
        (
            "valid_signature_coordinate_mismatch_binding",
            "coordinate/private mismatch",
        ),
        (
            "valid_signature_private_mismatch_binding",
            "coordinate/private mismatch",
        ),
        (
            "valid_signature_descriptor_mismatch_binding",
            "descriptor tuple",
        ),
        ("missing_nul_binding_signature", "signature invalid"),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-completion-verifier-binding-v1",
        )?;
        expect_negative_error(
            validate_binding_value(
                &value,
                &facts.context,
                &facts.verifier,
                1,
                facts.openings[0].private_digest,
            )
            .map(|_| ()),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        (
            "wrong_private_digest_commitment",
            "commitment binding mismatch",
        ),
        (
            "wrong_binding_digest_commitment",
            "commitment binding mismatch",
        ),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-leaf-commitment-v2",
        )?;
        expect_negative_error(
            validate_commitment_value(
                &value,
                &facts.context,
                1,
                facts.openings[0].private_digest,
                facts.openings[0].binding_digest,
                &facts.openings[0].evidence,
            )
            .map(|_| ()),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        (
            "stale_private_digest_opening",
            "coordinate/private mismatch",
        ),
        (
            "self_consistent_wrong_domain_opening",
            "coordinate/private mismatch",
        ),
        ("mixed_opening", "coordinate mismatch"),
    ] {
        let (_, value) =
            decode_negative_cddl(negative, cddl, field, "recovery-scope-catalog-opening-v2")?;
        expect_negative_error(
            validate_opening_value(&value, &facts.context, &facts.verifier, 1).map(|_| ()),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        ("reused_nonce_plaintext", "nonce reused"),
        ("unsorted_plaintext", "canonical-sorted"),
        ("duplicate_plaintext", "canonical-sorted"),
        ("nonconsecutive_plaintext", "coordinate mismatch"),
    ] {
        let (_, value) =
            decode_negative_cddl(negative, cddl, field, "recovery-scope-catalog-plaintext-v2")?;
        expect_negative_error(
            validate_plaintext_value(&value, &facts.context, &facts.verifier).map(|_| ()),
            field,
            expected,
        )?;
    }
    let positive_head_fields = numbered_fields(&facts.signed_head, 16, "positive head")?;
    let ciphertext_digest = cbor_fixed(positive_head_fields[7], "positive ciphertext digest")?;
    for (field, expected) in [
        ("wrong_merkle_root_head", "relational binding"),
        ("wrong_ciphertext_digest_head", "relational binding"),
        ("wrong_leaf_count_head", "relational binding"),
        ("wrong_identity_height_head", "relational binding"),
        ("wrong_identity_head_digest", "relational binding"),
        ("wrong_head_signature", "signature invalid"),
        ("path_catalog_mismatch_head", "relational binding"),
    ] {
        let (_, value) =
            decode_negative_cddl(negative, cddl, field, "recovery-scope-catalog-head-v2")?;
        expect_negative_error(
            validate_head_value(
                &value,
                &facts.context,
                facts.merkle_root,
                ciphertext_digest,
                facts.openings.len(),
            ),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        ("wrong_ciphertext_upload", "ciphertext digest mismatch"),
        ("plaintext_as_ciphertext_upload", "exposed plaintext"),
        ("private_body_as_ciphertext_upload", "exposed plaintext"),
    ] {
        let (_, value) = decode_exact_upload_cddl(cddl, json_string(negative, field)?, field)?;
        expect_negative_error(validate_upload_value(&value, facts), field, expected)?;
    }
    validate_negative_proofs(negative, cddl, facts)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the four reviewed adversarial constructions are proved together before rejection"
)]
pub(crate) fn validate_independent_negative_constructions(
    vector: &Value,
    negative: &Value,
    cddl: &str,
) -> Result<(), ProtocolToolError> {
    let authority = decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?;
    let wrong_authority = decode_json_fixed::<32>(vector, "wrong_authority_public_key_hex")?;

    let (_, opening) = decode_negative_cddl(
        negative,
        cddl,
        "self_consistent_wrong_domain_opening",
        "recovery-scope-catalog-opening-v2",
    )?;
    let opening_fields = numbered_fields(&opening, 3, "wrong-domain construction")?;
    let private_exact = encode_deterministic_cbor(opening_fields[0]).map_err(|error| {
        ProtocolToolError::new(format!("encode wrong-domain private body: {error}"))
    })?;
    let alternate_private_digest = domain_digest(PRIVATE_BODY_DOMAIN_WITHOUT_NUL, &private_exact);
    let binding_fields = numbered_fields(opening_fields[1], 23, "wrong-domain binding")?;
    if cbor_fixed::<32>(binding_fields[5], "wrong-domain private digest")?
        != alternate_private_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-domain opening does not use the exact missing-NUL private-body domain",
        ));
    }
    verify_signature(
        cbor_fixed(binding_fields[17], "wrong-domain evidence EPK")?,
        COMPLETION_EVIDENCE_POP_DOMAIN,
        &encoded_unsigned_prefix(opening_fields[1], 20, "wrong-domain evidence PoP")?,
        cbor_fixed(binding_fields[20], "wrong-domain evidence PoP signature")?,
        "Catalog V2 wrong-domain evidence PoP construction",
    )?;
    verify_signature(
        cbor_fixed(binding_fields[8], "wrong-domain origin verifier")?,
        COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
        &encoded_unsigned_prefix(opening_fields[1], 21, "wrong-domain origin authorization")?,
        cbor_fixed(
            binding_fields[21],
            "wrong-domain origin authorization signature",
        )?,
        "Catalog V2 wrong-domain origin authorization construction",
    )?;
    verify_signature(
        authority,
        VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &encoded_unsigned_prefix(opening_fields[1], 22, "wrong-domain binding")?,
        cbor_fixed(binding_fields[22], "wrong-domain binding signature")?,
        "Catalog V2 wrong-domain binding construction",
    )?;
    let binding_exact = encode_deterministic_cbor(opening_fields[1]).map_err(|error| {
        ProtocolToolError::new(format!("encode wrong-domain signed binding: {error}"))
    })?;
    let alternate_binding_digest = domain_digest(VERIFIER_BINDING_DOMAIN, &binding_exact);
    let commitment_fields = numbered_fields(opening_fields[2], 12, "wrong-domain commitment")?;
    if cbor_fixed::<32>(
        commitment_fields[4],
        "wrong-domain commitment private digest",
    )? != alternate_private_digest
        || cbor_fixed::<32>(
            commitment_fields[5],
            "wrong-domain commitment binding digest",
        )? != alternate_binding_digest
        || cbor_fixed::<32>(commitment_fields[11], "wrong-domain authorization digest")?
            != domain_digest(
                COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN,
                &encoded_unsigned_prefix(
                    opening_fields[1],
                    22,
                    "wrong-domain authorization digest",
                )?,
            )
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-domain opening descendants were not recomputed consistently",
        ));
    }

    let (_, missing_nul_binding) = decode_negative_cddl(
        negative,
        cddl,
        "missing_nul_binding_signature",
        "recovery-scope-catalog-completion-verifier-binding-v1",
    )?;
    let missing_nul_fields = numbered_fields(&missing_nul_binding, 23, "missing-NUL binding")?;
    let missing_nul_unsigned =
        encoded_unsigned_prefix(&missing_nul_binding, 22, "missing-NUL binding")?;
    let missing_nul_signature = cbor_fixed(missing_nul_fields[22], "missing-NUL signature")?;
    verify_signature(
        authority,
        VERIFIER_BINDING_SIGNATURE_DOMAIN_WITHOUT_NUL,
        &missing_nul_unsigned,
        missing_nul_signature,
        "Catalog V2 missing-NUL binding construction",
    )?;
    if verify_signature(
        authority,
        VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &missing_nul_unsigned,
        missing_nul_signature,
        "Catalog V2 frozen binding transcript",
    )
    .is_ok()
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 missing-NUL binding signature also verifies under the frozen transcript",
        ));
    }

    let (_, raw_scope_body) = decode_negative_cddl(
        negative,
        cddl,
        "wrong_scope_digest_encoding_private_body",
        "recovery-scope-catalog-private-body-v2",
    )?;
    let raw_scope_fields = numbered_fields(&raw_scope_body, 10, "raw-scope-digest body")?;
    let scope_fields = numbered_fields(raw_scope_fields[4], 2, "raw-scope recovery scope")?;
    let raw_scope_text = cbor_text(scope_fields[1], "raw recovery-scope text")?;
    let raw_scope_digest = domain_digest(RECOVERY_SCOPE_DOMAIN, raw_scope_text.as_bytes());
    let canonical_scope = encode_deterministic_cbor(raw_scope_fields[4]).map_err(|error| {
        ProtocolToolError::new(format!("encode canonical recovery scope: {error}"))
    })?;
    if cbor_fixed::<32>(raw_scope_fields[8], "raw recovery-scope digest")? != raw_scope_digest
        || raw_scope_digest == domain_digest(RECOVERY_SCOPE_DOMAIN, &canonical_scope)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 raw-scope negative does not prove raw text versus canonical field-5 CBOR",
        ));
    }

    let (_, wrong_head) = decode_negative_cddl(
        negative,
        cddl,
        "wrong_head_signature",
        "recovery-scope-catalog-head-v2",
    )?;
    let wrong_head_fields = numbered_fields(&wrong_head, 16, "wrong-authority head")?;
    let wrong_head_unsigned = encoded_unsigned_prefix(&wrong_head, 15, "wrong-authority head")?;
    let wrong_head_signature = cbor_fixed(wrong_head_fields[15], "wrong-authority signature")?;
    verify_signature(
        wrong_authority,
        HEAD_SIGNATURE_DOMAIN,
        &wrong_head_unsigned,
        wrong_head_signature,
        "Catalog V2 unrelated-authority head construction",
    )?;
    if verify_signature(
        authority,
        HEAD_SIGNATURE_DOMAIN,
        &wrong_head_unsigned,
        wrong_head_signature,
        "Catalog V2 frozen head authority",
    )
    .is_ok()
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-head signature also verifies under the frozen authority",
        ));
    }
    Ok(())
}

pub(crate) fn validate_negative_signature_fixtures(
    vector: &Value,
    negative: &Value,
) -> Result<(), ProtocolToolError> {
    let authority = decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?;
    let wrong_authority = decode_json_fixed::<32>(vector, "wrong_authority_public_key_hex")?;
    let rotated_verifier = decode_json_fixed::<32>(vector, "rotated_verifier_public_key_hex")?;
    if authority == wrong_authority {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-authority fixture equals catalog authority",
        ));
    }
    for (field, signer) in [
        ("wrong_authority_signer_binding", wrong_authority),
        ("valid_signature_authority_id_mismatch_binding", authority),
        ("valid_signature_coordinate_mismatch_binding", authority),
        ("valid_signature_private_mismatch_binding", authority),
        ("valid_signature_descriptor_mismatch_binding", authority),
    ] {
        let bytes = decode_lower_hex(json_string(negative, field)?)?;
        let value = decode_exact_bytes(&bytes, field)?;
        let fields = numbered_fields(&value, 23, field)?;
        verify_signature(
            signer,
            VERIFIER_BINDING_SIGNATURE_DOMAIN,
            &encoded_unsigned_prefix(&value, 22, field)?,
            cbor_fixed(fields[22], "negative binding signature")?,
            field,
        )?;
        if field == "valid_signature_descriptor_mismatch_binding"
            && cbor_fixed::<32>(fields[8], "rotated verifier fixture")? != rotated_verifier
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 rotated-verifier fixture assertion mismatch",
            ));
        }
    }
    Ok(())
}

pub(crate) fn decode_negative_cddl(
    negative: &Value,
    cddl: &str,
    field: &str,
    rule: &str,
) -> Result<(Vec<u8>, CanonicalValue), ProtocolToolError> {
    decode_exact_cddl(cddl, rule, json_string(negative, field)?, field)
}

pub(crate) fn expect_negative_error(
    result: Result<(), ProtocolToolError>,
    field: &str,
    expected: &str,
) -> Result<(), ProtocolToolError> {
    match result {
        Err(error) if error.to_string().contains(expected) => Ok(()),
        Err(error) => Err(ProtocolToolError::new(format!(
            "Catalog V2 negative {field} reached wrong check: {error}"
        ))),
        Ok(()) => Err(ProtocolToolError::new(format!(
            "Catalog V2 negative {field} was accepted"
        ))),
    }
}

pub(crate) fn validate_negative_proofs(
    negative: &Value,
    cddl: &str,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    for (field, index, leaf, expected) in [
        (
            "proof_wrong_catalog",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_wrong_generation",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_wrong_count",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_index_above_count",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_wrong_sibling",
            1,
            facts.openings[0].leaf_digest,
            "wrong root",
        ),
        (
            "proof_short_siblings",
            1,
            facts.openings[0].leaf_digest,
            "missing a sibling",
        ),
        (
            "proof_extra_siblings",
            1,
            facts.openings[0].leaf_digest,
            "surplus",
        ),
        (
            "proof_reordered_siblings",
            1,
            facts.openings[0].leaf_digest,
            "wrong root",
        ),
        (
            "proof_wrong_side",
            2,
            facts.openings[1].leaf_digest,
            "wrong root",
        ),
        (
            "proof_odd_final_supplied_sibling",
            3,
            facts.openings[2].leaf_digest,
            "surplus",
        ),
    ] {
        let (_, value) = decode_negative_cddl(negative, cddl, field, "catalog-merkle-proof-v2")?;
        expect_negative_error(
            validate_proof_value(&value, &facts.context, 3, index, leaf, facts.merkle_root),
            field,
            expected,
        )?;
    }
    Ok(())
}

pub(crate) fn rule_body<'a>(cddl: &'a str, rule: &str) -> Result<&'a str, ProtocolToolError> {
    let declaration = format!("{rule} = {{");
    let declaration_start = cddl.find(&declaration).ok_or_else(|| {
        ProtocolToolError::new(format!(
            "Recovery Scope Catalog V2 rule {rule} is not an inline map"
        ))
    })?;
    let body_start = declaration_start + declaration.len() - 1;
    let mut depth = 0_u32;
    for (offset, character) in cddl[body_start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&cddl[body_start..=body_start + offset]);
                }
            }
            _ => {}
        }
    }
    Err(ProtocolToolError::new(format!(
        "Recovery Scope Catalog V2 rule {rule} has an unterminated map"
    )))
}

pub(crate) fn numbered_map_keys(body: &str) -> Vec<usize> {
    let bytes = body.as_bytes();
    let mut keys = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_digit() || cursor > 0 && bytes[cursor - 1].is_ascii_digit() {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b':') {
            let key = body[start..cursor]
                .parse()
                .expect("ASCII decimal map key must parse as usize");
            keys.push(key);
        }
    }
    keys
}
