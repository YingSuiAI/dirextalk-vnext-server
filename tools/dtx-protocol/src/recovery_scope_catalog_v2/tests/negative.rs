#[test]
fn v42_catalog_v2_vector_positive_bytes_are_independently_derived() {
    super::validate_positive_vector(&vector(), &cddl())
        .expect("Catalog V2 positive bytes, digests, and signatures must derive exactly");
}

#[test]
fn v42_catalog_v2_vector_negative_family_fails_closed() {
    let vector = vector();
    let cddl = cddl();
    let facts = super::validate_positive_vector(&vector, &cddl)
        .expect("positive Catalog V2 vector must validate first");
    super::validate_negative_vector_family(&vector, &cddl, &facts)
        .expect("Catalog V2 fixed negative family must reach exact failure checks");
}

#[test]
fn v42_catalog_v2_completion_evidence_negatives_fail_closed() {
    let vector = vector();
    let cddl = cddl();
    let facts = super::validate_positive_vector(&vector, &cddl)
        .expect("positive Catalog V2 vector must validate first");
    super::validate_completion_evidence_negative_vector_family(&vector, &cddl, &facts)
        .expect("completion-evidence negatives must reach exact failure checks");
    let negative = vector
        .get("negative_completion_evidence")
        .expect("completion-evidence negatives");

    let binding = |name| {
        super::decode_negative_cddl(
            negative,
            &cddl,
            name,
            "recovery-scope-catalog-completion-verifier-binding-v1",
        )
        .unwrap_or_else(|error| panic!("{name} must be canonical and structural: {error}"))
        .1
    };
    let pop = binding("issuer_pop_missing_nul_domain_binding");
    let pop_fields = super::numbered_fields(&pop, 23, "missing-NUL PoP").unwrap();
    let pop_unsigned = independent_unsigned_prefix(&pop, 20);
    let epk = super::cbor_fixed(pop_fields[17], "missing-NUL PoP EPK").unwrap();
    let pop_signature = super::cbor_fixed(pop_fields[20], "missing-NUL PoP signature").unwrap();
    assert!(independently_verifies(
        epk,
        &super::COMPLETION_EVIDENCE_POP_DOMAIN[..super::COMPLETION_EVIDENCE_POP_DOMAIN.len() - 1],
        &pop_unsigned,
        pop_signature,
    ));
    assert!(!independently_verifies(
        epk,
        super::COMPLETION_EVIDENCE_POP_DOMAIN,
        &pop_unsigned,
        pop_signature,
    ));

    let origin = binding("issuer_origin_authorization_missing_nul_domain_binding");
    let origin_fields = super::numbered_fields(&origin, 23, "missing-NUL origin auth").unwrap();
    let origin_unsigned = independent_unsigned_prefix(&origin, 21);
    let verifier = super::cbor_fixed(origin_fields[8], "origin verifier").unwrap();
    let origin_signature =
        super::cbor_fixed(origin_fields[21], "missing-NUL origin signature").unwrap();
    assert!(independently_verifies(
        verifier,
        &super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN
            [..super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN.len() - 1],
        &origin_unsigned,
        origin_signature,
    ));
    assert!(!independently_verifies(
        verifier,
        super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
        &origin_unsigned,
        origin_signature,
    ));

    let wrong_descriptor = binding("issuer_origin_authorization_wrong_descriptor_key_binding");
    let wrong_descriptor_fields =
        super::numbered_fields(&wrong_descriptor, 23, "wrong descriptor key").unwrap();
    let wrong_descriptor_unsigned = independent_unsigned_prefix(&wrong_descriptor, 21);
    let wrong_descriptor_signature = super::cbor_fixed(
        wrong_descriptor_fields[21],
        "wrong descriptor authorization signature",
    )
    .unwrap();
    let rotated =
        super::decode_json_fixed::<32>(&vector, "rotated_verifier_public_key_hex").unwrap();
    assert!(independently_verifies(
        rotated,
        super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
        &wrong_descriptor_unsigned,
        wrong_descriptor_signature,
    ));
    assert!(!independently_verifies(
        verifier,
        super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
        &wrong_descriptor_unsigned,
        wrong_descriptor_signature,
    ));
}

#[test]
fn v42_catalog_v2_vector_odd_duplicate_last_proofs_are_exact() {
    let vector = vector();
    let cddl = cddl();
    let facts = super::validate_positive_vector(&vector, &cddl)
        .expect("positive Catalog V2 vector must validate");
    let catalog =
        super::json_field(&vector, "catalog", "Catalog V2 vector").expect("catalog must exist");
    let proofs = super::json_field(catalog, "proofs", "Catalog V2 catalog")
        .and_then(|value| {
            value
                .as_array()
                .ok_or_else(|| super::ProtocolToolError::new("Catalog V2 proofs must be an array"))
        })
        .expect("proof assertions must be an array");
    let sibling_counts = proofs
        .iter()
        .map(|proof| {
            let (_, value) = super::decode_exact_cddl(
                &cddl,
                "catalog-merkle-proof-v2",
                super::json_string(proof, "proof_cbor_hex").expect("proof bytes must exist"),
                "proof sibling-count test",
            )
            .expect("proof must decode");
            super::numbered_fields(&value, 6, "proof")
                .and_then(|fields| super::cbor_array(fields[5], "siblings"))
                .map(<[dtx_wire::CanonicalValue]>::len)
                .expect("proof siblings must decode")
        })
        .collect::<Vec<_>>();
    assert_eq!(sibling_counts, [2, 2, 1]);
    super::validate_positive_proofs(
        &cddl,
        catalog,
        &facts.context,
        &facts.openings,
        facts.merkle_root,
    )
    .expect("three-leaf and zero-sibling single-leaf proofs must validate");
}

#[test]
fn v42_catalog_v2_vector_json_claims_are_not_trusted() {
    let cddl = cddl();
    let mut derived_claim = vector();
    replace_openapi_value(
        &mut derived_claim,
        "/catalog/head_digest_hex",
        json!("00".repeat(32)),
    );
    let Err(derived_error) = super::validate_positive_vector(&derived_claim, &cddl) else {
        panic!("tampered derived JSON claim must fail");
    };
    assert!(
        derived_error
            .to_string()
            .contains("derived assertion mismatch")
    );

    let mut exact_bytes = vector();
    let corrupted = exact_bytes
        .pointer("/negative_cbor/wrong_head_signature")
        .cloned()
        .expect("wrong-head-signature bytes must exist");
    replace_openapi_value(&mut exact_bytes, "/catalog/head_signed_cbor_hex", corrupted);
    let Err(bytes_error) = super::validate_positive_vector(&exact_bytes, &cddl) else {
        panic!("corrupted exact CBOR with unchanged JSON claims must fail");
    };
    assert!(bytes_error.to_string().contains("signature invalid"));
}

#[test]
fn v42_catalog_v2_upload_decoder_honors_ciphertext_and_envelope_boundaries() {
    let vector = vector();
    let cddl = cddl();
    let facts = super::validate_positive_vector(&vector, &cddl)
        .expect("positive Catalog V2 vector must validate");
    let upload = |ciphertext_len| {
        dtx_wire::CanonicalValue::Map(vec![
            (
                dtx_wire::CanonicalValue::Unsigned(1),
                facts.signed_head.clone(),
            ),
            (
                dtx_wire::CanonicalValue::Unsigned(2),
                dtx_wire::CanonicalValue::Bytes(vec![0x5a; ciphertext_len]),
            ),
        ])
    };

    let maximum = dtx_wire::encode_deterministic_cbor_with_limit(&upload(1_048_576), 1_065_984)
        .expect("maximum ciphertext upload must fit the frozen envelope");
    let maximum_value = super::decode_exact_upload_bytes(&cddl, &maximum, "maximum upload")
        .expect("maximum ciphertext upload must pass canonical decoding and CDDL");
    assert!(
        super::validate_upload_value(&maximum_value, &facts)
            .is_err_and(|error| error.to_string().contains("ciphertext digest mismatch")),
        "maximum ciphertext upload must reach semantic validation"
    );

    let maximum_plus_one =
        dtx_wire::encode_deterministic_cbor_with_limit(&upload(1_048_577), 1_065_984)
            .expect("max-plus-one ciphertext still fits the outer envelope");
    assert!(
        super::decode_exact_upload_bytes(
            &cddl,
            &maximum_plus_one,
            "max-plus-one ciphertext upload",
        )
        .is_err_and(|error| error.to_string().contains("CDDL rejected")),
        "max-plus-one ciphertext must decode canonically, then fail its field bound"
    );

    let envelope_overflow =
        dtx_wire::encode_deterministic_cbor_with_limit(&upload(1_065_984), 1_070_080)
            .expect("test must construct a canonical over-limit envelope");
    assert!(envelope_overflow.len() > 1_065_984);
    assert!(
        super::decode_exact_upload_bytes(&cddl, &envelope_overflow, "over-limit upload envelope",)
            .is_err_and(|error| error.to_string().contains("configured byte limit")),
        "over-limit envelope must fail before CDDL or semantic validation"
    );
}

#[test]
fn v42_catalog_v2_verifier_origin_is_one_canonical_https_dns_authority() {
    for accepted in [
        "https://a",
        "https://a.co",
        "https://verifier.example",
        "https://verifier.example:80",
        "https://node-1.recovery.example:8443",
        "https://a1.b2:65535",
    ] {
        assert!(super::valid_https_origin(accepted), "rejected {accepted}");
    }
    for rejected in [
        "http://a.co",
        "HTTPS://a.co",
        "https://A.co",
        "https://bücher.example",
        "https://a..co",
        "https://-a.co",
        "https://a-.co",
        "https://a.co.",
        "https://127.0.0.1",
        "https://127.1",
        "https://2130706433",
        "https://017700000001",
        "https://0x7f000001",
        "https://a.1",
        "https://[::1]",
        "https://user@a.co",
        "https://a.co/",
        "https://a.co/path",
        "https://a.co?query",
        "https://a.co#fragment",
        "https://a.co:443",
        "https://a.co:0443",
        "https://a.co:0444",
        "https://a.co:0",
        "https://a.co:65536",
        "https://a.co:notaport",
        "https://a.co:",
    ] {
        assert!(!super::valid_https_origin(rejected), "accepted {rejected}");
    }
    assert!(!super::valid_https_origin(&format!(
        "https://{}.example",
        "a".repeat(2_040)
    )));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the four independent construction proofs mirror one production pre-rejection gate"
)]
fn v42_catalog_v2_negative_constructions_are_independently_proven() {
    const PRIVATE_BODY_WITHOUT_NUL: &[u8] = b"dirextalk.recovery-scope-catalog-private-body.v2";
    const BINDING_SIGNATURE_WITHOUT_NUL: &[u8] =
        b"dirextalk.recovery-scope-catalog-verifier-binding-signature.v1";

    let vector = vector();
    let cddl = cddl();
    let facts = super::validate_positive_vector(&vector, &cddl)
        .expect("positive Catalog V2 vector must validate");
    let negative = super::json_field(&vector, "negative_cbor", "Catalog V2 vector")
        .expect("negative family must exist");
    let authority = super::decode_json_fixed::<32>(&vector, "catalog_authority_public_key_hex")
        .expect("authority public key must decode");
    let wrong_authority = super::decode_json_fixed::<32>(&vector, "wrong_authority_public_key_hex")
        .expect("unrelated authority public key must decode");

    let (_, wrong_domain_opening) = super::decode_negative_cddl(
        negative,
        &cddl,
        "self_consistent_wrong_domain_opening",
        "recovery-scope-catalog-opening-v2",
    )
    .expect("wrong-domain opening must be canonical and structural");
    let opening_fields = super::numbered_fields(&wrong_domain_opening, 3, "wrong-domain opening")
        .expect("wrong-domain opening fields");
    let private_exact = dtx_wire::encode_deterministic_cbor(opening_fields[0])
        .expect("wrong-domain private body must encode");
    let alternate_private_digest = independent_digest(PRIVATE_BODY_WITHOUT_NUL, &private_exact);
    let binding_fields = super::numbered_fields(opening_fields[1], 23, "wrong-domain binding")
        .expect("wrong-domain binding fields");
    assert_eq!(
        super::cbor_fixed::<32>(binding_fields[5], "wrong-domain private digest")
            .expect("wrong-domain private digest"),
        alternate_private_digest
    );
    let binding_unsigned = independent_unsigned_prefix(opening_fields[1], 22);
    assert!(independently_verifies(
        authority,
        super::VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &binding_unsigned,
        super::cbor_fixed(binding_fields[22], "wrong-domain binding signature")
            .expect("wrong-domain binding signature"),
    ));
    let binding_exact = dtx_wire::encode_deterministic_cbor(opening_fields[1])
        .expect("wrong-domain signed binding must encode");
    let alternate_binding_digest =
        independent_digest(super::VERIFIER_BINDING_DOMAIN, &binding_exact);
    let commitment_fields =
        super::numbered_fields(opening_fields[2], 12, "wrong-domain commitment")
            .expect("wrong-domain commitment fields");
    assert_eq!(
        super::cbor_fixed::<32>(commitment_fields[4], "commitment private digest")
            .expect("commitment private digest"),
        alternate_private_digest
    );
    assert_eq!(
        super::cbor_fixed::<32>(commitment_fields[5], "commitment binding digest")
            .expect("commitment binding digest"),
        alternate_binding_digest
    );
    assert!(
        super::validate_opening_value(&wrong_domain_opening, &facts.context, &facts.verifier, 1,)
            .is_err()
    );

    let (_, missing_nul_binding) = super::decode_negative_cddl(
        negative,
        &cddl,
        "missing_nul_binding_signature",
        "recovery-scope-catalog-completion-verifier-binding-v1",
    )
    .expect("missing-NUL binding must be canonical and structural");
    let missing_nul_fields =
        super::numbered_fields(&missing_nul_binding, 23, "missing-NUL binding")
            .expect("missing-NUL binding fields");
    let missing_nul_unsigned = independent_unsigned_prefix(&missing_nul_binding, 22);
    let missing_nul_signature = super::cbor_fixed(missing_nul_fields[22], "missing-NUL signature")
        .expect("missing-NUL signature");
    assert!(independently_verifies(
        authority,
        BINDING_SIGNATURE_WITHOUT_NUL,
        &missing_nul_unsigned,
        missing_nul_signature,
    ));
    assert!(!independently_verifies(
        authority,
        super::VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &missing_nul_unsigned,
        missing_nul_signature,
    ));
    assert!(
        super::validate_binding_value(
            &missing_nul_binding,
            &facts.context,
            &facts.verifier,
            1,
            facts.openings[0].private_digest,
        )
        .is_err()
    );

    let (_, raw_scope_digest_body) = super::decode_negative_cddl(
        negative,
        &cddl,
        "wrong_scope_digest_encoding_private_body",
        "recovery-scope-catalog-private-body-v2",
    )
    .expect("raw-scope-digest body must be canonical and structural");
    let private_fields =
        super::numbered_fields(&raw_scope_digest_body, 10, "raw-scope-digest body")
            .expect("raw-scope-digest private fields");
    let scope_fields = super::numbered_fields(private_fields[4], 2, "recovery scope")
        .expect("recovery scope fields");
    let raw_scope_text =
        super::cbor_text(scope_fields[1], "recovery scope text").expect("recovery scope text");
    let raw_scope_digest =
        independent_digest(super::RECOVERY_SCOPE_DOMAIN, raw_scope_text.as_bytes());
    let canonical_scope = dtx_wire::encode_deterministic_cbor(private_fields[4])
        .expect("canonical recovery scope must encode");
    assert_eq!(
        super::cbor_fixed::<32>(private_fields[8], "raw scope digest").expect("raw scope digest"),
        raw_scope_digest
    );
    assert_ne!(
        raw_scope_digest,
        independent_digest(super::RECOVERY_SCOPE_DOMAIN, &canonical_scope)
    );
    assert!(super::validate_private_body_value(&raw_scope_digest_body, &facts.context, 1).is_err());

    let (_, wrong_head) = super::decode_negative_cddl(
        negative,
        &cddl,
        "wrong_head_signature",
        "recovery-scope-catalog-head-v2",
    )
    .expect("unrelated-authority head must be canonical and structural");
    let wrong_head_fields = super::numbered_fields(&wrong_head, 16, "unrelated-authority head")
        .expect("unrelated-authority head fields");
    let wrong_head_unsigned = independent_unsigned_prefix(&wrong_head, 15);
    let wrong_head_signature =
        super::cbor_fixed(wrong_head_fields[15], "unrelated-authority head signature")
            .expect("unrelated-authority head signature");
    assert!(independently_verifies(
        wrong_authority,
        super::HEAD_SIGNATURE_DOMAIN,
        &wrong_head_unsigned,
        wrong_head_signature,
    ));
    assert!(!independently_verifies(
        authority,
        super::HEAD_SIGNATURE_DOMAIN,
        &wrong_head_unsigned,
        wrong_head_signature,
    ));
    let positive_head_fields = super::numbered_fields(&facts.signed_head, 16, "positive head")
        .expect("positive head fields");
    assert!(
        super::validate_head_value(
            &wrong_head,
            &facts.context,
            facts.merkle_root,
            super::cbor_fixed(positive_head_fields[7], "positive ciphertext digest")
                .expect("positive ciphertext digest"),
            facts.openings.len(),
        )
        .is_err()
    );
}

#[test]
fn v42_catalog_v2_vector_metadata_equals_cddl_and_openapi() {
    super::validate_vector_metadata(&vector(), &cddl(), &openapi())
        .expect("Catalog V2 vector metadata must equal CDDL and OpenAPI");
}
