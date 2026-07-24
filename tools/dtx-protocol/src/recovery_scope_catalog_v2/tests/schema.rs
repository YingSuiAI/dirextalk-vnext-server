#[test]
fn v42_catalog_v2_cddl_parses() {
    super::validate_parse(&cddl()).expect("Recovery Scope Catalog V2 CDDL must parse");
}

#[test]
fn v42_catalog_v2_cddl_core_rule_names_are_frozen() {
    super::validate_rule_names(&cddl())
        .expect("Recovery Scope Catalog V2 must expose exactly the core rules");
}

#[test]
fn v42_catalog_v2_cddl_numbered_field_counts_are_frozen() {
    super::validate_field_counts(&cddl())
        .expect("Recovery Scope Catalog V2 field counts must remain frozen");
}

#[test]
fn v42_catalog_v2_cddl_wire_bounds_are_frozen() {
    super::validate_bounds(&cddl())
        .expect("Recovery Scope Catalog V2 wire bounds must remain frozen");
}

#[test]
fn v42_catalog_v2_count_ceiling_is_consecutive_index_and_size_derived() {
    let cddl = cddl();
    assert_eq!(super::MAX_CATALOG_LEAVES, 1_023);
    for (index, extra_bytes, accepted) in [
        (1, 0, true),
        (23, 0, true),
        (24, 3, true),
        (255, 3, true),
        (256, 6, true),
        (1_023, 6, true),
        (1_024, 6, false),
    ] {
        let opening = minimum_structural_catalog_opening(index);
        assert_eq!(structural_opening_indices(&opening), [index; 3]);
        let opening_exact = dtx_wire::encode_deterministic_cbor(&opening)
            .expect("index-aware structural opening must encode");
        assert_eq!(
            opening_exact.len(),
            super::MIN_CATALOG_OPENING_BYTES + extra_bytes
        );
        assert_eq!(
            cddl_cat::validate_cbor_bytes(
                "recovery-scope-catalog-opening-v2",
                &cddl,
                &opening_exact,
            )
            .is_ok(),
            accepted,
            "structural opening index {index} owner-bound result drifted"
        );
    }

    let maximum = consecutive_index_structural_catalog_plaintext_exact(super::MAX_CATALOG_LEAVES);
    assert_eq!(
        maximum.len(),
        super::MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
            + super::MAX_CATALOG_LEAVES * super::MIN_CATALOG_OPENING_BYTES
            + 232 * 3
            + 768 * 6
    );
    assert_eq!(maximum.len(), super::MAX_MINIMAL_CATALOG_BYTES);
    assert_eq!(maximum.len(), 1_047_888);
    assert!(maximum.len() <= super::MAX_CIPHERTEXT_BYTES);
    cddl_cat::validate_cbor_bytes("recovery-scope-catalog-plaintext-v2", &cddl, &maximum)
        .expect("1,023-opening consecutive-index structural plaintext must satisfy CDDL");
    let maximum_bstr = canonical_bstr_exact(&maximum);
    cddl_cat::validate_cbor_bytes("exact-catalog-plaintext-v2", &cddl, &maximum_bstr)
        .expect("minimum-sized 1,023-opening consecutive-index plaintext must fit 1 MiB");

    let overflow =
        consecutive_index_structural_catalog_plaintext_exact(super::MAX_CATALOG_LEAVES + 1);
    assert_eq!(overflow.len(), super::MIN_OVERFLOW_CATALOG_BYTES);
    assert_eq!(overflow.len(), 1_048_913);
    assert!(overflow.len() > super::MAX_CIPHERTEXT_BYTES);
    assert!(
        cddl_cat::validate_cbor_bytes("recovery-scope-catalog-plaintext-v2", &cddl, &overflow,)
            .is_err(),
        "1,024 consecutive-index openings must fail the owner count rule"
    );
    let overflow_bstr = canonical_bstr_exact(&overflow);
    assert!(
        cddl_cat::validate_cbor_bytes("exact-catalog-plaintext-v2", &cddl, &overflow_bstr).is_err(),
        "minimum-sized 1,024-opening consecutive-index plaintext must exceed 1 MiB"
    );
}

#[test]
fn v42_catalog_v2_proof_boundary_is_exact_and_mathematically_required() {
    let cddl = cddl();
    let vector = vector();
    let facts = super::validate_positive_vector(&vector, &cddl)
        .expect("positive Catalog V2 vector must validate");
    let leaf = [0x41; 32];
    let siblings = (0..super::MAX_PROOF_SIBLINGS)
        .map(|index| [u8::try_from(index + 1).expect("proof depth fits u8"); 32])
        .collect::<Vec<_>>();
    let root = independent_proof_root(
        u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
        1,
        leaf,
        &siblings,
    );
    let proof = proof_value(
        u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
        1,
        &siblings,
    );
    assert_eq!(super::MAX_PROOF_SIBLINGS, 10);
    let proof_exact = dtx_wire::encode_deterministic_cbor(&proof)
        .expect("10-sibling proof must encode canonically");
    cddl_cat::validate_cbor_bytes("catalog-merkle-proof-v2", &cddl, &proof_exact)
        .expect("mathematically required 10-sibling proof must satisfy CDDL");
    super::validate_proof_value(
        &proof,
        &facts.context,
        u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
        1,
        leaf,
        root,
    )
    .expect("mathematically required 10-sibling proof must verify");

    let mut surplus = siblings.clone();
    surplus.push([0xff; 32]);
    let surplus_proof = proof_value(
        u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
        1,
        &surplus,
    );
    let surplus_exact = dtx_wire::encode_deterministic_cbor(&surplus_proof)
        .expect("11-sibling proof must encode canonically");
    assert!(
        cddl_cat::validate_cbor_bytes("catalog-merkle-proof-v2", &cddl, &surplus_exact).is_err()
    );
    assert!(
        super::validate_proof_value(
            &surplus_proof,
            &facts.context,
            u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
            1,
            leaf,
            root,
        )
        .is_err()
    );

    let max_plus_one = u64::try_from(super::MAX_CATALOG_LEAVES + 1).expect("max+1 count fits u64");
    let max_plus_one_root = independent_proof_root(max_plus_one, 1, leaf, &siblings);
    let max_plus_one_proof = proof_value(max_plus_one, 1, &siblings);
    assert!(
        super::validate_proof_value(
            &max_plus_one_proof,
            &facts.context,
            max_plus_one,
            1,
            leaf,
            max_plus_one_root,
        )
        .is_err(),
        "semantic owner seam must reject count 1,024"
    );

    let single = proof_value(1, 1, &[]);
    super::validate_proof_value(&single, &facts.context, 1, 1, leaf, leaf)
        .expect("one-leaf proof must consume zero siblings");
}

#[test]
fn v42_catalog_v2_opening_digest_covers_complete_exact_opening() {
    let vector = vector();
    let openings = vector
        .pointer("/catalog/openings")
        .and_then(Value::as_array)
        .expect("positive openings must exist");
    assert_eq!(openings.len(), 3);
    for opening in openings {
        let exact = super::decode_lower_hex(
            super::json_string(opening, "opening_cbor_hex")
                .expect("opening exact bytes must exist"),
        )
        .expect("opening exact bytes must decode");
        let claimed = super::decode_json_fixed::<32>(opening, "opening_digest_hex")
            .expect("opening digest assertion must exist");
        assert_eq!(
            claimed,
            independent_digest(super::OPENING_DOMAIN, &exact),
            "opening digest must cover private body, full signed binding, and public leaf"
        );
    }
}

#[test]
fn v42_catalog_v2_device_add_v1_1_exact_maximum_is_533_bytes() {
    use dtx_wire::CanonicalValue::{Bytes, Map, Text, Unsigned};

    fn map(fields: Vec<(u64, dtx_wire::CanonicalValue)>) -> dtx_wire::CanonicalValue {
        Map(fields
            .into_iter()
            .map(|(key, value)| (Unsigned(key), value))
            .collect())
    }

    fn protocol_version(minor: u64) -> dtx_wire::CanonicalValue {
        map(vec![(1, Unsigned(1)), (2, Unsigned(minor))])
    }

    fn wire_version(minor: u64) -> dtx_wire::CanonicalValue {
        map(vec![
            (1, protocol_version(minor)),
            (2, protocol_version(minor)),
        ])
    }

    fn maximal_device_add(minor: u64) -> dtx_wire::CanonicalValue {
        let identity = Text("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la".to_owned());
        let certificate = map(vec![
            (1, wire_version(minor)),
            (2, identity.clone()),
            (3, Text("0190f2a5-7b1c-7abc-8def-0123456789b4".to_owned())),
            (4, Bytes(vec![0x44; 32])),
            (5, Bytes(vec![0x55; 32])),
            (6, Bytes(vec![0x66; 32])),
            (7, Unsigned(253_402_300_799_999)),
            (8, Bytes(vec![0x77; 64])),
        ]);
        map(vec![
            (1, wire_version(minor)),
            (2, identity),
            (3, Unsigned(9_007_199_254_740_991)),
            (4, Bytes(vec![0x33; 32])),
            (5, Unsigned(253_402_300_799_999)),
            (6, Unsigned(2)),
            (7, map(vec![(1, certificate)])),
            (8, Bytes(vec![0x88; 32])),
            (9, Bytes(vec![0x99; 64])),
        ])
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let identity_cddl = std::fs::read_to_string(
        root.join("protocol/cddl/identity-log/v1_1/identity-log-v1-1.cddl"),
    )
    .expect("owning Identity Log V1.1 CDDL must be readable");
    let exact_value = maximal_device_add(1);
    let exact = dtx_wire::encode_deterministic_cbor(&exact_value)
        .expect("maximum DeviceAdd must encode canonically");
    assert_eq!(exact.len(), super::MAX_DEVICE_ADD_BYTES);
    assert_eq!(
        dtx_wire::decode_deterministic_cbor(&exact).expect("maximum DeviceAdd must decode"),
        exact_value
    );
    assert_eq!(
        dtx_wire::encode_deterministic_cbor(
            &dtx_wire::decode_deterministic_cbor(&exact)
                .expect("maximum DeviceAdd must decode before re-encoding")
        )
        .expect("maximum DeviceAdd must re-encode"),
        exact
    );
    cddl_cat::validate_cbor_bytes("identity-log-device-add-event-v1-1", &identity_cddl, &exact)
        .expect("owning Identity Log V1.1 CDDL must accept the exact 533-byte maximum");
    let exact_bstr = dtx_wire::encode_deterministic_cbor(&Bytes(exact.clone()))
        .expect("exact DeviceAdd bstr must encode");
    cddl_cat::validate_cbor_bytes("exact-device-add-event-v1", &cddl(), &exact_bstr)
        .expect("Catalog V2 must accept the exact 533-byte DeviceAdd bstr boundary");

    let altered_version = dtx_wire::encode_deterministic_cbor(&maximal_device_add(2))
        .expect("altered version fixture must encode");
    assert!(
        cddl_cat::validate_cbor_bytes(
            "identity-log-device-add-event-v1-1",
            &identity_cddl,
            &altered_version,
        )
        .is_err()
    );

    let mut maximum_plus_one = exact;
    maximum_plus_one.push(0);
    assert_eq!(maximum_plus_one.len(), super::MAX_DEVICE_ADD_BYTES + 1);
    assert!(dtx_wire::decode_deterministic_cbor(&maximum_plus_one).is_err());
    let maximum_plus_one_bstr = dtx_wire::encode_deterministic_cbor(&Bytes(maximum_plus_one))
        .expect("oversized DeviceAdd bstr fixture must encode");
    assert!(
        cddl_cat::validate_cbor_bytes(
            "exact-device-add-event-v1",
            &cddl(),
            &maximum_plus_one_bstr,
        )
        .is_err()
    );
}

#[test]
fn v42_catalog_v2_cddl_crypto_domains_and_transcripts_are_frozen() {
    super::validate_crypto_transcripts(&cddl())
        .expect("Recovery Scope Catalog V2 crypto transcripts must remain frozen");
}

#[test]
fn v42_catalog_v2_cddl_handoff_maps_unions_and_semantics_are_frozen() {
    let source = cddl();
    super::validate_handoff_rules(&source)
        .expect("Recovery Scope Catalog V2 handoff maps and semantics must remain frozen");

    for (rule, _) in super::EXACT_HANDOFF_MAPS {
        let wrong_field = mutate_cddl_rule(&source, rule, |body| body.replacen("1:", "99:", 1));
        assert!(
            super::validate_field_counts(&wrong_field).is_err()
                || super::validate_handoff_rules(&wrong_field).is_err(),
            "handoff validator must reject a field-number mutation in {rule}"
        );

        let wrong_version = mutate_cddl_rule(&source, rule, |body| {
            for discriminant in ["1: 1", "1: 2", "1: 3"] {
                if body.contains(discriminant) {
                    return body.replacen(discriminant, "1: 99", 1);
                }
            }
            panic!("handoff map must have a frozen field-1 discriminant: {rule}");
        });
        assert!(
            super::validate_handoff_rules(&wrong_version).is_err(),
            "handoff validator must reject a version mutation in {rule}"
        );

        let widened_type = mutate_cddl_rule(&source, rule, |body| {
            let closing = body.rfind('}').expect("map body must close");
            format!("{} / null{}", &body[..closing], &body[closing..])
        });
        assert!(
            super::validate_handoff_rules(&widened_type).is_err(),
            "handoff validator must reject a type mutation in {rule}"
        );
    }

    for union_member in [
        "recovery-scope-catalog-recovery-authority-v2",
        "recovery-scope-catalog-status-invalidated-v2",
    ] {
        let mutated = source.replacen(union_member, "unknown-union-member-v2", 1);
        assert!(super::validate_handoff_rules(&mutated).is_err());
    }
    for required in super::REQUIRED_HANDOFF_RULES {
        let mutated = source.replacen(required, "drifted-semantic-contract", 1);
        assert!(
            super::validate_handoff_rules(&mutated).is_err(),
            "handoff validator must reject semantic drift: {required}"
        );
    }
}

#[test]
fn v42_catalog_v2_cddl_all_domains_and_hpke_info_are_exact_and_separate() {
    let source = cddl();
    for (name, domain) in super::REQUIRED_CRYPTO_DOMAIN_DECLARATIONS {
        let declaration = format!("{name} = `{domain}`.");
        let replacement = format!("{name} = `{domain}.drift`.");
        let mutated = source.replacen(&declaration, &replacement, 1);
        assert_ne!(mutated, source, "domain declaration must exist: {name}");
        assert!(
            super::validate_crypto_transcripts(&mutated).is_err(),
            "crypto validator must reject domain drift: {name}"
        );
    }
    let alternate_info = source.replacen(
        &format!("hpke-info = `{}`.", super::HPKE_INFO.replace('\0', "\\0")),
        "hpke-info = `dirextalk.recovery-scope-catalog-handoff-hpke.v2-alternate\\0`.",
        1,
    );
    assert!(super::validate_handoff_rules(&alternate_info).is_err());
    let aliased_info = format!(
        "{source}\n; hpke-info-alias-domain = `dirextalk.recovery-scope-catalog-handoff-hpke.v2\\0`.\n"
    );
    assert!(super::validate_crypto_transcripts(&aliased_info).is_err());
}

#[test]
fn v42_catalog_v2_cddl_rejects_extra_alias_and_alternate_domain_declarations() {
    let source = cddl();
    for (label, declaration) in [
        (
            "thirty-first domain",
            "; thirty-first-domain = `dirextalk.recovery-scope-catalog-thirty-first.v2\\0`.\n",
        ),
        (
            "domain alias",
            "; private-body-alias-domain = `dirextalk.recovery-scope-catalog-private-body.v2\\0`.\n",
        ),
        (
            "alternate domain transcript",
            "; private-body-domain = `dirextalk.recovery-scope-catalog-private-body.alternate\\0`.\n",
        ),
    ] {
        let mutated = format!("{source}\n{declaration}");
        assert!(
            super::validate_crypto_transcripts(&mutated).is_err(),
            "crypto validator must reject {label}"
        );
    }

    let prose = format!(
        "{source}\n; Prose may mention an eleventh-domain or {} without declaring either.\n",
        "dirextalk.recovery-scope-catalog-private-body.v2\\0"
    );
    super::validate_crypto_transcripts(&prose)
        .expect("non-declaration prose must not affect the exact domain set");
}

#[test]
fn v42_catalog_v2_cddl_timestamp_and_proof_rules_are_frozen() {
    super::validate_time_and_proof_rules(&cddl())
        .expect("Recovery Scope Catalog V2 timestamp and proof rules must remain frozen");
}

#[test]
fn v42_catalog_v2_cddl_hiding_nonce_policy_rejects_invalid_catalogs() {
    let first = [1_u8; 32];
    let second = [2_u8; 32];
    let zero = [0_u8; 32];
    super::validate_catalog_hiding_nonces([Some(first.as_slice()), Some(second.as_slice())])
        .expect("unique unpredictable hiding nonces must validate");
    assert!(super::validate_catalog_hiding_nonces(std::iter::empty()).is_err());
    assert!(super::validate_catalog_hiding_nonces([None]).is_err());
    assert!(super::validate_catalog_hiding_nonces([Some(zero.as_slice())]).is_err());
    assert!(
        super::validate_catalog_hiding_nonces([Some(first.as_slice()), Some(first.as_slice())])
            .is_err()
    );
}

#[test]
fn v42_catalog_v2_openapi_parses() {
    super::parse_openapi(&openapi()).expect("Recovery Scope Catalog V2 OpenAPI must parse");
}

#[test]
fn v42_catalog_v2_openapi_handoff_contract_is_frozen() {
    let document = openapi_document();
    super::validate_openapi_handoff_http_contract(&document)
        .expect("handoff HTTP contract must remain frozen");
    super::validate_openapi_handoff_metadata(&document)
        .expect("handoff metadata must remain frozen");
}

#[test]
fn v42_catalog_v2_reviewer_repair_caps_get_truth_and_idempotency_are_frozen() {
    assert_eq!(super::MAX_SIGNED_CATALOG_HEAD_BYTES, 466);
    assert_eq!(super::MAX_CATALOG_UPLOAD_BODY_BYTES, 1_049_050);
    assert_eq!(super::MAX_PROVIDER_PACKAGE_BYTES, 1_049_457);
    assert_eq!(super::MAX_HPKE_CIPHERTEXT_BYTES, 1_049_473);
    assert_eq!(super::MAX_HPKE_ENCODED_ENVELOPE_BYTES, 1_049_517);
    assert_eq!(super::MAX_PROVIDER_RESPONSE_BODY_BYTES, 1_050_929);
    assert_eq!(super::MAX_STATUS_BODY_BYTES, 1_050_986);
    assert_eq!(super::MAX_DEVICE_ADD_BYTES, 533);
    assert_eq!(super::MAX_ENVELOPE_BYTES, 1_065_984);
    assert_eq!(
        super::MAX_SIGNED_CATALOG_HEAD_BYTES,
        1 + 16 + 449,
        "signed head is map header + sixteen one-byte keys + values"
    );
    assert_eq!(
        super::MAX_CATALOG_UPLOAD_BODY_BYTES,
        3 + super::MAX_SIGNED_CATALOG_HEAD_BYTES + 5 + super::MAX_CIPHERTEXT_BYTES,
        "upload is map/key bytes + raw signed head + encoded ciphertext bstr"
    );
    assert_eq!(
        super::MAX_PROVIDER_PACKAGE_BYTES,
        18 + 1
            + 38
            + 34
            + 3
            + super::MAX_SIGNED_CATALOG_HEAD_BYTES
            + 5
            + super::MAX_CIPHERTEXT_BYTES
            + 59
            + 38
            + 9
            + 38
            + 34
            + 9
            + 34
            + 9
            + 34
            + 34
            + 18,
        "provider package arithmetic must include both nested bstr headers"
    );
    assert_eq!(
        super::MAX_HPKE_CIPHERTEXT_BYTES,
        super::MAX_PROVIDER_PACKAGE_BYTES + 16
    );
    assert_eq!(
        super::MAX_HPKE_ENCODED_ENVELOPE_BYTES,
        1 + 2 + 35 + 1 + 5 + super::MAX_HPKE_CIPHERTEXT_BYTES
    );
    assert_eq!(
        super::MAX_PROVIDER_RESPONSE_BODY_BYTES,
        31 + 1
            + 38
            + 34
            + 59
            + 38
            + 9
            + 34
            + 38
            + 34
            + 9
            + 34
            + 9
            + 34
            + 34
            + 77
            + 77
            + 136
            + 18
            + 132
            + 3
            + super::MAX_DEVICE_ADD_BYTES
            + super::MAX_HPKE_ENCODED_ENVELOPE_BYTES,
        "provider response arithmetic must include map/key and DeviceAdd bstr headers"
    );
    assert_eq!(
        super::MAX_STATUS_BODY_BYTES,
        super::MAX_PROVIDER_RESPONSE_BODY_BYTES + 57
    );

    let document = openapi_document();
    let responses = document
        .pointer(&format!("{}/responses", super::STATUS_OPERATION))
        .and_then(Value::as_object)
        .expect("status responses must be an object");
    assert_eq!(
        responses.keys().map(String::as_str).collect::<Vec<_>>(),
        ["200", "401", "406"]
    );
    assert_eq!(
        document.pointer("/components/parameters/IdempotencyKey/schema/pattern"),
        Some(&json!("^[A-Za-z0-9_-]{16,128}$"))
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive maximum-object matrix keeps all dependent protocol ceilings together"
)]
fn v42_catalog_v2_actual_max_objects_match_every_dependent_ceiling() {
    use dtx_wire::CanonicalValue::{Bytes, Map, Null, Text, Unsigned};

    let entry = |key, value| (Unsigned(key), value);
    let uuid = || Text("0".repeat(36));
    let identity = || Text("a".repeat(57));
    let digest = || Bytes(vec![0; 32]);
    let signature = || Bytes(vec![0; 64]);
    let maximum = || Unsigned(9_007_199_254_740_991);
    let highwater = || Unsigned(9_007_199_254_740_990);
    let encode = |value: &dtx_wire::CanonicalValue| {
        dtx_wire::encode_deterministic_cbor_with_limit(value, 2_000_000)
            .expect("maximum Catalog object must encode canonically")
    };
    let cddl = cddl();

    let signed_head = Map(vec![
        entry(1, Unsigned(2)),
        entry(2, uuid()),
        entry(3, identity()),
        entry(4, maximum()),
        entry(5, digest()),
        entry(6, Unsigned(1_023)),
        entry(7, digest()),
        entry(8, digest()),
        entry(9, maximum()),
        entry(10, digest()),
        entry(11, uuid()),
        entry(12, uuid()),
        entry(13, digest()),
        entry(14, maximum()),
        entry(15, maximum()),
        entry(16, signature()),
    ]);
    let signed_head_exact = encode(&signed_head);
    assert_eq!(
        signed_head_exact.len(),
        super::MAX_SIGNED_CATALOG_HEAD_BYTES
    );
    cddl_cat::validate_cbor_bytes("recovery-scope-catalog-head-v2", &cddl, &signed_head_exact)
        .expect("actual maximum signed head must satisfy its closed CDDL map");

    let upload = Map(vec![
        entry(1, signed_head.clone()),
        entry(2, Bytes(vec![0; super::MAX_CIPHERTEXT_BYTES])),
    ]);
    let upload_exact = encode(&upload);
    assert_eq!(upload_exact.len(), super::MAX_CATALOG_UPLOAD_BODY_BYTES);
    assert!(upload_exact.len() < super::MAX_ENVELOPE_BYTES);
    cddl_cat::validate_cbor_bytes("recovery-scope-catalog-upload-v2", &cddl, &upload_exact)
        .expect("actual maximum upload must satisfy its closed CDDL map");

    let provider_package = Map(vec![
        entry(1, Unsigned(2)),
        entry(2, uuid()),
        entry(3, digest()),
        entry(4, Bytes(signed_head_exact)),
        entry(5, Bytes(vec![0; super::MAX_CIPHERTEXT_BYTES])),
        entry(6, identity()),
        entry(7, uuid()),
        entry(8, maximum()),
        entry(9, uuid()),
        entry(10, digest()),
        entry(11, highwater()),
        entry(12, digest()),
        entry(13, maximum()),
        entry(14, digest()),
        entry(15, digest()),
        entry(16, maximum()),
        entry(17, maximum()),
    ]);
    let provider_package_exact = encode(&provider_package);
    assert_eq!(
        provider_package_exact.len(),
        super::MAX_PROVIDER_PACKAGE_BYTES
    );
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-provider-package-v2",
        &cddl,
        &provider_package_exact,
    )
    .expect("actual maximum provider package must satisfy its closed CDDL map");

    let hpke_ciphertext = Bytes(vec![0; super::MAX_HPKE_CIPHERTEXT_BYTES]);
    let hpke_ciphertext_exact = encode(&hpke_ciphertext);
    assert_eq!(
        hpke_ciphertext_exact.len(),
        super::MAX_HPKE_CIPHERTEXT_BYTES + 5
    );
    cddl_cat::validate_cbor_bytes("hpke-ciphertext-v2", &cddl, &hpke_ciphertext_exact)
        .expect("actual maximum HPKE ciphertext must satisfy its CDDL bound");

    let hpke_envelope = Map(vec![
        entry(1, Unsigned(2)),
        entry(2, digest()),
        entry(3, hpke_ciphertext),
    ]);
    let hpke_envelope_exact = encode(&hpke_envelope);
    assert_eq!(
        hpke_envelope_exact.len(),
        super::MAX_HPKE_ENCODED_ENVELOPE_BYTES
    );
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-hpke-envelope-v2",
        &cddl,
        &hpke_envelope_exact,
    )
    .expect("actual maximum HPKE envelope must satisfy its closed CDDL map");

    let provider_descriptor = Map(vec![
        entry(1, Unsigned(2)),
        entry(2, uuid()),
        entry(3, digest()),
    ]);
    let independent_authority = Map(vec![
        entry(1, Unsigned(1)),
        entry(2, uuid()),
        entry(3, digest()),
    ]);
    let provider_response = Map(vec![
        entry(1, Unsigned(2)),
        entry(2, uuid()),
        entry(3, digest()),
        entry(4, identity()),
        entry(5, uuid()),
        entry(6, maximum()),
        entry(7, digest()),
        entry(8, uuid()),
        entry(9, digest()),
        entry(10, highwater()),
        entry(11, digest()),
        entry(12, maximum()),
        entry(13, digest()),
        entry(14, digest()),
        entry(15, provider_descriptor),
        entry(16, independent_authority),
        entry(17, digest()),
        entry(18, digest()),
        entry(19, digest()),
        entry(20, digest()),
        entry(21, maximum()),
        entry(22, maximum()),
        entry(23, signature()),
        entry(24, signature()),
        entry(25, Bytes(vec![0; super::MAX_DEVICE_ADD_BYTES])),
        entry(26, hpke_envelope),
    ]);
    let provider_response_exact = encode(&provider_response);
    assert_eq!(
        provider_response_exact.len(),
        super::MAX_PROVIDER_RESPONSE_BODY_BYTES
    );
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-provider-response-v2",
        &cddl,
        &provider_response_exact,
    )
    .expect("actual maximum provider response must satisfy its closed CDDL map");

    let ready_status = Map(vec![
        entry(1, Unsigned(2)),
        entry(2, uuid()),
        entry(3, Unsigned(2)),
        entry(4, provider_response),
        entry(5, Null),
        entry(6, maximum()),
    ]);
    let ready_status_exact = encode(&ready_status);
    assert_eq!(ready_status_exact.len(), super::MAX_STATUS_BODY_BYTES);
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-status-ready-v2",
        &cddl,
        &ready_status_exact,
    )
    .expect("actual maximum ready status must satisfy its closed CDDL map");
}

#[test]
fn v42_catalog_v2_reviewer_repair_exact_size_boundaries_reject_max_plus_one() {
    fn encoded_bstr(length: usize) -> Vec<u8> {
        let length = u32::try_from(length).expect("boundary length must fit u32");
        let mut encoded = Vec::with_capacity(length as usize + 5);
        encoded.push(0x5a);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.resize(length as usize + 5, 0);
        encoded
    }

    let cddl = cddl();
    for (rule, maximum) in [
        (
            "exact-signed-catalog-head-v2",
            super::MAX_SIGNED_CATALOG_HEAD_BYTES,
        ),
        (
            "exact-provider-package-v2",
            super::MAX_PROVIDER_PACKAGE_BYTES,
        ),
        ("hpke-ciphertext-v2", super::MAX_HPKE_CIPHERTEXT_BYTES),
        (
            "exact-hpke-envelope-v2",
            super::MAX_HPKE_ENCODED_ENVELOPE_BYTES,
        ),
        (
            "exact-provider-response-v2",
            super::MAX_PROVIDER_RESPONSE_BODY_BYTES,
        ),
        ("exact-ready-status-v2", super::MAX_STATUS_BODY_BYTES),
    ] {
        cddl_cat::validate_cbor_bytes(rule, &cddl, &encoded_bstr(maximum))
            .unwrap_or_else(|error| panic!("{rule} must accept exact maximum: {error}"));
        assert!(
            cddl_cat::validate_cbor_bytes(rule, &cddl, &encoded_bstr(maximum + 1)).is_err(),
            "{rule} must reject max+1"
        );
    }
}

#[test]
fn v42_catalog_v2_reviewer_repair_vector_metadata_rejects_limit_and_domain_drift() {
    let original = vector();
    for limit in [
        "catalog_plaintext_ceiling_bytes",
        "index_occurrences_per_opening",
        "indices_24_through_255_count",
        "indices_24_through_255_extra_bytes_per_opening",
        "indices_256_plus_extra_bytes_per_opening",
        "indices_256_through_1023_count",
        "max_catalog_upload_body_bytes",
        "max_ciphertext_bytes",
        "max_envelope_bytes",
        "max_provider_package_bytes",
        "max_hpke_ciphertext_bytes",
        "max_hpke_encoded_envelope_bytes",
        "max_leaf_count",
        "max_leaf_count_minimum_bytes",
        "max_leaf_count_plus_one",
        "max_leaf_count_plus_one_minimum_bytes",
        "max_proof_siblings",
        "max_device_add_bytes",
        "max_provider_response_body_bytes",
        "max_signed_catalog_head_bytes",
        "max_status_body_bytes",
        "minimum_outer_plaintext_overhead_bytes",
        "minimum_valid_opening_bytes",
        "one_byte_index_maximum",
        "two_byte_index_maximum",
    ] {
        let pointer = format!("/limits/{limit}");
        let current = original
            .pointer(&pointer)
            .and_then(Value::as_u64)
            .expect("frozen limit must be an integer");
        let mut mutated = original.clone();
        replace_openapi_value(&mut mutated, &pointer, json!(current + 1));
        assert!(
            super::validate_vector_metadata(&mutated, &cddl(), &openapi()).is_err(),
            "vector metadata must reject {limit} max+1"
        );
    }
    let mut consecutive_indices = original.clone();
    replace_openapi_value(
        &mut consecutive_indices,
        "/limits/consecutive_one_based_indices_required",
        json!(false),
    );
    assert!(super::validate_vector_metadata(&consecutive_indices, &cddl(), &openapi()).is_err());
    let mut classification = original.clone();
    replace_openapi_value(
        &mut classification,
        "/limits/count_boundary_classification",
        json!("full_crypto_fixture"),
    );
    assert!(super::validate_vector_metadata(&classification, &cddl(), &openapi()).is_err());
    let mut domain = original.clone();
    replace_openapi_value(
        &mut domain,
        "/domains/identity_device_add",
        json!("dirextalk.identity-log-event.v1\0"),
    );
    assert!(super::validate_vector_metadata(&domain, &cddl(), &openapi()).is_err());
    let mut opening_domain = original;
    replace_openapi_value(
        &mut opening_domain,
        "/domains/opening",
        json!("dirextalk.recovery-scope-catalog-opening.v2"),
    );
    assert!(super::validate_vector_metadata(&opening_domain, &cddl(), &openapi()).is_err());
}

#[test]
fn v42_catalog_v2_final_hidden_verifier_privacy_boundary_is_frozen() {
    let document = openapi_document();
    assert_eq!(
        document.pointer("/x-dirextalk-handoff-currentness/hidden-verifier-currentness"),
        Some(&json!(
            "candidate-only-never-server-admission-cas-replay-or-status"
        ))
    );
    for operation in [
        super::PREPARATION_OPERATION,
        super::PROVIDER_RESPONSE_OPERATION,
    ] {
        let fences = document
            .pointer(&format!(
                "{operation}/x-dirextalk-cas-transaction/final-predicate-fences"
            ))
            .and_then(Value::as_array)
            .expect("final CAS fences must be arrays");
        assert!(
            fences
                .iter()
                .all(|fence| !fence.as_str().is_some_and(|text| text.contains("verifier"))),
            "server CAS must not fence hidden verifier tuples"
        );
    }

    let mut server_tuple = document.clone();
    server_tuple
        .pointer_mut("/x-dirextalk-handoff-currentness")
        .and_then(Value::as_object_mut)
        .expect("handoff currentness must be mutable")
        .insert("server-visible-verifier-tuple".to_owned(), json!(true));
    assert_openapi_document_rejected("server-visible hidden verifier tuple", &server_tuple);

    for (label, pointer, replacement) in [
        (
            "server verifier invalidation drift",
            "/x-dirextalk-handoff-currentness/server-visible-invalidation-drift/1".to_owned(),
            json!("verifier"),
        ),
        (
            "server direct verifier status",
            format!(
                "{}/x-dirextalk-currentness/hidden-verifier-status",
                super::STATUS_OPERATION
            ),
            json!("direct-hidden-tuple-comparison"),
        ),
        (
            "server may observe verifier tuple",
            "/x-dirextalk-handoff-equality-validity/identity-server-validation/never/3".to_owned(),
            json!("observe-completion-verifier-origin-key-epoch-descriptor"),
        ),
    ] {
        let mut mutated = document.clone();
        replace_openapi_value(&mut mutated, &pointer, replacement);
        assert_openapi_document_rejected(label, &mutated);
    }
    for operation in [
        super::PREPARATION_OPERATION,
        super::PROVIDER_RESPONSE_OPERATION,
    ] {
        let mut mutated = document.clone();
        replace_openapi_value(
            &mut mutated,
            &format!("{operation}/x-dirextalk-cas-transaction/final-predicate-fences/3"),
            json!("catalog-head-and-all-verifier-tuples-with-rotation-epochs"),
        );
        assert_openapi_document_rejected("server CAS verifier tuple reintroduction", &mutated);
    }
}

#[test]
fn v42_catalog_v2_final_hpke_raw_canonical_aad_boundary_is_frozen() {
    let document = openapi_document();
    assert_eq!(
        document.pointer("/x-dirextalk-handoff-hpke/aad-input"),
        Some(&json!(
            "exact-deterministic-canonical-cbor-bytes-of-recovery-scope-catalog-provider-public-aad-v2"
        ))
    );
    assert_eq!(
        vector().pointer("/hpke_aad/input"),
        Some(&json!("exact_deterministic_canonical_cbor_bytes"))
    );

    for forbidden in [
        "response-field-18-digest",
        "provider-aad-domain-prefixed",
        "json",
        "hex",
        "alternate-cbor-encoding",
    ] {
        let mut mutated = document.clone();
        replace_openapi_value(
            &mut mutated,
            "/x-dirextalk-handoff-hpke/aad-input",
            json!(forbidden),
        );
        assert_openapi_document_rejected(&format!("HPKE aad must reject {forbidden}"), &mutated);
    }
    for (pointer, replacement) in [
        (
            "/x-dirextalk-handoff-hpke/public-aad-cddl-rule",
            json!("recovery-scope-catalog-provider-aad-v2"),
        ),
        (
            "/x-dirextalk-handoff-hpke/deterministic-hpke-vector-required-in",
            json!("optional"),
        ),
    ] {
        let mut mutated = document.clone();
        replace_openapi_value(&mut mutated, pointer, replacement);
        assert_openapi_document_rejected("HPKE aad metadata drift", &mutated);
    }

    for forbidden in [
        "response_field_18_digest",
        "provider_aad_domain_prefixed",
        "json",
        "hex",
        "alternate_cbor_encoding",
    ] {
        let mut mutated = vector();
        replace_openapi_value(&mut mutated, "/hpke_aad/input", json!(forbidden));
        assert!(
            super::validate_vector_metadata(&mutated, &cddl(), &openapi()).is_err(),
            "vector HPKE aad must reject {forbidden}"
        );
    }
    for (pointer, replacement) in [
        (
            "/hpke_aad/cddl_rule",
            json!("recovery-scope-catalog-provider-aad-v2"),
        ),
        (
            "/hpke_aad/deterministic_vector_required_in",
            json!("optional"),
        ),
    ] {
        let mut mutated = vector();
        replace_openapi_value(&mut mutated, pointer, replacement);
        assert!(super::validate_vector_metadata(&mutated, &cddl(), &openapi()).is_err());
    }
}
