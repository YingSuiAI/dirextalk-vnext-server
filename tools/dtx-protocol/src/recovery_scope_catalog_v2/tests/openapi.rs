#[test]
fn v42_catalog_v2_c1bb_positive_handoff_fixture_is_present() {
    let handoff = vector()
        .get("handoff")
        .cloned()
        .expect("C1b-B1 must freeze one complete deterministic handoff fixture");
    assert_eq!(
        handoff.pointer("/test_only_inputs/classification"),
        Some(&json!("public-deterministic-test-fixture-not-a-credential"))
    );
    assert!(handoff.pointer("/preparation/cbor_hex").is_some());
    assert!(handoff.pointer("/hpke_envelope/cbor_hex").is_some());
    assert!(handoff.pointer("/provider_response/cbor_hex").is_some());
    assert!(handoff.pointer("/statuses/ready/cbor_hex").is_some());
}

#[test]
fn v42_catalog_v2_c1bb_positive_bytes_and_crypto_are_independently_derived() {
    let value = vector();
    let cddl = cddl();
    let (catalog, server) = positive_handoff(&value);
    super::validate_candidate_handoff(&value, &cddl, &server, &catalog)
        .expect("candidate must open and validate the exact positive package");
    assert_eq!(server.preparation_exact.len(), 517);
    assert_eq!(server.device_add_exact.len(), 526);
    assert_eq!(server.envelope_exact.len(), 4_479);
    assert_eq!(server.provider_response_exact.len(), 5_862);
    assert_eq!(server.status_exact[1].len(), 5_919);
}

#[test]
fn v42_catalog_v2_c1bb_server_visible_projection_never_decrypts() {
    let original = vector();
    let (catalog, server) = positive_handoff(&original);
    let mut wrong_private = original.clone();
    replace_openapi_value(
        &mut wrong_private,
        "/handoff/test_only_inputs/x25519_recipient_private_key_hex",
        json!("00"),
    );
    validate_server_handoff(&wrong_private)
        .expect("server-visible admission must not parse or use candidate private material");
    assert!(super::validate_candidate_handoff(&wrong_private, &cddl(), &server, &catalog).is_err());

    let source = include_str!("../vector.rs");
    let declaration = source
        .split("struct ServerVisibleHandoffFacts")
        .nth(1)
        .expect("typed server-visible facts declaration")
        .split("}\n")
        .next()
        .expect("typed declaration end");
    for forbidden in ["private_key", "package_exact", "plaintext", "verifier"] {
        assert!(
            !declaration.contains(forbidden),
            "server-visible type must not contain {forbidden}"
        );
    }
}

#[test]
fn v42_catalog_v2_c1bb_hpke_uses_exact_raw_aad_and_info() {
    use hpke::{Deserializable as _, OpModeR};

    type Kem = hpke::kem::X25519HkdfSha256;
    type Aead = hpke::aead::ChaCha20Poly1305;
    type Kdf = hpke::kdf::HkdfSha256;

    let value = vector();
    let (catalog, server) = positive_handoff(&value);
    super::validate_candidate_handoff(&value, &cddl(), &server, &catalog)
        .expect("exact raw AAD and NUL-terminated info must open");

    let mut prefixed_aad = server.clone();
    let mut bytes = super::PROVIDER_AAD_DOMAIN.to_vec();
    bytes.extend_from_slice(&prefixed_aad.public_aad_exact);
    prefixed_aad.public_aad_exact = bytes;
    assert!(
        super::validate_candidate_handoff(&value, &cddl(), &prefixed_aad, &catalog).is_err(),
        "domain-prefixed AAD must not open"
    );

    let mut altered_raw_aad = server.clone();
    altered_raw_aad.public_aad_exact[0] ^= 1;
    assert!(
        super::validate_candidate_handoff(&value, &cddl(), &altered_raw_aad, &catalog).is_err(),
        "alternate raw AAD bytes must not open"
    );

    let private = super::decode_json_fixed::<32>(
        value
            .pointer("/handoff/test_only_inputs")
            .expect("test-only inputs"),
        "x25519_recipient_private_key_hex",
    )
    .expect("candidate private test input");
    let private_key =
        <Kem as hpke::Kem>::PrivateKey::from_bytes(&private).expect("candidate private key");
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&server.envelope_enc)
        .expect("exact encapped key");
    let mut wrong_info = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encapped,
        b"dirextalk.recovery-scope-catalog-handoff-hpke.v2",
    )
    .expect("well-formed alternate-info receiver context");
    assert!(
        wrong_info
            .open(&server.envelope_ciphertext, &server.public_aad_exact)
            .is_err(),
        "missing-NUL HPKE info must not open"
    );
}

#[test]
fn v42_catalog_v2_c1bb_identity_log_v1_1_transition_is_current() {
    let original = vector();
    let (_catalog, server) = positive_handoff(&original);
    assert_eq!(
        server.identity_log.at_h_plus_1.sequence,
        server.identity_log.at_h.sequence + 1
    );
    let event = dtx_identity_log::IdentityLogEventV1::decode_and_verify(&server.device_add_exact)
        .expect("exact DeviceAdd must verify");
    assert_eq!(event.wire(), dtx_identity_log::IDENTITY_LOG_WIRE_VERSION);
    assert_eq!(
        event.entry_hash().expect("event hash").as_bytes(),
        &server.identity_log.at_h_plus_1.head_digest
    );

    let mut drifted = original;
    replace_openapi_value(
        &mut drifted,
        "/handoff/origin_authenticated_identity_log/at_h_plus_1/head_digest_hex",
        json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    );
    assert!(validate_server_handoff(&drifted).is_err());
}

#[test]
fn v42_catalog_v2_c1bb_h_plus_1_is_exact_device_add_reduction() {
    let original = vector();
    let response_before = original
        .pointer("/handoff/provider_response/cbor_hex")
        .cloned();
    let receipt_before = original
        .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
        .cloned();
    let assert_rejected = |drifted: &Value, label: &str| {
        assert_eq!(
            drifted.pointer("/handoff/provider_response/cbor_hex"),
            response_before.as_ref(),
            "{label} must not rewrite portable response bytes"
        );
        assert_eq!(
            drifted.pointer("/handoff/mutation_receipts/provider_response/cbor_hex"),
            receipt_before.as_ref(),
            "{label} must not rewrite the immutable receipt"
        );
        assert!(
            validate_server_handoff(drifted).is_err(),
            "{label} must fail origin-authenticated first admission/currentness"
        );
    };
    for (label, index) in [
        ("provider removed only at H+1", 0),
        ("authority removed only at H+1", 1),
    ] {
        let mut drifted = original.clone();
        drifted
            .pointer_mut("/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices")
            .and_then(Value::as_array_mut)
            .expect("H+1 active devices")
            .remove(index);
        assert_rejected(&drifted, label);
    }
    for (label, pointer, replacement) in [
        (
            "provider rekeyed only at H+1",
            "/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices/0/signing_public_key_hex",
            json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ),
        (
            "authority rekeyed only at H+1",
            "/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices/1/signing_public_key_hex",
            json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ),
    ] {
        let mut drifted = original.clone();
        replace_openapi_value(&mut drifted, pointer, replacement);
        assert_rejected(&drifted, label);
    }
    let mut extra = original;
    extra
        .pointer_mut(
            "/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices",
        )
        .and_then(Value::as_array_mut)
        .expect("H+1 active devices")
        .push(json!({
            "device_id": "0190f2a5-7b1c-7abc-8def-0123456789d5",
            "encryption_public_key_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "signing_public_key_hex": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }));
    assert_rejected(&extra, "unrelated extra mutation only at H+1");
}

#[test]
fn v42_catalog_v2_c1bb_candidate_uses_independent_verifier_oracle() {
    let original = vector();
    assert_eq!(
        original.pointer("/origin_authenticated_completion_verifier_descriptors/classification"),
        Some(&json!(
            "trusted-origin-authenticated-completion-verifier-test-oracle-not-portable-wire-proof"
        ))
    );
    let response_before = original
        .pointer("/handoff/provider_response/cbor_hex")
        .cloned();
    let receipt_before = original
        .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
        .cloned();
    let status_before = original
        .pointer("/handoff/statuses/ready/cbor_hex")
        .cloned();
    let (catalog, server) = positive_handoff(&original);
    for (label, pointer, replacement) in [
        (
            "origin mismatch",
            "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/origin",
            json!("https://other.example.test"),
        ),
        (
            "key id rotation",
            "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/key_id",
            json!("0190f2a5-7b1c-7abc-8def-0123456789c2"),
        ),
        (
            "public key rotation",
            "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/public_key_hex",
            json!("2012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7"),
        ),
        (
            "epoch rotation",
            "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/epoch",
            json!(5),
        ),
        (
            "descriptor digest rotation",
            "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/descriptor_digest_hex",
            json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ),
        (
            "stale descriptor validity",
            "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/expires_at",
            json!(1_701_003_500_000_u64),
        ),
        (
            "descriptor signature substitution",
            "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/signature_hex",
            json!("00".repeat(64)),
        ),
    ] {
        let mut drifted = original.clone();
        replace_openapi_value(&mut drifted, pointer, replacement);
        assert_eq!(
            drifted
                .pointer("/handoff/provider_response/cbor_hex")
                .cloned(),
            response_before,
            "{label} must not rewrite portable response bytes"
        );
        assert_eq!(
            drifted
                .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
                .cloned(),
            receipt_before,
            "{label} must not rewrite the immutable server receipt"
        );
        assert_eq!(
            drifted.pointer("/handoff/statuses/ready/cbor_hex").cloned(),
            status_before,
            "{label} must not rewrite server status"
        );
        validate_server_handoff(&drifted)
            .unwrap_or_else(|error| panic!("server must not observe {label}: {error}"));
        assert!(
            super::validate_candidate_handoff(&drifted, &cddl(), &server, &catalog).is_err(),
            "candidate must reject {label} against the trusted nonportable oracle"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "exact destructuring and private-mutation checks freeze one closed server projection boundary"
)]
fn v42_catalog_v2_c1bb_server_catalog_projection_type_is_closed() {
    let projection = super::validate_catalog_server_projection(&vector(), &cddl())
        .expect("server projection must derive from signed public bytes");
    let super::CatalogServerProjection {
        signed_head_exact,
        signed_head_digest,
        identity_id,
        catalog_id,
        generation,
        previous_head_digest,
        leaf_count,
        merkle_root,
        identity_sequence,
        identity_head_digest,
        authority_device_id,
        authority_key_id,
        authority_public_key,
        head_issued_at,
        head_expires_at,
        validation_time,
        ciphertext,
        ciphertext_digest,
    } = projection;
    assert!(!signed_head_exact.is_empty());
    assert_ne!(signed_head_digest, [0; 32]);
    assert!(!identity_id.is_empty() && !catalog_id.is_empty());
    assert!(generation > 0 && leaf_count > 0 && identity_sequence > 0);
    assert_ne!(previous_head_digest, [0; 32]);
    assert_ne!(merkle_root, [0; 32]);
    assert_ne!(identity_head_digest, [0; 32]);
    assert!(!authority_device_id.is_empty() && !authority_key_id.is_empty());
    assert_ne!(authority_public_key, [0; 32]);
    assert!(head_issued_at <= validation_time && validation_time < head_expires_at);
    assert!(!ciphertext.is_empty() && ciphertext_digest != [0; 32]);

    let input = super::parse_server_visible_handoff_input(&vector())
        .expect("server-visible handoff input must parse");
    let super::ServerVisibleHandoffInput {
        preparation,
        origin_authenticated_identity_log,
        device_add,
        provider_response,
        public_aad,
        hpke_envelope,
        mutation_receipts,
        statuses,
        enrollment_candidate_recipient_public_key,
        response_capability,
        preparation_idempotency_key,
        response_idempotency_key,
    } = input;
    for public_state in [
        preparation,
        origin_authenticated_identity_log,
        device_add,
        provider_response,
        public_aad,
        hpke_envelope,
        mutation_receipts,
        statuses,
    ] {
        assert!(public_state.is_object());
    }
    assert_ne!(enrollment_candidate_recipient_public_key, [0; 32]);
    assert_ne!(response_capability, [0; 32]);
    assert!(!preparation_idempotency_key.is_empty());
    assert!(!response_idempotency_key.is_empty());

    let source = include_str!("../vector.rs");
    let declaration = source
        .split("struct CatalogServerProjection")
        .nth(1)
        .expect("dedicated Catalog server projection declaration")
        .split("}\n")
        .next()
        .expect("Catalog server projection declaration end");
    for forbidden in [
        "plaintext",
        "opening",
        "scope",
        "verifier",
        "private_key",
        "package",
    ] {
        assert!(
            !declaration.contains(forbidden),
            "Catalog server projection must not contain {forbidden}"
        );
    }
    let pipeline = source
        .split("fn validate_catalog_vector")
        .nth(1)
        .expect("Catalog validation pipeline")
        .split("fn read_catalog_vector")
        .next()
        .expect("pipeline end");
    let server = pipeline
        .find("validate_server_visible_handoff")
        .expect("server validation in pipeline");
    let private = pipeline
        .find("validate_positive_vector")
        .expect("candidate-private validation in pipeline");
    assert!(
        server < private,
        "server admission must complete before candidate-private Catalog validation"
    );

    let original = vector();
    for (pointer, replacement) in [
        ("/catalog/plaintext_cbor_hex", json!("00")),
        ("/catalog/openings", json!({"hidden": true})),
        (
            "/catalog/verifier_descriptor/origin",
            json!("not-a-canonical-origin"),
        ),
        ("/handoff/package/cbor_hex", json!("00")),
        (
            "/handoff/test_only_inputs/x25519_recipient_private_key_hex",
            json!("00"),
        ),
        (
            "/origin_authenticated_completion_verifier_descriptors/classification",
            json!("not-trusted"),
        ),
    ] {
        let mut private_drift = original.clone();
        replace_openapi_value(&mut private_drift, pointer, replacement);
        validate_server_handoff(&private_drift).unwrap_or_else(|error| {
            panic!("server projection accessed candidate-private {pointer}: {error}")
        });
    }
}

#[test]
fn v42_catalog_v2_c1bb_receipts_statuses_and_read_only_drift_are_exact() {
    let original = vector();
    let response_before = original
        .pointer("/handoff/provider_response/cbor_hex")
        .cloned();
    let receipt_before = original
        .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
        .cloned();
    let (_catalog, server) = positive_handoff(&original);
    assert_eq!(server.status_exact.len(), 5);
    assert_ne!(
        server.preparation_receipt_exact,
        server.provider_response_receipt_exact
    );

    let mut drifted = original;
    replace_openapi_value(
        &mut drifted,
        "/handoff/origin_authenticated_identity_log/at_h/active_devices/0/signing_public_key_hex",
        json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    );
    assert_eq!(
        drifted
            .pointer("/handoff/provider_response/cbor_hex")
            .cloned(),
        response_before
    );
    assert_eq!(
        drifted
            .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
            .cloned(),
        receipt_before
    );
    assert!(
        validate_server_handoff(&drifted).is_err(),
        "origin currentness drift must affect admission/GET without rewriting portable bytes"
    );
}

#[test]
fn v42_catalog_v2_c1bb_json_labels_are_assertions_not_trusted_inputs() {
    let original = vector();
    let (catalog, server) = positive_handoff(&original);
    let mut package_label = original.clone();
    replace_openapi_value(
        &mut package_label,
        "/handoff/package/digest_hex",
        json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    );
    assert!(
        super::validate_candidate_handoff(&package_label, &cddl(), &server, &catalog).is_err(),
        "candidate must derive rather than trust the package digest label"
    );

    let mut preparation_label = original;
    replace_openapi_value(
        &mut preparation_label,
        "/handoff/preparation/signature_hex",
        json!("00"),
    );
    assert!(
        validate_server_handoff(&preparation_label).is_err(),
        "server must derive rather than trust the preparation signature label"
    );
}

#[test]
fn v42_catalog_v2_c1b_b2a_all_authority_modes_are_full_crypto() {
    let value = vector();
    let cddl = cddl();
    let projection = super::validate_catalog_server_projection(&value, &cddl)
        .expect("Catalog projection must validate");
    let (catalog, base) = positive_handoff(&value);
    super::validate_handoff_authority_variants(&value, &cddl, &projection, &base, &catalog).expect(
        "current-root and current-recovery must each pass full server and candidate crypto",
    );

    let mut drifted = value.clone();
    let base_response = value
        .pointer("/handoff/provider_response/cbor_hex")
        .cloned()
        .expect("base provider response");
    replace_openapi_value(
        &mut drifted,
        "/handoff_authority_variants/current_root/provider_response/cbor_hex",
        base_response,
    );
    assert!(
        super::validate_handoff_authority_variants(&drifted, &cddl, &projection, &base, &catalog,)
            .is_err(),
        "an authority label with stale response bytes must fail full validation"
    );
}

#[test]
fn v42_catalog_v2_c1b_b2a_hpke_alternates_are_independently_valid_then_rejected() {
    let value = vector();
    let (_catalog, base) = positive_handoff(&value);
    super::validate_handoff_hpke_alternates(&value, &cddl(), &base)
        .expect("every alternate HPKE transcript must open itself then fail production inputs");

    let mut drifted = value.clone();
    let base_envelope = value
        .pointer("/handoff/hpke_envelope/cbor_hex")
        .cloned()
        .expect("base HPKE envelope");
    replace_openapi_value(
        &mut drifted,
        "/handoff_alternate_constructions/hpke/missing_nul_info/envelope_cbor_hex",
        base_envelope,
    );
    assert!(
        super::validate_handoff_hpke_alternates(&drifted, &cddl(), &base).is_err(),
        "an alternate label with a production envelope must not count as a crypto proof"
    );
}

#[test]
fn v42_catalog_v2_c1b_b2a_signature_alternates_are_independently_valid_then_rejected() {
    let value = vector();
    let (_catalog, base) = positive_handoff(&value);
    super::validate_handoff_signature_alternates(&value, &cddl(), &base)
        .expect("every alternate signature must verify itself then fail production checks");

    let mut drifted = value.clone();
    let base_response = value
        .pointer("/handoff/provider_response/cbor_hex")
        .cloned()
        .expect("base provider response");
    replace_openapi_value(
        &mut drifted,
        "/handoff_alternate_constructions/provider_response_signatures/wrong_domains/cbor_hex",
        base_response,
    );
    assert!(
        super::validate_handoff_signature_alternates(&drifted, &cddl(), &base).is_err(),
        "a production signature relabeled as an alternate must fail its own-domain proof"
    );
}

#[test]
fn v42_catalog_v2_c1b_b2b_authentic_boundary_families_are_closed() {
    let value = vector();
    let cddl = cddl();
    let projection = super::validate_catalog_server_projection(&value, &cddl)
        .expect("Catalog projection must validate");
    let (catalog, base) = positive_handoff(&value);
    super::validate_handoff_b2b_families(&value, &cddl, &projection, &base, &catalog)
        .expect("all B2b families must prove authentic lower layers and exact target rejection");

    let mut drifted = value;
    replace_openapi_value(
        &mut drifted,
        "/handoff_b2b/classification",
        json!("untrusted"),
    );
    assert!(
        super::validate_handoff_b2b_families(&drifted, &cddl, &projection, &base, &catalog,)
            .is_err(),
        "B2b family labels must not weaken fixture provenance"
    );
}

#[test]
fn v42_catalog_v2_c1b_b2b_cross_bindings_and_hidden_rotation_reject_stale_artifacts() {
    let original = vector();
    let cddl = cddl();
    let projection =
        super::validate_catalog_server_projection(&original, &cddl).expect("Catalog projection");
    let (catalog, base) = positive_handoff(&original);

    let mut recipient = original.clone();
    let base_recipient = original
        .pointer("/handoff/preparation/recipient_public_key_hex")
        .cloned()
        .expect("base recipient");
    replace_openapi_value(
        &mut recipient,
        "/handoff_b2b/recipient_bindings/alternate_recipient_device_add_mismatch/test_only_inputs/enrollment_candidate_recipient_public_key_hex",
        base_recipient,
    );
    assert!(
        super::validate_b2b_recipient_bindings(
            &recipient,
            &cddl,
            &projection,
            &base,
            &catalog,
            recipient.get("handoff_b2b").expect("B2b"),
        )
        .is_err(),
        "alternate recipient label must not survive a stale enrollment binding"
    );

    let mut sealed = original.clone();
    let base_envelope = original
        .pointer("/handoff/hpke_envelope")
        .cloned()
        .expect("base envelope");
    replace_openapi_value(
        &mut sealed,
        "/handoff_b2b/sealed_package_mismatches/request_coordinate/hpke_envelope",
        base_envelope,
    );
    assert!(
        super::validate_b2b_sealed_package_mismatches(
            &sealed,
            &cddl,
            &projection,
            &base,
            &catalog,
            sealed.get("handoff_b2b").expect("B2b"),
        )
        .is_err(),
        "re-sealed mismatch must reject a stale envelope"
    );

    let mut rotation = original.clone();
    let current_oracle = original
        .get("origin_authenticated_completion_verifier_descriptors")
        .cloned()
        .expect("current oracle");
    replace_openapi_value(
        &mut rotation,
        "/handoff_b2b/verifier_rotation/rotated_origin_authenticated_oracle",
        current_oracle,
    );
    assert!(
        super::validate_b2b_verifier_rotation(
            &rotation,
            &cddl,
            &projection,
            &base,
            &catalog,
            rotation.get("handoff_b2b").expect("B2b"),
        )
        .is_err(),
        "hidden rotation fixture must contain a genuinely different signed descriptor"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "state, GET, and authenticated-currentness mutations form one closed B2b boundary portfolio"
)]
fn v42_catalog_v2_c1b_b2b_state_get_and_currentness_traces_fail_closed() {
    let original = vector();
    let cddl = cddl();
    let projection =
        super::validate_catalog_server_projection(&original, &cddl).expect("Catalog projection");
    let (catalog, base) = positive_handoff(&original);

    let mut state = original.clone();
    replace_openapi_value(
        &mut state,
        "/handoff_b2b/state_idempotency_traces/preparation/trace/1/writes",
        json!(1),
    );
    assert!(
        super::validate_b2b_state_idempotency(
            &state,
            &cddl,
            &projection,
            &base,
            &catalog,
            state.get("handoff_b2b").expect("B2b"),
        )
        .is_err(),
        "exact replay must never acquire a write"
    );

    let mut get = original.clone();
    replace_openapi_value(
        &mut get,
        "/handoff_b2b/get_state_traces/tie_priority",
        json!(["invalidated", "cancelled", "expired"]),
    );
    assert!(
        super::validate_b2b_get_states(&get, &cddl, &base, get.get("handoff_b2b").expect("B2b"),)
            .is_err(),
        "equal-time terminal selection must stay cancelled-first"
    );

    super::validate_b2b_currentness(
        &original,
        &cddl,
        &projection,
        &base,
        original.get("handoff_b2b").expect("B2b"),
    )
    .expect("authenticated current snapshots must drive all three currentness negatives");

    for (label, pointer, replacement) in [
        (
            "relabeled authority kind",
            "/handoff_b2b/currentness_drifts/authority_kinds/0/kind",
            json!("current_root"),
        ),
        (
            "invalid snapshot head assertion",
            "/handoff_b2b/currentness_drifts/authority_kinds/1/current_identity_snapshot/head_digest_hex",
            json!(super::encode_lower_hex(&[0; 32])),
        ),
        (
            "arbitrary current-key assertion",
            "/handoff_b2b/currentness_drifts/authority_kinds/1/current_identity_snapshot/current_root_public_key_hex",
            json!(super::encode_lower_hex(&base.candidate_signing_public_key)),
        ),
    ] {
        let mut mutation = original.clone();
        replace_openapi_value(&mut mutation, pointer, replacement);
        assert!(
            super::validate_b2b_currentness(
                &mutation,
                &cddl,
                &projection,
                &base,
                mutation.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "{label} must not satisfy an authenticated currentness case"
        );
    }

    let mut invalid_signature = original.clone();
    let signed_pointer = "/handoff_b2b/currentness_drifts/authority_kinds/2/current_identity_snapshot/signed_cbor_hex";
    let signature_pointer =
        "/handoff_b2b/currentness_drifts/authority_kinds/2/current_identity_snapshot/signature_hex";
    let mut signed = super::decode_lower_hex(
        invalid_signature
            .pointer(signed_pointer)
            .and_then(Value::as_str)
            .expect("signed current snapshot"),
    )
    .expect("signed snapshot hex");
    let mut signature = super::decode_lower_hex(
        invalid_signature
            .pointer(signature_pointer)
            .and_then(Value::as_str)
            .expect("current snapshot signature"),
    )
    .expect("snapshot signature hex");
    *signed.last_mut().expect("signed snapshot byte") ^= 1;
    *signature.last_mut().expect("snapshot signature byte") ^= 1;
    replace_openapi_value(
        &mut invalid_signature,
        signed_pointer,
        json!(super::encode_lower_hex(&signed)),
    );
    replace_openapi_value(
        &mut invalid_signature,
        signature_pointer,
        json!(super::encode_lower_hex(&signature)),
    );
    let error = super::validate_b2b_currentness(
        &invalid_signature,
        &cddl,
        &projection,
        &base,
        invalid_signature.get("handoff_b2b").expect("B2b"),
    )
    .expect_err("invalid authenticated-current-snapshot signature must reject");
    assert!(error.to_string().contains("signature invalid"));
}
