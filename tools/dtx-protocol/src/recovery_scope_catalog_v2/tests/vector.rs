#[test]
#[allow(
    clippy::too_many_lines,
    reason = "time, decoder, X25519 semantics, privacy, and wire limitations form one closed B2b boundary portfolio"
)]
fn v42_catalog_v2_c1b_b2b_time_decoder_privacy_and_limitations_fail_closed() {
    let original = vector();
    let cddl = cddl();
    let projection =
        super::validate_catalog_server_projection(&original, &cddl).expect("Catalog projection");
    let (catalog, base) = positive_handoff(&original);

    super::validate_b2b_decoder_privacy(
        &original,
        &cddl,
        &projection,
        original.get("handoff_b2b").expect("B2b"),
    )
    .expect("authentic low-order preparations must reach the shared recipient-key seam");
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let key: [u8; 32] = super::decode_lower_hex(encoded)
            .expect("low-order hex")
            .try_into()
            .expect("32-byte low-order encoding");
        let error = super::validate_recipient_public_key_semantics(key)
            .expect_err("every X25519 low-order point must reject");
        assert!(
            error
                .to_string()
                .contains("all-zero or low-order X25519 recipient key rejected")
        );
    }
    super::validate_recipient_public_key_semantics(base.candidate_recipient_public_key)
        .expect("base recipient key must pass the production semantic seam");
    let alternate_recipient: [u8; 32] = super::decode_lower_hex(
        original
            .pointer("/handoff_b2b/recipient_bindings/alternate_recipient_device_add_mismatch/preparation/recipient_public_key_hex")
            .and_then(Value::as_str)
            .expect("authentic alternate recipient key"),
    )
    .expect("alternate recipient hex")
    .try_into()
    .expect("32-byte alternate recipient key");
    super::validate_recipient_public_key_semantics(alternate_recipient)
        .expect("authentic alternate recipient key must pass the production semantic seam");

    let all_zero_path =
        "/handoff_b2b/decoder_privacy_closure/low_order_recipient_preparations/all_zero";
    let one_path =
        "/handoff_b2b/decoder_privacy_closure/low_order_recipient_preparations/u_coordinate_one";
    let all_zero = original
        .pointer(all_zero_path)
        .cloned()
        .expect("all-zero fixture");
    let one = original.pointer(one_path).cloned().expect("u=1 fixture");
    let mut one_key = [0; 32];
    one_key[0] = 1;
    for (name, preparation, recipient_key) in [
        ("all_zero", &all_zero, [0; 32]),
        ("u_coordinate_one", &one, one_key),
    ] {
        let mut input = super::parse_server_visible_handoff_input(&original)
            .expect("base server-visible handoff input");
        input.preparation = preparation.clone();
        input.enrollment_candidate_recipient_public_key = recipient_key;
        let error = super::validate_server_visible_handoff(&cddl, &projection, &input)
            .expect_err("normal preparation admission must reject low-order X25519 keys");
        assert!(
            error
                .to_string()
                .contains("all-zero or low-order X25519 recipient key rejected"),
            "{name} did not reach the shared normal-admission recipient semantic seam"
        );
    }
    let mut relabeled = original.clone();
    replace_openapi_value(&mut relabeled, all_zero_path, one);
    replace_openapi_value(&mut relabeled, one_path, all_zero);
    super::validate_b2b_decoder_privacy(
        &relabeled,
        &cddl,
        &projection,
        relabeled.get("handoff_b2b").expect("B2b"),
    )
    .expect("fixture labels must not decide low-order recipient rejection");
    let mut valid_key_under_negative_label = original.clone();
    replace_openapi_value(
        &mut valid_key_under_negative_label,
        all_zero_path,
        original
            .pointer("/handoff/preparation")
            .cloned()
            .expect("base preparation"),
    );
    let error = super::validate_b2b_decoder_privacy(
        &valid_key_under_negative_label,
        &cddl,
        &projection,
        valid_key_under_negative_label
            .get("handoff_b2b")
            .expect("B2b"),
    )
    .expect_err("a valid recipient key must not reject because of a fixture label");
    assert!(
        error
            .to_string()
            .contains("all_zero X25519 recipient was accepted")
    );

    let mut time = original.clone();
    replace_openapi_value(
        &mut time,
        "/handoff_b2b/time_boundaries/preparation/issued_before_catalog/expected_valid",
        json!(true),
    );
    assert!(
        super::validate_b2b_time_boundaries(
            &time,
            &cddl,
            &projection,
            &base,
            &catalog,
            time.get("handoff_b2b").expect("B2b"),
        )
        .is_err(),
        "a re-signed out-of-window preparation must not be relabeled valid"
    );

    let mut decoder = original.clone();
    let canonical = original
        .pointer("/handoff/preparation/cbor_hex")
        .cloned()
        .expect("canonical preparation");
    replace_openapi_value(
        &mut decoder,
        "/handoff_b2b/decoder_privacy_closure/noncanonical_preparation_cbor_hex",
        canonical,
    );
    assert!(
        super::validate_b2b_decoder_privacy(
            &decoder,
            &cddl,
            &projection,
            decoder.get("handoff_b2b").expect("B2b"),
        )
        .is_err(),
        "canonical bytes must not count as a noncanonical decoder negative"
    );

    let mut limitations = original;
    replace_openapi_value(
        &mut limitations,
        "/handoff_b2b/limitations/generic_counter_is_wire",
        json!(true),
    );
    assert!(
        super::validate_b2b_limitations(limitations.get("handoff_b2b").expect("B2b")).is_err(),
        "B2b must not invent a generic counter wire field"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-driven mutation portfolio freezes the complete handoff security contract"
)]
fn v42_catalog_v2_openapi_rejects_handoff_contract_mutations() {
    let original = openapi_document();
    let mutations = vec![
        ("preparation operation", format!("{}/operationId", super::PREPARATION_OPERATION), json!("driftedOperation")),
        ("preparation authentication", format!("{}/x-dirextalk-authentication/authorization-header", super::PREPARATION_OPERATION), json!("optional")),
        ("candidate protected recipient key", format!("{}/x-dirextalk-path-body-binding/recipient-key-source", super::PREPARATION_OPERATION), json!("caller-supplied")),
        ("preparation idempotency", format!("{}/x-dirextalk-idempotency/same-key-identical-body", super::PREPARATION_OPERATION), json!("recompute")),
        ("preparation reject order", format!("{}/x-dirextalk-reject-before-write-order/0", super::PREPARATION_OPERATION), json!("capabilities")),
        ("preparation CAS", format!("{}/x-dirextalk-cas-transaction/count", super::PREPARATION_OPERATION), json!(2)),
        ("preparation media", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-preparation.v2+cbor/x-dirextalk-cddl-rule", super::PREPARATION_OPERATION), json!("alternate-rule")),
        ("preparation cap", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-preparation.v2+cbor/x-dirextalk-max-body-bytes", super::PREPARATION_OPERATION), json!(534)),
        ("status response auth", format!("{}/x-dirextalk-authentication/kind", super::STATUS_OPERATION), json!("bearer")),
        ("status currentness", format!("{}/x-dirextalk-currentness/required-state", super::STATUS_OPERATION), json!("portable-signatures")),
        ("status H+2", format!("{}/x-dirextalk-currentness/no-h-plus-2", super::STATUS_OPERATION), json!(false)),
        ("status checkpoint", format!("{}/x-dirextalk-currentness/portable-checkpoint-claimed", super::STATUS_OPERATION), json!(true)),
        ("provider authorization", format!("{}/x-dirextalk-authentication/authenticated-session-equals-provider-descriptor", super::PROVIDER_RESPONSE_OPERATION), json!(false)),
        ("candidate provider", format!("{}/x-dirextalk-authentication/candidate-can-never-be-provider", super::PROVIDER_RESPONSE_OPERATION), json!(false)),
        ("provider path binding", format!("{}/x-dirextalk-path-body-binding/request-id-cbor-path", super::PROVIDER_RESPONSE_OPERATION), json!([3])),
        ("response idempotency", format!("{}/x-dirextalk-idempotency/different-key-after-existence", super::PROVIDER_RESPONSE_OPERATION), json!(201)),
        ("provider reject order", format!("{}/x-dirextalk-reject-before-write-order/4", super::PROVIDER_RESPONSE_OPERATION), json!("single-signature")),
        ("provider CAS lock order", format!("{}/x-dirextalk-cas-transaction/lock-order", super::PROVIDER_RESPONSE_OPERATION), json!(["preparation", "identity", "challenge"])),
        ("portable signatures wording", format!("{}/x-dirextalk-portable-evidence/dual-signatures", super::PROVIDER_RESPONSE_OPERATION), json!("portable-currentness-proof")),
        ("provider DeviceAdd cap", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor/x-dirextalk-max-device-add-bytes", super::PROVIDER_RESPONSE_OPERATION), json!(549)),
        ("provider body cap", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor/x-dirextalk-max-body-bytes", super::PROVIDER_RESPONSE_OPERATION), json!(super::MAX_PROVIDER_RESPONSE_BODY_BYTES + 1)),
        ("HPKE mode", "/x-dirextalk-handoff-hpke/mode".to_owned(), json!("auth")),
        ("HPKE KEM", "/x-dirextalk-handoff-hpke/kem/id".to_owned(), json!(33)),
        ("HPKE info", "/x-dirextalk-handoff-hpke/info".to_owned(), json!("alternate\0")),
        ("HPKE replay", "/x-dirextalk-handoff-hpke/exact-replay".to_owned(), json!("re-encrypt")),
        ("HPKE envelope digest", "/x-dirextalk-handoff-hpke/envelope-digest-input".to_owned(), json!("ciphertext-alone")),
        ("package max", "/x-dirextalk-handoff-hpke/package-max-bytes".to_owned(), json!(super::MAX_PROVIDER_PACKAGE_BYTES + 1)),
        ("HPKE ciphertext max", "/x-dirextalk-handoff-hpke/ciphertext-max-bytes".to_owned(), json!(super::MAX_HPKE_CIPHERTEXT_BYTES + 1)),
        ("exact envelope max", "/x-dirextalk-handoff-hpke/encoded-envelope-max-bytes".to_owned(), json!(super::MAX_HPKE_ENCODED_ENVELOPE_BYTES + 1)),
        ("decoder ceiling separation", "/x-dirextalk-handoff-hpke/decoder-ceiling-is-not-envelope-allowance".to_owned(), json!(false)),
        ("provider key id", "/x-dirextalk-handoff-signers/provider-descriptor/key-id-present".to_owned(), json!(true)),
        ("authority open union", "/x-dirextalk-handoff-signers/independent-authority/closed-union".to_owned(), json!(false)),
        ("authority unknown kind", "/x-dirextalk-handoff-signers/independent-authority/unknown-kind".to_owned(), json!("accepted")),
        ("authority kind", "/x-dirextalk-handoff-signers/independent-authority/kinds/recovery-authority/kind".to_owned(), json!(4)),
        ("pairwise signer key", "/x-dirextalk-handoff-signers/key-separation/candidate-provider-and-authority-ed25519-public-keys".to_owned(), json!("may-match")),
        ("candidate cross-algorithm key bytes", "/x-dirextalk-handoff-signers/key-separation/candidate-ed25519-and-x25519-public-key-bytes".to_owned(), json!("may-match")),
        ("active signer ids", "/x-dirextalk-handoff-signers/key-separation/candidate-provider-and-active-authority-device-ids".to_owned(), json!("may-match")),
        ("H highwater", "/x-dirextalk-handoff-equality-validity/highwater/h".to_owned(), json!("0..9007199254740991")),
        ("H+1 equality", "/x-dirextalk-handoff-equality-validity/highwater/h-plus-1".to_owned(), json!("positive-but-not-successor")),
        ("duplicate coordinate", "/x-dirextalk-handoff-equality-validity/duplicate-coordinates/preparation-to-response/0/request-id".to_owned(), json!("partial-coordinate-set")),
        ("signed head exact bytes", "/x-dirextalk-handoff-equality-validity/signed-head/package-field-4".to_owned(), json!("reencoded-head")),
        ("signed head digest equality", "/x-dirextalk-handoff-equality-validity/signed-head/digest-equals/1".to_owned(), json!("wrong-field")),
        ("Catalog plaintext count/root", "/x-dirextalk-handoff-equality-validity/catalog-plaintext/validates-against-signed-head/4".to_owned(), json!("ciphertext-digest")),
        ("DeviceAdd kind", "/x-dirextalk-handoff-equality-validity/device-add/canonical-kind".to_owned(), json!("any-event")),
        ("DeviceAdd sequence", "/x-dirextalk-handoff-equality-validity/device-add/validates/1".to_owned(), json!("sequence-at-least-h-plus-1")),
        ("DeviceAdd signature", "/x-dirextalk-handoff-equality-validity/device-add/validates/6".to_owned(), json!("certificate-signature-optional")),
        ("DeviceAdd digest domain", "/x-dirextalk-handoff-equality-validity/device-add/digest-domain".to_owned(), json!("dirextalk.identity-log-event.v1\0")),
        ("issued/expires", "/x-dirextalk-handoff-equality-validity/validity/every-issued-at-before-expires-at".to_owned(), json!(false)),
        ("repeated times", "/x-dirextalk-handoff-equality-validity/validity/response-package-aad-times".to_owned(), json!("independent")),
        ("acceptance time", "/x-dirextalk-handoff-equality-validity/validity/provider-accepted-at".to_owned(), json!("recomputed")),
        ("server projection", "/x-dirextalk-handoff-equality-validity/identity-server-validation/never/0".to_owned(), json!("decrypt-package-allowed")),
        ("candidate post-decryption", "/x-dirextalk-handoff-equality-validity/candidate-post-decryption-validation/validates/0".to_owned(), json!("package-digest-optional")),
        ("replay authentication", "/x-dirextalk-handoff-replay-order/prerequisite".to_owned(), json!("none")),
        ("replay static order", "/x-dirextalk-handoff-replay-order/before-claim-resolution/1".to_owned(), json!("mutable-currentness")),
        ("committed replay order", "/x-dirextalk-handoff-replay-order/committed-exact-claim".to_owned(), json!("after-mutable-currentness")),
        ("first-admission gates", "/x-dirextalk-handoff-replay-order/mutable-currentness-and-final-cas".to_owned(), json!("every-replay")),
        ("status enum", "/x-dirextalk-handoff-state-machine/status-codes/invalidated".to_owned(), json!(6)),
        ("state_changed_at", "/x-dirextalk-handoff-state-machine/state-changed-at/invalidated".to_owned(), json!("get-time")),
        ("terminal earliest", "/x-dirextalk-handoff-state-machine/terminal-selection/primary".to_owned(), json!("latest")),
        ("terminal tie priority", "/x-dirextalk-handoff-state-machine/terminal-selection/equal-time-state-priority/0".to_owned(), json!("expired")),
        ("invalidation reason priority", "/x-dirextalk-handoff-state-machine/reason-codes/invalidated-priority/provider-session-or-key".to_owned(), json!(1)),
        ("GET read-only", "/x-dirextalk-handoff-state-machine/get-semantics".to_owned(), json!("writes-transition")),
        ("ready response", "/x-dirextalk-handoff-state-machine/only-ready-embeds-response".to_owned(), json!(false)),
        ("receipt immutability", "/x-dirextalk-handoff-state-machine/receipts-remain-immutable-after-get-invalidation".to_owned(), json!(false)),
        ("privacy", "/x-dirextalk-handoff-privacy/forbidden-persistence-and-responses/0".to_owned(), json!("raw-capability-is-safe")),
        ("preparation receipt cap", "/components/responses/PreparationCreated/content/application~1vnd.dirextalk.recovery-scope-catalog-preparation-receipt.v2+cbor/x-dirextalk-max-body-bytes".to_owned(), json!(88)),
        ("provider receipt rule", "/components/responses/ProviderResponseReplay/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response-receipt.v2+cbor/x-dirextalk-cddl-rule".to_owned(), json!("alternate-receipt")),
        ("status cap", "/components/responses/HandoffStatus/content/application~1vnd.dirextalk.recovery-scope-catalog-status.v2+cbor/x-dirextalk-max-body-bytes".to_owned(), json!(super::MAX_STATUS_BODY_BYTES + 1)),
        ("idempotency ASCII pattern", "/components/parameters/IdempotencyKey/schema/pattern".to_owned(), json!("^.{16,128}$")),
    ];
    for (label, pointer, replacement) in mutations {
        let mut mutated = original.clone();
        replace_openapi_value(&mut mutated, &pointer, replacement);
        assert_openapi_document_rejected(label, &mutated);
    }

    for operation in [
        super::PREPARATION_OPERATION,
        super::PROVIDER_RESPONSE_OPERATION,
    ] {
        let pointer = format!("{operation}/x-dirextalk-cas-transaction/final-predicate-fences");
        let fence_count = original
            .pointer(&pointer)
            .and_then(Value::as_array)
            .expect("CAS fences must be an array")
            .len();
        for index in 0..fence_count {
            let mut mutated = original.clone();
            mutated
                .pointer_mut(&pointer)
                .and_then(Value::as_array_mut)
                .expect("CAS fences must be mutable")
                .remove(index);
            assert_openapi_document_rejected(
                &format!("omitted CAS fence {operation} index {index}"),
                &mutated,
            );
        }
    }
    for mapping in [
        "preparation-to-response",
        "response-to-package",
        "response-to-public-aad",
        "response-to-package-times",
        "preparation-to-device-add",
    ] {
        let pointer =
            format!("/x-dirextalk-handoff-equality-validity/duplicate-coordinates/{mapping}");
        let mapping_count = original
            .pointer(&pointer)
            .and_then(Value::as_array)
            .expect("coordinate mappings must be arrays")
            .len();
        for index in 0..mapping_count {
            let mut mutated = original.clone();
            mutated
                .pointer_mut(&pointer)
                .and_then(Value::as_array_mut)
                .expect("coordinate mappings must be mutable")
                .remove(index);
            assert_openapi_document_rejected(
                &format!("omitted equality mapping {mapping} index {index}"),
                &mutated,
            );
        }
    }
    for forbidden_status in ["410", "412"] {
        let mut mutated = original.clone();
        mutated
            .pointer_mut(&format!("{}/responses", super::STATUS_OPERATION))
            .and_then(Value::as_object_mut)
            .expect("GET responses must be mutable")
            .insert(
                forbidden_status.to_owned(),
                json!({"$ref": "#/components/responses/HandoffGone"}),
            );
        assert_openapi_document_rejected(
            &format!("GET must not expose {forbidden_status}"),
            &mutated,
        );
    }

    for route in [
        super::PREPARATION_ROUTE,
        super::STATUS_ROUTE,
        super::PROVIDER_RESPONSE_ROUTE,
    ] {
        let mut mutated = original.clone();
        mutated
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("paths must be an object")
            .remove(route);
        assert_openapi_document_rejected(route, &mutated);
    }
    let domains = original
        .pointer("/x-dirextalk-handoff-crypto-domains")
        .and_then(Value::as_object)
        .expect("handoff domains must be an object");
    for domain in domains.keys() {
        let mut mutated = original.clone();
        replace_openapi_value(
            &mut mutated,
            &format!("/x-dirextalk-handoff-crypto-domains/{domain}"),
            json!("alternate-domain\0"),
        );
        assert_openapi_document_rejected(domain, &mutated);
    }
}

#[test]
fn v42_catalog_v2_openapi_http_contract_is_frozen() {
    let document = super::parse_openapi(&openapi()).expect("OpenAPI must parse");
    super::validate_openapi_http_contract(&document)
        .expect("Recovery Scope Catalog V2 HTTP contract must remain frozen");
}

#[test]
fn v42_catalog_v2_openapi_projection_and_proof_are_frozen() {
    let document = super::parse_openapi(&openapi()).expect("OpenAPI must parse");
    super::validate_openapi_projection_and_proof(&document)
        .expect("Recovery Scope Catalog V2 privacy and proof metadata must remain frozen");
}

#[test]
fn v42_catalog_v2_openapi_rejects_path_and_privacy_drift() {
    let original = openapi_document();

    let mut missing = original.clone();
    missing
        .pointer_mut("/paths")
        .and_then(Value::as_object_mut)
        .expect("paths must be an object")
        .remove(super::OPENAPI_ROUTE);
    assert_openapi_document_rejected("missing path declaration", &missing);

    let mut extra = original.clone();
    let route = extra
        .pointer("/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}")
        .expect("frozen route must exist")
        .clone();
    extra
        .pointer_mut("/paths")
        .and_then(Value::as_object_mut)
        .expect("paths must be an object")
        .insert(
            "/v2/recovery-scope-catalogs/{catalog_id}/{generation}".to_owned(),
            route,
        );
    assert_openapi_document_rejected("extra path declaration", &extra);

    let mut mismatched = original.clone();
    let paths = mismatched
        .pointer_mut("/paths")
        .and_then(Value::as_object_mut)
        .expect("paths must be an object");
    let route = paths
        .remove(super::OPENAPI_ROUTE)
        .expect("frozen route must exist");
    paths.insert(
        "/v2/recovery-scope-catalogs/{wrong_catalog_id}".to_owned(),
        route,
    );
    assert_openapi_document_rejected("mismatched path declaration", &mismatched);

    let mut binding = original.clone();
    replace_openapi_value(
        &mut binding,
        &format!(
            "{}/x-dirextalk-path-coordinate-binding/coordinates/catalog_id/cbor-path",
            super::OPENAPI_OPERATION
        ),
        json!([1, 3]),
    );
    assert_openapi_document_rejected("mismatched signed binding", &binding);

    let mut leakage = original.clone();
    leakage
        .pointer_mut(&format!(
            "{}/x-dirextalk-server-visible-projection/allowed-cbor-paths",
            super::OPENAPI_OPERATION
        ))
        .and_then(Value::as_array_mut)
        .expect("allowed projection paths must be an array")
        .push(json!([3]));
    assert_openapi_document_rejected("forbidden projection leakage", &leakage);
}

#[test]
fn v42_catalog_v2_openapi_rejects_v2_response_contract_mutations() {
    const PREPARATION_RESPONSES: &str =
        "/paths/~1v3~1devices~1enroll~1catalog-preparations/post/responses";

    let original = openapi_document();
    super::validate_openapi_document(&original)
        .expect("the frozen V2 response contract must validate before mutations");

    let mut missing_required = original.clone();
    missing_required
        .pointer_mut(
            "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}/get/parameters",
        )
        .and_then(Value::as_array_mut)
        .expect("GET parameters must be an array")
        .remove(1);
    assert_openapi_document_rejected(
        "a missing required response capability parameter",
        &missing_required,
    );

    let mut extra_field = original.clone();
    extra_field
        .pointer_mut("/components/schemas/ErrorEnvelopeV2/properties")
        .and_then(Value::as_object_mut)
        .expect("error envelope properties must be an object")
        .insert("details".to_owned(), json!({"type": "string"}));
    assert_openapi_document_rejected("an extra error-envelope field", &extra_field);

    let mut wrong_status = original.clone();
    *wrong_status
        .pointer_mut(&format!("{PREPARATION_RESPONSES}/201/$ref"))
        .expect("preparation 201 response reference") =
        json!("#/components/responses/PreparationReplay");
    assert_openapi_document_rejected("a wrong mutation status mapping", &wrong_status);

    let mut wrong_code = original.clone();
    *wrong_code
        .pointer_mut(
            "/components/schemas/HandoffGoneErrorV2/allOf/1/properties/error/properties/code/enum/0",
        )
        .expect("HandoffGone stable error code") = json!("RECOVERY_CATALOG_EXPIRED");
    assert_openapi_document_rejected("a wrong stable error code", &wrong_code);

    let mut wrong_body = original.clone();
    *wrong_body
        .pointer_mut("/components/responses/HandoffConflict/content")
        .expect("mutation error response content") = json!({
        "application/vnd.dirextalk.recovery-scope-catalog-status.v2+cbor": {
            "x-dirextalk-exact-cbor": true,
            "x-dirextalk-cddl-rule": "recovery-scope-catalog-status-v2",
            "x-dirextalk-max-body-bytes": super::MAX_STATUS_BODY_BYTES,
            "schema": {"$ref": "#/components/schemas/ExactCanonicalCbor"}
        }
    });
    assert_openapi_document_rejected(
        "a mutation error with terminal-CBOR body shape",
        &wrong_body,
    );

    let mut wrong_envelope = original.clone();
    wrong_envelope
        .pointer_mut("/components/schemas/ErrorEnvelopeV2/required")
        .and_then(Value::as_array_mut)
        .expect("error envelope required fields")
        .retain(|field| field != "error");
    assert_openapi_document_rejected("a malformed error envelope", &wrong_envelope);

    let mut missing_header = original.clone();
    missing_header
        .pointer_mut("/components/responses/HandoffConflict/headers")
        .and_then(Value::as_object_mut)
        .expect("mutation response headers")
        .remove("X-Request-Id");
    assert_openapi_document_rejected("a missing required response header", &missing_header);

    let mut wrong_header = original;
    *wrong_header
        .pointer_mut("/components/responses/HandoffConflict/headers/X-Request-Id/$ref")
        .expect("mutation response request-id header") = json!("#/components/headers/NoStore");
    assert_openapi_document_rejected("a wrong required response header binding", &wrong_header);
}

#[test]
fn v42_catalog_v2_openapi_get_errors_remain_separate_from_mutation_and_terminal_cbor() {
    const STATUS_RESPONSES: &str =
        "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}/get/responses";

    let original = openapi_document();
    super::validate_openapi_document(&original)
        .expect("the frozen V2 GET contract must validate before mutations");

    let status_responses = original
        .pointer(STATUS_RESPONSES)
        .and_then(Value::as_object)
        .expect("GET response map must be an object");
    assert_eq!(
        status_responses.keys().collect::<Vec<_>>(),
        vec!["200", "401", "406"]
    );
    for status in ["401", "406"] {
        let component = status_responses
            .get(status)
            .and_then(|value| value.get("$ref"))
            .and_then(Value::as_str)
            .expect("GET error must reference a response component")
            .strip_prefix("#/components/responses/")
            .expect("GET error reference must be local");
        assert!(
            original
                .pointer(&format!(
                    "/components/responses/{component}/content/application~1json"
                ))
                .is_some(),
            "GET {status} must use the JSON error envelope"
        );
    }
    assert!(
        original
            .pointer(
                "/components/responses/HandoffStatus/content/application~1vnd.dirextalk.recovery-scope-catalog-status.v2+cbor",
            )
            .is_some(),
        "the successful GET status must remain terminal status CBOR"
    );

    let mut extra_terminal_status = original.clone();
    extra_terminal_status
        .pointer_mut(STATUS_RESPONSES)
        .and_then(Value::as_object_mut)
        .expect("GET response map must be mutable")
        .insert(
            "410".to_owned(),
            json!({"$ref": "#/components/responses/HandoffGone"}),
        );
    assert_openapi_document_rejected(
        "an extra mutation terminal status on GET",
        &extra_terminal_status,
    );

    let mut mutation_error_on_get = original.clone();
    *mutation_error_on_get
        .pointer_mut(&format!("{STATUS_RESPONSES}/401/$ref"))
        .expect("GET capability error reference") = json!("#/components/responses/HandoffConflict");
    assert_openapi_document_rejected(
        "a mutation error substituted for GET 401",
        &mutation_error_on_get,
    );

    let mut terminal_cbor_on_get_error = original.clone();
    *terminal_cbor_on_get_error
        .pointer_mut(&format!("{STATUS_RESPONSES}/406/$ref"))
        .expect("GET not-acceptable error reference") =
        json!("#/components/responses/HandoffStatus");
    assert_openapi_document_rejected(
        "terminal status CBOR substituted for GET 406 error",
        &terminal_cbor_on_get_error,
    );

    let mut mutation_receipt_on_get_success = original.clone();
    *mutation_receipt_on_get_success
        .pointer_mut(&format!("{STATUS_RESPONSES}/200/$ref"))
        .expect("GET success response reference") =
        json!("#/components/responses/ProviderResponseCreated");
    assert_openapi_document_rejected(
        "mutation receipt substituted for GET terminal status",
        &mutation_receipt_on_get_success,
    );

    let mut json_status = original;
    *json_status
        .pointer_mut("/components/responses/HandoffStatus/content")
        .expect("terminal status content") = json!({
        "application/json": {
            "schema": {"$ref": "#/components/schemas/HandoffCapabilityErrorV2"}
        }
    });
    assert_openapi_document_rejected(
        "JSON body substituted for terminal GET status CBOR",
        &json_status,
    );
}

#[test]
fn v42_catalog_v2_openapi_rejects_frozen_field_drift() {
    let original = openapi_document();
    let request_schema = format!(
        "{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/schema/$ref",
        super::OPENAPI_OPERATION
    );
    let created_schema = "/components/responses/CatalogCreated/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/schema/$ref";
    let replay_schema = "/components/responses/CatalogReplay/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/schema/$ref";
    let membership_domain = format!(
        "{}/x-dirextalk-crypto-domains/membership-receipt",
        super::OPENAPI_OPERATION
    );
    let scope_domain = format!(
        "{}/x-dirextalk-crypto-domains/recovery-scope",
        super::OPENAPI_OPERATION
    );
    let mutations = [
        ("info.version", "/info/version", json!("2.0.1")),
        (
            "signed head ceiling",
            "/x-dirextalk-canonical-cbor-ceilings/signed-catalog-head/maximum-bytes",
            json!(467),
        ),
        (
            "upload body ceiling",
            "/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}/put/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/x-dirextalk-max-body-bytes",
            json!(super::MAX_CATALOG_UPLOAD_BODY_BYTES + 1),
        ),
        (
            "upload decoder separation",
            "/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}/put/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/x-dirextalk-decoder-ceiling-is-not-body-allowance",
            json!(false),
        ),
        (
            "created signed head response ceiling",
            "/components/responses/CatalogCreated/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/x-dirextalk-max-body-bytes",
            json!(467),
        ),
        (
            "request schema ref",
            request_schema.as_str(),
            json!("#/components/schemas/UuidV7"),
        ),
        (
            "created schema ref",
            created_schema,
            json!("#/components/schemas/UuidV7"),
        ),
        (
            "replay schema ref",
            replay_schema,
            json!("#/components/schemas/UuidV7"),
        ),
        (
            "exact CBOR type",
            "/components/schemas/ExactCanonicalCbor/type",
            json!("object"),
        ),
        (
            "exact CBOR content encoding",
            "/components/schemas/ExactCanonicalCbor/contentEncoding",
            json!("base64"),
        ),
        (
            "UUIDv7 type",
            "/components/schemas/UuidV7/type",
            json!("integer"),
        ),
        (
            "Authorization type",
            "/components/parameters/DeviceAuthorization/schema/type",
            json!("integer"),
        ),
        (
            "Idempotency-Key type",
            "/components/parameters/IdempotencyKey/schema/type",
            json!("integer"),
        ),
        (
            "membership receipt domain",
            membership_domain.as_str(),
            json!("dirextalk.recovery-scope-membership-receipt.v2\0"),
        ),
        (
            "recovery scope domain",
            scope_domain.as_str(),
            json!("dirextalk.recovery-scope.v2\0"),
        ),
    ];
    for (label, pointer, replacement) in mutations {
        let mut mutated = original.clone();
        replace_openapi_value(&mut mutated, pointer, replacement);
        assert_openapi_document_rejected(label, &mutated);
    }
}

#[test]
fn v42_catalog_v2_openapi_rejects_each_private_verifier_projection() {
    let original = openapi_document();
    let pointer = format!(
        "{}/x-dirextalk-server-visible-projection/forbidden-data",
        super::OPENAPI_OPERATION
    );
    for token in [
        "verifier-public-key",
        "verifier-key-id",
        "verifier-epoch",
        "completion-evidence-issuer-epk",
        "completion-evidence-issuer-pop",
        "completion-evidence-issuer-origin-authorization",
        "completion-evidence-issuer-authorization-digest",
    ] {
        let mut mutated = original.clone();
        let forbidden = mutated
            .pointer_mut(&pointer)
            .and_then(Value::as_array_mut)
            .expect("forbidden projection data must be an array");
        let item = forbidden
            .iter_mut()
            .find(|value| value.as_str() == Some(token))
            .unwrap_or_else(|| panic!("frozen privacy token must exist: {token}"));
        *item = json!(format!("{token}-drift"));
        assert_openapi_document_rejected(token, &mutated);
    }
}

#[test]
fn v42_catalog_v2_openapi_rejects_private_body_digest_metadata_drift() {
    let original = openapi_document();
    let base = format!(
        "{}/x-dirextalk-private-body-derived-digests",
        super::OPENAPI_OPERATION
    );
    for (digest, wrong_domain) in [
        (
            "membership-receipt",
            "dirextalk.recovery-scope-membership-receipt.v2\0",
        ),
        ("recovery-scope", "dirextalk.recovery-scope.v2\0"),
    ] {
        for (field, replacement) in [
            ("algorithm", json!("SHA-512")),
            ("domain", json!(wrong_domain)),
            ("output-cbor-path", json!([99])),
            ("input-cbor-path", json!([99])),
            ("input-encoding", json!("implementation-defined")),
        ] {
            let mut mutated = original.clone();
            replace_openapi_value(
                &mut mutated,
                &format!("{base}/{digest}/{field}"),
                replacement,
            );
            assert_openapi_document_rejected(
                &format!("{digest} derived digest {field} drift"),
                &mutated,
            );
        }

        let mut extra = original.clone();
        extra
            .pointer_mut(&format!("{base}/{digest}"))
            .and_then(Value::as_object_mut)
            .expect("derived digest metadata must be an object")
            .insert("extra".to_owned(), json!(true));
        assert_openapi_document_rejected(&format!("{digest} derived digest extra key"), &extra);
    }
}
