use super::{
    MAX_DEVICE_ADD_BYTES, MAX_HPKE_ENCODED_ENVELOPE_BYTES, MAX_PREPARATION_BODY_BYTES,
    MAX_PROVIDER_RESPONSE_BODY_BYTES, MAX_STATUS_BODY_BYTES, PREPARATION_MEDIA,
    PREPARATION_OPERATION, PREPARATION_RECEIPT_MEDIA, PROVIDER_RESPONSE_MEDIA,
    PROVIDER_RESPONSE_OPERATION, PROVIDER_RESPONSE_RECEIPT_MEDIA, ProtocolToolError, STATUS_MEDIA,
    STATUS_OPERATION, Value, expect_object_keys, expect_value, json, validate_error_response,
    validate_response_headers,
};
#[allow(
    clippy::too_many_lines,
    reason = "the additive handoff freezes three operations, five media, receipts, status, and uniform failures"
)]
pub(crate) fn validate_openapi_handoff_http_contract(
    document: &Value,
) -> Result<(), ProtocolToolError> {
    for (operation, expected) in [
        (
            PREPARATION_OPERATION,
            "createRecoveryScopeCatalogPreparationV2",
        ),
        (STATUS_OPERATION, "getRecoveryScopeCatalogStatusV2"),
        (
            PROVIDER_RESPONSE_OPERATION,
            "putRecoveryScopeCatalogProviderResponseV2",
        ),
    ] {
        expect_value(
            document,
            &format!("{operation}/operationId"),
            &json!(expected),
        )?;
    }
    expect_value(
        document,
        &format!("{PREPARATION_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/EnrollmentCapability"},
            {"$ref": "#/components/parameters/ResponseCapability"},
            {"$ref": "#/components/parameters/IdempotencyKey"}
        ]),
    )?;
    expect_value(
        document,
        &format!("{STATUS_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/RequestId"},
            {"$ref": "#/components/parameters/ResponseCapability"},
            {"$ref": "#/components/parameters/StatusAccept"}
        ]),
    )?;
    expect_value(
        document,
        &format!("{PROVIDER_RESPONSE_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/RequestId"},
            {"$ref": "#/components/parameters/DeviceAuthorization"},
            {"$ref": "#/components/parameters/IdempotencyKey"},
            {"$ref": "#/components/parameters/ProviderReceiptAccept"}
        ]),
    )?;
    for (parameter, name, location) in [
        ("RequestId", "request_id", "path"),
        (
            "EnrollmentCapability",
            "DTX-Enrollment-Capability",
            "header",
        ),
        (
            "ResponseCapability",
            "DTX-Recovery-Response-Capability",
            "header",
        ),
        ("StatusAccept", "Accept", "header"),
        ("ProviderReceiptAccept", "Accept", "header"),
    ] {
        let base = format!("/components/parameters/{parameter}");
        expect_value(document, &format!("{base}/name"), &json!(name))?;
        expect_value(document, &format!("{base}/in"), &json!(location))?;
        expect_value(document, &format!("{base}/required"), &json!(true))?;
    }
    for capability in ["EnrollmentCapability", "ResponseCapability"] {
        expect_value(
            document,
            &format!("/components/parameters/{capability}/schema/pattern"),
            &json!("^[A-Za-z0-9_-]{43}$"),
        )?;
    }
    expect_value(
        document,
        "/components/parameters/RequestId/schema/$ref",
        &json!("#/components/schemas/UuidV7"),
    )?;
    expect_value(
        document,
        "/components/parameters/StatusAccept/schema/const",
        &json!(STATUS_MEDIA),
    )?;
    expect_value(
        document,
        "/components/parameters/ProviderReceiptAccept/schema/const",
        &json!(PROVIDER_RESPONSE_RECEIPT_MEDIA),
    )?;
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/pattern",
        &json!("^[A-Za-z0-9_-]{16,128}$"),
    )?;
    if document
        .pointer(&format!("{STATUS_OPERATION}/requestBody"))
        .is_some()
    {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 status GET must not declare a request body",
        ));
    }
    validate_handoff_request_media(
        document,
        PREPARATION_OPERATION,
        PREPARATION_MEDIA,
        "recovery-scope-catalog-preparation-v2",
        MAX_PREPARATION_BODY_BYTES,
    )?;
    validate_handoff_request_media(
        document,
        PROVIDER_RESPONSE_OPERATION,
        PROVIDER_RESPONSE_MEDIA,
        "recovery-scope-catalog-provider-response-v2",
        MAX_PROVIDER_RESPONSE_BODY_BYTES,
    )?;
    let provider_media = format!(
        "{PROVIDER_RESPONSE_OPERATION}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor"
    );
    expect_value(
        document,
        &format!("{provider_media}/x-dirextalk-max-device-add-bytes"),
        &json!(MAX_DEVICE_ADD_BYTES),
    )?;
    expect_value(
        document,
        &format!("{provider_media}/x-dirextalk-max-hpke-envelope-bytes"),
        &json!(MAX_HPKE_ENCODED_ENVELOPE_BYTES),
    )?;
    for (operation, expected) in [
        (
            PREPARATION_OPERATION,
            &[
                ("200", "PreparationReplay"),
                ("201", "PreparationCreated"),
                ("401", "HandoffCapabilityRejected"),
                ("409", "HandoffConflict"),
                ("410", "HandoffGone"),
                ("412", "HandoffPreconditionFailed"),
                ("413", "HandoffTooLarge"),
                ("415", "HandoffUnsupportedMedia"),
                ("422", "HandoffInvalidExactCbor"),
            ][..],
        ),
        (
            STATUS_OPERATION,
            &[
                ("200", "HandoffStatus"),
                ("401", "HandoffCapabilityRejected"),
                ("406", "HandoffNotAcceptable"),
            ][..],
        ),
        (
            PROVIDER_RESPONSE_OPERATION,
            &[
                ("200", "ProviderResponseReplay"),
                ("201", "ProviderResponseCreated"),
                ("401", "DeviceAuthenticationFailed"),
                ("403", "HandoffProviderForbidden"),
                ("406", "HandoffNotAcceptable"),
                ("409", "HandoffConflict"),
                ("410", "HandoffGone"),
                ("412", "HandoffProviderPreconditionFailed"),
                ("413", "HandoffTooLarge"),
                ("415", "HandoffUnsupportedMedia"),
                ("422", "HandoffInvalidExactCbor"),
            ][..],
        ),
    ] {
        let responses = format!("{operation}/responses");
        expect_object_keys(
            document,
            &responses,
            &expected
                .iter()
                .map(|(status, _)| *status)
                .collect::<Vec<_>>(),
        )?;
        for (status, response) in expected {
            expect_value(
                document,
                &format!("{responses}/{status}/$ref"),
                &json!(format!("#/components/responses/{response}")),
            )?;
        }
    }
    let all_responses = [
        "CatalogCreated",
        "CatalogReplay",
        "DeviceAuthenticationFailed",
        "CatalogConflict",
        "CatalogGone",
        "HeadOrAuthorityChanged",
        "InvalidExactCbor",
        "PreparationCreated",
        "PreparationReplay",
        "ProviderResponseCreated",
        "ProviderResponseReplay",
        "HandoffStatus",
        "HandoffCapabilityRejected",
        "HandoffProviderForbidden",
        "HandoffNotAcceptable",
        "HandoffConflict",
        "HandoffGone",
        "HandoffPreconditionFailed",
        "HandoffProviderPreconditionFailed",
        "HandoffTooLarge",
        "HandoffUnsupportedMedia",
        "HandoffInvalidExactCbor",
    ];
    expect_object_keys(document, "/components/responses", &all_responses)?;
    for response in all_responses {
        validate_response_headers(document, response)?;
    }
    for (response, media, rule, cap) in [
        (
            "PreparationCreated",
            PREPARATION_RECEIPT_MEDIA,
            "recovery-scope-catalog-preparation-receipt-v2",
            87,
        ),
        (
            "PreparationReplay",
            PREPARATION_RECEIPT_MEDIA,
            "recovery-scope-catalog-preparation-receipt-v2",
            87,
        ),
        (
            "ProviderResponseCreated",
            PROVIDER_RESPONSE_RECEIPT_MEDIA,
            "recovery-scope-catalog-provider-response-receipt-v2",
            87,
        ),
        (
            "ProviderResponseReplay",
            PROVIDER_RESPONSE_RECEIPT_MEDIA,
            "recovery-scope-catalog-provider-response-receipt-v2",
            87,
        ),
        (
            "HandoffStatus",
            STATUS_MEDIA,
            "recovery-scope-catalog-status-v2",
            MAX_STATUS_BODY_BYTES,
        ),
    ] {
        validate_handoff_response_media(document, response, media, rule, cap)?;
    }
    for (response, schema, codes) in [
        (
            "HandoffCapabilityRejected",
            "HandoffCapabilityErrorV2",
            &["RECOVERY_RESPONSE_CAPABILITY_REJECTED"][..],
        ),
        (
            "HandoffProviderForbidden",
            "HandoffProviderForbiddenErrorV2",
            &["RECOVERY_PROVIDER_FORBIDDEN"][..],
        ),
        (
            "HandoffNotAcceptable",
            "HandoffNotAcceptableErrorV2",
            &["RECOVERY_HANDOFF_NOT_ACCEPTABLE"][..],
        ),
        (
            "HandoffConflict",
            "HandoffConflictErrorV2",
            &["IDEMPOTENCY_CONFLICT", "RECOVERY_PREPARATION_CONFLICT"][..],
        ),
        (
            "HandoffGone",
            "HandoffGoneErrorV2",
            &[
                "RECOVERY_PREPARATION_EXPIRED",
                "RECOVERY_PREPARATION_REVOKED",
            ][..],
        ),
        (
            "HandoffPreconditionFailed",
            "HandoffPreconditionErrorV2",
            &[
                "IDENTITY_HEAD_CHANGED",
                "CATALOG_HEAD_CHANGED",
                "CATALOG_AUTHORITY_CHANGED",
                "CANDIDATE_KEY_CHANGED",
            ][..],
        ),
        (
            "HandoffProviderPreconditionFailed",
            "HandoffProviderPreconditionErrorV2",
            &[
                "IDENTITY_HEAD_CHANGED",
                "CATALOG_HEAD_CHANGED",
                "CATALOG_AUTHORITY_CHANGED",
                "CANDIDATE_KEY_CHANGED",
                "PROVIDER_KEY_CHANGED",
                "AUTHORITY_CHANGED",
            ][..],
        ),
        (
            "HandoffTooLarge",
            "HandoffTooLargeErrorV2",
            &["RECOVERY_HANDOFF_TOO_LARGE"][..],
        ),
        (
            "HandoffUnsupportedMedia",
            "HandoffUnsupportedMediaErrorV2",
            &["RECOVERY_HANDOFF_UNSUPPORTED_MEDIA_TYPE"][..],
        ),
        (
            "HandoffInvalidExactCbor",
            "InvalidCatalogErrorV2",
            &["EXACT_CBOR_INVALID", "RECOVERY_CATALOG_INVALID"][..],
        ),
    ] {
        validate_error_response(document, response, schema, codes)?;
    }
    Ok(())
}

pub(crate) fn validate_handoff_request_media(
    document: &Value,
    operation: &str,
    media: &str,
    rule: &str,
    cap: usize,
) -> Result<(), ProtocolToolError> {
    expect_value(
        document,
        &format!("{operation}/requestBody/required"),
        &json!(true),
    )?;
    expect_object_keys(
        document,
        &format!("{operation}/requestBody/content"),
        &[media],
    )?;
    let pointer = format!(
        "{operation}/requestBody/content/{}",
        media.replace('/', "~1")
    );
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-exact-cbor"),
        &json!(true),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-cddl-rule"),
        &json!(rule),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-max-body-bytes"),
        &json!(cap),
    )?;
    expect_value(
        document,
        &format!("{pointer}/schema/$ref"),
        &json!("#/components/schemas/ExactCanonicalCbor"),
    )
}

pub(crate) fn validate_handoff_response_media(
    document: &Value,
    response: &str,
    media: &str,
    rule: &str,
    cap: usize,
) -> Result<(), ProtocolToolError> {
    let content = format!("/components/responses/{response}/content");
    expect_object_keys(document, &content, &[media])?;
    let pointer = format!("{content}/{}", media.replace('/', "~1"));
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-exact-cbor"),
        &json!(true),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-cddl-rule"),
        &json!(rule),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-max-body-bytes"),
        &json!(cap),
    )?;
    expect_value(
        document,
        &format!("{pointer}/schema/$ref"),
        &json!("#/components/schemas/ExactCanonicalCbor"),
    )
}
