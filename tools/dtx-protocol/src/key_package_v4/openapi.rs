use serde_json::{Value, json};

use crate::ProtocolToolError;

use super::helpers::{object_at, require_exact_keys, require_json, string_at};
use super::{CDDL_RELATIVE, DOMAINS};

pub(super) fn validate_contract(document: &Value) -> Result<(), ProtocolToolError> {
    if string_at(document, "/openapi", "OpenAPI version")? != "3.1.0"
        || string_at(document, "/info/version", "OpenAPI info version")? != "4.0.0"
        || string_at(
            document,
            "/x-dirextalk-cddl-artifact",
            "OpenAPI CDDL artifact",
        )? != CDDL_RELATIVE
    {
        return Err(ProtocolToolError::new(
            "Key Package V4 OpenAPI version/artifact relationship drift",
        ));
    }

    let domains = object_at(
        document,
        "/x-dirextalk-crypto-domains",
        "Key Package V4 domains",
    )?;
    require_exact_keys(domains, DOMAINS.iter().map(|(name, _)| *name), "domains")?;
    for (name, value) in DOMAINS {
        if domains.get(*name).and_then(Value::as_str) != Some(*value) {
            return Err(ProtocolToolError::new(format!(
                "Key Package V4 domain value drift: {name}"
            )));
        }
    }

    let ceilings = object_at(
        document,
        "/x-dirextalk-body-ceilings",
        "Key Package V4 body ceilings",
    )?;
    let expected_ceilings = [
        ("publish-binding-v4", 1_683),
        ("publish-v4", 67_294),
        ("publish-receipt-v4", 67_531),
        ("claim-v4", 527),
        ("claim-receipt-v4", 135_564),
    ];
    require_exact_keys(
        ceilings,
        expected_ceilings.iter().map(|(name, _)| *name),
        "body ceilings",
    )?;
    for (name, maximum) in expected_ceilings {
        if ceilings.get(name).and_then(Value::as_u64) != Some(maximum) {
            return Err(ProtocolToolError::new(format!(
                "Key Package V4 OpenAPI body ceiling drift: {name}"
            )));
        }
    }
    for (pointer, fragment) in [
        (
            "/x-dirextalk-cbor-ceiling-arithmetic/publish-receipt-v4",
            "67299-encoded-publish-bstr",
        ),
        (
            "/x-dirextalk-cbor-ceiling-arithmetic/claim-receipt-v4",
            "67536-publish-receipt-bstr",
        ),
        (
            "/x-dirextalk-cbor-ceiling-arithmetic/claim-receipt-v4",
            "530-claim-bstr",
        ),
    ] {
        if !string_at(document, pointer, "canonical bstr ceiling arithmetic")?.contains(fragment) {
            return Err(ProtocolToolError::new(format!(
                "Key Package V4 canonical bstr relationship drift at {pointer}"
            )));
        }
    }

    let paths = object_at(document, "/paths", "Key Package V4 OpenAPI paths")?;
    require_exact_keys(
        paths,
        ["/v4/key-packages/{package_id}", "/v4/key-packages/claim"],
        "paths",
    )?;
    for (path, method) in [
        ("/v4/key-packages/{package_id}", "put"),
        ("/v4/key-packages/claim", "post"),
    ] {
        let item = paths
            .get(path)
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolToolError::new(format!("OpenAPI path missing: {path}")))?;
        require_exact_keys(item, [method], path)?;
    }

    validate_operation(
        document,
        "/paths/~1v4~1key-packages~1{package_id}/put",
        "publishRecoveryKeyPackageV4",
        67_294,
        "application/vnd.dirextalk.key-package-publish.v4+cbor",
        "key-package-publish-v4",
        &[
            "#/components/parameters/PackageId",
            "#/components/parameters/DeviceAuthorization",
            "#/components/parameters/IdempotencyKey",
        ],
        &[
            ("200", "#/components/responses/PublishReceipt"),
            ("201", "#/components/responses/PublishReceipt"),
            ("401", "#/components/responses/Unauthorized"),
            ("409", "#/components/responses/Conflict"),
            ("410", "#/components/responses/Gone"),
            ("412", "#/components/responses/Invalidated"),
            ("422", "#/components/responses/InvalidExactCbor"),
        ],
    )?;
    validate_operation(
        document,
        "/paths/~1v4~1key-packages~1claim/post",
        "claimRecoveryKeyPackageV4",
        527,
        "application/vnd.dirextalk.key-package-claim.v4+cbor",
        "key-package-claim-v4",
        &[
            "#/components/parameters/DeviceAuthorization",
            "#/components/parameters/IdempotencyKey",
        ],
        &[
            ("200", "#/components/responses/ClaimReceipt"),
            ("201", "#/components/responses/ClaimReceipt"),
            ("401", "#/components/responses/Unauthorized"),
            ("404", "#/components/responses/Unavailable"),
            ("409", "#/components/responses/Conflict"),
            ("410", "#/components/responses/Gone"),
            ("412", "#/components/responses/Invalidated"),
            ("422", "#/components/responses/InvalidExactCbor"),
        ],
    )?;
    validate_response(
        document,
        "PublishReceipt",
        67_531,
        "application/vnd.dirextalk.key-package-publish-receipt.v4+cbor",
        "key-package-publish-receipt-v4",
    )?;
    validate_response(
        document,
        "ClaimReceipt",
        135_564,
        "application/vnd.dirextalk.key-package-claim-receipt.v4+cbor",
        "key-package-claim-receipt-v4",
    )?;

    for (pointer, expected) in [
        ("/components/parameters/IdempotencyKey/schema/minLength", 16),
        (
            "/components/parameters/IdempotencyKey/schema/maxLength",
            128,
        ),
        (
            "/paths/~1v4~1key-packages~1{package_id}/put/x-dirextalk-catalog-validation/maximum-count",
            1_023,
        ),
        (
            "/paths/~1v4~1key-packages~1{package_id}/put/x-dirextalk-catalog-validation/maximum-siblings",
            10,
        ),
        (
            "/paths/~1v4~1key-packages~1{package_id}/put/x-dirextalk-catalog-validation/exact-proof-ceiling-bytes",
            402,
        ),
    ] {
        if document.pointer(pointer).and_then(Value::as_u64) != Some(expected) {
            return Err(ProtocolToolError::new(format!(
                "Key Package V4 OpenAPI schema maximum drift at {pointer}"
            )));
        }
    }
    require_json(
        document,
        "/components/parameters/IdempotencyKey/schema/pattern",
        &json!("^[!-~]{16,128}$"),
        "Idempotency-Key schema pattern",
    )?;

    for (pointer, expected) in [
        (
            "/x-dirextalk-strict-wire",
            json!({
                "deterministic-canonical-cbor": "required",
                "closed-maps-and-enums": "required",
                "unknown-or-duplicate-map-keys": "rejected",
                "exact-version-discriminator": 4,
                "v2-v3-v4-conversion": "forbidden",
                "decoder-fallback": "forbidden",
                "strict-ed25519-semantics": "required",
                "header-idempotency-digest-equals-body": "required",
                "raw-idempotency-key-persisted": false,
                "raw-idempotency-key-returned": false
            }),
        ),
        (
            "/x-dirextalk-field-equalities/claim-to-stored-publish-binding",
            json!({
                "claim-field-2": "publish-binding-field-2",
                "claim-field-3": "publish-binding-field-3",
                "claim-field-4": "publish-binding-field-5",
                "claim-field-5": "publish-binding-field-6",
                "claim-field-6": "publish-binding-field-4",
                "claim-field-7": "publish-binding-field-7",
                "claim-field-8": "publish-binding-field-8",
                "claim-field-9": "publish-binding-field-10",
                "claim-field-10": "publish-binding-field-11",
                "claim-field-11": "publish-binding-field-12",
                "claim-field-12": "publish-binding-field-14",
                "claim-field-13": "publish-binding-field-16",
                "claim-field-14": "publish-binding-field-17",
                "claim-field-15": "publish-binding-field-19",
                "claim-field-16": "publish-binding-field-20",
                "claim-field-17": "publish-binding-field-23",
                "claim-field-18": "claim-idempotency-digest-of-exact-accepted-header-octets"
            }),
        ),
        (
            "/x-dirextalk-field-equalities/authenticated-publish-candidate",
            json!({
                "identity-id": {"authenticated-value-equals-cbor-path": [1, 2], "comparison": "exact"},
                "device-id": {"authenticated-value-equals-cbor-path": [1, 3], "comparison": "exact"},
                "current-signing-public-key": {"authenticated-value-equals-cbor-path": [1, 18], "comparison": "exact"},
                "envelope-signature-cbor-path": [3],
                "envelope-signature-key-cbor-path": [1, 18]
            }),
        ),
        (
            "/x-dirextalk-field-equalities/authenticated-claim-controller",
            json!({
                "kind": "current-scope-controller",
                "authenticated-identity-and-device-equal-current-authorization-subject": "required",
                "authorized-target-equalities": {
                    "recovering-identity": {"claim-cbor-path": [2], "comparison": "exact"},
                    "candidate-device-id": {"claim-cbor-path": [3], "comparison": "exact"},
                    "request-id": {"claim-cbor-path": [4], "comparison": "exact"},
                    "signed-request-digest": {"claim-cbor-path": [5], "comparison": "exact"},
                    "package-id": {"claim-cbor-path": [6], "comparison": "exact"},
                    "catalog-id": {"claim-cbor-path": [7], "comparison": "exact"},
                    "catalog-generation": {"claim-cbor-path": [8], "comparison": "exact"},
                    "signed-catalog-head-digest": {"claim-cbor-path": [9], "comparison": "exact"},
                    "catalog-count": {"claim-cbor-path": [10], "comparison": "exact"},
                    "catalog-index": {"claim-cbor-path": [11], "comparison": "exact"},
                    "catalog-public-leaf-digest": {"claim-cbor-path": [12], "comparison": "exact"},
                    "public-leaf-issuer-epk": {"claim-cbor-path": [13], "comparison": "exact"},
                    "public-leaf-authorization-digest-a": {"claim-cbor-path": [14], "comparison": "exact"},
                    "direct-device-add-h-plus-1": {"claim-cbor-path": [15], "comparison": "exact"},
                    "identity-log-head-at-h-plus-1": {"claim-cbor-path": [16], "comparison": "exact"},
                    "opaque-package-digest": {"claim-cbor-path": [17], "comparison": "exact"}
                },
                "candidate-fields-not-controller-identity-or-device": [2, 3],
                "scope-or-controller-identifier-in-body-or-receipt": "forbidden"
            }),
        ),
        (
            "/x-dirextalk-field-equalities/publish-receipt",
            json!({
                "field-2": "decoded-exact-field-5-publish-binding-field-4",
                "field-3": "decoded-exact-field-5-publish-binding-field-5",
                "field-4": "publish-binding-domain-digest-of-decoded-exact-field-5-inner-binding",
                "field-5": "exact-accepted-http-publish-body-octets",
                "field-6": "publish-envelope-domain-digest-of-exact-field-5",
                "field-7": [
                    "decoded-exact-field-5-publish-binding-field-23",
                    "package-domain-digest-of-decoded-exact-field-5-opaque-body"
                ],
                "field-8": [
                    "decoded-exact-field-5-publish-binding-field-24",
                    "publish-idempotency-digest-of-exact-accepted-header-octets"
                ]
            }),
        ),
        (
            "/x-dirextalk-field-equalities/claim-receipt",
            json!({
                "field-2": [
                    "decoded-exact-field-4-publish-binding-field-4",
                    "decoded-exact-field-6-publish-receipt-field-2",
                    "decoded-exact-field-8-claim-field-6"
                ],
                "field-3": [
                    "decoded-exact-field-4-publish-binding-field-5",
                    "decoded-exact-field-6-publish-receipt-field-3",
                    "decoded-exact-field-8-claim-field-4"
                ],
                "field-4": [
                    "exact-original-publish-envelope-octets",
                    "decoded-exact-field-6-publish-receipt-field-5-byte-for-byte"
                ],
                "field-5": [
                    "publish-envelope-domain-digest-of-exact-field-4",
                    "decoded-exact-field-6-publish-receipt-field-6"
                ],
                "field-6": "exact-original-publish-receipt-octets",
                "field-7": "publish-receipt-domain-digest-of-exact-field-6",
                "field-8": "exact-accepted-http-claim-body-octets",
                "field-9": "claim-domain-digest-of-exact-field-8",
                "decoded-field-8-to-decoded-field-4-binding": "exact-claim-to-publish-mapping-above"
            }),
        ),
        (
            "/x-dirextalk-idempotency-key",
            json!({
                "common-grammar": {
                    "exact-http-header-fields": 1,
                    "exact-parser-exposed-values": 1,
                    "length-octets": {"minimum": 16, "maximum": 128},
                    "accepted-ascii-octets-inclusive": ["0x21", "0x7e"],
                    "schema-pattern": "^[!-~]{16,128}$",
                    "obs-fold": "rejected",
                    "whitespace-including-leading-or-trailing": "rejected",
                    "duplicate-fields-or-values": "rejected-before-idempotency-lookup",
                    "non-ascii-or-invalid-length": "rejected-before-idempotency-lookup",
                    "normalization-or-re-encoding": "forbidden",
                    "digest-input": "exact-accepted-ascii-octets-after-http-field-parsing-before-storage",
                    "raw-key-persisted-or-returned": false
                },
                "publish": {
                    "digest-domain": "dirextalk.key-package.publish-idempotency.v4\0",
                    "digest-formula": "SHA-256(domain-bytes || exact-accepted-ascii-octets)",
                    "equals-cbor-path": [1, 24]
                },
                "claim": {
                    "digest-domain": "dirextalk.key-package.claim-idempotency.v4\0",
                    "digest-formula": "SHA-256(domain-bytes || exact-accepted-ascii-octets)",
                    "equals-cbor-path": [18]
                }
            }),
        ),
        (
            "/x-dirextalk-public-projection/allowed",
            json!([
                "identity-id",
                "candidate-device-id-and-signing-key",
                "package-id-and-opaque-package-digest",
                "recovery-request-id-and-exact-digest",
                "catalog-id-generation-exact-signed-head-and-digest",
                "catalog-count-index-exact-public-leaf-digest-and-proof",
                "public-leaf-issuer-epk-and-authorization-digest-a",
                "exact-device-add-h-plus-1-and-head",
                "validity-times-and-idempotency-digest"
            ]),
        ),
        (
            "/x-dirextalk-public-projection/forbidden",
            json!([
                "recovery-scope",
                "recovery-scope-digest",
                "scope-origin",
                "verifier-descriptor-key-id-key-or-epoch",
                "private-catalog-body",
                "full-verifier-binding",
                "membership-receipt",
                "catalog-opening",
                "hiding-nonce",
                "issuer-private-key-or-key-handle",
                "raw-idempotency-key"
            ]),
        ),
        (
            "/x-dirextalk-store-invariants",
            json!({
                "one-publish-per-full-versioned-tuple": true,
                "at-most-one-claim-per-full-versioned-tuple": true,
                "package-digest-global-uniqueness-across": ["v2", "v3", "v4"],
                "package-consumption-global-across": ["v2", "v3", "v4"],
                "issuer-epk-global-uniqueness-across-requests": false,
                "same-issuer-epk-in-multiple-recovery-requests": "allowed",
                "v4-tuple": [
                    "exact-version",
                    "identity",
                    "candidate",
                    "request-id-and-digest",
                    "catalog-id-generation-head-digest-count-index-leaf-digest",
                    "package-id-and-package-digest"
                ],
                "partial-reservation-or-consumption": "forbidden"
            }),
        ),
        (
            "/x-dirextalk-replay-order",
            json!({
                "first": "authenticate-authorize-and-check-immutable-explicit-revocation",
                "second": "static-path-media-size-version-signature-and-idempotency-shape",
                "committed-exact-replay": "return-byte-identical-original-receipt-before-mutable-currentness",
                "committed-conflict": "reject-without-write",
                "first-admission": "validate-revocation-expiry-head-keys-and-proof-then-one-final-cas"
            }),
        ),
    ] {
        require_json(
            document,
            pointer,
            &expected,
            "privacy/authorization binding",
        )?;
    }

    for (pointer, expected) in [
        (
            "/x-dirextalk-field-equalities/authenticated-publish-candidate/current-signing-public-key/authenticated-value-equals-cbor-path",
            json!([1, 18]),
        ),
        (
            "/x-dirextalk-field-equalities/authenticated-publish-candidate/envelope-signature-key-cbor-path",
            json!([1, 18]),
        ),
        (
            "/x-dirextalk-idempotency-key/publish/equals-cbor-path",
            json!([1, 24]),
        ),
        (
            "/x-dirextalk-idempotency-key/claim/equals-cbor-path",
            json!([18]),
        ),
    ] {
        require_json(
            document,
            pointer,
            &expected,
            "signature/idempotency binding",
        )?;
    }
    for (pointer, expected) in [
        (
            "/paths/~1v4~1key-packages~1{package_id}/put/x-dirextalk-authentication/kind",
            "candidate-device",
        ),
        (
            "/paths/~1v4~1key-packages~1claim/post/x-dirextalk-authentication/kind",
            "current-scope-controller",
        ),
        (
            "/paths/~1v4~1key-packages~1claim/post/x-dirextalk-authentication/scope-identifier-in-body-or-receipt",
            "forbidden",
        ),
        (
            "/x-dirextalk-replay-order/committed-exact-replay",
            "return-byte-identical-original-receipt-before-mutable-currentness",
        ),
        (
            "/x-dirextalk-store-invariants/partial-reservation-or-consumption",
            "forbidden",
        ),
    ] {
        if string_at(document, pointer, "privacy/authorization semantic")? != expected {
            return Err(ProtocolToolError::new(format!(
                "Key Package V4 privacy/authorization semantic drift at {pointer}"
            )));
        }
    }
    Ok(())
}

fn validate_operation(
    document: &Value,
    pointer: &str,
    operation_id: &str,
    ceiling: u64,
    media_type: &str,
    rule: &str,
    parameters: &[&str],
    responses: &[(&str, &str)],
) -> Result<(), ProtocolToolError> {
    let operation = document.pointer(pointer).ok_or_else(|| {
        ProtocolToolError::new(format!(
            "Key Package V4 OpenAPI operation missing: {pointer}"
        ))
    })?;
    if operation.get("operationId").and_then(Value::as_str) != Some(operation_id)
        || operation
            .get("x-dirextalk-body-ceiling-bytes")
            .and_then(Value::as_u64)
            != Some(ceiling)
    {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 OpenAPI operation/ceiling drift: {operation_id}"
        )));
    }
    let content = operation
        .pointer("/requestBody/content")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProtocolToolError::new(format!(
                "Key Package V4 request content missing: {operation_id}"
            ))
        })?;
    require_exact_keys(content, [media_type], operation_id)?;
    validate_media(content.get(media_type), rule, operation_id, true)?;

    let actual_parameters = operation
        .get("parameters")
        .and_then(Value::as_array)
        .ok_or_else(|| ProtocolToolError::new(format!("parameters missing: {operation_id}")))?
        .iter()
        .map(|item| item.get("$ref").and_then(Value::as_str))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| ProtocolToolError::new(format!("parameter ref drift: {operation_id}")))?;
    if actual_parameters != parameters {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 parameter relationship drift: {operation_id}"
        )));
    }

    let actual_responses = operation
        .get("responses")
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new(format!("responses missing: {operation_id}")))?;
    require_exact_keys(
        actual_responses,
        responses.iter().map(|(status, _)| *status),
        operation_id,
    )?;
    for (status, expected_ref) in responses {
        if actual_responses
            .get(*status)
            .and_then(|response| response.get("$ref"))
            .and_then(Value::as_str)
            != Some(*expected_ref)
        {
            return Err(ProtocolToolError::new(format!(
                "Key Package V4 response relationship drift: {operation_id} {status}"
            )));
        }
    }
    Ok(())
}

fn validate_response(
    document: &Value,
    name: &str,
    ceiling: u64,
    media_type: &str,
    rule: &str,
) -> Result<(), ProtocolToolError> {
    let response = document
        .pointer(&format!("/components/responses/{name}"))
        .ok_or_else(|| ProtocolToolError::new(format!("response missing: {name}")))?;
    if response
        .get("x-dirextalk-body-ceiling-bytes")
        .and_then(Value::as_u64)
        != Some(ceiling)
    {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 response schema maximum drift: {name}"
        )));
    }
    let content = response
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new(format!("response content missing: {name}")))?;
    require_exact_keys(content, [media_type], name)?;
    validate_media(content.get(media_type), rule, name, false)
}

fn validate_media(
    media: Option<&Value>,
    rule: &str,
    label: &str,
    require_exact_marker: bool,
) -> Result<(), ProtocolToolError> {
    let media = media.ok_or_else(|| ProtocolToolError::new(format!("media missing: {label}")))?;
    if media.get("x-dirextalk-cddl-rule").and_then(Value::as_str) != Some(rule)
        || media.pointer("/schema/$ref").and_then(Value::as_str)
            != Some("#/components/schemas/ExactCanonicalCbor")
        || require_exact_marker
            && media.get("x-dirextalk-exact-cbor").and_then(Value::as_bool) != Some(true)
    {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 canonical CBOR schema drift: {label}"
        )));
    }
    Ok(())
}
