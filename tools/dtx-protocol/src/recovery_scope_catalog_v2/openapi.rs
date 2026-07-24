use super::{
    MAX_CATALOG_LEAVES, MAX_CATALOG_UPLOAD_BODY_BYTES, MAX_ENVELOPE_BYTES,
    MAX_HPKE_CIPHERTEXT_BYTES, MAX_HPKE_ENCODED_ENVELOPE_BYTES, MAX_PROVIDER_PACKAGE_BYTES,
    MAX_PROVIDER_RESPONSE_BODY_BYTES, MAX_SIGNED_CATALOG_HEAD_BYTES, MAX_STATUS_BODY_BYTES,
    OPENAPI_OPERATION, OPENAPI_PATH, OPENAPI_ROUTE, PREPARATION_ROUTE, PROVIDER_RESPONSE_ROUTE,
    Path, ProtocolToolError, REQUEST_MEDIA, RESPONSE_MEDIA, STATUS_ROUTE, Value,
    expect_object_keys, expect_value, fs, json, validate_openapi_handoff_http_contract,
    validate_openapi_handoff_metadata,
};
pub(crate) fn read_openapi(root: &Path) -> Result<String, ProtocolToolError> {
    let path = root.join(OPENAPI_PATH);
    fs::read_to_string(&path).map_err(|error| {
        ProtocolToolError::new(format!(
            "read Recovery Scope Catalog V2 OpenAPI {}: {error}",
            path.display()
        ))
    })
}

pub(crate) fn parse_openapi(source: &str) -> Result<Value, ProtocolToolError> {
    oas3::from_yaml(source).map_err(|error| {
        ProtocolToolError::new(format!("parse Recovery Scope Catalog V2 OpenAPI: {error}"))
    })?;
    yaml_serde::from_str(source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Recovery Scope Catalog V2 OpenAPI tree: {error}"
        ))
    })
}

pub(crate) fn validate_openapi_source(source: &str) -> Result<(), ProtocolToolError> {
    let document = parse_openapi(source)?;
    validate_openapi_document(&document)
}

pub(crate) fn validate_openapi_document(document: &Value) -> Result<(), ProtocolToolError> {
    validate_openapi_canonical_cbor_ceilings(document)?;
    validate_openapi_http_contract(document)?;
    validate_openapi_projection_and_proof(document)?;
    validate_openapi_handoff_http_contract(document)?;
    validate_openapi_handoff_metadata(document)
}

pub(crate) fn validate_openapi_canonical_cbor_ceilings(
    document: &Value,
) -> Result<(), ProtocolToolError> {
    expect_value(
        document,
        "/x-dirextalk-canonical-cbor-ceilings",
        &json!({
            "signed-catalog-head": {
                "cddl-rule": "recovery-scope-catalog-head-v2",
                "maximum-bytes": MAX_SIGNED_CATALOG_HEAD_BYTES,
                "arithmetic": "map-header-1-plus-sixteen-one-byte-keys-16-plus-values-449",
                "encoded-as-bstr-maximum-bytes": MAX_SIGNED_CATALOG_HEAD_BYTES + 3
            },
            "catalog-upload": {
                "cddl-rule": "recovery-scope-catalog-upload-v2",
                "maximum-body-bytes": MAX_CATALOG_UPLOAD_BODY_BYTES,
                "arithmetic": "map-and-keys-3-plus-signed-head-466-plus-encoded-ciphertext-bstr-1048581",
                "decoder-ceiling-bytes": MAX_ENVELOPE_BYTES,
                "decoder-ceiling-is-not-valid-body-allowance": true
            },
            "provider-package": {
                "cddl-rule": "recovery-scope-catalog-provider-package-v2",
                "maximum-bytes": MAX_PROVIDER_PACKAGE_BYTES
            },
            "hpke-ciphertext": {
                "cddl-rule": "hpke-ciphertext-v2",
                "maximum-bytes": MAX_HPKE_CIPHERTEXT_BYTES,
                "arithmetic": "provider-package-1049457-plus-aead-tag-16"
            },
            "hpke-envelope": {
                "cddl-rule": "recovery-scope-catalog-hpke-envelope-v2",
                "maximum-bytes": MAX_HPKE_ENCODED_ENVELOPE_BYTES
            },
            "provider-response": {
                "cddl-rule": "recovery-scope-catalog-provider-response-v2",
                "maximum-body-bytes": MAX_PROVIDER_RESPONSE_BODY_BYTES
            },
            "ready-status": {
                "cddl-rule": "recovery-scope-catalog-status-ready-v2",
                "maximum-body-bytes": MAX_STATUS_BODY_BYTES
            }
        }),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the OpenAPI gate intentionally freezes the complete one-operation contract"
)]
pub(crate) fn validate_openapi_http_contract(document: &Value) -> Result<(), ProtocolToolError> {
    expect_value(document, "/openapi", &json!("3.1.0"))?;
    expect_value(document, "/info/version", &json!("2.0.0"))?;
    expect_object_keys(
        document,
        "/paths",
        &[
            OPENAPI_ROUTE,
            PREPARATION_ROUTE,
            STATUS_ROUTE,
            PROVIDER_RESPONSE_ROUTE,
        ],
    )?;
    let route_pointer = "/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}";
    expect_object_keys(document, route_pointer, &["put"])?;
    expect_object_keys(
        document,
        "/paths/~1v3~1devices~1enroll~1catalog-preparations",
        &["post"],
    )?;
    expect_object_keys(
        document,
        "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}",
        &["get"],
    )?;
    expect_object_keys(
        document,
        "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}~1provider-response",
        &["put"],
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/operationId"),
        &json!("putRecoveryScopeCatalogV2"),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-authentication"),
        &json!({"kind": "active-device", "header": "Authorization", "required": true}),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/CatalogId"},
            {"$ref": "#/components/parameters/DeviceAuthorization"},
            {"$ref": "#/components/parameters/IdempotencyKey"}
        ]),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/name",
        &json!("catalog_id"),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/in",
        &json!("path"),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/required",
        &json!(true),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/schema/$ref",
        &json!("#/components/schemas/UuidV7"),
    )?;
    for (parameter, name) in [
        ("DeviceAuthorization", "Authorization"),
        ("IdempotencyKey", "Idempotency-Key"),
    ] {
        expect_value(
            document,
            &format!("/components/parameters/{parameter}/name"),
            &json!(name),
        )?;
        expect_value(
            document,
            &format!("/components/parameters/{parameter}/in"),
            &json!("header"),
        )?;
        expect_value(
            document,
            &format!("/components/parameters/{parameter}/required"),
            &json!(true),
        )?;
    }
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/minLength",
        &json!(16),
    )?;
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/maxLength",
        &json!(128),
    )?;
    expect_value(
        document,
        "/components/parameters/DeviceAuthorization/schema/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/schemas/UuidV7/pattern",
        &json!("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    )?;
    expect_value(
        document,
        "/components/schemas/UuidV7/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/schemas/ExactCanonicalCbor/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/schemas/ExactCanonicalCbor/contentEncoding",
        &json!("binary"),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/requestBody/required"),
        &json!(true),
    )?;
    expect_object_keys(
        document,
        &format!("{OPENAPI_OPERATION}/requestBody/content"),
        &[REQUEST_MEDIA],
    )?;
    let media_pointer = format!(
        "{OPENAPI_OPERATION}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor"
    );
    expect_value(
        document,
        &format!("{media_pointer}/x-dirextalk-exact-cbor"),
        &json!(true),
    )?;
    expect_value(
        document,
        &format!("{media_pointer}/schema/$ref"),
        &json!("#/components/schemas/ExactCanonicalCbor"),
    )?;
    for (name, expected) in [
        (
            "x-dirextalk-max-leaf-count",
            u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits u64"),
        ),
        ("x-dirextalk-max-ciphertext-bytes", 1_048_576),
        (
            "x-dirextalk-max-body-bytes",
            u64::try_from(MAX_CATALOG_UPLOAD_BODY_BYTES).expect("upload body maximum fits u64"),
        ),
        (
            "x-dirextalk-decoder-ceiling-bytes",
            u64::try_from(MAX_ENVELOPE_BYTES).expect("upload decoder ceiling fits u64"),
        ),
    ] {
        expect_value(
            document,
            &format!("{media_pointer}/{name}"),
            &json!(expected),
        )?;
    }
    expect_value(
        document,
        &format!("{media_pointer}/x-dirextalk-decoder-ceiling-is-not-body-allowance"),
        &json!(true),
    )?;
    let responses_pointer = format!("{OPENAPI_OPERATION}/responses");
    expect_object_keys(
        document,
        &responses_pointer,
        &["200", "201", "401", "409", "410", "412", "422"],
    )?;
    for (status, response) in [
        ("201", "CatalogCreated"),
        ("200", "CatalogReplay"),
        ("401", "DeviceAuthenticationFailed"),
        ("409", "CatalogConflict"),
        ("410", "CatalogGone"),
        ("412", "HeadOrAuthorityChanged"),
        ("422", "InvalidExactCbor"),
    ] {
        expect_value(
            document,
            &format!("{responses_pointer}/{status}/$ref"),
            &json!(format!("#/components/responses/{response}")),
        )?;
        validate_response_headers(document, response)?;
    }
    for response in ["CatalogCreated", "CatalogReplay"] {
        expect_object_keys(
            document,
            &format!("/components/responses/{response}/content"),
            &[RESPONSE_MEDIA],
        )?;
        expect_value(
            document,
            &format!(
                "/components/responses/{response}/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/x-dirextalk-exact-cbor"
            ),
            &json!(true),
        )?;
        expect_value(
            document,
            &format!(
                "/components/responses/{response}/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/x-dirextalk-max-body-bytes"
            ),
            &json!(MAX_SIGNED_CATALOG_HEAD_BYTES),
        )?;
        expect_value(
            document,
            &format!(
                "/components/responses/{response}/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/schema/$ref"
            ),
            &json!("#/components/schemas/ExactCanonicalCbor"),
        )?;
    }
    for (response, description) in [
        (
            "CatalogCreated",
            "Created; returns the exact signed V2 catalog head bytes.",
        ),
        (
            "CatalogReplay",
            "Exact request replay; returns byte-identical signed V2 catalog head bytes.",
        ),
        (
            "CatalogConflict",
            "RECOVERY_CATALOG_CONFLICT or IDEMPOTENCY_CONFLICT; no write occurs.",
        ),
        ("CatalogGone", "RECOVERY_CATALOG_EXPIRED; no write occurs."),
        (
            "HeadOrAuthorityChanged",
            "CATALOG_HEAD_CHANGED or CATALOG_AUTHORITY_CHANGED; no write occurs.",
        ),
        (
            "InvalidExactCbor",
            "EXACT_CBOR_INVALID or RECOVERY_CATALOG_INVALID; no write occurs.",
        ),
    ] {
        expect_value(
            document,
            &format!("/components/responses/{response}/description"),
            &json!(description),
        )?;
    }
    expect_value(
        document,
        "/components/headers/NoStore/schema/const",
        &json!("no-store"),
    )?;
    expect_value(
        document,
        "/components/headers/NoSniff/schema/const",
        &json!("nosniff"),
    )?;
    expect_value(
        document,
        "/components/headers/XRequestId",
        &json!({"schema": {"$ref": "#/components/schemas/UuidV7"}}),
    )?;
    expect_value(
        document,
        "/components/schemas/ErrorEnvelopeV2",
        &json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["error"],
            "properties": {
                "error": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["code", "request_id", "retryable"],
                    "properties": {
                        "code": {"type": "string"},
                        "request_id": {"$ref": "#/components/headers/XRequestId/schema"},
                        "retryable": {"type": "boolean"}
                    }
                }
            }
        }),
    )?;
    for (response, schema, codes) in [
        (
            "DeviceAuthenticationFailed",
            "DeviceAuthenticationErrorV2",
            &["DEVICE_AUTHENTICATION_FAILED"][..],
        ),
        (
            "CatalogConflict",
            "CatalogConflictErrorV2",
            &["RECOVERY_CATALOG_CONFLICT", "IDEMPOTENCY_CONFLICT"][..],
        ),
        (
            "CatalogGone",
            "CatalogGoneErrorV2",
            &["RECOVERY_CATALOG_EXPIRED"][..],
        ),
        (
            "HeadOrAuthorityChanged",
            "CatalogPreconditionErrorV2",
            &["CATALOG_HEAD_CHANGED", "CATALOG_AUTHORITY_CHANGED"][..],
        ),
        (
            "InvalidExactCbor",
            "InvalidCatalogErrorV2",
            &["EXACT_CBOR_INVALID", "RECOVERY_CATALOG_INVALID"][..],
        ),
    ] {
        validate_error_response(document, response, schema, codes)?;
    }
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-path-coordinate-binding"),
        &json!({
            "reject": "reject-before-durable-writes",
            "coordinates": {
                "catalog_id": {
                    "source": "signed-request-cbor",
                    "cddl-rule": "recovery-scope-catalog-upload-v2",
                    "cbor-path": [1, 2],
                    "comparison": "exact"
                }
            }
        }),
    )
}

pub(crate) fn validate_response_headers(
    document: &Value,
    response: &str,
) -> Result<(), ProtocolToolError> {
    let pointer = format!("/components/responses/{response}/headers");
    expect_object_keys(
        document,
        &pointer,
        &["Cache-Control", "X-Content-Type-Options", "X-Request-Id"],
    )?;
    expect_value(
        document,
        &format!("{pointer}/Cache-Control/$ref"),
        &json!("#/components/headers/NoStore"),
    )?;
    expect_value(
        document,
        &format!("{pointer}/X-Content-Type-Options/$ref"),
        &json!("#/components/headers/NoSniff"),
    )?;
    expect_value(
        document,
        &format!("{pointer}/X-Request-Id/$ref"),
        &json!("#/components/headers/XRequestId"),
    )
}

pub(crate) fn validate_error_response(
    document: &Value,
    response: &str,
    schema: &str,
    codes: &[&str],
) -> Result<(), ProtocolToolError> {
    let response_pointer = format!("/components/responses/{response}");
    expect_object_keys(
        document,
        &response_pointer,
        &[
            "description",
            "x-dirextalk-request-id-header-matches-body",
            "headers",
            "content",
        ],
    )?;
    expect_value(
        document,
        &format!("{response_pointer}/x-dirextalk-request-id-header-matches-body"),
        &json!(true),
    )?;
    validate_response_headers(document, response)?;
    expect_value(
        document,
        &format!("{response_pointer}/content"),
        &json!({
            "application/json": {
                "schema": {"$ref": format!("#/components/schemas/{schema}")}
            }
        }),
    )?;
    expect_value(
        document,
        &format!("/components/schemas/{schema}"),
        &json!({
            "allOf": [
                {"$ref": "#/components/schemas/ErrorEnvelopeV2"},
                {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string", "enum": codes},
                                "retryable": {"type": "boolean", "const": false}
                            }
                        }
                    }
                }
            ]
        }),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the privacy, crypto, validity, and proof metadata are one exact contract object"
)]
pub(crate) fn validate_openapi_projection_and_proof(
    document: &Value,
) -> Result<(), ProtocolToolError> {
    let allowed_paths = (1..=16)
        .map(|field| json!([1, field]))
        .chain(std::iter::once(json!([2])))
        .collect::<Vec<_>>();
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-server-visible-projection"),
        &json!({
            "signed-head-cddl-rule": "recovery-scope-catalog-head-v2",
            "opaque-ciphertext-cbor-path": [2],
            "allowed-cbor-paths": allowed_paths,
            "forbidden-data": [
                "recovery-scope",
                "membership-receipt",
                "private-body",
                "hiding-nonce",
                "completion-verifier-binding",
                "verifier-origin",
                "verifier-public-key",
                "verifier-key-id",
                "verifier-epoch",
                "verifier-descriptor",
                "completion-evidence-issuer-epk",
                "completion-evidence-issuer-pop",
                "completion-evidence-issuer-origin-authorization",
                "completion-evidence-issuer-authorization-digest"
            ]
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-validity"),
        &json!({
            "head-issued-at-cbor-path": [1, 14],
            "head-expires-at-cbor-path": [1, 15],
            "head-relation": "issued-at-before-expires-at",
            "candidate-post-decryption-binding-validity-contained-in-head": true,
            "candidate-validates-every-verifier-binding-against-current-origin-authenticated-descriptor-before-leaf-acceptance-or-delivery": true,
            "candidate-verifier-rotation-before-child-issuance": "stops-new-child-issuance",
            "committed-child-certificate-and-evidence": "non-retroactive-across-routine-descriptor-rotation-or-head-advance",
            "identity-server-hidden-verifier-enforcement": "impossible-ciphertext-only"
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-crypto-domains"),
        &json!({
            "membership-receipt": "dirextalk.recovery-scope-membership-receipt.v1\0",
            "recovery-scope": "dirextalk.recovery-scope.v1\0",
            "private-body": "dirextalk.recovery-scope-catalog-private-body.v2\0",
            "opening": "dirextalk.recovery-scope-catalog-opening.v2\0",
            "verifier-binding": "dirextalk.recovery-scope-catalog-verifier-binding.v1\0",
            "verifier-binding-signature": "dirextalk.recovery-scope-catalog-verifier-binding-signature.v1\0",
            "completion-verifier-descriptor": "dirextalk.recovery-scope-catalog-completion-verifier-descriptor.v1\0",
            "completion-verifier-descriptor-signature": "dirextalk.recovery-scope-catalog-completion-verifier-descriptor-signature.v1\0",
            "completion-evidence-pop": "dirextalk.recovery-scope-catalog-completion-evidence-pop.v1\0",
            "completion-evidence-origin-authorization": "dirextalk.recovery-scope-catalog-completion-evidence-origin-authorization.v1\0",
            "completion-evidence-authorization-digest": "dirextalk.recovery-scope-catalog-completion-evidence-authorization-digest.v1\0",
            "leaf-commitment": "dirextalk.recovery-scope-catalog-leaf-commitment.v2\0",
            "ciphertext": "dirextalk.recovery-scope-catalog-ciphertext.v2\0",
            "head": "dirextalk.recovery-scope-catalog-head.v2\0",
            "head-signature": "dirextalk.recovery-scope-catalog-head-signature.v2\0",
            "merkle-node": "dirextalk.recovery-scope-catalog-node.v2\0"
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-opening-digest"),
        &json!({
            "algorithm": "SHA-256",
            "domain": "dirextalk.recovery-scope-catalog-opening.v2\0",
            "cddl-rule": "recovery-scope-catalog-opening-v2",
            "input": "exact-deterministic-canonical-cbor-complete-opening",
            "complete-cbor-fields": {
                "private-body": [1],
                "full-signed-issuer-binding": [2],
                "public-leaf": [3]
            },
            "subset-or-reencoding": "forbidden"
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-private-body-derived-digests"),
        &json!({
            "membership-receipt": {
                "algorithm": "SHA-256",
                "domain": "dirextalk.recovery-scope-membership-receipt.v1\0",
                "output-cbor-path": [7],
                "input-cbor-path": [6],
                "input-encoding": "exact raw bstr bytes"
            },
            "recovery-scope": {
                "algorithm": "SHA-256",
                "domain": "dirextalk.recovery-scope.v1\0",
                "output-cbor-path": [9],
                "input-cbor-path": [5],
                "input-encoding": "exact deterministic canonical CBOR"
            }
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-merkle-proof"),
        &json!({
            "cddl-rule": "catalog-merkle-proof-v2",
            "leaf-cddl-rule": "recovery-scope-catalog-leaf-commitment-v2",
            "leaf-digest-domain": "dirextalk.recovery-scope-catalog-leaf-commitment.v2\0",
            "node-digest-domain": "dirextalk.recovery-scope-catalog-node.v2\0",
            "sibling-order": "bottom-up",
            "index-base": 1,
            "count-minimum": 1,
            "count-maximum": 1_023,
            "maximum-siblings": 10,
            "odd-node-rule": "duplicate-last",
            "odd-final-node-consumes-sibling": false,
            "sibling-count-rule": "exact-count-index-height",
            "reject-surplus-or-missing-siblings": true,
            "field-bindings": {
                "version": {"cbor-path": [1], "const": 2},
                "catalog_id": {"cbor-path": [2], "signed-head-cbor-path": [2], "comparison": "exact"},
                "generation": {"cbor-path": [3], "signed-head-cbor-path": [4], "comparison": "exact"},
                "count": {"cbor-path": [4], "signed-head-cbor-path": [6], "comparison": "exact"},
                "index": {"cbor-path": [5], "minimum": 1, "maximum-from": "count"},
                "siblings": {"cbor-path": [6], "maximum-items": 10, "order": "bottom-up"}
            }
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-catalog-count-boundary"),
        &json!({
            "count-minimum": 1,
            "count-maximum": 1_023,
            "exact-plaintext-ceiling-bytes": 1_048_576,
            "minimum-valid-opening-bytes": 1_019,
            "minimum-outer-plaintext-overhead-bytes": 147,
            "index-occurrences-per-opening": 3,
            "one-byte-index-maximum": 23,
            "two-byte-index-maximum": 255,
            "indices-24-through-255-count": 232,
            "indices-24-through-255-extra-bytes-per-opening": 3,
            "indices-256-through-1023-count": 768,
            "indices-256-plus-extra-bytes-per-opening": 6,
            "consecutive-one-based-indices-required": true,
            "count-maximum-minimum-bytes": 1_047_888,
            "count-maximum-plus-one": 1_024,
            "count-maximum-plus-one-minimum-bytes": 1_048_913,
            "count-maximum-fits-ceiling": true,
            "count-maximum-plus-one-exceeds-ceiling": true,
            "validation-classification": "structural-cddl-and-consecutive-index-semantic-size-model",
            "full-cryptographic-1023-opening-fixture": "intentionally-not-claimed"
        }),
    )?;
    expect_value(
        document,
        &format!(
            "{OPENAPI_OPERATION}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/x-dirextalk-max-leaf-count"
        ),
        &json!(1_023),
    )
}
