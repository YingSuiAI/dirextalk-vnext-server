use serde_json::Value;

use crate::ProtocolToolError;

use super::helpers::{json_pointer_segment, object_at, require_exact_keys, string_at};
use super::{CDDL_RELATIVE, DOMAINS};

#[derive(Clone, Copy)]
struct RequestSpec<'a> {
    ceiling: u64,
    media_type: &'a str,
    rule: &'a str,
    schema: &'a str,
}

#[derive(Clone, Copy)]
struct OperationSpec<'a> {
    path: &'a str,
    method: &'a str,
    operation_id: &'a str,
    authentication: &'a str,
    parameters: &'a [&'a str],
    responses: &'a [(&'a str, &'a str)],
    request: Option<RequestSpec<'a>>,
}

#[derive(Clone, Copy)]
pub(super) struct ResponseSpec<'a> {
    pub(super) name: &'a str,
    pub(super) ceiling: u64,
    pub(super) media_type: &'a str,
    pub(super) rule_marker: &'a str,
    pub(super) rule: &'a str,
    pub(super) schema: &'a str,
}

pub(super) const OPENAPI_SCHEMA_NAMES: &[&str] = &[
    "ExactCanonicalCbor",
    "IssuerAuthorizationRequestCbor",
    "RecoveryAddRequestCbor",
    "ConfirmationCommandCbor",
    "ActivationCommandCbor",
    "EvidenceIssuanceCommandCbor",
    "CompletionCacheCommandCbor",
    "CatalogDescriptorCbor",
    "IssuerAuthorizationCbor",
    "SignedAddReceiptCbor",
    "SignedConfirmationReceiptCbor",
    "SignedActivationReceiptCbor",
    "ActivationReadbackCbor",
    "EvidenceIssuanceReceiptCbor",
    "SignedCompletionCacheReceiptCbor",
    "UuidV7",
    "ChannelId",
    "GroupScopeId",
];

pub(super) const BINARY_SCHEMA_SPECS: &[(&str, u64, &str, &str)] = &[
    (
        "IssuerAuthorizationRequestCbor",
        8_953,
        "x-dirextalk-cddl-rule",
        "mls-recovery-issuer-authorization-request-v1",
    ),
    (
        "RecoveryAddRequestCbor",
        4_489_217,
        "x-dirextalk-cddl-rule",
        "mls-recovery-add-request-v7",
    ),
    (
        "ConfirmationCommandCbor",
        1_510,
        "x-dirextalk-cddl-rule",
        "mls-recovery-confirmation-v2",
    ),
    (
        "ActivationCommandCbor",
        6_023,
        "x-dirextalk-cddl-rule",
        "mls-recovery-activation-command-v2",
    ),
    (
        "EvidenceIssuanceCommandCbor",
        12_756,
        "x-dirextalk-cddl-rule",
        "mls-recovery-evidence-issuance-command-v1",
    ),
    (
        "CompletionCacheCommandCbor",
        17_155,
        "x-dirextalk-cddl-rule",
        "mls-recovery-completion-cache-command-v2",
    ),
    (
        "CatalogDescriptorCbor",
        2_226,
        "x-dirextalk-owner-cddl-rule",
        "recovery-scope-catalog-completion-verifier-descriptor-v1",
    ),
    (
        "IssuerAuthorizationCbor",
        2_613,
        "x-dirextalk-owner-cddl-rule",
        "recovery-scope-catalog-completion-verifier-binding-unsigned-v1",
    ),
    (
        "SignedAddReceiptCbor",
        791,
        "x-dirextalk-cddl-rule",
        "signed-mls-recovery-add-receipt-v7",
    ),
    (
        "SignedConfirmationReceiptCbor",
        791,
        "x-dirextalk-cddl-rule",
        "signed-mls-recovery-confirmation-receipt-v2",
    ),
    (
        "SignedActivationReceiptCbor",
        903,
        "x-dirextalk-cddl-rule",
        "signed-mls-recovery-activation-receipt-v2",
    ),
    (
        "ActivationReadbackCbor",
        1_556,
        "x-dirextalk-cddl-rule",
        "mls-recovery-activation-readback-v2",
    ),
    (
        "EvidenceIssuanceReceiptCbor",
        975,
        "x-dirextalk-cddl-rule",
        "mls-recovery-evidence-issuance-receipt-v1",
    ),
    (
        "SignedCompletionCacheReceiptCbor",
        660,
        "x-dirextalk-cddl-rule",
        "signed-mls-recovery-completion-cache-receipt-v2",
    ),
];

pub(super) const OPENAPI_RESPONSE_NAMES: &[&str] = &[
    "CatalogDescriptor",
    "IssuerAuthorization",
    "AddReceipt",
    "ConfirmationReceipt",
    "ActivationReceipt",
    "ActivationReadback",
    "EvidenceIssuanceReceipt",
    "CompletionCacheReceipt",
    "Unauthorized",
    "Conflict",
    "Gone",
    "Invalidated",
    "PreIssuanceGone",
    "PreIssuanceInvalidated",
    "PostIssuanceCacheGone",
    "PostIssuanceCacheInvalidated",
    "InvalidExactCbor",
    "NotFound",
];

pub(super) const SUCCESS_RESPONSE_SPECS: &[ResponseSpec<'static>] = &[
    ResponseSpec {
        name: "CatalogDescriptor",
        ceiling: 2_226,
        media_type: "application/vnd.dirextalk.recovery-scope-catalog-completion-verifier-descriptor.v1+cbor",
        rule_marker: "x-dirextalk-owner-cddl-rule",
        rule: "recovery-scope-catalog-completion-verifier-descriptor-v1",
        schema: "CatalogDescriptorCbor",
    },
    ResponseSpec {
        name: "IssuerAuthorization",
        ceiling: 2_613,
        media_type: "application/vnd.dirextalk.recovery-scope-catalog-completion-verifier-binding-unsigned.v1+cbor",
        rule_marker: "x-dirextalk-owner-cddl-rule",
        rule: "recovery-scope-catalog-completion-verifier-binding-unsigned-v1",
        schema: "IssuerAuthorizationCbor",
    },
    ResponseSpec {
        name: "AddReceipt",
        ceiling: 791,
        media_type: "application/vnd.dirextalk.mls-recovery-commit-receipt.v7+cbor",
        rule_marker: "x-dirextalk-cddl-rule",
        rule: "signed-mls-recovery-add-receipt-v7",
        schema: "SignedAddReceiptCbor",
    },
    ResponseSpec {
        name: "ConfirmationReceipt",
        ceiling: 791,
        media_type: "application/vnd.dirextalk.mls-recovery-confirmation-receipt.v2+cbor",
        rule_marker: "x-dirextalk-cddl-rule",
        rule: "signed-mls-recovery-confirmation-receipt-v2",
        schema: "SignedConfirmationReceiptCbor",
    },
    ResponseSpec {
        name: "ActivationReceipt",
        ceiling: 903,
        media_type: "application/vnd.dirextalk.mls-recovery-activation-receipt.v2+cbor",
        rule_marker: "x-dirextalk-cddl-rule",
        rule: "signed-mls-recovery-activation-receipt-v2",
        schema: "SignedActivationReceiptCbor",
    },
    ResponseSpec {
        name: "ActivationReadback",
        ceiling: 1_556,
        media_type: "application/vnd.dirextalk.mls-recovery-activation-readback.v2+cbor",
        rule_marker: "x-dirextalk-cddl-rule",
        rule: "mls-recovery-activation-readback-v2",
        schema: "ActivationReadbackCbor",
    },
    ResponseSpec {
        name: "EvidenceIssuanceReceipt",
        ceiling: 975,
        media_type: "application/vnd.dirextalk.mls-recovery-evidence-issuance-receipt.v1+cbor",
        rule_marker: "x-dirextalk-cddl-rule",
        rule: "mls-recovery-evidence-issuance-receipt-v1",
        schema: "EvidenceIssuanceReceiptCbor",
    },
    ResponseSpec {
        name: "CompletionCacheReceipt",
        ceiling: 660,
        media_type: "application/vnd.dirextalk.mls-recovery-completion-cache-receipt.v2+cbor",
        rule_marker: "x-dirextalk-cddl-rule",
        rule: "signed-mls-recovery-completion-cache-receipt-v2",
        schema: "SignedCompletionCacheReceiptCbor",
    },
];

#[allow(clippy::too_many_lines)]
pub(super) fn validate_contract(document: &Value) -> Result<(), ProtocolToolError> {
    if string_at(document, "/openapi", "OpenAPI version")? != "3.1.0"
        || string_at(document, "/info/version", "OpenAPI info version")? != "7.0.0"
        || string_at(
            document,
            "/x-dirextalk-cddl-artifact",
            "OpenAPI CDDL artifact",
        )? != CDDL_RELATIVE
    {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V7 OpenAPI version/artifact relationship drift",
        ));
    }

    let domains = object_at(
        document,
        "/x-dirextalk-crypto-domains",
        "MLS Sequencer V7 domains",
    )?;
    require_exact_keys(domains, DOMAINS.iter().map(|(name, _)| *name), "domains")?;
    if domains.len() != 40 {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 OpenAPI domain count drift: expected 40, found {}",
            domains.len()
        )));
    }
    for (name, expected) in DOMAINS {
        if domains.get(*name).and_then(Value::as_str) != Some(*expected) {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 OpenAPI domain value drift: {name}"
            )));
        }
    }

    let body_ceilings = [
        ("catalog-descriptor-response", 2_226),
        ("issuer-authorization-request", 8_953),
        ("issuer-authorization-response-fields-1-through-22", 2_613),
        ("route-v1", 2_304),
        ("controller-proof-v1", 4_507),
        ("recovery-add-v7", 4_489_217),
        ("recovery-add-receipt-v7", 613),
        ("signed-recovery-add-receipt-v7", 791),
        ("confirmation-v2", 1_510),
        ("confirmation-receipt-v2", 613),
        ("signed-confirmation-receipt-v2", 791),
        ("activation-v2", 6_023),
        ("activation-receipt-v2", 725),
        ("signed-activation-receipt-v2", 903),
        ("activation-readback-v2", 1_556),
        ("evidence-issuance-v1", 12_756),
        ("child-certificate-v1", 389),
        ("redacted-evidence-v1", 250),
        ("evidence-issuance-receipt-v1", 975),
        ("completion-cache-v2", 17_155),
        ("completion-cache-receipt-v2", 482),
        ("signed-completion-cache-receipt-v2", 660),
    ];
    let ceilings = object_at(
        document,
        "/x-dirextalk-body-ceilings",
        "MLS Sequencer V7 body ceilings",
    )?;
    require_exact_keys(
        ceilings,
        body_ceilings.iter().map(|(name, _)| *name),
        "body ceilings",
    )?;
    for (name, maximum) in body_ceilings {
        if ceilings.get(name).and_then(Value::as_u64) != Some(maximum) {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 OpenAPI body ceiling drift: {name}"
            )));
        }
    }

    let paths = object_at(document, "/paths", "MLS Sequencer V7 paths")?;
    let path_methods = [
        (
            "/v2/groups/{scope_kind}/{scope_id}/recovery-completion-verifier-descriptor",
            &["get"][..],
        ),
        (
            "/v2/groups/{scope_kind}/{scope_id}/recovery-completion-issuer-authorizations/{catalog_id}/{generation}/{index}",
            &["put"][..],
        ),
        (
            "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}",
            &["post"][..],
        ),
        (
            "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}/confirmation",
            &["put"][..],
        ),
        (
            "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-activations/{activation_id}",
            &["put", "get"][..],
        ),
        (
            "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-evidence-issuances/{issuance_id}",
            &["post"][..],
        ),
        (
            "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-activations/{activation_id}/completion-cache",
            &["put"][..],
        ),
    ];
    require_exact_keys(paths, path_methods.iter().map(|(path, _)| *path), "paths")?;
    if paths.len() != 7 {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V7 OpenAPI must expose exactly 7 paths",
        ));
    }
    for (path, methods) in path_methods {
        let item = paths
            .get(path)
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolToolError::new(format!("OpenAPI path missing: {path}")))?;
        require_exact_keys(item, methods.iter().copied(), path)?;
    }

    let operations = [
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/recovery-completion-verifier-descriptor",
            method: "get",
            operation_id: "getCatalogCompletionVerifierDescriptorV1",
            authentication: "origin-authenticated-https",
            parameters: &["ScopeKind", "ScopeId"],
            responses: &[
                ("200", "CatalogDescriptor"),
                ("404", "NotFound"),
                ("410", "Gone"),
                ("412", "Invalidated"),
            ],
            request: None,
        },
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/recovery-completion-issuer-authorizations/{catalog_id}/{generation}/{index}",
            method: "put",
            operation_id: "authorizeCatalogCompletionIssuerV1",
            authentication: "current-catalog-authority",
            parameters: &[
                "ScopeKind",
                "ScopeId",
                "CatalogId",
                "Generation",
                "Index",
                "Authorization",
                "IdempotencyKey",
            ],
            responses: &[
                ("201", "IssuerAuthorization"),
                ("200", "IssuerAuthorization"),
                ("401", "Unauthorized"),
                ("409", "Conflict"),
                ("410", "Gone"),
                ("412", "Invalidated"),
                ("422", "InvalidExactCbor"),
            ],
            request: Some(RequestSpec {
                ceiling: 8_953,
                media_type: "application/vnd.dirextalk.mls-recovery-issuer-authorization-request.v1+cbor",
                rule: "mls-recovery-issuer-authorization-request-v1",
                schema: "IssuerAuthorizationRequestCbor",
            }),
        },
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}",
            method: "post",
            operation_id: "submitMlsRecoveryCommitV7",
            authentication: "current-scope-controller",
            parameters: &[
                "ScopeKind",
                "ScopeId",
                "SubmissionId",
                "Authorization",
                "IdempotencyKey",
            ],
            responses: &[
                ("201", "AddReceipt"),
                ("200", "AddReceipt"),
                ("401", "Unauthorized"),
                ("409", "Conflict"),
                ("410", "Gone"),
                ("412", "Invalidated"),
                ("422", "InvalidExactCbor"),
            ],
            request: Some(RequestSpec {
                ceiling: 4_489_217,
                media_type: "application/vnd.dirextalk.mls-recovery-commit.v7+cbor",
                rule: "mls-recovery-add-request-v7",
                schema: "RecoveryAddRequestCbor",
            }),
        },
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}/confirmation",
            method: "put",
            operation_id: "confirmMlsRecoveryCommitV2",
            authentication: "candidate-device",
            parameters: &[
                "ScopeKind",
                "ScopeId",
                "SubmissionId",
                "Authorization",
                "IdempotencyKey",
            ],
            responses: &[
                ("200", "ConfirmationReceipt"),
                ("401", "Unauthorized"),
                ("409", "Conflict"),
                ("410", "Gone"),
                ("412", "Invalidated"),
                ("422", "InvalidExactCbor"),
            ],
            request: Some(RequestSpec {
                ceiling: 1_510,
                media_type: "application/vnd.dirextalk.mls-recovery-confirmation.v2+cbor",
                rule: "mls-recovery-confirmation-v2",
                schema: "ConfirmationCommandCbor",
            }),
        },
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-activations/{activation_id}",
            method: "put",
            operation_id: "activateMlsRecoveryV2",
            authentication: "current-scope-controller",
            parameters: &[
                "ScopeKind",
                "ScopeId",
                "ActivationId",
                "Authorization",
                "IdempotencyKey",
            ],
            responses: &[
                ("201", "ActivationReceipt"),
                ("200", "ActivationReceipt"),
                ("401", "Unauthorized"),
                ("409", "Conflict"),
                ("410", "Gone"),
                ("412", "Invalidated"),
                ("422", "InvalidExactCbor"),
            ],
            request: Some(RequestSpec {
                ceiling: 6_023,
                media_type: "application/vnd.dirextalk.mls-recovery-activation.v2+cbor",
                rule: "mls-recovery-activation-command-v2",
                schema: "ActivationCommandCbor",
            }),
        },
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-activations/{activation_id}",
            method: "get",
            operation_id: "getMlsRecoveryActivationReadbackV2",
            authentication: "candidate-device",
            parameters: &["ScopeKind", "ScopeId", "ActivationId", "Authorization"],
            responses: &[
                ("200", "ActivationReadback"),
                ("401", "Unauthorized"),
                ("404", "NotFound"),
                ("410", "Gone"),
                ("412", "Invalidated"),
            ],
            request: None,
        },
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-evidence-issuances/{issuance_id}",
            method: "post",
            operation_id: "issueMlsRecoveryCompletionEvidenceV1",
            authentication: "current-scope-controller",
            parameters: &[
                "ScopeKind",
                "ScopeId",
                "IssuanceId",
                "Authorization",
                "IdempotencyKey",
            ],
            responses: &[
                ("201", "EvidenceIssuanceReceipt"),
                ("200", "EvidenceIssuanceReceipt"),
                ("401", "Unauthorized"),
                ("409", "Conflict"),
                ("410", "PreIssuanceGone"),
                ("412", "PreIssuanceInvalidated"),
                ("422", "InvalidExactCbor"),
            ],
            request: Some(RequestSpec {
                ceiling: 12_756,
                media_type: "application/vnd.dirextalk.mls-recovery-evidence-issuance.v1+cbor",
                rule: "mls-recovery-evidence-issuance-command-v1",
                schema: "EvidenceIssuanceCommandCbor",
            }),
        },
        OperationSpec {
            path: "/v2/groups/{scope_kind}/{scope_id}/mls-recovery-activations/{activation_id}/completion-cache",
            method: "put",
            operation_id: "cacheMlsRecoveryCompletionV2",
            authentication: "current-scope-controller",
            parameters: &[
                "ScopeKind",
                "ScopeId",
                "ActivationId",
                "Authorization",
                "IdempotencyKey",
            ],
            responses: &[
                ("201", "CompletionCacheReceipt"),
                ("200", "CompletionCacheReceipt"),
                ("401", "Unauthorized"),
                ("409", "Conflict"),
                ("410", "PostIssuanceCacheGone"),
                ("412", "PostIssuanceCacheInvalidated"),
                ("422", "InvalidExactCbor"),
            ],
            request: Some(RequestSpec {
                ceiling: 17_155,
                media_type: "application/vnd.dirextalk.mls-recovery-completion-cache.v2+cbor",
                rule: "mls-recovery-completion-cache-command-v2",
                schema: "CompletionCacheCommandCbor",
            }),
        },
    ];
    if operations.len() != 8 {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V7 OpenAPI must expose exactly 8 operations",
        ));
    }
    for operation in operations {
        validate_operation(document, operation)?;
    }

    super::semantics::validate_schemas(document)?;
    super::semantics::validate_responses(document)?;
    super::semantics::validate_semantics(document)
}

fn validate_operation(
    document: &Value,
    expected: OperationSpec<'_>,
) -> Result<(), ProtocolToolError> {
    let operation = operation_at(document, expected)?;
    validate_operation_identity(operation, expected)?;
    validate_operation_parameters(operation, expected)?;
    validate_operation_responses(operation, expected)?;
    validate_operation_request(operation, expected)
}

fn operation_at<'a>(
    document: &'a Value,
    expected: OperationSpec<'_>,
) -> Result<&'a Value, ProtocolToolError> {
    let pointer = format!(
        "/paths/{}/{}",
        json_pointer_segment(expected.path),
        expected.method
    );
    document.pointer(&pointer).ok_or_else(|| {
        ProtocolToolError::new(format!(
            "MLS Sequencer V7 OpenAPI operation missing: {} {}",
            expected.method, expected.path
        ))
    })
}

fn validate_operation_identity(
    operation: &Value,
    expected: OperationSpec<'_>,
) -> Result<(), ProtocolToolError> {
    if operation.get("operationId").and_then(Value::as_str) != Some(expected.operation_id) {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 OpenAPI operationId drift: {}",
            expected.operation_id
        )));
    }
    if operation
        .pointer("/x-dirextalk-authentication/kind")
        .and_then(Value::as_str)
        != Some(expected.authentication)
    {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 OpenAPI authorization binding drift: {}",
            expected.operation_id
        )));
    }
    Ok(())
}

fn validate_operation_parameters(
    operation: &Value,
    expected: OperationSpec<'_>,
) -> Result<(), ProtocolToolError> {
    let parameters = operation
        .get("parameters")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProtocolToolError::new(format!("parameters missing: {}", expected.operation_id))
        })?;
    let actual_parameters = parameters
        .iter()
        .map(|parameter| {
            parameter
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/components/parameters/"))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            ProtocolToolError::new(format!(
                "MLS Sequencer V7 parameter ref drift: {}",
                expected.operation_id
            ))
        })?;
    if actual_parameters != expected.parameters {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 parameter relationship drift: {}",
            expected.operation_id
        )));
    }
    Ok(())
}

fn validate_operation_responses(
    operation: &Value,
    expected: OperationSpec<'_>,
) -> Result<(), ProtocolToolError> {
    let responses = operation
        .get("responses")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProtocolToolError::new(format!("responses missing: {}", expected.operation_id))
        })?;
    require_exact_keys(
        responses,
        expected.responses.iter().map(|(status, _)| *status),
        expected.operation_id,
    )?;
    for (status, name) in expected.responses {
        let expected_ref = format!("#/components/responses/{name}");
        if responses
            .get(*status)
            .and_then(|response| response.get("$ref"))
            .and_then(Value::as_str)
            != Some(expected_ref.as_str())
        {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 response relationship drift: {} {status}",
                expected.operation_id
            )));
        }
    }
    Ok(())
}

fn validate_operation_request(
    operation: &Value,
    expected: OperationSpec<'_>,
) -> Result<(), ProtocolToolError> {
    match expected.request {
        Some(request) => {
            if operation
                .get("x-dirextalk-body-ceiling-bytes")
                .and_then(Value::as_u64)
                != Some(request.ceiling)
            {
                return Err(ProtocolToolError::new(format!(
                    "MLS Sequencer V7 OpenAPI operation body ceiling drift: {}",
                    expected.operation_id
                )));
            }
            let request_body = operation.get("requestBody").ok_or_else(|| {
                ProtocolToolError::new(format!("request body missing: {}", expected.operation_id))
            })?;
            if request_body.get("required").and_then(Value::as_bool) != Some(true) {
                return Err(ProtocolToolError::new(format!(
                    "MLS Sequencer V7 request body must be required: {}",
                    expected.operation_id
                )));
            }
            let content = request_body
                .get("content")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ProtocolToolError::new(format!(
                        "request content missing: {}",
                        expected.operation_id
                    ))
                })?;
            require_exact_keys(content, [request.media_type], expected.operation_id)?;
            let media = content.get(request.media_type).ok_or_else(|| {
                ProtocolToolError::new(format!("media missing: {}", expected.operation_id))
            })?;
            let schema_ref = format!("#/components/schemas/{}", request.schema);
            if media.get("x-dirextalk-cddl-rule").and_then(Value::as_str) != Some(request.rule)
                || media.get("x-dirextalk-exact-cbor").and_then(Value::as_bool) != Some(true)
                || media.pointer("/schema/$ref").and_then(Value::as_str)
                    != Some(schema_ref.as_str())
            {
                return Err(ProtocolToolError::new(format!(
                    "MLS Sequencer V7 canonical request media/schema drift: {}",
                    expected.operation_id
                )));
            }
        }
        None => {
            if operation.get("requestBody").is_some()
                || operation.get("x-dirextalk-body-ceiling-bytes").is_some()
            {
                return Err(ProtocolToolError::new(format!(
                    "MLS Sequencer V7 bodyless operation drift: {}",
                    expected.operation_id
                )));
            }
        }
    }
    Ok(())
}
