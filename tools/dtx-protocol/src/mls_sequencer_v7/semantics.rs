use serde_json::{Map, Value, json};

use crate::ProtocolToolError;

use super::helpers::{object_at, require_exact_keys, require_json, string_at};
use super::openapi::{
    BINARY_SCHEMA_SPECS, OPENAPI_RESPONSE_NAMES, OPENAPI_SCHEMA_NAMES, SUCCESS_RESPONSE_SPECS,
};

pub(super) fn validate_schemas(document: &Value) -> Result<(), ProtocolToolError> {
    let schemas = object_at(document, "/components/schemas", "MLS Sequencer V7 schemas")?;
    require_exact_keys(schemas, OPENAPI_SCHEMA_NAMES.iter().copied(), "schemas")?;
    validate_binary_schemas(schemas)?;
    validate_identifier_schemas(document)?;
    validate_parameter_schemas(document)
}

fn validate_binary_schemas(schemas: &Map<String, Value>) -> Result<(), ProtocolToolError> {
    for &(name, maximum, marker, rule) in BINARY_SCHEMA_SPECS {
        let schema = schemas
            .get(name)
            .ok_or_else(|| ProtocolToolError::new(format!("schema missing: {name}")))?;
        if schema.get("type").and_then(Value::as_str) != Some("string")
            || schema.get("contentEncoding").and_then(Value::as_str) != Some("binary")
            || schema.get("maxLength").and_then(Value::as_u64) != Some(maximum)
            || schema
                .get("x-dirextalk-exact-cbor")
                .and_then(Value::as_bool)
                != Some(true)
            || schema.get(marker).and_then(Value::as_str) != Some(rule)
        {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 OpenAPI schema maximum/media rule drift: {name}"
            )));
        }
    }
    Ok(())
}

fn validate_identifier_schemas(document: &Value) -> Result<(), ProtocolToolError> {
    require_json(
        document,
        "/components/schemas/ExactCanonicalCbor",
        &json!({
            "type": "string",
            "contentEncoding": "binary",
            "x-dirextalk-exact-cbor": true
        }),
        "canonical CBOR schema",
    )?;
    require_json(
        document,
        "/components/schemas/UuidV7",
        &json!({
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        }),
        "UUIDv7 schema",
    )?;
    require_json(
        document,
        "/components/schemas/ChannelId",
        &json!({
            "type": "string",
            "minLength": 57,
            "maxLength": 57,
            "pattern": "^dtxc1[a-z2-7]{52}$"
        }),
        "Channel ID schema",
    )?;
    require_json(
        document,
        "/components/schemas/GroupScopeId",
        &json!({
            "oneOf": [
                {"$ref": "#/components/schemas/UuidV7"},
                {"$ref": "#/components/schemas/ChannelId"}
            ]
        }),
        "scope schema",
    )
}

fn validate_parameter_schemas(document: &Value) -> Result<(), ProtocolToolError> {
    for (pointer, expected) in [
        ("/components/parameters/Generation/schema/minimum", 1),
        (
            "/components/parameters/Generation/schema/maximum",
            9_007_199_254_740_991,
        ),
        ("/components/parameters/Index/schema/minimum", 1),
        ("/components/parameters/Index/schema/maximum", 1_023),
        ("/components/parameters/IdempotencyKey/schema/minLength", 16),
        (
            "/components/parameters/IdempotencyKey/schema/maxLength",
            128,
        ),
    ] {
        if document.pointer(pointer).and_then(Value::as_u64) != Some(expected) {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 OpenAPI schema maximum drift at {pointer}"
            )));
        }
    }
    require_json(
        document,
        "/components/parameters/IdempotencyKey/schema/pattern",
        &json!("^[!-~]{16,128}$"),
        "Idempotency-Key schema",
    )
}

pub(super) fn validate_responses(document: &Value) -> Result<(), ProtocolToolError> {
    let responses = object_at(
        document,
        "/components/responses",
        "MLS Sequencer V7 responses",
    )?;
    require_exact_keys(
        responses,
        OPENAPI_RESPONSE_NAMES.iter().copied(),
        "responses",
    )?;

    validate_success_responses(responses)?;
    validate_no_store_responses(document)
}

fn validate_success_responses(responses: &Map<String, Value>) -> Result<(), ProtocolToolError> {
    for &expected in SUCCESS_RESPONSE_SPECS {
        let response = responses.get(expected.name).ok_or_else(|| {
            ProtocolToolError::new(format!("response missing: {}", expected.name))
        })?;
        if response
            .get("x-dirextalk-body-ceiling-bytes")
            .and_then(Value::as_u64)
            != Some(expected.ceiling)
        {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 response schema maximum drift: {}",
                expected.name
            )));
        }
        let content = response
            .get("content")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProtocolToolError::new(format!("response content missing: {}", expected.name))
            })?;
        require_exact_keys(content, [expected.media_type], expected.name)?;
        let media = content.get(expected.media_type).ok_or_else(|| {
            ProtocolToolError::new(format!("response media missing: {}", expected.name))
        })?;
        let schema_ref = format!("#/components/schemas/{}", expected.schema);
        if media.get(expected.rule_marker).and_then(Value::as_str) != Some(expected.rule)
            || media.pointer("/schema/$ref").and_then(Value::as_str) != Some(schema_ref.as_str())
        {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 response media/rule drift: {}",
                expected.name
            )));
        }
    }
    Ok(())
}

fn validate_no_store_responses(document: &Value) -> Result<(), ProtocolToolError> {
    for &name in OPENAPI_RESPONSE_NAMES {
        let pointer = format!("/components/responses/{name}/headers/Cache-Control/$ref");
        if document.pointer(&pointer).and_then(Value::as_str)
            != Some("#/components/headers/NoStore")
        {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 no-store response binding drift: {name}"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_semantics(document: &Value) -> Result<(), ProtocolToolError> {
    require_json(
        document,
        "/x-dirextalk-strict-wire",
        &json!({
            "deterministic-canonical-cbor": "required",
            "closed-maps-and-enums": "required",
            "duplicate-or-unknown-map-keys": "rejected",
            "exact-version-discriminator": "required",
            "v6-v7-conversion-or-decoder-fallback": "forbidden",
            "strict-ed25519-and-x25519-semantics": "required",
            "dns-https-authority-origin-only": true,
            "exact-header-body-idempotency-digest": "required",
            "raw-authorization-or-idempotency-values-persisted": false,
            "no-partial-durable-writes": true,
            "request-content-type": "exactly-the-operation-media-type-with-no-parameters",
            "request-content-encoding-header": "forbidden",
            "response-content-encoding-header": "forbidden",
            "body-trailing-bytes": "rejected"
        }),
        "canonical-wire binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-domain-inventory",
        &json!({
            "exact-count": 40,
            "cddl-and-openapi-exactly-equal": "required",
            "terminal-nul-on-every-domain": "required",
            "phase-1-exact-count": 38,
            "phase-2a-only-additions": ["raw-mls-commit", "raw-mls-welcome"],
            "membership-receipt-domain-owner": "recovery-scope-catalog-v2",
            "membership-receipt-domain-counted-as-mls-owned": false,
            "history-context-domain-owner": "history-recovery-v3",
            "history-context-domain-added-to-mls-inventory": false,
            "raw-commit-welcome-or-proof-digest-domains-added-in-phase-1": false,
            "raw-commit-and-welcome-domains-added-in-phase-2a": true,
            "raw-proof-or-membership-receipt-domain-added-in-phase-2a": false
        }),
        "domain ownership",
    )?;
    require_json(
        document,
        "/x-dirextalk-catalog-type-ownership/external-domain-ownership/membership-receipt",
        &json!({
            "owner-artifact": "protocol/cddl/recovery-scope-catalog/v2/recovery-scope-catalog-v2.cddl",
            "owner-private-body-rule": "recovery-scope-catalog-private-body-v2",
            "payload-cbor-path": [6],
            "digest-cbor-path": [7],
            "domain": "dirextalk.recovery-scope-membership-receipt.v1\0",
            "digest-input": "exact-raw-bstr-payload-bytes-without-enclosing-cbor-header",
            "owner-validator-and-currentness": "required",
            "imported-verbatim-without-mls-rehash": "required",
            "counted-in-mls-owned-domain-inventory": false,
            "bounded-bstr-alone-is-validation": false
        }),
        "Catalog membership receipt ownership",
    )?;
    require_json(
        document,
        "/x-dirextalk-history-completion-context-owner",
        &json!({
            "owner-artifact": "protocol/cddl/history-recovery/v3/history-recovery-v3.cddl",
            "owner-rule": "history-recovery-completion-context-v2",
            "formula": "completion_context_digest = SHA-256(\"dirextalk.history-recovery-completion-context.v2\\0\" || exact deterministic-canonical history-recovery-completion-context-v2 bytes)",
            "imported-verbatim": "required",
            "mls-domain-alias-second-hash-or-re-encoding": "forbidden",
            "exact-equalities": {
                "child-certificate-cbor-path": [9],
                "evidence-cbor-path": [3],
                "issuance-command-cbor-path": [11],
                "issuance-receipt-cbor-path": [9],
                "cache-command-cbor-path": [9],
                "cache-receipt-cbor-path": [7],
                "history-presentation-receipt-cbor-path": [2, 1, 26]
            }
        }),
        "imported History context binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-add-validation",
        &json!({
            "all-before-any-write": true,
            "validates": [
                "exact-ready-history-request-manifest-grant-offer-and-immutable-delivery-fact",
                "direct-device-add-and-final-identity-log-h-plus-1",
                "exact-catalog-head-full-private-opening-public-leaf-and-proof",
                "current-origin-descriptor-and-full-issuer-binding",
                "exact-key-package-v4-publish-and-claim-receipts-and-global-consumption",
                "mls-commit-welcome-route-and-current-controller-proof",
                "every-repeated-coordinate-digest-signature-and-validity-window",
                "candidate-request-device-catalog-authority-controller-and-mls-currentness"
            ],
            "final-atomic-cas": {
                "from": "exact-prior-authority-mls-epoch-and-head",
                "to": "exact-next-epoch-and-committed-authority-mls-head"
            },
            "first-state": "welcome_pending"
        }),
        "Add authorization/currentness/CAS binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-state-machine",
        &json!({
            "states": {"welcome_pending": 1, "candidate_confirmed": 2, "activated_fenced": 3},
            "transitions": [
                "welcome_pending-to-candidate_confirmed-by-exact-candidate-confirmation",
                "candidate_confirmed-to-activated_fenced-by-current-controller-and-final-head-cas"
            ],
            "skip-or-regress": "forbidden",
            "activation-enables-routing": false,
            "identity-recovery-complete-enables-routing": false,
            "final-heads": {
                "identity": "exact-identity-log-head-at-direct-device-add-h-plus-1",
                "authority-mls": "exact-scope-authority-mls-head-after-recovery-commit",
                "interchangeable": false
            }
        }),
        "state/CAS binding",
    )?;

    require_raw_mls_semantics(document)?;
    require_receipt_and_idempotency_bindings(document)?;
    require_persistence_and_privacy_semantics(document)?;

    let arithmetic = string_at(
        document,
        "/x-dirextalk-cbor-ceiling-arithmetic/recovery-add-v7",
        "Add ceiling arithmetic",
    )?;
    if !arithmetic.contains("81-map-header-and-key-bytes + 4489068-value-bytes = 4489149") {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V7 Add canonical ceiling arithmetic drift",
        ));
    }
    Ok(())
}

fn require_raw_mls_semantics(document: &Value) -> Result<(), ProtocolToolError> {
    for (pointer, expected) in [
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-add-request-v7/40",
            json!({
                "name": "exact-raw-mls-commit",
                "validation": [
                    "one-wholly-consumed-canonical-mls-wire-commit",
                    "parser-remainder-rejected",
                    "reencoding-rejected",
                    "welcome-or-other-type-substitution-rejected"
                ]
            }),
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-add-request-v7/41",
            json!({
                "name": "raw-mls-commit-digest",
                "source": "raw-mls-commit-domain-over-exact-field-40-bstr-payload",
                "digest-input-excludes": "enclosing-cbor-bstr-header"
            }),
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-add-request-v7/42",
            json!({
                "name": "exact-raw-mls-welcome",
                "validation": [
                    "one-wholly-consumed-canonical-mls-wire-welcome",
                    "parser-remainder-rejected",
                    "reencoding-rejected",
                    "commit-or-other-type-substitution-rejected"
                ]
            }),
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-add-request-v7/43",
            json!({
                "name": "raw-mls-welcome-digest",
                "source": "raw-mls-welcome-domain-over-exact-field-42-bstr-payload",
                "digest-input-excludes": "enclosing-cbor-bstr-header"
            }),
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-add-request-v7/51",
            json!({
                "name": "candidate-signature",
                "source": "field-7-key-signs-exact-fields-1-through-50"
            }),
        ),
    ] {
        require_json(
            document,
            pointer,
            &expected,
            "raw MLS ownership/type binding",
        )?;
    }
    Ok(())
}

fn require_receipt_and_idempotency_bindings(document: &Value) -> Result<(), ProtocolToolError> {
    for (pointer, expected) in [
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-issuer-authorization-request-v1/16/source",
            "issuer-authorization-idempotency-domain-over-exact-header-octets",
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-add-request-v7/50/source",
            "add-idempotency-domain-over-exact-header-octets",
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-confirmation-v2/23/source",
            "confirmation-idempotency-domain-over-exact-header-octets",
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-activation-command-v2/24/source",
            "activation-idempotency-domain-over-exact-header-octets",
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-evidence-issuance-command-v1/27/source",
            "exact-header-domain-digest",
        ),
        (
            "/x-dirextalk-compact-map-fields/mls-recovery-completion-cache-command-v2/27/source",
            "exact-header-domain-digest",
        ),
        (
            "/x-dirextalk-compact-map-fields/signed-mls-recovery-add-receipt-v7/2/source",
            "add-receipt-domain-digest-of-exact-field-1",
        ),
        (
            "/x-dirextalk-compact-map-fields/signed-mls-recovery-confirmation-receipt-v2/2/source",
            "confirmation-receipt-domain-digest-of-exact-field-1",
        ),
        (
            "/x-dirextalk-compact-map-fields/signed-mls-recovery-activation-receipt-v2/2/source",
            "activation-receipt-domain-digest-of-exact-field-1",
        ),
        (
            "/x-dirextalk-compact-map-fields/signed-mls-recovery-completion-cache-receipt-v2/2/source",
            "completion-cache-receipt-domain-digest-of-exact-field-1",
        ),
    ] {
        if string_at(document, pointer, "receipt/idempotency binding")? != expected {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 receipt/idempotency binding drift at {pointer}"
            )));
        }
    }
    for (pointer, expected) in [
        (
            "/x-dirextalk-exact-http-operations/authorize-catalog-completion-issuer/idempotency-digest-cbor-path",
            json!([16]),
        ),
        (
            "/x-dirextalk-exact-http-operations/submit-mls-recovery-commit/idempotency-digest-cbor-path",
            json!([50]),
        ),
        (
            "/x-dirextalk-exact-http-operations/confirm-mls-recovery-commit/idempotency-digest-cbor-path",
            json!([23]),
        ),
        (
            "/x-dirextalk-exact-http-operations/activate-mls-recovery/idempotency-digest-cbor-path",
            json!([24]),
        ),
        (
            "/x-dirextalk-exact-http-operations/issue-mls-recovery-evidence/idempotency-digest-cbor-path",
            json!([27]),
        ),
        (
            "/x-dirextalk-exact-http-operations/cache-mls-recovery-completion/idempotency-digest-cbor-path",
            json!([27]),
        ),
    ] {
        require_json(document, pointer, &expected, "HTTP idempotency binding")?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn require_persistence_and_privacy_semantics(document: &Value) -> Result<(), ProtocolToolError> {
    require_json(
        document,
        "/x-dirextalk-child-evidence/final-atomic-cas",
        &json!({
            "rechecks": [
                "exact-current-origin-descriptor",
                "exact-activation-receipt-and-current-readback",
                "exact-authority-mls-anchor",
                "authorization-revisions",
                "explicit-revocation-revisions"
            ],
            "child-generated-after-rechecks": true,
            "persists-atomically": [
                "exact-issuance-receipt-bytes-containing-child-certificate-and-redacted-evidence",
                "private-exact-issuance-command-bytes-and-digest-including-catalog-opening",
                "private-exact-descriptor-bytes-and-digest",
                "private-exact-activation-receipt-snapshot-bytes-and-digest",
                "private-exact-activation-readback-snapshot-bytes-and-digest",
                "private-authority-mls-anchor",
                "private-authorization-and-revocation-revisions"
            ],
            "losing-race": "destroy-child-and-write-nothing"
        }),
        "issuance snapshot/CAS binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-child-evidence/after-commit-still-fenced-by",
        &json!([
            "explicit-issuer-revocation",
            "explicit-catalog-request-candidate-device-member-or-activation-revocation"
        ]),
        "issuance revocation binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-redacted-evidence-privacy",
        &json!({
            "contains": [
                "child-certificate-digest",
                "history-completion-context-digest",
                "generation-signed-catalog-head-count-index-and-public-leaf-digest",
                "activated-fenced-state-issued-at-expires-at-and-child-signature"
            ],
            "forbidden": [
                "scope-or-scope-origin",
                "raw-identity-candidate-controller-completion-request-or-catalog-id",
                "deterministic-digest-of-any-raw-identity-candidate-controller-completion-request-or-catalog-id",
                "signed-request-digest",
                "activation-receipt-or-readback-correlation",
                "membership-receipt",
                "descriptor-or-verifier-key-id-epoch",
                "private-opening-or-full-verifier-binding",
                "route-or-authority-key-id",
                "issuer-or-child-private-key-handle"
            ]
        }),
        "redacted evidence privacy",
    )?;
    require_json(
        document,
        "/x-dirextalk-completion-cache",
        &json!({
            "semantic-key": ["scope", "history-completion-context-digest"],
            "cache-id-is-semantic-key": false,
            "consumes": [
                "exact-history-completion-presentation-with-signed-receipt-own-entry-and-proof",
                "exact-stored-child-issuance-receipt",
                "exact-private-catalog-opening-from-stored-issuance-command",
                "exact-private-stored-issuance-descriptor-bytes-and-digest",
                "exact-private-stored-issuance-activation-receipt-snapshot-bytes-and-digest",
                "exact-private-stored-issuance-readback-snapshot-bytes-and-digest"
            ],
            "validates": [
                "history-completion-key-descriptor-signature-historical-chain-and-origin",
                "history-signed-receipt-own-entry-proof-count-index-and-public-leaf-equality",
                "private-opening-and-persistent-issuer-delegation",
                "child-certificate-pop-issuer-signature-and-single-evidence-signature",
                "stored-historical-descriptor-signature-digest-and-validity-at-issuance",
                "exact-issuance-time-activation-receipt-and-readback-snapshots-at-activated-fenced",
                "history-first-admission-accepted-at-path-2-1-30-less-than-evidence-expires-at"
            ],
            "current-descriptor-fetch": "forbidden",
            "evidence-expiry-after-timely-signed-history-admission": "allowed",
            "final-atomic-cas-rechecks": [
                "exact-history-completion-presentation",
                "current-identity-device-member-and-controller-authorization",
                "explicit-revocation-generations",
                "stored-activation-anchor-remains-in-current-local-mls-lineage"
            ],
            "routine-post-issuance-descriptor-rotation-is-412": false,
            "ordinary-descendant-authority-mls-head-is-412": false,
            "exact-semantic-key-body-idempotency-replay": "byte-identical-stored-receipt",
            "changed-body-idempotency-cache-id-or-activation-under-semantic-key": "conflict-no-write",
            "immutable-exact-cache": true,
            "generic-recovery-complete-boolean-accepted": false
        }),
        "completion cache snapshot/CAS/revocation binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-issuance-and-cache-errors",
        &json!({
            "pre-issuance-410": [
                "explicit-issuer-catalog-request-candidate-device-member-or-activation-revocation",
                "workflow-or-authority-window-expired"
            ],
            "pre-issuance-412": [
                "descriptor-activation-readback-or-authority-anchor-changed-before-final-cas",
                "authorization-or-revocation-revision-changed-before-final-cas"
            ],
            "post-issuance-cache-410": [
                "explicit-issuer-catalog-request-candidate-device-member-or-activation-revocation"
            ],
            "post-issuance-cache-410-excludes": "evidence-expiry-alone",
            "post-issuance-cache-412": [
                "stored-issuance-snapshot-mismatch",
                "invalid-or-changed-history-presentation-during-first-admission",
                "history-first-admission-not-before-evidence-expiry",
                "current-authorization-or-revocation-race",
                "stored-activation-anchor-not-in-current-local-mls-lineage"
            ],
            "committed-semantic-key-with-changed-command-including-presentation": 409,
            "post-issuance-cache-412-excludes": [
                "routine-descriptor-rotation",
                "ordinary-descendant-authority-mls-head-advance"
            ]
        }),
        "issuance/cache error binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-routing-predicate",
        &json!({
            "all-required": [
                "durable-state-equals-activated-fenced",
                "exact-immutable-scope-and-history-context-cache-exists",
                "current-identity-device-member-and-controller-authorization",
                "local-activation-anchor-remains-valid-in-current-local-mls-lineage",
                "no-explicit-issuer-catalog-request-candidate-device-member-or-activation-revocation"
            ],
            "recovery-complete-without-cache": "deny",
            "cache-without-current-authorization": "deny",
            "current-descriptor-fetch-or-equality": "not-a-predicate",
            "historical-issuer-currentness": "not-a-predicate",
            "historical-descriptor-currentness": "not-a-predicate",
            "nonretroactive-after-durable-issuance": [
                "routine-authority-rotation",
                "routine-controller-rotation",
                "ordinary-descendant-authority-mls-head-advance"
            ]
        }),
        "routing authorization/revocation binding",
    )?;
    require_json(
        document,
        "/x-dirextalk-replay-order",
        &json!({
            "first": "parse-exact-path-and-header-shapes-then-authenticate-caller-current-route-authorization-and-immutable-explicit-revocation",
            "second": "exact-media-content-encoding-size-version-signature-and-idempotency-digest-equality",
            "committed-exact-replay": "return-byte-identical-receipt-before-mutable-currentness",
            "committed-conflict": "reject-without-write",
            "first-admission": "complete-mutable-validation-then-one-final-cas",
            "partial-write-or-key-generation-before-required-checks": "forbidden"
        }),
        "replay/currentness ordering",
    )?;
    require_json(
        document,
        "/paths/~1v2~1groups~1{scope_kind}~1{scope_id}~1mls-recovery-activations~1{activation_id}~1completion-cache/put/x-dirextalk-snapshot-validation",
        &json!({
            "activation-receipt-and-readback": "exact-private-issuance-time-snapshots",
            "historical-descriptor-validity": "evaluated-at-issuance",
            "current-descriptor-fetch": "forbidden",
            "later-cache-after-evidence-expiry": "allowed-only-after-signed-timely-history-admission"
        }),
        "cache operation snapshot binding",
    )
}
