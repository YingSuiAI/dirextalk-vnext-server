use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

use cddl_cat::ast::{
    Cddl, GrpEntVal, MemberKeyVal, Rule, RuleVal, Type, Type1, Type2, Value as CddlValue,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::ProtocolToolError;

const CDDL_RELATIVE: &str = "protocol/cddl/history-recovery/v3/history-recovery-v3.cddl";
const OPENAPI_RELATIVE: &str = "protocol/openapi/history-recovery/v3/openapi.yaml";
const CDDL_SHA256: &str = "cbc9d894a2edefed2e5df4b6843ec7eb7bd1666d53d2d1be47f8dbb026282a95";
const OPENAPI_SHA256: &str = "57ed5f87f35c5d20a1ee901eb7fdef6980db243b8b9fe7543599b166d22b3ac1";

const DOMAINS: &[(&str, &str)] = &[
    ("manifest", "dirextalk.history-recovery.manifest.v2\0"),
    ("leaf-set", "dirextalk.history-recovery.leaf-set.v2\0"),
    (
        "request-signature",
        "dirextalk.history-recovery.request-signature.v4\0",
    ),
    ("request", "dirextalk.history-recovery.request.v4\0"),
    (
        "request-idempotency",
        "dirextalk.history-recovery.request-idempotency.v4\0",
    ),
    ("offer", "dirextalk.history-recovery.recipient-offer.v3\0"),
    (
        "offer-ciphertext",
        "dirextalk.history-recovery.offer-ciphertext.v3\0",
    ),
    (
        "grant-provider-signature",
        "dirextalk.history-recovery.grant-provider-signature.v5\0",
    ),
    (
        "grant-authority-signature",
        "dirextalk.history-recovery.grant-authority-signature.v5\0",
    ),
    ("grant", "dirextalk.history-recovery.grant.v5\0"),
    (
        "grant-idempotency",
        "dirextalk.history-recovery.grant-idempotency.v5\0",
    ),
    (
        "delivery-fact",
        "dirextalk.history-recovery.delivery-fact.v2\0",
    ),
    (
        "completion-key-descriptor",
        "dirextalk.history-recovery.completion-key-descriptor.v2\0",
    ),
    (
        "completion-key-descriptor-signature",
        "dirextalk.history-recovery.completion-key-descriptor-signature.v2\0",
    ),
    (
        "completion-context",
        "dirextalk.history-recovery-completion-context.v2\0",
    ),
    (
        "completion-command-signature",
        "dirextalk.history-recovery.completion-command-signature.v2\0",
    ),
    (
        "completion-command",
        "dirextalk.history-recovery.completion-command.v2\0",
    ),
    (
        "completion-idempotency",
        "dirextalk.history-recovery.completion-idempotency.v2\0",
    ),
    (
        "completion-entry",
        "dirextalk.history-recovery.completion-entry.v2\0",
    ),
    (
        "completion-entry-node",
        "dirextalk.history-recovery.completion-entry-node.v2\0",
    ),
    ("offer-ack", "dirextalk.history-recovery.offer-ack.v2\0"),
    (
        "recovery-complete",
        "dirextalk.history-recovery.complete.v2\0",
    ),
    (
        "completion-receipt",
        "dirextalk.history-recovery.completion-receipt.v2\0",
    ),
    (
        "completion-receipt-signature",
        "dirextalk.history-recovery.completion-receipt-signature.v2\0",
    ),
    (
        "presentation",
        "dirextalk.history-recovery.completion-presentation.v2\0",
    ),
];

#[derive(Clone, Copy)]
enum ExpectedType<'a> {
    Literal(u64),
    Name(&'a str),
    FixedBstr(u64),
}

pub(crate) fn validate(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = fs::read_to_string(root.join(CDDL_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {CDDL_RELATIVE}: {error}")))?;
    let openapi = fs::read_to_string(root.join(OPENAPI_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {OPENAPI_RELATIVE}: {error}")))?;
    validate_sources(&cddl, &openapi)
}

fn validate_sources(cddl_source: &str, openapi_source: &str) -> Result<(), ProtocolToolError> {
    let cddl = cddl_cat::parse_cddl(cddl_source).map_err(|error| {
        ProtocolToolError::new(format!("parse History Recovery V3 CDDL: {error}"))
    })?;
    validate_cddl_contract(&cddl)?;

    let spec = oas3::from_yaml(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse History Recovery V3 OpenAPI: {error}"))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "History Recovery V3 OpenAPI must declare 3.1.0",
        ));
    }
    let openapi: Value = yaml_serde::from_str(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse History Recovery V3 OpenAPI tree: {error}"))
    })?;
    validate_openapi_contract(&openapi)?;

    require_sha256(cddl_source, CDDL_SHA256, "History Recovery V3 CDDL")?;
    require_sha256(
        openapi_source,
        OPENAPI_SHA256,
        "History Recovery V3 OpenAPI",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "one structural gate keeps all frozen History Recovery V3 CDDL relationships adjacent"
)]
fn validate_cddl_contract(cddl: &Cddl) -> Result<(), ProtocolToolError> {
    for (rule, maximum) in [
        ("exact-history-recovery-manifest-v2", 35_477),
        ("exact-history-recovery-request-v4", 37_114),
        ("exact-recipient-history-offer-v3", 1_049_093),
        ("exact-history-recovery-grant-v5", 1_050_733),
        ("exact-history-recovery-completion-command-v2", 3_593_836),
        ("exact-history-recovery-completion-entry-v2", 1_387),
        ("exact-signed-history-recovery-completion-receipt-v2", 3_770),
        ("exact-history-recovery-completion-presentation-v2", 5_660),
        ("exact-mls-child-certificate-v1", 389),
        ("exact-mls-redacted-completion-evidence-v1", 250),
    ] {
        validate_bstr_ceiling(cddl, rule, maximum)?;
    }

    for (rule, version, fields) in [
        ("history-recovery-manifest-v2", 2, 10),
        ("history-recovery-request-unsigned-v4", 4, 20),
        ("history-recovery-request-v4", 4, 21),
        ("history-recovery-request-receipt-v4", 4, 5),
        ("recipient-history-offer-v3", 3, 16),
        ("history-recovery-grant-unsigned-v5", 5, 33),
        ("history-recovery-grant-v5", 5, 36),
        ("history-recovery-delivery-fact-v2", 2, 12),
        ("history-recovery-delivery-receipt-v2", 2, 4),
        (
            "history-recovery-completion-key-descriptor-unsigned-v2",
            2,
            9,
        ),
        ("history-recovery-completion-key-descriptor-v2", 2, 10),
        ("history-recovery-completion-context-v2", 2, 12),
        ("history-recovery-completion-entry-v2", 2, 9),
        ("history-recovery-completion-entry-proof-v2", 2, 6),
        ("history-recovery-completion-command-unsigned-v2", 2, 35),
        ("history-recovery-completion-command-v2", 2, 36),
        ("history-recovery-offer-ack-v2", 2, 8),
        ("history-recovery-complete-v2", 2, 11),
        ("history-recovery-completion-receipt-v2", 2, 31),
        ("history-recovery-completion-presentation-v2", 2, 6),
    ] {
        validate_versioned_map(cddl, rule, version, fields)?;
    }

    validate_exact_map(
        cddl,
        "history-recovery-completion-context-v2",
        &[
            ExpectedType::Literal(2),
            ExpectedType::FixedBstr(32),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("identity-id"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("catalog-exhaustive-count"),
            ExpectedType::Name("digest"),
        ],
    )?;
    validate_exact_map(
        cddl,
        "history-recovery-completion-receipt-v2",
        &[
            ExpectedType::Literal(2),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("identity-id"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("safe-highwater"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("catalog-exhaustive-count"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("catalog-exhaustive-count"),
            ExpectedType::Name("history-recovery-offer-ack-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("history-recovery-complete-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("utc-millis"),
            ExpectedType::Literal(1),
        ],
    )?;
    validate_exact_map(
        cddl,
        "signed-history-recovery-completion-receipt-v2",
        &[
            ExpectedType::Name("history-recovery-completion-receipt-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("history-recovery-completion-key-descriptor-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("signature"),
        ],
    )?;
    validate_exact_map(
        cddl,
        "history-recovery-completion-presentation-v2",
        &[
            ExpectedType::Literal(2),
            ExpectedType::Name("signed-history-recovery-completion-receipt-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("history-recovery-completion-entry-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("history-recovery-completion-entry-proof-v2"),
        ],
    )?;

    validate_field_type(
        cddl,
        "history-recovery-request-v4",
        21,
        ExpectedType::Name("signature"),
    )?;
    validate_field_type(
        cddl,
        "history-recovery-grant-v5",
        36,
        ExpectedType::Name("recipient-history-offer-v3"),
    )?;
    for (field, expected) in [
        (
            34,
            ExpectedType::Name("exact-history-recovery-completion-context-v2"),
        ),
        (35, ExpectedType::Name("digest")),
        (36, ExpectedType::Name("signature")),
    ] {
        validate_field_type(
            cddl,
            "history-recovery-completion-command-v2",
            field,
            expected,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one structural gate keeps all frozen History Recovery V3 OpenAPI relationships adjacent"
)]
fn validate_openapi_contract(document: &Value) -> Result<(), ProtocolToolError> {
    if string_at(document, "/openapi", "OpenAPI version")? != "3.1.0"
        || string_at(document, "/info/version", "OpenAPI info version")? != "4.0.0"
        || string_at(
            document,
            "/x-dirextalk-cddl-artifact",
            "OpenAPI CDDL artifact",
        )? != CDDL_RELATIVE
    {
        return Err(ProtocolToolError::new(
            "History Recovery V3 OpenAPI version/artifact relationship drift",
        ));
    }

    let domains = object_at(
        document,
        "/x-dirextalk-crypto-domains",
        "History Recovery V3 domains",
    )?;
    require_exact_keys(domains, DOMAINS.iter().map(|(name, _)| *name), "domains")?;
    for (name, value) in DOMAINS {
        if domains.get(*name).and_then(Value::as_str) != Some(*value) {
            return Err(ProtocolToolError::new(format!(
                "History Recovery V3 domain value drift: {name}"
            )));
        }
    }

    let ceilings = object_at(
        document,
        "/x-dirextalk-history-body-ceilings",
        "History Recovery V3 body ceilings",
    )?;
    let expected_ceilings = [
        ("manifest-v2", 35_477),
        ("request-v4", 37_114),
        ("completion-context-v2", 373),
        ("completion-entry-v2", 1_387),
        ("completion-entry-proof-v2", 427),
        ("completion-command-v2", 3_593_836),
        ("offer-application-ack-v2", 235),
        ("recovery-complete-v2", 301),
        ("completion-receipt-v2", 1_359),
        ("signed-completion-receipt-v2", 3_770),
        ("completion-presentation-v2", 5_660),
    ];
    require_exact_keys(
        ceilings,
        expected_ceilings.iter().map(|(name, _)| *name),
        "body ceilings",
    )?;
    for (name, maximum) in expected_ceilings {
        if ceilings.get(name).and_then(Value::as_u64) != Some(maximum) {
            return Err(ProtocolToolError::new(format!(
                "History Recovery V3 OpenAPI body ceiling drift: {name}"
            )));
        }
    }

    let paths = object_at(document, "/paths", "History Recovery V3 OpenAPI paths")?;
    let path_contract = [
        ("/v4/devices/history-recovery-requests", &["post"][..]),
        ("/v5/devices/history-grants", &["post"][..]),
        (
            "/v2/identity-home/history-recovery-completion-key",
            &["get"][..],
        ),
        (
            "/v2/identity-home/history-recovery-completion-keys/{descriptor_digest}",
            &["get"][..],
        ),
        (
            "/v2/identity-home/history-recovery-completions/{completion_id}",
            &["post", "get"][..],
        ),
    ];
    require_exact_keys(paths, path_contract.iter().map(|(path, _)| *path), "paths")?;
    for (path, methods) in path_contract {
        let item = paths
            .get(path)
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolToolError::new(format!("OpenAPI path missing: {path}")))?;
        require_exact_keys(item, methods.iter().copied(), path)?;
    }

    validate_operation(
        document,
        "/paths/~1v4~1devices~1history-recovery-requests/post",
        "createHistoryRecoveryRequestV4",
        Some(37_114),
        Some((
            "application/vnd.dirextalk.history-recovery-request.v4+cbor",
            "history-recovery-request-v4",
        )),
    )?;
    validate_operation(
        document,
        "/paths/~1v5~1devices~1history-grants/post",
        "grantDeviceHistoryV5",
        Some(1_050_733),
        Some((
            "application/vnd.dirextalk.history-recovery-grant.v5+cbor",
            "history-recovery-grant-v5",
        )),
    )?;
    validate_operation(
        document,
        "/paths/~1v2~1identity-home~1history-recovery-completion-key/get",
        "getCurrentHistoryRecoveryCompletionKeyV2",
        None,
        None,
    )?;
    validate_operation(
        document,
        "/paths/~1v2~1identity-home~1history-recovery-completion-keys~1{descriptor_digest}/get",
        "getHistoricalHistoryRecoveryCompletionKeyV2",
        None,
        None,
    )?;
    validate_operation(
        document,
        "/paths/~1v2~1identity-home~1history-recovery-completions~1{completion_id}/post",
        "completeHistoryRecoveryV2",
        Some(3_593_836),
        Some((
            "application/vnd.dirextalk.history-recovery-completion-command.v2+cbor",
            "history-recovery-completion-command-v2",
        )),
    )?;
    validate_operation(
        document,
        "/paths/~1v2~1identity-home~1history-recovery-completions~1{completion_id}/get",
        "getHistoryRecoveryCompletionV2",
        None,
        None,
    )?;

    for (pointer, expected) in [
        (
            "/x-dirextalk-catalog-exhaustiveness/maximum-valid-catalog-count",
            1_023,
        ),
        (
            "/x-dirextalk-catalog-exhaustiveness/completion-command-decoder-and-body-ceiling-bytes",
            3_593_836,
        ),
        (
            "/x-dirextalk-entry-owned-mls-evidence/child-certificate-exact-byte-ceiling",
            389,
        ),
        (
            "/x-dirextalk-entry-owned-mls-evidence/redacted-evidence-exact-byte-ceiling",
            250,
        ),
        (
            "/components/parameters/IdempotencyKey/schema/maxLength",
            128,
        ),
    ] {
        if document.pointer(pointer).and_then(Value::as_u64) != Some(expected) {
            return Err(ProtocolToolError::new(format!(
                "History Recovery V3 OpenAPI schema maximum drift at {pointer}"
            )));
        }
    }

    let privacy = document
        .pointer("/x-dirextalk-privacy/identity-home-never-receives")
        .ok_or_else(|| ProtocolToolError::new("History Recovery V3 privacy boundary is missing"))?;
    if privacy
        != &json!([
            "recovery-scope",
            "scope-origin",
            "private-catalog-body",
            "full-verifier-binding",
            "origin-verifier-descriptor",
            "raw-membership-receipt",
            "raw-capability",
            "raw-idempotency-key",
            "mls-private-state",
            "mls-epoch-secret"
        ])
        || document.pointer(
            "/x-dirextalk-completion-context/scope-presentation/exact-context-bytes-disclosed",
        ) != Some(&Value::Bool(false))
        || string_at(
            document,
            "/x-dirextalk-completion/presentation/field-3-binding-kind",
            "presentation receipt binding",
        )? != "context-specific-signed-receipt-binding"
        || document.pointer(
            "/x-dirextalk-completion/presentation/field-3-is-self-digest-of-containing-presentation",
        ) != Some(&Value::Bool(false))
        || document.pointer(
            "/paths/~1v2~1identity-home~1history-recovery-completions~1{completion_id}/get/x-dirextalk-readback-authorization/authenticated-identity-equals-cbor-path",
        ) != Some(&json!([1, 3]))
        || document.pointer(
            "/paths/~1v2~1identity-home~1history-recovery-completions~1{completion_id}/get/x-dirextalk-readback-authorization/authenticated-device-id-equals-cbor-path",
        ) != Some(&json!([1, 4]))
    {
        return Err(ProtocolToolError::new(
            "History Recovery V3 privacy or receipt/presentation binding drift",
        ));
    }
    Ok(())
}

fn validate_operation(
    document: &Value,
    pointer: &str,
    operation_id: &str,
    ceiling: Option<u64>,
    body: Option<(&str, &str)>,
) -> Result<(), ProtocolToolError> {
    let operation = document.pointer(pointer).ok_or_else(|| {
        ProtocolToolError::new(format!(
            "History Recovery V3 OpenAPI operation missing: {pointer}"
        ))
    })?;
    if operation.get("operationId").and_then(Value::as_str) != Some(operation_id) {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 OpenAPI operationId drift: {operation_id}"
        )));
    }
    if let Some(expected) = ceiling
        && operation
            .get("x-dirextalk-body-ceiling-bytes")
            .and_then(Value::as_u64)
            != Some(expected)
    {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 OpenAPI route body ceiling drift: {operation_id}"
        )));
    }
    if let Some((media_type, rule)) = body {
        let content = operation
            .pointer("/requestBody/content")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProtocolToolError::new(format!(
                    "History Recovery V3 request content missing: {operation_id}"
                ))
            })?;
        require_exact_keys(content, [media_type], operation_id)?;
        let media = content.get(media_type).expect("key checked above");
        if media.get("x-dirextalk-cddl-rule").and_then(Value::as_str) != Some(rule)
            || media.get("x-dirextalk-exact-cbor").and_then(Value::as_bool) != Some(true)
            || media.pointer("/schema/$ref").and_then(Value::as_str)
                != Some("#/components/schemas/ExactCanonicalCbor")
        {
            return Err(ProtocolToolError::new(format!(
                "History Recovery V3 request schema drift: {operation_id}"
            )));
        }
    }
    Ok(())
}

fn validate_bstr_ceiling(
    cddl: &Cddl,
    rule_name: &str,
    expected_maximum: u64,
) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL ceiling rule is not a type: {rule_name}"
        )));
    };
    let [Type1::Control(control)] = items.as_slice() else {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL ceiling shape drift: {rule_name}"
        )));
    };
    let valid_target = matches!(
        &control.target,
        Type2::Typename(name) if name.name == "bstr" && name.generic_args.is_empty()
    );
    let valid_range = matches!(
        &control.arg,
        Type2::Parethesized(Type(items))
            if matches!(
                items.as_slice(),
                [Type1::Range(range)]
                    if range.inclusive
                        && matches!(&range.start, Type2::Value(CddlValue::Uint(1)))
                        && matches!(&range.end, Type2::Value(CddlValue::Uint(value)) if *value == expected_maximum)
            )
    );
    if control.op != "size" || !valid_target || !valid_range {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL ceiling drift: {rule_name} must be bstr .size (1..{expected_maximum})"
        )));
    }
    Ok(())
}

fn validate_versioned_map(
    cddl: &Cddl,
    rule_name: &str,
    version: u64,
    field_count: usize,
) -> Result<(), ProtocolToolError> {
    let fields = map_fields(unique_rule(cddl, rule_name)?, rule_name)?;
    if fields.len() != field_count
        || fields.first().map(|(key, _)| *key) != Some(1)
        || !type_matches(fields[0].1, ExpectedType::Literal(version))
    {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL version/field relationship drift: {rule_name} must be V{version} with {field_count} fields"
        )));
    }
    Ok(())
}

fn validate_exact_map(
    cddl: &Cddl,
    rule_name: &str,
    expected: &[ExpectedType<'_>],
) -> Result<(), ProtocolToolError> {
    let fields = map_fields(unique_rule(cddl, rule_name)?, rule_name)?;
    if fields.len() != expected.len()
        || fields
            .iter()
            .zip(expected)
            .enumerate()
            .any(|(index, ((key, actual), expected))| {
                *key != u64::try_from(index + 1).expect("small CDDL map")
                    || !type_matches(actual, *expected)
            })
    {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL required field/type drift: {rule_name}"
        )));
    }
    Ok(())
}

fn validate_field_type(
    cddl: &Cddl,
    rule_name: &str,
    key: u64,
    expected: ExpectedType<'_>,
) -> Result<(), ProtocolToolError> {
    let fields = map_fields(unique_rule(cddl, rule_name)?, rule_name)?;
    if fields
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .is_none_or(|(_, actual)| !type_matches(actual, expected))
    {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL field {key} relationship drift: {rule_name}"
        )));
    }
    Ok(())
}

fn unique_rule<'a>(cddl: &'a Cddl, name: &str) -> Result<&'a Rule, ProtocolToolError> {
    let matches = cddl
        .rules
        .iter()
        .filter(|rule| rule.name == name)
        .collect::<Vec<_>>();
    let [rule] = matches.as_slice() else {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL rule {name} must occur exactly once, found {}",
            matches.len()
        )));
    };
    if !rule.generic_parms.is_empty() {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 CDDL rule {name} must not be generic"
        )));
    }
    Ok(rule)
}

fn map_fields<'a>(rule: &'a Rule, label: &str) -> Result<Vec<(u64, &'a Type)>, ProtocolToolError> {
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(ProtocolToolError::new(format!("{label} must be a type")));
    };
    let [Type1::Simple(Type2::Map(group))] = items.as_slice() else {
        return Err(ProtocolToolError::new(format!(
            "{label} must be exactly one closed map"
        )));
    };
    let [choice] = group.0.as_slice() else {
        return Err(ProtocolToolError::new(format!(
            "{label} must not contain map choices"
        )));
    };
    let mut keys = BTreeSet::new();
    let mut fields = Vec::with_capacity(choice.0.len());
    for entry in &choice.0 {
        if entry.occur.is_some() {
            return Err(ProtocolToolError::new(format!(
                "{label} fields must be required"
            )));
        }
        let GrpEntVal::Member(member) = &entry.val else {
            return Err(ProtocolToolError::new(format!(
                "{label} must contain only direct members"
            )));
        };
        let Some(key) = &member.key else {
            return Err(ProtocolToolError::new(format!(
                "{label} member is missing a numeric key"
            )));
        };
        let MemberKeyVal::Value(CddlValue::Uint(key)) = &key.val else {
            return Err(ProtocolToolError::new(format!(
                "{label} member key must be an unsigned integer"
            )));
        };
        if !keys.insert(*key) {
            return Err(ProtocolToolError::new(format!(
                "{label} contains duplicate field {key}"
            )));
        }
        fields.push((*key, &member.value));
    }
    Ok(fields)
}

fn type_matches(actual: &Type, expected: ExpectedType<'_>) -> bool {
    match (actual.0.as_slice(), expected) {
        (
            [Type1::Simple(Type2::Value(CddlValue::Uint(actual)))],
            ExpectedType::Literal(expected),
        ) => *actual == expected,
        ([Type1::Simple(Type2::Typename(actual))], ExpectedType::Name(expected)) => {
            actual.name == expected && actual.generic_args.is_empty()
        }
        ([Type1::Control(control)], ExpectedType::FixedBstr(expected)) => {
            control.op == "size"
                && matches!(
                    &control.target,
                    Type2::Typename(name)
                        if name.name == "bstr" && name.generic_args.is_empty()
                )
                && matches!(
                    &control.arg,
                    Type2::Value(CddlValue::Uint(actual)) if *actual == expected
                )
        }
        _ => false,
    }
}

fn object_at<'a>(
    document: &'a Value,
    pointer: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, ProtocolToolError> {
    document
        .pointer(pointer)
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new(format!("{label} must be an object")))
}

fn string_at<'a>(
    document: &'a Value,
    pointer: &str,
    label: &str,
) -> Result<&'a str, ProtocolToolError> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolToolError::new(format!("{label} must be a string")))
}

fn require_exact_keys<'a>(
    object: &Map<String, Value>,
    expected: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<(), ProtocolToolError> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.into_iter().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(ProtocolToolError::new(format!(
            "History Recovery V3 OpenAPI {label} key set drift: expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

fn require_sha256(source: &str, expected: &str, label: &str) -> Result<(), ProtocolToolError> {
    let digest = Sha256::digest(source.as_bytes());
    let mut actual = String::with_capacity(64);
    for byte in digest {
        write!(&mut actual, "{byte:02x}").expect("writing to String cannot fail");
    }
    if actual != expected {
        return Err(ProtocolToolError::new(format!(
            "{label} SHA-256 drift: expected {expected}, found {actual}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CDDL: &str =
        include_str!("../../../protocol/cddl/history-recovery/v3/history-recovery-v3.cddl");
    const OPENAPI: &str =
        include_str!("../../../protocol/openapi/history-recovery/v3/openapi.yaml");

    fn rejected(cddl: &str, openapi: &str, expected: &str) {
        let error = validate_sources(cddl, openapi).expect_err("mutation must be rejected");
        assert!(
            error.to_string().contains(expected),
            "expected diagnostic containing {expected:?}, got {error}"
        );
    }

    #[test]
    fn frozen_history_recovery_v3_contract_passes() {
        validate_sources(CDDL, OPENAPI).expect("frozen History Recovery V3 must validate");
    }

    #[test]
    fn rejects_cddl_ceiling_increment() {
        let mutated = CDDL.replacen(
            "exact-history-recovery-request-v4 = bstr .size (1..37114)",
            "exact-history-recovery-request-v4 = bstr .size (1..37115)",
            1,
        );
        rejected(&mutated, OPENAPI, "CDDL ceiling drift");
    }

    #[test]
    fn rejects_required_context_field_type_mutation() {
        let mutated = CDDL.replacen(
            "  12: digest                    ; exact Request V4 field-16 manifest digest",
            "  12: uuid-v7                   ; invalid required field type",
            1,
        );
        rejected(&mutated, OPENAPI, "required field/type drift");
    }

    #[test]
    fn rejects_domain_count_and_value_mutations() {
        let missing = OPENAPI.replacen(
            "  presentation: \"dirextalk.history-recovery.completion-presentation.v2\\0\"\n",
            "",
            1,
        );
        rejected(CDDL, &missing, "domains key set drift");

        let changed = OPENAPI.replacen(
            "dirextalk.history-recovery.request.v4\\0",
            "dirextalk.history-recovery.request.v5\\0",
            1,
        );
        rejected(CDDL, &changed, "domain value drift");
    }

    #[test]
    fn rejects_openapi_path_mutation() {
        let mutated = OPENAPI.replacen(
            "  /v5/devices/history-grants:\n",
            "  /v6/devices/history-grants:\n",
            1,
        );
        rejected(CDDL, &mutated, "paths key set drift");
    }

    #[test]
    fn rejects_openapi_schema_maximum_mutation() {
        let mutated = OPENAPI.replacen("maxLength: 128", "maxLength: 129", 1);
        rejected(CDDL, &mutated, "schema maximum drift");
    }
}
