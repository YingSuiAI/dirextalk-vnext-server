use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
};

use cddl_cat::ast::{
    Cddl, GrpEntVal, MemberKeyVal, Rule, RuleVal, Type, Type1, Type2, Value as CddlValue,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::ProtocolToolError;

const CDDL_RELATIVE: &str = "protocol/cddl/mls-sequencer/v7/mls-sequencer-v7.cddl";
const OPENAPI_RELATIVE: &str = "protocol/openapi/mls-sequencer/v7/openapi.yaml";
const CDDL_SHA256: &str = "ff74d5fe4a1c9bd54a3cbadf0b5ee22e9ea87aeb4cceb21413b2b20168c54d85";
const OPENAPI_SHA256: &str = "6eddf81cd0dbe0c8ec57fc6bb7a284c0d4a5d840b0e118cd6255268faa3ee197";

const DOMAINS: &[(&str, &str)] = &[
    (
        "issuer-authorization-request-signature",
        "dirextalk.mls-recovery.issuer-authorization-request-signature.v1\0",
    ),
    (
        "issuer-authorization-request",
        "dirextalk.mls-recovery.issuer-authorization-request.v1\0",
    ),
    (
        "issuer-authorization-idempotency",
        "dirextalk.mls-recovery.issuer-authorization-idempotency.v1\0",
    ),
    (
        "route-signature",
        "dirextalk.mls-recovery.route-signature.v1\0",
    ),
    ("route", "dirextalk.mls-recovery.route.v1\0"),
    (
        "controller-proof-signature",
        "dirextalk.mls-recovery.controller-proof-signature.v1\0",
    ),
    (
        "controller-proof",
        "dirextalk.mls-recovery.controller-proof.v1\0",
    ),
    (
        "raw-mls-commit",
        "dirextalk.mls-recovery.raw-mls-commit.v7\0",
    ),
    (
        "raw-mls-welcome",
        "dirextalk.mls-recovery.raw-mls-welcome.v7\0",
    ),
    ("add-signature", "dirextalk.mls-recovery.add-signature.v7\0"),
    ("add", "dirextalk.mls-recovery.add.v7\0"),
    (
        "add-idempotency",
        "dirextalk.mls-recovery.add-idempotency.v7\0",
    ),
    ("add-receipt", "dirextalk.mls-recovery.add-receipt.v7\0"),
    (
        "add-receipt-signature",
        "dirextalk.mls-recovery.add-receipt-signature.v7\0",
    ),
    (
        "confirmation-signature",
        "dirextalk.mls-recovery.confirmation-signature.v2\0",
    ),
    ("confirmation", "dirextalk.mls-recovery.confirmation.v2\0"),
    (
        "confirmation-idempotency",
        "dirextalk.mls-recovery.confirmation-idempotency.v2\0",
    ),
    (
        "confirmation-receipt",
        "dirextalk.mls-recovery.confirmation-receipt.v2\0",
    ),
    (
        "confirmation-receipt-signature",
        "dirextalk.mls-recovery.confirmation-receipt-signature.v2\0",
    ),
    (
        "activation-signature",
        "dirextalk.mls-recovery.activation-signature.v2\0",
    ),
    ("activation", "dirextalk.mls-recovery.activation.v2\0"),
    (
        "activation-idempotency",
        "dirextalk.mls-recovery.activation-idempotency.v2\0",
    ),
    (
        "activation-receipt",
        "dirextalk.mls-recovery.activation-receipt.v2\0",
    ),
    (
        "activation-receipt-signature",
        "dirextalk.mls-recovery.activation-receipt-signature.v2\0",
    ),
    (
        "activation-readback-signature",
        "dirextalk.mls-recovery.activation-readback-signature.v2\0",
    ),
    (
        "activation-readback",
        "dirextalk.mls-recovery.activation-readback.v2\0",
    ),
    (
        "child-pop",
        "dirextalk.mls-recovery.completion-child-pop.v1\0",
    ),
    (
        "child-certificate-signature",
        "dirextalk.mls-recovery.completion-child-certificate-signature.v1\0",
    ),
    (
        "child-certificate",
        "dirextalk.mls-recovery.completion-child-certificate.v1\0",
    ),
    (
        "redacted-evidence-signature",
        "dirextalk.mls-recovery.redacted-evidence-signature.v1\0",
    ),
    (
        "redacted-evidence",
        "dirextalk.mls-recovery.redacted-evidence.v1\0",
    ),
    (
        "evidence-issuance-signature",
        "dirextalk.mls-recovery.evidence-issuance-signature.v1\0",
    ),
    (
        "evidence-issuance",
        "dirextalk.mls-recovery.evidence-issuance.v1\0",
    ),
    (
        "evidence-issuance-idempotency",
        "dirextalk.mls-recovery.evidence-issuance-idempotency.v1\0",
    ),
    (
        "evidence-issuance-receipt",
        "dirextalk.mls-recovery.evidence-issuance-receipt.v1\0",
    ),
    (
        "completion-cache-signature",
        "dirextalk.mls-recovery.completion-cache-signature.v2\0",
    ),
    (
        "completion-cache",
        "dirextalk.mls-recovery.completion-cache.v2\0",
    ),
    (
        "completion-cache-idempotency",
        "dirextalk.mls-recovery.completion-cache-idempotency.v2\0",
    ),
    (
        "completion-cache-receipt",
        "dirextalk.mls-recovery.completion-cache-receipt.v2\0",
    ),
    (
        "completion-cache-receipt-signature",
        "dirextalk.mls-recovery.completion-cache-receipt-signature.v2\0",
    ),
];

const RULES: &[&str] = &[
    "digest",
    "signature",
    "ed25519-public-key",
    "uuid-v7",
    "identity-id",
    "channel-id",
    "https-authority-origin",
    "safe-sequence",
    "safe-parent",
    "positive-uint",
    "utc-millis",
    "catalog-exhaustive-count",
    "scope",
    "welcome-pending",
    "candidate-confirmed",
    "activated-fenced",
    "exact-catalog-completion-verifier-descriptor-v1",
    "exact-catalog-private-body-v2",
    "exact-catalog-verifier-binding-fields-1-through-22-v1",
    "exact-catalog-opening-v2",
    "exact-signed-catalog-head-v2",
    "exact-catalog-proof-v2",
    "exact-history-recovery-request-v4",
    "exact-history-recovery-manifest-v2",
    "exact-history-recovery-grant-v4",
    "exact-recipient-history-offer-v2",
    "exact-history-recovery-delivery-fact-v2",
    "exact-key-package-publish-receipt-v4",
    "exact-key-package-claim-receipt-v4",
    "exact-history-recovery-completion-presentation-v2",
    "mls-recovery-issuer-authorization-request-v1",
    "mls-recovery-issuer-authorization-v1",
    "mls-recovery-route-v1",
    "mls-recovery-controller-proof-v1",
    "mls-recovery-add-request-v7",
    "mls-recovery-add-receipt-v7",
    "signed-mls-recovery-add-receipt-v7",
    "exact-signed-mls-recovery-add-receipt-v7",
    "mls-recovery-confirmation-v2",
    "mls-recovery-confirmation-receipt-v2",
    "signed-mls-recovery-confirmation-receipt-v2",
    "exact-signed-mls-recovery-confirmation-receipt-v2",
    "mls-recovery-activation-command-v2",
    "mls-recovery-activation-receipt-v2",
    "signed-mls-recovery-activation-receipt-v2",
    "exact-signed-mls-recovery-activation-receipt-v2",
    "mls-recovery-activation-readback-v2",
    "exact-mls-recovery-activation-readback-v2",
    "mls-recovery-completion-child-certificate-v1",
    "exact-mls-recovery-completion-child-certificate-v1",
    "mls-recovery-redacted-completion-evidence-v1",
    "exact-mls-recovery-redacted-completion-evidence-v1",
    "mls-recovery-evidence-issuance-command-v1",
    "mls-recovery-evidence-issuance-receipt-v1",
    "exact-mls-recovery-evidence-issuance-receipt-v1",
    "mls-recovery-completion-cache-command-v2",
    "mls-recovery-completion-cache-receipt-v2",
    "signed-mls-recovery-completion-cache-receipt-v2",
];

// Tokens are exact field types in numeric-key order. Decimal tokens are literal uints;
// `bstr:N` is an inclusive 1..N byte string.
const MAP_LAYOUTS: &[(&str, &str)] = &[
    (
        "mls-recovery-issuer-authorization-request-v1",
        "1 scope identity-id uuid-v7 positive-uint catalog-exhaustive-count exact-catalog-private-body-v2 digest digest uuid-v7 uuid-v7 1 1 utc-millis utc-millis digest bstr:4096 digest signature",
    ),
    (
        "mls-recovery-route-v1",
        "1 https-authority-origin uuid-v7 uuid-v7 uuid-v7 positive-uint digest utc-millis utc-millis signature",
    ),
    (
        "mls-recovery-controller-proof-v1",
        "1 scope identity-id uuid-v7 uuid-v7 ed25519-public-key bstr:4096 digest positive-uint digest utc-millis utc-millis signature",
    ),
    (
        "mls-recovery-add-request-v7",
        "7 uuid-v7 scope identity-id identity-id uuid-v7 ed25519-public-key uuid-v7 exact-history-recovery-request-v4 digest exact-history-recovery-manifest-v2 digest exact-history-recovery-grant-v4 digest exact-recipient-history-offer-v2 digest exact-history-recovery-delivery-fact-v2 digest uuid-v7 positive-uint exact-signed-catalog-head-v2 digest catalog-exhaustive-count catalog-exhaustive-count exact-catalog-opening-v2 digest exact-catalog-proof-v2 digest exact-key-package-publish-receipt-v4 digest exact-key-package-claim-receipt-v4 digest safe-parent digest positive-uint digest safe-parent positive-uint digest bstr:1048576 digest bstr:1048576 digest mls-recovery-route-v1 digest mls-recovery-controller-proof-v1 digest utc-millis utc-millis digest signature",
    ),
    (
        "mls-recovery-add-receipt-v7",
        "7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest digest welcome-pending utc-millis",
    ),
    (
        "signed-mls-recovery-add-receipt-v7",
        "mls-recovery-add-receipt-v7 digest uuid-v7 ed25519-public-key signature",
    ),
    (
        "mls-recovery-confirmation-v2",
        "2 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest exact-signed-mls-recovery-add-receipt-v7 digest utc-millis digest signature",
    ),
    (
        "mls-recovery-confirmation-receipt-v2",
        "2 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest digest candidate-confirmed utc-millis",
    ),
    (
        "signed-mls-recovery-confirmation-receipt-v2",
        "mls-recovery-confirmation-receipt-v2 digest uuid-v7 ed25519-public-key signature",
    ),
    (
        "mls-recovery-activation-command-v2",
        "2 uuid-v7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest exact-signed-mls-recovery-confirmation-receipt-v2 digest mls-recovery-controller-proof-v1 digest utc-millis digest signature",
    ),
    (
        "mls-recovery-activation-receipt-v2",
        "2 uuid-v7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest digest digest digest activated-fenced utc-millis",
    ),
    (
        "signed-mls-recovery-activation-receipt-v2",
        "mls-recovery-activation-receipt-v2 digest uuid-v7 ed25519-public-key signature",
    ),
    (
        "mls-recovery-activation-readback-v2",
        "2 scope uuid-v7 uuid-v7 identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest activated-fenced exact-signed-mls-recovery-activation-receipt-v2 digest utc-millis signature",
    ),
    (
        "mls-recovery-completion-child-certificate-v1",
        "1 ed25519-public-key digest positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest digest 1 1 ed25519-public-key utc-millis utc-millis signature signature",
    ),
    (
        "mls-recovery-redacted-completion-evidence-v1",
        "1 digest digest positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest activated-fenced utc-millis utc-millis signature",
    ),
    (
        "mls-recovery-evidence-issuance-command-v1",
        "1 uuid-v7 uuid-v7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count exact-catalog-opening-v2 digest exact-catalog-completion-verifier-descriptor-v1 digest exact-signed-mls-recovery-activation-receipt-v2 digest exact-mls-recovery-activation-readback-v2 digest utc-millis utc-millis digest signature",
    ),
    (
        "mls-recovery-evidence-issuance-receipt-v1",
        "1 uuid-v7 digest mls-recovery-completion-child-certificate-v1 digest mls-recovery-redacted-completion-evidence-v1 digest digest digest digest digest digest utc-millis activated-fenced",
    ),
    (
        "mls-recovery-completion-cache-command-v2",
        "2 uuid-v7 scope uuid-v7 uuid-v7 identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest exact-catalog-opening-v2 digest exact-signed-mls-recovery-activation-receipt-v2 digest exact-mls-recovery-activation-readback-v2 digest exact-mls-recovery-evidence-issuance-receipt-v1 digest exact-history-recovery-completion-presentation-v2 digest utc-millis digest signature",
    ),
    (
        "mls-recovery-completion-cache-receipt-v2",
        "2 uuid-v7 scope uuid-v7 uuid-v7 uuid-v7 digest digest digest digest digest digest digest activated-fenced true utc-millis",
    ),
    (
        "signed-mls-recovery-completion-cache-receipt-v2",
        "mls-recovery-completion-cache-receipt-v2 digest uuid-v7 ed25519-public-key signature",
    ),
];

const MAP_MAXIMA: &[(&str, u64)] = &[
    ("mls-recovery-issuer-authorization-request-v1", 8_953),
    ("mls-recovery-route-v1", 2_304),
    ("mls-recovery-controller-proof-v1", 4_507),
    ("mls-recovery-add-request-v7", 4_489_149),
    ("mls-recovery-add-receipt-v7", 613),
    ("signed-mls-recovery-add-receipt-v7", 791),
    ("mls-recovery-confirmation-v2", 1_510),
    ("mls-recovery-confirmation-receipt-v2", 613),
    ("signed-mls-recovery-confirmation-receipt-v2", 791),
    ("mls-recovery-activation-command-v2", 6_023),
    ("mls-recovery-activation-receipt-v2", 725),
    ("signed-mls-recovery-activation-receipt-v2", 903),
    ("mls-recovery-activation-readback-v2", 1_556),
    ("mls-recovery-completion-child-certificate-v1", 389),
    ("mls-recovery-redacted-completion-evidence-v1", 250),
    ("mls-recovery-evidence-issuance-command-v1", 12_756),
    ("mls-recovery-evidence-issuance-receipt-v1", 975),
    ("mls-recovery-completion-cache-command-v2", 17_155),
    ("mls-recovery-completion-cache-receipt-v2", 482),
    ("signed-mls-recovery-completion-cache-receipt-v2", 660),
];

pub(crate) fn validate(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = fs::read_to_string(root.join(CDDL_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {CDDL_RELATIVE}: {error}")))?;
    let openapi = fs::read_to_string(root.join(OPENAPI_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {OPENAPI_RELATIVE}: {error}")))?;
    validate_sources(&cddl, &openapi)
}

fn validate_sources(cddl_source: &str, openapi_source: &str) -> Result<(), ProtocolToolError> {
    let cddl = cddl_cat::parse_cddl(cddl_source)
        .map_err(|error| ProtocolToolError::new(format!("parse MLS Sequencer V7 CDDL: {error}")))?;
    validate_cddl_contract(cddl_source, &cddl)?;

    let spec = oas3::from_yaml(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse MLS Sequencer V7 OpenAPI: {error}"))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V7 OpenAPI must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse MLS Sequencer V7 OpenAPI tree: {error}"))
    })?;
    validate_openapi_contract(&document)?;

    require_sha256(cddl_source, CDDL_SHA256, "MLS Sequencer V7 CDDL")?;
    require_sha256(openapi_source, OPENAPI_SHA256, "MLS Sequencer V7 OpenAPI")
}

fn validate_cddl_contract(cddl_source: &str, cddl: &Cddl) -> Result<(), ProtocolToolError> {
    let actual_rules = cddl
        .rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_rules = RULES.iter().copied().collect::<BTreeSet<_>>();
    if actual_rules != expected_rules || cddl.rules.len() != RULES.len() {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 CDDL rule set drift: expected {expected_rules:?}, found {actual_rules:?}"
        )));
    }

    validate_cddl_domains(cddl_source)?;
    for (rule, typename, size) in [
        ("digest", "bstr", 32),
        ("signature", "bstr", 64),
        ("ed25519-public-key", "bstr", 32),
        ("uuid-v7", "tstr", 36),
        ("identity-id", "tstr", 57),
        ("channel-id", "tstr", 57),
    ] {
        validate_fixed_size(cddl, rule, typename, size)?;
    }
    validate_size_range(cddl, "https-authority-origin", "tstr", 9, 2_048)?;
    for (rule, minimum, maximum) in [
        ("safe-sequence", 0, 9_007_199_254_740_991),
        ("safe-parent", 0, 9_007_199_254_740_990),
        ("positive-uint", 1, 9_007_199_254_740_991),
        ("utc-millis", 0, 9_007_199_254_740_991),
        ("catalog-exhaustive-count", 1, 1_023),
    ] {
        validate_uint_range(cddl, rule, minimum, maximum)?;
    }
    for (rule, value) in [
        ("welcome-pending", 1),
        ("candidate-confirmed", 2),
        ("activated-fenced", 3),
    ] {
        validate_literal(cddl, rule, value)?;
    }
    validate_scope(cddl)?;

    for (rule, maximum) in [
        ("exact-catalog-completion-verifier-descriptor-v1", 2_226),
        ("exact-catalog-private-body-v2", 4_360),
        (
            "exact-catalog-verifier-binding-fields-1-through-22-v1",
            2_613,
        ),
        ("exact-catalog-opening-v2", 7_264),
        ("exact-signed-catalog-head-v2", 466),
        ("exact-catalog-proof-v2", 402),
        ("exact-history-recovery-request-v4", 37_114),
        ("exact-history-recovery-manifest-v2", 35_477),
        ("exact-history-recovery-grant-v4", 1_050_699),
        ("exact-recipient-history-offer-v2", 1_049_059),
        ("exact-history-recovery-delivery-fact-v2", 366),
        ("exact-key-package-publish-receipt-v4", 67_531),
        ("exact-key-package-claim-receipt-v4", 135_564),
        ("exact-history-recovery-completion-presentation-v2", 5_660),
        ("exact-signed-mls-recovery-add-receipt-v7", 791),
        ("exact-signed-mls-recovery-confirmation-receipt-v2", 791),
        ("exact-signed-mls-recovery-activation-receipt-v2", 903),
        ("exact-mls-recovery-activation-readback-v2", 1_556),
        ("exact-mls-recovery-completion-child-certificate-v1", 389),
        ("exact-mls-recovery-redacted-completion-evidence-v1", 250),
        ("exact-mls-recovery-evidence-issuance-receipt-v1", 975),
    ] {
        validate_bstr_ceiling(cddl, rule, maximum)?;
    }
    validate_alias(
        cddl,
        "mls-recovery-issuer-authorization-v1",
        "exact-catalog-verifier-binding-fields-1-through-22-v1",
    )?;

    let actual_maps = cddl
        .rules
        .iter()
        .filter_map(|rule| closed_map_fields(rule).ok().map(|_| rule.name.as_str()))
        .collect::<BTreeSet<_>>();
    let expected_maps = MAP_LAYOUTS
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    if actual_maps != expected_maps || actual_maps.len() != 20 {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 closed map inventory drift: expected exactly 20 {expected_maps:?}, found {actual_maps:?}"
        )));
    }
    for (rule, expected) in MAP_LAYOUTS {
        validate_map_layout(cddl, rule, expected)?;
    }
    for (rule, expected) in MAP_MAXIMA {
        let actual = max_encoded_rule(cddl, rule, &mut Vec::new())?;
        if actual != *expected {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 CDDL ceiling drift: {rule} computed {actual}, expected {expected}"
            )));
        }
    }
    Ok(())
}

fn validate_cddl_domains(source: &str) -> Result<(), ProtocolToolError> {
    let mut actual = BTreeMap::new();
    for line in source.lines() {
        let Some(declaration) = line.strip_prefix("; ") else {
            continue;
        };
        let Some((name, encoded)) = declaration.split_once(" = `") else {
            continue;
        };
        let Some(name) = name.strip_suffix("-domain") else {
            continue;
        };
        let Some(encoded) = encoded.strip_suffix("`.") else {
            continue;
        };
        let value = encoded.replace("\\0", "\0");
        if actual.insert(name, value).is_some() {
            return Err(ProtocolToolError::new(format!(
                "MLS Sequencer V7 CDDL duplicate domain constant: {name}"
            )));
        }
    }
    let expected = DOMAINS
        .iter()
        .map(|(name, value)| (*name, (*value).to_owned()))
        .collect::<BTreeMap<_, _>>();
    if actual != expected || actual.len() != 40 {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 CDDL domain count/value drift: expected exactly 40 constants, found {}",
            actual.len()
        )));
    }
    Ok(())
}

fn validate_fixed_size(
    cddl: &Cddl,
    rule_name: &str,
    typename: &str,
    size: u64,
) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(type_drift(rule_name));
    };
    let valid = matches!(
        items.as_slice(),
        [Type1::Control(control)]
            if control.op == "size"
                && matches!(&control.target, Type2::Typename(name) if name.name == typename && name.generic_args.is_empty())
                && matches!(&control.arg, Type2::Value(CddlValue::Uint(actual)) if *actual == size)
    );
    if !valid {
        return Err(type_drift(rule_name));
    }
    Ok(())
}

fn validate_size_range(
    cddl: &Cddl,
    rule_name: &str,
    typename: &str,
    minimum: u64,
    maximum: u64,
) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(type_drift(rule_name));
    };
    let valid = matches!(
        items.as_slice(),
        [Type1::Control(control)]
            if control.op == "size"
                && matches!(&control.target, Type2::Typename(name) if name.name == typename && name.generic_args.is_empty())
                && matches!(
                    &control.arg,
                    Type2::Parethesized(Type(range))
                        if matches!(
                            range.as_slice(),
                            [Type1::Range(range)]
                                if range.inclusive
                                    && matches!(&range.start, Type2::Value(CddlValue::Uint(value)) if *value == minimum)
                                    && matches!(&range.end, Type2::Value(CddlValue::Uint(value)) if *value == maximum)
                        )
                )
    );
    if !valid {
        return Err(type_drift(rule_name));
    }
    Ok(())
}

fn validate_uint_range(
    cddl: &Cddl,
    rule_name: &str,
    minimum: u64,
    maximum: u64,
) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(type_drift(rule_name));
    };
    let valid = matches!(
        items.as_slice(),
        [Type1::Range(range)]
            if range.inclusive
                && matches!(&range.start, Type2::Value(CddlValue::Uint(value)) if *value == minimum)
                && matches!(&range.end, Type2::Value(CddlValue::Uint(value)) if *value == maximum)
    );
    if !valid {
        return Err(type_drift(rule_name));
    }
    Ok(())
}

fn validate_literal(cddl: &Cddl, rule_name: &str, expected: u64) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(type_drift(rule_name));
    };
    if !matches!(items.as_slice(), [Type1::Simple(Type2::Value(CddlValue::Uint(value)))] if *value == expected)
    {
        return Err(type_drift(rule_name));
    }
    Ok(())
}

fn validate_scope(cddl: &Cddl) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, "scope")?;
    let RuleVal::AssignType(Type(choices)) = &rule.val else {
        return Err(type_drift("scope"));
    };
    if choices.len() != 2 {
        return Err(type_drift("scope"));
    }
    for (choice, kind, id_type) in [(&choices[0], 1, "uuid-v7"), (&choices[1], 2, "channel-id")] {
        let Type1::Simple(Type2::Map(group)) = choice else {
            return Err(type_drift("scope"));
        };
        let fields = map_group_fields(group, "scope")?;
        if fields.len() != 2
            || fields[0].0 != 1
            || fields[1].0 != 2
            || field_type_token(fields[0].1).as_deref() != Some(&kind.to_string())
            || field_type_token(fields[1].1).as_deref() != Some(id_type)
        {
            return Err(type_drift("scope"));
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
    let RuleVal::AssignType(actual) = &rule.val else {
        return Err(type_drift(rule_name));
    };
    if bounded_size(actual, "bstr") != Some((1, expected_maximum)) {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 CDDL ceiling drift: {rule_name} must be bstr .size (1..{expected_maximum})"
        )));
    }
    Ok(())
}

fn validate_alias(cddl: &Cddl, rule_name: &str, target: &str) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(type_drift(rule_name));
    };
    if !matches!(
        items.as_slice(),
        [Type1::Simple(Type2::Typename(name))]
            if name.name == target && name.generic_args.is_empty()
    ) {
        return Err(type_drift(rule_name));
    }
    Ok(())
}

fn validate_map_layout(
    cddl: &Cddl,
    rule_name: &str,
    expected_layout: &str,
) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let fields = closed_map_fields(rule)?;
    let expected = expected_layout.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != expected.len() {
        return Err(map_drift(rule_name));
    }
    for (index, ((key, field_type), expected_type)) in fields.iter().zip(expected).enumerate() {
        let expected_key = u64::try_from(index + 1).expect("V7 maps are small");
        if *key != expected_key || field_type_token(field_type).as_deref() != Some(expected_type) {
            return Err(map_drift(rule_name));
        }
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
            "MLS Sequencer V7 CDDL rule {name} must occur exactly once, found {}",
            matches.len()
        )));
    };
    if !rule.generic_parms.is_empty() {
        return Err(type_drift(name));
    }
    Ok(rule)
}

fn closed_map_fields(rule: &Rule) -> Result<Vec<(u64, &Type)>, ProtocolToolError> {
    let RuleVal::AssignType(Type(items)) = &rule.val else {
        return Err(map_drift(&rule.name));
    };
    let [Type1::Simple(Type2::Map(group))] = items.as_slice() else {
        return Err(map_drift(&rule.name));
    };
    map_group_fields(group, &rule.name)
}

fn map_group_fields<'a>(
    group: &'a cddl_cat::ast::Group,
    label: &str,
) -> Result<Vec<(u64, &'a Type)>, ProtocolToolError> {
    let [choice] = group.0.as_slice() else {
        return Err(map_drift(label));
    };
    let mut keys = BTreeSet::new();
    let mut fields = Vec::with_capacity(choice.0.len());
    for entry in &choice.0 {
        if entry.occur.is_some() {
            return Err(map_drift(label));
        }
        let GrpEntVal::Member(member) = &entry.val else {
            return Err(map_drift(label));
        };
        let Some(key) = &member.key else {
            return Err(map_drift(label));
        };
        let MemberKeyVal::Value(CddlValue::Uint(key)) = &key.val else {
            return Err(map_drift(label));
        };
        if !keys.insert(*key) {
            return Err(map_drift(label));
        }
        fields.push((*key, &member.value));
    }
    Ok(fields)
}

fn field_type_token(field_type: &Type) -> Option<String> {
    match field_type.0.as_slice() {
        [Type1::Simple(Type2::Value(CddlValue::Uint(value)))] => Some(value.to_string()),
        [Type1::Simple(Type2::Typename(name))] if name.generic_args.is_empty() => {
            Some(name.name.clone())
        }
        _ => bounded_size(field_type, "bstr").map(|(_, maximum)| format!("bstr:{maximum}")),
    }
}

fn bounded_size(field_type: &Type, typename: &str) -> Option<(u64, u64)> {
    let [Type1::Control(control)] = field_type.0.as_slice() else {
        return None;
    };
    if control.op != "size"
        || !matches!(&control.target, Type2::Typename(name) if name.name == typename && name.generic_args.is_empty())
    {
        return None;
    }
    match &control.arg {
        Type2::Value(CddlValue::Uint(value)) => Some((*value, *value)),
        Type2::Parethesized(Type(items)) => match items.as_slice() {
            [Type1::Range(range)] if range.inclusive => match (&range.start, &range.end) {
                (
                    Type2::Value(CddlValue::Uint(minimum)),
                    Type2::Value(CddlValue::Uint(maximum)),
                ) => Some((*minimum, *maximum)),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn max_encoded_rule(
    cddl: &Cddl,
    rule_name: &str,
    stack: &mut Vec<String>,
) -> Result<u64, ProtocolToolError> {
    if rule_name == "true" {
        return Ok(1);
    }
    if stack.iter().any(|entry| entry == rule_name) {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 recursive CDDL rule is not allowed: {rule_name}"
        )));
    }
    stack.push(rule_name.to_owned());
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(field_type) = &rule.val else {
        return Err(type_drift(rule_name));
    };
    let result = max_encoded_type(cddl, field_type, stack);
    stack.pop();
    result
}

fn max_encoded_type(
    cddl: &Cddl,
    field_type: &Type,
    stack: &mut Vec<String>,
) -> Result<u64, ProtocolToolError> {
    field_type
        .0
        .iter()
        .map(|choice| max_encoded_type1(cddl, choice, stack))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or_else(|| ProtocolToolError::new("MLS Sequencer V7 empty CDDL type choice"))
}

fn max_encoded_type1(
    cddl: &Cddl,
    field_type: &Type1,
    stack: &mut Vec<String>,
) -> Result<u64, ProtocolToolError> {
    match field_type {
        Type1::Simple(value) => max_encoded_type2(cddl, value, stack),
        Type1::Range(range) if range.inclusive => match &range.end {
            Type2::Value(CddlValue::Uint(value)) => Ok(cbor_header_len(*value)),
            _ => Err(ProtocolToolError::new(
                "MLS Sequencer V7 unsupported CDDL range maximum",
            )),
        },
        Type1::Control(control) if control.op == "size" => {
            let Type2::Typename(name) = &control.target else {
                return Err(type_drift("controlled size"));
            };
            let maximum = size_control_maximum(&control.arg)?;
            match name.name.as_str() {
                "bstr" | "tstr" => Ok(cbor_header_len(maximum) + maximum),
                _ => Err(type_drift("controlled size")),
            }
        }
        _ => Err(ProtocolToolError::new(
            "MLS Sequencer V7 unsupported CDDL construct in ceiling calculation",
        )),
    }
}

fn max_encoded_type2(
    cddl: &Cddl,
    field_type: &Type2,
    stack: &mut Vec<String>,
) -> Result<u64, ProtocolToolError> {
    match field_type {
        Type2::Value(CddlValue::Uint(value)) => Ok(cbor_header_len(*value)),
        Type2::Typename(name) if name.generic_args.is_empty() => {
            max_encoded_rule(cddl, &name.name, stack)
        }
        Type2::Parethesized(field_type) => max_encoded_type(cddl, field_type, stack),
        Type2::Map(group) => {
            let fields = map_group_fields(group, "ceiling map")?;
            let mut total = cbor_header_len(u64::try_from(fields.len()).expect("small map"));
            for (key, value) in fields {
                total = total
                    .checked_add(cbor_header_len(key))
                    .and_then(|sum| {
                        max_encoded_type(cddl, value, stack)
                            .ok()
                            .and_then(|maximum| sum.checked_add(maximum))
                    })
                    .ok_or_else(|| {
                        ProtocolToolError::new("MLS Sequencer V7 CDDL ceiling overflow")
                    })?;
            }
            Ok(total)
        }
        _ => Err(ProtocolToolError::new(
            "MLS Sequencer V7 unsupported CDDL type in ceiling calculation",
        )),
    }
}

fn size_control_maximum(arg: &Type2) -> Result<u64, ProtocolToolError> {
    match arg {
        Type2::Value(CddlValue::Uint(value)) => Ok(*value),
        Type2::Parethesized(Type(items)) => match items.as_slice() {
            [Type1::Range(range)] if range.inclusive => match &range.end {
                Type2::Value(CddlValue::Uint(value)) => Ok(*value),
                _ => Err(type_drift("size range")),
            },
            _ => Err(type_drift("size range")),
        },
        _ => Err(type_drift("size range")),
    }
}

const fn cbor_header_len(value: u64) -> u64 {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

fn type_drift(rule_name: &str) -> ProtocolToolError {
    ProtocolToolError::new(format!("MLS Sequencer V7 CDDL type drift: {rule_name}"))
}

fn map_drift(rule_name: &str) -> ProtocolToolError {
    ProtocolToolError::new(format!(
        "MLS Sequencer V7 CDDL required field/type/key or closed map layout drift: {rule_name}"
    ))
}

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
struct ResponseSpec<'a> {
    name: &'a str,
    ceiling: u64,
    media_type: &'a str,
    rule_marker: &'a str,
    rule: &'a str,
    schema: &'a str,
}

const OPENAPI_SCHEMA_NAMES: &[&str] = &[
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

const BINARY_SCHEMA_SPECS: &[(&str, u64, &str, &str)] = &[
    (
        "IssuerAuthorizationRequestCbor",
        8_953,
        "x-dirextalk-cddl-rule",
        "mls-recovery-issuer-authorization-request-v1",
    ),
    (
        "RecoveryAddRequestCbor",
        4_489_149,
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

const OPENAPI_RESPONSE_NAMES: &[&str] = &[
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

const SUCCESS_RESPONSE_SPECS: &[ResponseSpec<'static>] = &[
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

#[allow(
    clippy::too_many_lines,
    reason = "one structural gate keeps all frozen MLS Sequencer V7 OpenAPI relationships adjacent"
)]
fn validate_openapi_contract(document: &Value) -> Result<(), ProtocolToolError> {
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
        ("recovery-add-v7", 4_489_149),
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
                ceiling: 4_489_149,
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

    validate_openapi_schemas(document)?;
    validate_openapi_responses(document)?;
    validate_openapi_semantics(document)
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

fn validate_openapi_schemas(document: &Value) -> Result<(), ProtocolToolError> {
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

fn validate_openapi_responses(document: &Value) -> Result<(), ProtocolToolError> {
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

#[allow(
    clippy::too_many_lines,
    reason = "security and persistence relationships are asserted together as one frozen contract"
)]
fn validate_openapi_semantics(document: &Value) -> Result<(), ProtocolToolError> {
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

#[allow(
    clippy::too_many_lines,
    reason = "snapshot, revocation, privacy, and routing fences form one contract"
)]
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

fn require_json(
    document: &Value,
    pointer: &str,
    expected: &Value,
    label: &str,
) -> Result<(), ProtocolToolError> {
    if document.pointer(pointer) != Some(expected) {
        return Err(ProtocolToolError::new(format!(
            "MLS Sequencer V7 {label} drift at {pointer}"
        )));
    }
    Ok(())
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
            "MLS Sequencer V7 OpenAPI {label} key set drift: expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
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
        include_str!("../../../protocol/cddl/mls-sequencer/v7/mls-sequencer-v7.cddl");
    const OPENAPI: &str = include_str!("../../../protocol/openapi/mls-sequencer/v7/openapi.yaml");

    fn rejected(cddl: &str, openapi: &str, expected: &str) {
        let error = validate_sources(cddl, openapi).expect_err("mutation must be rejected");
        assert!(
            error.to_string().contains(expected),
            "expected diagnostic containing {expected:?}, got {error}"
        );
    }

    fn replace_once(source: &str, from: &str, to: &str) -> String {
        let mutated = source.replacen(from, to, 1);
        assert_ne!(mutated, source, "mutation fixture did not match {from:?}");
        mutated
    }

    #[test]
    fn frozen_mls_sequencer_v7_contract_passes() {
        validate_sources(CDDL, OPENAPI).expect("frozen MLS Sequencer V7 must validate");
    }

    #[test]
    fn rejects_add_ceiling_mutation() {
        let mutated = replace_once(
            OPENAPI,
            "  recovery-add-v7: 4489149",
            "  recovery-add-v7: 4489150",
        );
        rejected(CDDL, &mutated, "body ceiling drift");
    }

    #[test]
    fn rejects_required_field_type_and_key_mutations() {
        let missing = replace_once(CDDL, "  51: signature\n", "");
        rejected(&missing, OPENAPI, "required field/type/key");

        let changed_type = replace_once(CDDL, "  51: signature", "  51: digest");
        rejected(&changed_type, OPENAPI, "required field/type/key");

        let changed_key = replace_once(CDDL, "  51: signature", "  52: signature");
        rejected(&changed_key, OPENAPI, "required field/type/key");
    }

    #[test]
    fn rejects_domain_count_and_value_mutations() {
        let missing = replace_once(
            OPENAPI,
            "  raw-mls-welcome: \"dirextalk.mls-recovery.raw-mls-welcome.v7\\0\"\n",
            "",
        );
        rejected(CDDL, &missing, "domains key set drift");

        let changed = replace_once(
            OPENAPI,
            "dirextalk.mls-recovery.raw-mls-commit.v7\\0",
            "dirextalk.mls-recovery.raw-mls-commit.v8\\0",
        );
        rejected(CDDL, &changed, "domain value drift");

        let cddl_changed = replace_once(
            CDDL,
            "dirextalk.mls-recovery.raw-mls-welcome.v7\\0",
            "dirextalk.mls-recovery.raw-mls-welcome.v8\\0",
        );
        rejected(&cddl_changed, OPENAPI, "CDDL domain count/value drift");
    }

    #[test]
    fn rejects_closed_map_count_and_layout_mutations() {
        let wrapper = "signed-mls-recovery-completion-cache-receipt-v2 = {\n  1: mls-recovery-completion-cache-receipt-v2,\n  2: digest, 3: uuid-v7, 4: ed25519-public-key,\n  5: signature                    ; authority signs exact fields 1..4\n}";
        let missing_map = replace_once(
            CDDL,
            wrapper,
            "signed-mls-recovery-completion-cache-receipt-v2 = digest",
        );
        rejected(&missing_map, OPENAPI, "closed map inventory drift");

        let changed_layout = replace_once(
            CDDL,
            "  2: digest, 3: uuid-v7, 4: ed25519-public-key,\n  5: signature                    ; authority signs exact fields 1..4\n}",
            "  2: digest, 3: uuid-v7, 5: ed25519-public-key,\n  4: signature                    ; invalid field ordering\n}",
        );
        rejected(&changed_layout, OPENAPI, "required field/type/key");
    }

    #[test]
    fn rejects_raw_commit_and_welcome_type_mutations() {
        let commit = replace_once(CDDL, "  40: bstr .size (1..1048576),", "  40: digest,");
        rejected(&commit, OPENAPI, "required field/type/key");

        let welcome = replace_once(CDDL, "  42: bstr .size (1..1048576),", "  42: digest,");
        rejected(&welcome, OPENAPI, "required field/type/key");
    }

    #[test]
    fn rejects_imported_history_context_rehash_mutation() {
        let mutated = replace_once(
            OPENAPI,
            "  mls-domain-alias-second-hash-or-re-encoding: forbidden",
            "  mls-domain-alias-second-hash-or-re-encoding: allowed",
        );
        rejected(CDDL, &mutated, "imported History context binding drift");
    }

    #[test]
    fn rejects_openapi_path_operation_and_schema_maximum_mutations() {
        let path = replace_once(
            OPENAPI,
            "  /v2/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}:\n",
            "  /v3/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}:\n",
        );
        rejected(CDDL, &path, "paths key set drift");

        let operation = replace_once(
            OPENAPI,
            "operationId: submitMlsRecoveryCommitV7",
            "operationId: submitMlsRecoveryCommitV8",
        );
        rejected(CDDL, &operation, "operationId drift");

        let schema = replace_once(
            OPENAPI,
            "      maxLength: 4489149",
            "      maxLength: 4489150",
        );
        rejected(CDDL, &schema, "schema maximum/media rule drift");
    }

    #[test]
    fn rejects_openapi_media_relationship_mutation() {
        let mutated = replace_once(
            OPENAPI,
            "application/vnd.dirextalk.mls-recovery-commit.v7+cbor:",
            "application/vnd.dirextalk.mls-recovery-commit.v8+cbor:",
        );
        rejected(CDDL, &mutated, "key set drift");
    }

    #[test]
    fn rejects_snapshot_cas_and_revocation_binding_mutations() {
        let snapshot = replace_once(
            OPENAPI,
            "activation-receipt-and-readback: exact-private-issuance-time-snapshots",
            "activation-receipt-and-readback: current-readback",
        );
        rejected(CDDL, &snapshot, "cache operation snapshot binding drift");

        let revocation = replace_once(
            OPENAPI,
            "    - explicit-revocation-generations",
            "    - descriptor-generation-only",
        );
        rejected(
            CDDL,
            &revocation,
            "completion cache snapshot/CAS/revocation binding drift",
        );
    }
}
