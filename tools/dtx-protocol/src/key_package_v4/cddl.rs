use std::collections::BTreeSet;

use cddl_cat::ast::{
    Cddl, GrpEntVal, MemberKeyVal, Rule, RuleVal, Type, Type1, Type2, Value as CddlValue,
};

use crate::ProtocolToolError;

use super::ExpectedType;

#[allow(clippy::too_many_lines)]
pub(super) fn validate_contract(cddl: &Cddl) -> Result<(), ProtocolToolError> {
    let expected_rules = [
        "digest",
        "signature",
        "ed25519-public-key",
        "uuid-v7",
        "identity-id",
        "positive-uint",
        "utc-millis",
        "catalog-exhaustive-count",
        "exact-signed-catalog-head-v2",
        "exact-catalog-public-leaf-v2",
        "exact-catalog-proof-v2",
        "key-package-publish-binding-v4",
        "key-package-publish-v4",
        "exact-key-package-publish-v4",
        "key-package-publish-receipt-v4",
        "exact-key-package-publish-receipt-v4",
        "key-package-claim-v4",
        "exact-key-package-claim-v4",
        "key-package-claim-receipt-v4",
        "exact-key-package-claim-receipt-v4",
    ];
    let actual_rules = cddl
        .rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_rules = expected_rules.into_iter().collect::<BTreeSet<_>>();
    if actual_rules != expected_rules || cddl.rules.len() != expected_rules.len() {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 CDDL rule set drift: expected {expected_rules:?}, found {actual_rules:?}"
        )));
    }

    for (rule, typename, size) in [
        ("digest", "bstr", 32),
        ("signature", "bstr", 64),
        ("ed25519-public-key", "bstr", 32),
        ("uuid-v7", "tstr", 36),
        ("identity-id", "tstr", 57),
    ] {
        validate_type_rule(cddl, rule, ExpectedType::FixedSize(typename, size))?;
    }
    for (rule, minimum, maximum) in [
        ("positive-uint", 1, 9_007_199_254_740_991),
        ("utc-millis", 0, 9_007_199_254_740_991),
        ("catalog-exhaustive-count", 1, 1_023),
    ] {
        validate_uint_range(cddl, rule, minimum, maximum)?;
    }
    for (rule, maximum) in [
        ("exact-signed-catalog-head-v2", 466),
        ("exact-catalog-public-leaf-v2", 220),
        ("exact-catalog-proof-v2", 402),
        ("exact-key-package-publish-v4", 67_294),
        ("exact-key-package-publish-receipt-v4", 67_531),
        ("exact-key-package-claim-v4", 527),
        ("exact-key-package-claim-receipt-v4", 135_564),
    ] {
        validate_bstr_ceiling(cddl, rule, maximum)?;
    }

    validate_exact_map(
        cddl,
        "key-package-publish-binding-v4",
        &[
            ExpectedType::Literal(4),
            ExpectedType::Name("identity-id"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("exact-signed-catalog-head-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("catalog-exhaustive-count"),
            ExpectedType::Name("catalog-exhaustive-count"),
            ExpectedType::Name("exact-catalog-public-leaf-v2"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("exact-catalog-proof-v2"),
            ExpectedType::Name("ed25519-public-key"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("ed25519-public-key"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("utc-millis"),
            ExpectedType::Name("utc-millis"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
        ],
    )?;
    validate_exact_map(
        cddl,
        "key-package-publish-v4",
        &[
            ExpectedType::Name("key-package-publish-binding-v4"),
            ExpectedType::BoundedBstr(65_536),
            ExpectedType::Name("signature"),
        ],
    )?;
    validate_exact_map(
        cddl,
        "key-package-publish-receipt-v4",
        &[
            ExpectedType::Literal(4),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("exact-key-package-publish-v4"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("utc-millis"),
        ],
    )?;
    validate_exact_map(
        cddl,
        "key-package-claim-v4",
        &[
            ExpectedType::Literal(4),
            ExpectedType::Name("identity-id"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("catalog-exhaustive-count"),
            ExpectedType::Name("catalog-exhaustive-count"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("ed25519-public-key"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("positive-uint"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("digest"),
        ],
    )?;
    validate_exact_map(
        cddl,
        "key-package-claim-receipt-v4",
        &[
            ExpectedType::Literal(4),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("uuid-v7"),
            ExpectedType::Name("exact-key-package-publish-v4"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("exact-key-package-publish-receipt-v4"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("exact-key-package-claim-v4"),
            ExpectedType::Name("digest"),
            ExpectedType::Name("utc-millis"),
        ],
    )?;
    Ok(())
}
fn validate_type_rule(
    cddl: &Cddl,
    rule_name: &str,
    expected: ExpectedType<'_>,
) -> Result<(), ProtocolToolError> {
    let rule = unique_rule(cddl, rule_name)?;
    let RuleVal::AssignType(actual) = &rule.val else {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 CDDL type rule drift: {rule_name}"
        )));
    };
    if !type_matches(actual, expected) {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 CDDL type rule drift: {rule_name}"
        )));
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
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 CDDL integer range drift: {rule_name}"
        )));
    };
    let valid = matches!(
        items.as_slice(),
        [Type1::Range(range)]
            if range.inclusive
                && matches!(&range.start, Type2::Value(CddlValue::Uint(value)) if *value == minimum)
                && matches!(&range.end, Type2::Value(CddlValue::Uint(value)) if *value == maximum)
    );
    if !valid {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 CDDL integer range drift: {rule_name}"
        )));
    }
    Ok(())
}

fn validate_bstr_ceiling(
    cddl: &Cddl,
    rule_name: &str,
    expected_maximum: u64,
) -> Result<(), ProtocolToolError> {
    validate_type_rule(cddl, rule_name, ExpectedType::BoundedBstr(expected_maximum)).map_err(
        |_| {
            ProtocolToolError::new(format!(
                "Key Package V4 CDDL ceiling drift: {rule_name} must be bstr .size (1..{expected_maximum})"
            ))
        },
    )
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
            "Key Package V4 CDDL required field/type drift: {rule_name}"
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
            "Key Package V4 CDDL rule {name} must occur exactly once, found {}",
            matches.len()
        )));
    };
    if !rule.generic_parms.is_empty() {
        return Err(ProtocolToolError::new(format!(
            "Key Package V4 CDDL rule {name} must not be generic"
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
        ([Type1::Control(control)], ExpectedType::FixedSize(typename, expected)) => {
            control.op == "size"
                && matches!(
                    &control.target,
                    Type2::Typename(name)
                        if name.name == typename && name.generic_args.is_empty()
                )
                && matches!(
                    &control.arg,
                    Type2::Value(CddlValue::Uint(actual)) if *actual == expected
                )
        }
        ([Type1::Control(control)], ExpectedType::BoundedBstr(expected)) => {
            control.op == "size"
                && matches!(
                    &control.target,
                    Type2::Typename(name)
                        if name.name == "bstr" && name.generic_args.is_empty()
                )
                && matches!(
                    &control.arg,
                    Type2::Parethesized(Type(items))
                        if matches!(
                            items.as_slice(),
                            [Type1::Range(range)]
                                if range.inclusive
                                    && matches!(&range.start, Type2::Value(CddlValue::Uint(1)))
                                    && matches!(&range.end, Type2::Value(CddlValue::Uint(value)) if *value == expected)
                        )
                )
        }
        _ => false,
    }
}
