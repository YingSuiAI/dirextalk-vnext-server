use std::collections::{BTreeMap, BTreeSet};

use cddl_cat::ast::{
    Cddl, GrpEntVal, MemberKeyVal, Rule, RuleVal, Type, Type1, Type2, Value as CddlValue,
};

use crate::ProtocolToolError;

use super::{DOMAINS, MAP_LAYOUTS, MAP_MAXIMA, RULES};

pub(super) fn validate_contract(cddl_source: &str, cddl: &Cddl) -> Result<(), ProtocolToolError> {
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
        ("exact-history-recovery-grant-v5", 1_050_733),
        ("exact-recipient-history-offer-v3", 1_049_093),
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
