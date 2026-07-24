use super::{
    BTreeMap, CDDL_PATH, CORE_RULE_FIELD_COUNTS, EXACT_HANDOFF_MAPS, HPKE_INFO, Path,
    ProtocolToolError, REQUIRED_BOUNDS, REQUIRED_CRYPTO_DOMAIN_DECLARATIONS,
    REQUIRED_CRYPTO_TRANSCRIPTS, REQUIRED_HANDOFF_RULES, REQUIRED_TIME_AND_PROOF_RULES, fs,
    numbered_map_keys, read_openapi, rule_body, validate_catalog_vector, validate_openapi_source,
};
#[cfg(test)]
use std::collections::BTreeSet;
pub(crate) fn validate(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read_cddl(root)?;
    validate_parse(&cddl)?;
    validate_rule_names(&cddl)?;
    validate_field_counts(&cddl)?;
    validate_bounds(&cddl)?;
    validate_crypto_transcripts(&cddl)?;
    validate_time_and_proof_rules(&cddl)?;
    validate_handoff_rules(&cddl)?;
    let openapi = read_openapi(root)?;
    validate_openapi_source(&openapi)?;
    validate_catalog_vector(root, &cddl, &openapi)
}

pub(crate) fn read_cddl(root: &Path) -> Result<String, ProtocolToolError> {
    let path = root.join(CDDL_PATH);
    fs::read_to_string(&path).map_err(|error| {
        ProtocolToolError::new(format!(
            "read Recovery Scope Catalog V2 CDDL {}: {error}",
            path.display()
        ))
    })
}

pub(crate) fn validate_parse(cddl: &str) -> Result<(), ProtocolToolError> {
    cddl_cat::parse_cddl(cddl).map(|_| ()).map_err(|error| {
        ProtocolToolError::new(format!("parse Recovery Scope Catalog V2 CDDL: {error}"))
    })
}

pub(crate) fn validate_rule_names(cddl: &str) -> Result<(), ProtocolToolError> {
    for (rule, _) in CORE_RULE_FIELD_COUNTS {
        let declaration = format!("{rule} =");
        let count = cddl
            .lines()
            .filter(|line| line.trim_start().starts_with(&declaration))
            .count();
        if count != 1 {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 must declare {rule} exactly once"
            )));
        }
    }

    Ok(())
}

pub(crate) fn validate_field_counts(cddl: &str) -> Result<(), ProtocolToolError> {
    for (rule, expected_count) in CORE_RULE_FIELD_COUNTS {
        let body = rule_body(cddl, rule)?;
        let actual_keys = numbered_map_keys(body);
        let expected_keys = (1..=*expected_count).collect::<Vec<_>>();
        if actual_keys != expected_keys {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 rule {rule} keys {actual_keys:?} do not match frozen keys {expected_keys:?}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_bounds(cddl: &str) -> Result<(), ProtocolToolError> {
    for (label, required) in REQUIRED_BOUNDS {
        if !cddl.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 {label} bound is not frozen"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_crypto_transcripts(cddl: &str) -> Result<(), ProtocolToolError> {
    let actual_domains = parse_crypto_domain_declarations(cddl)?;
    let expected_domains = REQUIRED_CRYPTO_DOMAIN_DECLARATIONS
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect::<BTreeMap<_, _>>();
    if actual_domains != expected_domains {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 crypto domain declaration set does not match the exact 30-domain contract",
        ));
    }
    for transcript in REQUIRED_CRYPTO_TRANSCRIPTS {
        if !cddl.contains(transcript) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 must freeze transcript {transcript}"
            )));
        }
    }
    if !cddl.contains("Strict Ed25519") || !cddl.contains("deterministic canonical CBOR") {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 must require strict Ed25519 and deterministic canonical CBOR",
        ));
    }
    Ok(())
}

pub(crate) fn parse_crypto_domain_declarations(
    cddl: &str,
) -> Result<BTreeMap<String, String>, ProtocolToolError> {
    let mut declarations = BTreeMap::new();
    for line in cddl.lines() {
        let line = line.trim();
        let declaration = line.strip_prefix(';').map_or(line, str::trim);
        let Some((name, value)) = declaration.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !name.ends_with("-domain") {
            continue;
        }
        let value = value
            .trim()
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix("`."))
            .ok_or_else(|| {
                ProtocolToolError::new(format!(
                    "Recovery Scope Catalog V2 crypto domain declaration {name} is malformed"
                ))
            })?;
        if declarations
            .insert(name.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 crypto domain declaration {name} is duplicated"
            )));
        }
    }
    Ok(declarations)
}

pub(crate) fn validate_time_and_proof_rules(cddl: &str) -> Result<(), ProtocolToolError> {
    for rule in REQUIRED_TIME_AND_PROOF_RULES {
        if !cddl.contains(rule) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 must freeze semantic rule {rule}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_handoff_rules(cddl: &str) -> Result<(), ProtocolToolError> {
    for required in REQUIRED_HANDOFF_RULES {
        if !cddl.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 handoff rule drifted: {required}"
            )));
        }
    }
    let hpke_info_cddl = HPKE_INFO.replace('\0', "\\0");
    if !cddl.contains(&format!("hpke-info = `{hpke_info_cddl}`.")) {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 HPKE info literal drifted",
        ));
    }
    for (rule, expected) in EXACT_HANDOFF_MAPS {
        let actual = compact_cddl(rule_body(cddl, rule)?);
        if actual != *expected {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 handoff rule {rule} field contract drifted"
            )));
        }
    }
    let compact_source = compact_cddl(cddl);
    for exact_union in [
        "recovery-scope-catalog-independent-authority-v2=recovery-scope-catalog-active-authority-v2/recovery-scope-catalog-root-authority-v2/recovery-scope-catalog-recovery-authority-v2",
        "recovery-scope-catalog-status-v2=recovery-scope-catalog-status-pending-v2/recovery-scope-catalog-status-ready-v2/recovery-scope-catalog-status-expired-v2/recovery-scope-catalog-status-cancelled-v2/recovery-scope-catalog-status-invalidated-v2",
    ] {
        if !compact_source.contains(exact_union) {
            return Err(ProtocolToolError::new(
                "Recovery Scope Catalog V2 handoff closed union drifted",
            ));
        }
    }
    Ok(())
}

pub(crate) fn compact_cddl(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once(';').map_or(line, |(code, _)| code))
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[cfg(test)]
pub(crate) fn validate_catalog_hiding_nonces<'a>(
    nonces: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> Result<(), ProtocolToolError> {
    let mut seen = BTreeSet::new();
    let mut count = 0_usize;
    for nonce in nonces {
        count += 1;
        let nonce = nonce.ok_or_else(|| {
            ProtocolToolError::new("Recovery Scope Catalog V2 hiding nonce is absent")
        })?;
        let nonce: [u8; 32] = nonce.try_into().map_err(|_| {
            ProtocolToolError::new("Recovery Scope Catalog V2 hiding nonce must be 32 bytes")
        })?;
        if nonce == [0; 32] {
            return Err(ProtocolToolError::new(
                "Recovery Scope Catalog V2 hiding nonce must not be all zero",
            ));
        }
        if !seen.insert(nonce) {
            return Err(ProtocolToolError::new(
                "Recovery Scope Catalog V2 hiding nonce is reused within one catalog",
            ));
        }
    }
    if count == 0 {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 catalog has no hiding nonces",
        ));
    }
    Ok(())
}
