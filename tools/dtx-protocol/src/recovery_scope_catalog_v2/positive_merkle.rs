use super::{
    BTreeSet, CIPHERTEXT_DOMAIN, CanonicalValue, CatalogOpeningFacts, CatalogPositiveFacts,
    CatalogVectorContext, HEAD_SIGNATURE_DOMAIN, MAX_CATALOG_LEAVES, MAX_PROOF_SIBLINGS,
    MERKLE_NODE_DOMAIN, ProtocolToolError, Value, VerifierTuple, cbor_array, cbor_bytes,
    cbor_fixed, cbor_text, cbor_unsigned, decode_exact_cddl, decode_exact_upload_cddl,
    decode_json_fixed, domain_digest, encode_deterministic_cbor, encoded_unsigned_prefix,
    json_field, json_string, json_u64, numbered_fields, require_json_keys, validate_opening_value,
    verify_signature,
};
pub(crate) fn derive_merkle_root(mut level: Vec<[u8; 32]>) -> Result<[u8; 32], ProtocolToolError> {
    if level.is_empty() {
        return Err(ProtocolToolError::new("Catalog V2 Merkle tree is empty"));
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(merkle_node(pair[0], right));
        }
        level = next;
    }
    Ok(level[0])
}

pub(crate) fn merkle_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut children = [0_u8; 64];
    children[..32].copy_from_slice(&left);
    children[32..].copy_from_slice(&right);
    domain_digest(MERKLE_NODE_DOMAIN, &children)
}

pub(crate) fn validate_head_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    merkle_root: [u8; 32],
    ciphertext_digest: [u8; 32],
    leaf_count: usize,
) -> Result<(), ProtocolToolError> {
    if !(1..=MAX_CATALOG_LEAVES).contains(&leaf_count) {
        return Err(ProtocolToolError::new(
            "Catalog V2 signed head leaf count exceeds owner bound",
        ));
    }
    let fields = numbered_fields(value, 16, "Catalog V2 signed head")?;
    if cbor_unsigned(fields[0], "head version")? != 2
        || cbor_text(fields[1], "head catalog id")? != context.catalog_id
        || cbor_text(fields[2], "head identity")? != context.identity_id
        || cbor_unsigned(fields[3], "head generation")? != context.generation
        || cbor_fixed::<32>(fields[4], "head previous head")? != context.previous_head
        || cbor_unsigned(fields[5], "head leaf count")?
            != u64::try_from(leaf_count).expect("leaf count fits u64")
        || cbor_fixed::<32>(fields[6], "head Merkle root")? != merkle_root
        || cbor_fixed::<32>(fields[7], "head ciphertext digest")? != ciphertext_digest
        || cbor_unsigned(fields[8], "head identity H")? != context.identity_sequence
        || cbor_fixed::<32>(fields[9], "head identity digest")? != context.identity_head
        || cbor_text(fields[10], "head authority device")? != context.authority_device_id
        || cbor_text(fields[11], "head authority key")? != context.authority_key_id
        || cbor_fixed::<32>(fields[12], "head authority public key")?
            != context.authority_public_key
        || cbor_unsigned(fields[13], "head issued_at")? != context.head_issued_at
        || cbor_unsigned(fields[14], "head expires_at")? != context.head_expires_at
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 signed head relational binding mismatch",
        ));
    }
    verify_signature(
        context.authority_public_key,
        HEAD_SIGNATURE_DOMAIN,
        &encoded_unsigned_prefix(value, 15, "Catalog V2 head")?,
        cbor_fixed(fields[15], "head signature")?,
        "Catalog V2 head",
    )
}

pub(crate) fn validate_upload_assertion(
    cddl: &str,
    catalog: &Value,
    signed_head: &CanonicalValue,
    ciphertext: &[u8],
    plaintext_exact: &[u8],
    openings: &[CatalogOpeningFacts],
) -> Result<(), ProtocolToolError> {
    let (_, upload) = decode_exact_upload_cddl(
        cddl,
        json_string(catalog, "upload_cbor_hex")?,
        "Catalog V2 upload",
    )?;
    let fields = numbered_fields(&upload, 2, "Catalog V2 upload")?;
    if fields[0] != signed_head || cbor_bytes(fields[1], "upload ciphertext")? != ciphertext {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload head/ciphertext binding mismatch",
        ));
    }
    if ciphertext == plaintext_exact
        || openings.iter().any(|opening| {
            encode_deterministic_cbor(
                numbered_fields(&opening.value, 3, "privacy opening")
                    .expect("validated opening has three fields")[0],
            )
            .is_ok_and(|private| private == ciphertext)
        })
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload exposed plaintext or private body",
        ));
    }
    Ok(())
}

pub(crate) fn validate_positive_proofs(
    cddl: &str,
    catalog: &Value,
    context: &CatalogVectorContext,
    openings: &[CatalogOpeningFacts],
    root: [u8; 32],
) -> Result<(), ProtocolToolError> {
    let assertions = json_field(catalog, "proofs", "Catalog V2 catalog")?
        .as_array()
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 proofs must be an array"))?;
    if assertions.len() != openings.len() {
        return Err(ProtocolToolError::new("Catalog V2 proof count drift"));
    }
    for (position, (assertion, opening)) in assertions.iter().zip(openings).enumerate() {
        require_json_keys(
            assertion,
            &["index", "proof_cbor_hex"],
            "Catalog V2 proof assertion",
        )?;
        let index = u64::try_from(position + 1).expect("three proofs fit u64");
        if json_u64(assertion, "index")? != index {
            return Err(ProtocolToolError::new("Catalog V2 proof JSON index drift"));
        }
        let (_, proof) = decode_exact_cddl(
            cddl,
            "catalog-merkle-proof-v2",
            json_string(assertion, "proof_cbor_hex")?,
            "Catalog V2 Merkle proof",
        )?;
        validate_proof_value(
            &proof,
            context,
            u64::try_from(openings.len()).expect("opening count fits u64"),
            index,
            opening.leaf_digest,
            root,
        )?;
        let sibling_count = cbor_array(
            numbered_fields(&proof, 6, "Catalog V2 proof")?[5],
            "Catalog V2 proof siblings",
        )?
        .len();
        let expected = if index == 3 { 1 } else { 2 };
        if sibling_count != expected {
            return Err(ProtocolToolError::new(
                "Catalog V2 three-leaf proof sibling count drift",
            ));
        }
    }
    let (_, single) = decode_exact_cddl(
        cddl,
        "catalog-merkle-proof-v2",
        json_string(catalog, "single_leaf_proof_cbor_hex")?,
        "Catalog V2 single-leaf proof",
    )?;
    let single_root = decode_json_fixed::<32>(catalog, "single_leaf_root_hex")?;
    if single_root != openings[0].leaf_digest {
        return Err(ProtocolToolError::new(
            "Catalog V2 single-leaf root assertion mismatch",
        ));
    }
    validate_proof_value(&single, context, 1, 1, openings[0].leaf_digest, single_root)
}

pub(crate) fn validate_proof_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    expected_count: u64,
    expected_index: u64,
    leaf: [u8; 32],
    root: [u8; 32],
) -> Result<(), ProtocolToolError> {
    let fields = numbered_fields(value, 6, "Catalog V2 Merkle proof")?;
    let mut count = cbor_unsigned(fields[3], "proof count")?;
    let mut index = cbor_unsigned(fields[4], "proof index")?;
    if cbor_unsigned(fields[0], "proof version")? != 2
        || cbor_text(fields[1], "proof catalog id")? != context.catalog_id
        || cbor_unsigned(fields[2], "proof generation")? != context.generation
        || count != expected_count
        || index != expected_index
        || count == 0
        || count > u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits u64")
        || index == 0
        || index > count
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof coordinate mismatch",
        ));
    }
    let siblings = cbor_array(fields[5], "proof siblings")?;
    if siblings.len() > MAX_PROOF_SIBLINGS {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof exceeds sibling cap",
        ));
    }
    let mut sibling_index = 0_usize;
    let mut current = leaf;
    while count > 1 {
        if count % 2 == 1 && index == count {
            current = merkle_node(current, current);
        } else {
            let sibling = siblings.get(sibling_index).ok_or_else(|| {
                ProtocolToolError::new("Catalog V2 Merkle proof is missing a sibling")
            })?;
            sibling_index += 1;
            let sibling = cbor_fixed(sibling, "proof sibling")?;
            current = if index % 2 == 1 {
                merkle_node(current, sibling)
            } else {
                merkle_node(sibling, current)
            };
        }
        count = count.div_ceil(2);
        index = index.div_ceil(2);
    }
    if sibling_index != siblings.len() {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof has surplus or implicit-duplicate sibling",
        ));
    }
    if current != root {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof reconstructed wrong root or sibling side",
        ));
    }
    Ok(())
}

pub(crate) fn validate_plaintext_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
) -> Result<Vec<CatalogOpeningFacts>, ProtocolToolError> {
    let fields = numbered_fields(value, 8, "Catalog V2 plaintext")?;
    if cbor_unsigned(fields[0], "plaintext version")? != 2
        || cbor_text(fields[1], "plaintext identity")? != context.identity_id
        || cbor_text(fields[2], "plaintext catalog id")? != context.catalog_id
        || cbor_unsigned(fields[3], "plaintext generation")? != context.generation
        || cbor_fixed::<32>(fields[4], "plaintext previous head")? != context.previous_head
        || cbor_unsigned(fields[5], "plaintext identity H")? != context.identity_sequence
        || cbor_fixed::<32>(fields[6], "plaintext identity head")? != context.identity_head
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 plaintext coordinate/head mismatch",
        ));
    }
    let values = cbor_array(fields[7], "Catalog V2 plaintext openings")?;
    if values.is_empty() || values.len() > MAX_CATALOG_LEAVES {
        return Err(ProtocolToolError::new("Catalog V2 plaintext count invalid"));
    }
    let mut facts = Vec::with_capacity(values.len());
    let mut previous_scope: Option<Vec<u8>> = None;
    let mut nonces = BTreeSet::new();
    let mut issuer_keys = Vec::with_capacity(values.len());
    let mut issuer_window = None;
    for (position, value) in values.iter().enumerate() {
        let index = u64::try_from(position + 1).expect("catalog count fits u64");
        let opening = validate_opening_value(value, context, verifier, index)?;
        if previous_scope
            .as_ref()
            .is_some_and(|previous| previous >= &opening.scope_exact)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 scopes are not strictly canonical-sorted and unique",
            ));
        }
        previous_scope = Some(opening.scope_exact.clone());
        if !nonces.insert(opening.nonce) {
            return Err(ProtocolToolError::new(
                "Catalog V2 hiding nonce reused within catalog",
            ));
        }
        issuer_keys.push(opening.evidence.issuer_epk);
        let window = (
            opening.evidence.issuer_authorization_not_before,
            opening.evidence.issuer_authorization_expires_at,
        );
        if issuer_window
            .replace(window)
            .is_some_and(|first| first != window)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 catalog-wide issuer authorization window drifted across leaves",
            ));
        }
        facts.push(opening);
    }
    validate_global_issuer_epk_uniqueness(issuer_keys)?;
    Ok(facts)
}

pub(crate) fn validate_global_issuer_epk_uniqueness(
    issuer_keys: impl IntoIterator<Item = [u8; 32]>,
) -> Result<(), ProtocolToolError> {
    let mut seen = BTreeSet::new();
    for issuer_epk in issuer_keys {
        if !seen.insert(issuer_epk) {
            return Err(ProtocolToolError::new(
                "Catalog V2 completion evidence issuer EPK reused across retained Catalog V2 bindings or generations",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_upload_value(
    value: &CanonicalValue,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let fields = numbered_fields(value, 2, "Catalog V2 upload")?;
    if fields[0] != &facts.signed_head {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload path/head catalog or signed-head mismatch",
        ));
    }
    let ciphertext = cbor_bytes(fields[1], "Catalog V2 upload ciphertext")?;
    if ciphertext == facts.plaintext_exact
        || facts.openings.iter().any(|opening| {
            encode_deterministic_cbor(
                numbered_fields(&opening.value, 3, "privacy opening")
                    .expect("validated opening has three fields")[0],
            )
            .is_ok_and(|private| private == ciphertext)
        })
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload exposed plaintext or private body",
        ));
    }
    let head_fields = numbered_fields(&facts.signed_head, 16, "positive signed head")?;
    if domain_digest(CIPHERTEXT_DOMAIN, ciphertext)
        != cbor_fixed(head_fields[7], "positive ciphertext digest")?
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload ciphertext digest mismatch",
        ));
    }
    Ok(())
}
