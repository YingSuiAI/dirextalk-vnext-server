use super::{
    BTreeSet, BindingFacts, CIPHERTEXT_DOMAIN, COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN,
    COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN, COMPLETION_EVIDENCE_POP_DOMAIN,
    CanonicalValue, CatalogOpeningFacts, CatalogPositiveFacts, CatalogVectorContext,
    CompletionEvidenceFacts, HEAD_DOMAIN, LEAF_COMMITMENT_DOMAIN, MAX_CIPHERTEXT_BYTES,
    MEMBERSHIP_RECEIPT_DOMAIN, OPENING_DOMAIN, PRIVATE_BODY_DOMAIN, PrivateBodyFacts,
    ProtocolToolError, RECOVERY_SCOPE_DOMAIN, VERIFIER_BINDING_DOMAIN,
    VERIFIER_BINDING_SIGNATURE_DOMAIN, Value, VerifierTuple, cbor_array, cbor_bytes, cbor_fixed,
    cbor_text, cbor_unsigned, decode_exact_cddl, decode_json_fixed, decode_lower_hex,
    derive_merkle_root, domain_digest, encode_deterministic_cbor, encoded_unsigned_prefix,
    json_field, json_string, json_u64, numbered_fields, require_json_keys,
    validate_global_issuer_epk_uniqueness, validate_head_value, validate_positive_proofs,
    validate_upload_assertion, verify_signature,
};
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_positive_vector(
    vector: &Value,
    cddl: &str,
) -> Result<CatalogPositiveFacts, ProtocolToolError> {
    let catalog = json_field(vector, "catalog", "Catalog V2 vector")?;
    require_json_keys(
        catalog,
        &[
            "authority_device_id",
            "authority_key_id",
            "catalog_id",
            "ciphertext_digest_hex",
            "ciphertext_hex",
            "generation",
            "head_digest_hex",
            "head_expires_at",
            "head_issued_at",
            "head_signature_hex",
            "head_signed_cbor_hex",
            "head_unsigned_cbor_hex",
            "identity_head",
            "identity_id",
            "merkle_root_hex",
            "openings",
            "plaintext_cbor_hex",
            "previous_head_digest_hex",
            "proofs",
            "single_leaf_proof_cbor_hex",
            "single_leaf_root_hex",
            "upload_cbor_hex",
            "validation_time",
            "verifier_descriptor",
        ],
        "Catalog V2 positive catalog",
    )?;
    let (plaintext_exact, plaintext) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-plaintext-v2",
        json_string(catalog, "plaintext_cbor_hex")?,
        "Catalog V2 plaintext",
    )?;
    let plaintext_fields = numbered_fields(&plaintext, 8, "Catalog V2 plaintext")?;
    let (_, signed_head) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-head-v2",
        json_string(catalog, "head_signed_cbor_hex")?,
        "Catalog V2 signed head",
    )?;
    let head_fields = numbered_fields(&signed_head, 16, "Catalog V2 signed head")?;
    if cbor_unsigned(plaintext_fields[0], "plaintext version")? != 2
        || cbor_unsigned(head_fields[0], "head version")? != 2
    {
        return Err(ProtocolToolError::new("Catalog V2 version drift"));
    }
    let context = CatalogVectorContext {
        identity_id: cbor_text(plaintext_fields[1], "plaintext identity")?.to_owned(),
        catalog_id: cbor_text(plaintext_fields[2], "plaintext catalog id")?.to_owned(),
        generation: cbor_unsigned(plaintext_fields[3], "plaintext generation")?,
        previous_head: cbor_fixed(plaintext_fields[4], "plaintext previous head")?,
        identity_sequence: cbor_unsigned(plaintext_fields[5], "plaintext identity H")?,
        identity_head: cbor_fixed(plaintext_fields[6], "plaintext identity head")?,
        authority_device_id: cbor_text(head_fields[10], "head authority device")?.to_owned(),
        authority_key_id: cbor_text(head_fields[11], "head authority key")?.to_owned(),
        authority_public_key: cbor_fixed(head_fields[12], "head authority public key")?,
        head_issued_at: cbor_unsigned(head_fields[13], "head issued_at")?,
        head_expires_at: cbor_unsigned(head_fields[14], "head expires_at")?,
        validation_time: json_u64(catalog, "validation_time")?,
    };
    validate_context_syntax(&context)?;
    if context.head_issued_at >= context.head_expires_at
        || context.validation_time < context.head_issued_at
        || context.validation_time >= context.head_expires_at
    {
        return Err(ProtocolToolError::new("Catalog V2 head validity invalid"));
    }
    if json_string(catalog, "identity_id")? != context.identity_id
        || json_string(catalog, "catalog_id")? != context.catalog_id
        || json_u64(catalog, "generation")? != context.generation
        || decode_json_fixed::<32>(catalog, "previous_head_digest_hex")? != context.previous_head
        || json_string(catalog, "authority_device_id")? != context.authority_device_id
        || json_string(catalog, "authority_key_id")? != context.authority_key_id
        || json_u64(catalog, "head_issued_at")? != context.head_issued_at
        || json_u64(catalog, "head_expires_at")? != context.head_expires_at
        || decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?
            != context.authority_public_key
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON coordinate assertion mismatch",
        ));
    }
    let identity_head = json_field(catalog, "identity_head", "Catalog V2 catalog")?;
    require_json_keys(
        identity_head,
        &["digest_hex", "sequence"],
        "Catalog V2 identity head",
    )?;
    if json_u64(identity_head, "sequence")? != context.identity_sequence
        || decode_json_fixed::<32>(identity_head, "digest_hex")? != context.identity_head
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON identity-head assertion mismatch",
        ));
    }
    let opening_values = cbor_array(plaintext_fields[7], "Catalog V2 openings")?;
    let opening_json = json_field(catalog, "openings", "Catalog V2 catalog")?
        .as_array()
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 opening assertions must be an array"))?;
    if opening_values.len() != 3 || opening_json.len() != 3 {
        return Err(ProtocolToolError::new(
            "Catalog V2 positive vector must contain exactly three openings",
        ));
    }
    let first_binding = numbered_fields(
        numbered_fields(&opening_values[0], 3, "first opening")?[1],
        23,
        "first verifier binding",
    )?;
    let verifier = VerifierTuple {
        origin: cbor_text(first_binding[6], "verifier origin")?.to_owned(),
        key_id: cbor_text(first_binding[7], "verifier key id")?.to_owned(),
        public_key: cbor_fixed(first_binding[8], "verifier public key")?,
        epoch: cbor_unsigned(first_binding[9], "verifier epoch")?,
        descriptor_digest: cbor_fixed(first_binding[10], "verifier descriptor digest")?,
    };
    validate_verifier_assertions(vector, catalog, &verifier)?;
    let mut openings = Vec::with_capacity(3);
    let mut previous_scope: Option<Vec<u8>> = None;
    let mut nonces = BTreeSet::new();
    let mut issuer_keys = Vec::with_capacity(opening_values.len());
    let mut issuer_window = None;
    for (position, (value, assertion)) in opening_values.iter().zip(opening_json).enumerate() {
        let index = u64::try_from(position + 1).expect("three openings fit u64");
        let facts = validate_opening_value(value, &context, &verifier, index)?;
        let opening_fields = numbered_fields(value, 3, "Catalog V2 validity opening")?;
        let binding_fields = numbered_fields(opening_fields[1], 23, "Catalog V2 validity binding")?;
        if cbor_unsigned(binding_fields[11], "fixture binding issued_at")? != context.head_issued_at
            || cbor_unsigned(binding_fields[12], "fixture binding expires_at")?
                != context.head_expires_at
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 outer validity equality fixture drift",
            ));
        }
        if previous_scope
            .as_ref()
            .is_some_and(|previous| previous >= &facts.scope_exact)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 scopes are not strictly canonical-sorted and unique",
            ));
        }
        previous_scope = Some(facts.scope_exact.clone());
        if !nonces.insert(facts.nonce) {
            return Err(ProtocolToolError::new(
                "Catalog V2 hiding nonce reused within catalog",
            ));
        }
        issuer_keys.push(facts.evidence.issuer_epk);
        let window = (
            facts.evidence.issuer_authorization_not_before,
            facts.evidence.issuer_authorization_expires_at,
        );
        if issuer_window
            .replace(window)
            .is_some_and(|first| first != window)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 catalog-wide issuer authorization window drifted across leaves",
            ));
        }
        validate_opening_json_assertions(assertion, &facts, index)?;
        if value != &facts.value {
            return Err(ProtocolToolError::new("Catalog V2 opening value drift"));
        }
        openings.push(facts);
    }
    validate_global_issuer_epk_uniqueness(issuer_keys)?;
    let merkle_root =
        derive_merkle_root(openings.iter().map(|opening| opening.leaf_digest).collect())?;
    if decode_json_fixed::<32>(catalog, "merkle_root_hex")? != merkle_root {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON Merkle-root assertion mismatch",
        ));
    }
    let ciphertext = decode_lower_hex(json_string(catalog, "ciphertext_hex")?)?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ProtocolToolError::new(
            "Catalog V2 ciphertext bound invalid",
        ));
    }
    let ciphertext_digest = domain_digest(CIPHERTEXT_DOMAIN, &ciphertext);
    if decode_json_fixed::<32>(catalog, "ciphertext_digest_hex")? != ciphertext_digest {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON ciphertext digest assertion mismatch",
        ));
    }
    validate_head_value(
        &signed_head,
        &context,
        merkle_root,
        ciphertext_digest,
        openings.len(),
    )?;
    let head_unsigned = encoded_unsigned_prefix(&signed_head, 15, "Catalog V2 head")?;
    if decode_lower_hex(json_string(catalog, "head_unsigned_cbor_hex")?)? != head_unsigned
        || decode_json_fixed::<64>(catalog, "head_signature_hex")?
            != cbor_fixed(head_fields[15], "head signature")?
        || decode_json_fixed::<32>(catalog, "head_digest_hex")?
            != domain_digest(
                HEAD_DOMAIN,
                &encode_deterministic_cbor(&signed_head).map_err(|error| {
                    ProtocolToolError::new(format!("encode signed head: {error}"))
                })?,
            )
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON head derived assertion mismatch",
        ));
    }
    validate_upload_assertion(
        cddl,
        catalog,
        &signed_head,
        &ciphertext,
        &plaintext_exact,
        &openings,
    )?;
    validate_positive_proofs(cddl, catalog, &context, &openings, merkle_root)?;
    Ok(CatalogPositiveFacts {
        context,
        verifier,
        openings,
        plaintext_exact,
        merkle_root,
        signed_head,
    })
}

pub(crate) fn validate_context_syntax(
    context: &CatalogVectorContext,
) -> Result<(), ProtocolToolError> {
    if !valid_identity_id(&context.identity_id)
        || !valid_uuid_v7(&context.catalog_id)
        || !valid_uuid_v7(&context.authority_device_id)
        || !valid_uuid_v7(&context.authority_key_id)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 canonical identity or UUIDv7 syntax invalid",
        ));
    }
    Ok(())
}

pub(crate) fn valid_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || matches!(*byte, b'a'..=b'f')
        })
}

pub(crate) fn valid_identity_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 57
        && bytes.starts_with(b"dtxi1")
        && bytes[5..]
            .iter()
            .all(|byte| matches!(*byte, b'a'..=b'z' | b'2'..=b'7'))
        && matches!(bytes[56], b'a' | b'q')
}

pub(crate) fn validate_verifier_assertions(
    vector: &Value,
    catalog: &Value,
    verifier: &VerifierTuple,
) -> Result<(), ProtocolToolError> {
    let descriptor = json_field(catalog, "verifier_descriptor", "Catalog V2 catalog")?;
    require_json_keys(
        descriptor,
        &[
            "binding_expires_at",
            "binding_issued_at",
            "digest_hex",
            "epoch",
            "key_id",
            "origin",
        ],
        "Catalog V2 verifier descriptor",
    )?;
    if json_string(descriptor, "origin")? != verifier.origin
        || json_string(descriptor, "key_id")? != verifier.key_id
        || json_u64(descriptor, "epoch")? != verifier.epoch
        || decode_json_fixed::<32>(descriptor, "digest_hex")? != verifier.descriptor_digest
        || decode_json_fixed::<32>(vector, "verifier_public_key_hex")? != verifier.public_key
        || json_u64(descriptor, "binding_issued_at")? != json_u64(catalog, "head_issued_at")?
        || json_u64(descriptor, "binding_expires_at")? != json_u64(catalog, "head_expires_at")?
        || !valid_uuid_v7(&verifier.key_id)
        || !valid_https_origin(&verifier.origin)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 current verifier descriptor assertion mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn valid_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if !(9..=2_048).contains(&value.len())
        || !value.is_ascii()
        || authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\', '%', '[', ']'])
        || authority.matches(':').count() > 1
        || value.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    valid_canonical_dns_host(host) && port.is_none_or(valid_canonical_port)
}

// Keep this byte parser aligned with the repository's strict public-origin
// contracts: URL-library normalization must never turn an alternate spelling
// or an IP-looking authority into a different verifier endpoint.
pub(crate) fn valid_canonical_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
        && host.bytes().any(|byte| byte.is_ascii_lowercase())
        && !looks_like_whatwg_ipv4_host(host)
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

pub(crate) fn looks_like_whatwg_ipv4_host(host: &str) -> bool {
    host.split('.')
        .next_back()
        .is_some_and(is_whatwg_ipv4_number)
}

pub(crate) fn is_whatwg_ipv4_number(part: &str) -> bool {
    !part.is_empty()
        && (part.bytes().all(|byte| byte.is_ascii_digit())
            || part.strip_prefix("0x").is_some_and(|hex| {
                !hex.is_empty()
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }))
}

pub(crate) fn valid_canonical_port(port: &str) -> bool {
    !port.is_empty()
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port
            .parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed != 443)
}

pub(crate) fn validate_opening_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
    expected_index: u64,
) -> Result<CatalogOpeningFacts, ProtocolToolError> {
    let fields = numbered_fields(value, 3, "Catalog V2 opening")?;
    let private = validate_private_body_value(fields[0], context, expected_index)?;
    let binding =
        validate_binding_value(fields[1], context, verifier, expected_index, private.digest)?;
    let leaf_digest = validate_commitment_value(
        fields[2],
        context,
        expected_index,
        private.digest,
        binding.digest,
        &binding.evidence,
    )?;
    let opening_exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode complete opening: {error}")))?;
    Ok(CatalogOpeningFacts {
        value: value.clone(),
        opening_digest: domain_digest(OPENING_DOMAIN, &opening_exact),
        private_digest: private.digest,
        binding_digest: binding.digest,
        evidence: binding.evidence,
        leaf_digest,
        scope_exact: private.scope_exact,
        nonce: private.nonce,
    })
}

pub(crate) fn validate_private_body_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    expected_index: u64,
) -> Result<PrivateBodyFacts, ProtocolToolError> {
    let fields = numbered_fields(value, 10, "Catalog V2 private body")?;
    if cbor_unsigned(fields[0], "private-body version")? != 2
        || cbor_text(fields[1], "private-body catalog id")? != context.catalog_id
        || cbor_unsigned(fields[2], "private-body generation")? != context.generation
        || cbor_unsigned(fields[3], "private-body index")? != expected_index
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 private-body coordinate mismatch",
        ));
    }
    let receipt = cbor_bytes(fields[5], "private-body membership receipt")?;
    if receipt.is_empty()
        || cbor_fixed::<32>(fields[6], "private-body receipt digest")?
            != domain_digest(MEMBERSHIP_RECEIPT_DOMAIN, receipt)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 membership-receipt digest mismatch",
        ));
    }
    let scope_exact = encode_deterministic_cbor(fields[4])
        .map_err(|error| ProtocolToolError::new(format!("encode recovery scope: {error}")))?;
    if cbor_fixed::<32>(fields[8], "private-body recovery-scope digest")?
        != domain_digest(RECOVERY_SCOPE_DOMAIN, &scope_exact)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 recovery-scope digest mismatch",
        ));
    }
    let nonce = cbor_fixed::<32>(fields[9], "private-body hiding nonce")?;
    if nonce == [0; 32] {
        return Err(ProtocolToolError::new(
            "Catalog V2 hiding nonce must not be all zero",
        ));
    }
    let exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode private body: {error}")))?;
    Ok(PrivateBodyFacts {
        digest: domain_digest(PRIVATE_BODY_DOMAIN, &exact),
        scope_exact,
        nonce,
    })
}

pub(crate) fn validate_binding_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
    expected_index: u64,
    private_digest: [u8; 32],
) -> Result<BindingFacts, ProtocolToolError> {
    let fields = numbered_fields(value, 23, "Catalog V2 verifier binding")?;
    if cbor_unsigned(fields[0], "binding version")? != 1
        || cbor_text(fields[1], "binding identity")? != context.identity_id
        || cbor_text(fields[2], "binding catalog id")? != context.catalog_id
        || cbor_unsigned(fields[3], "binding generation")? != context.generation
        || cbor_unsigned(fields[4], "binding index")? != expected_index
        || cbor_fixed::<32>(fields[5], "binding private digest")? != private_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding coordinate/private mismatch",
        ));
    }
    let observed = VerifierTuple {
        origin: cbor_text(fields[6], "binding verifier origin")?.to_owned(),
        key_id: cbor_text(fields[7], "binding verifier key id")?.to_owned(),
        public_key: cbor_fixed(fields[8], "binding verifier public key")?,
        epoch: cbor_unsigned(fields[9], "binding verifier epoch")?,
        descriptor_digest: cbor_fixed(fields[10], "binding descriptor digest")?,
    };
    if observed != *verifier {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding current descriptor tuple mismatch",
        ));
    }
    let issued_at = cbor_unsigned(fields[11], "binding issued_at")?;
    let expires_at = cbor_unsigned(fields[12], "binding expires_at")?;
    if issued_at >= expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding inner validity invalid",
        ));
    }
    if issued_at < context.head_issued_at || expires_at > context.head_expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding validity escapes head",
        ));
    }
    if context.validation_time < issued_at || context.validation_time >= expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding expired at use",
        ));
    }
    if cbor_text(fields[13], "binding authority device")? != context.authority_device_id
        || cbor_text(fields[14], "binding authority key")? != context.authority_key_id
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 binding/head authority mismatch",
        ));
    }
    let (evidence, unsigned) = validate_completion_evidence_issuer_binding(
        value, &fields, context, verifier, issued_at, expires_at,
    )?;
    verify_signature(
        context.authority_public_key,
        VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &unsigned,
        cbor_fixed(fields[22], "binding catalog countersignature")?,
        "Catalog V2 verifier binding",
    )?;
    let exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode verifier binding: {error}")))?;
    Ok(BindingFacts {
        digest: domain_digest(VERIFIER_BINDING_DOMAIN, &exact),
        evidence,
    })
}

pub(crate) fn validate_completion_evidence_issuer_binding(
    value: &CanonicalValue,
    fields: &[&CanonicalValue],
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
    issued_at: u64,
    expires_at: u64,
) -> Result<(CompletionEvidenceFacts, Vec<u8>), ProtocolToolError> {
    let algorithm = cbor_unsigned(fields[15], "completion evidence algorithm")?;
    let purpose = cbor_unsigned(fields[16], "completion evidence purpose")?;
    if algorithm != 1 || purpose != 1 {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence algorithm or purpose is not the closed value",
        ));
    }
    let issuer_epk = cbor_fixed::<32>(fields[17], "completion evidence issuer EPK")?;
    if issuer_epk == verifier.public_key || issuer_epk == context.authority_public_key {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence issuer EPK violates key separation",
        ));
    }
    let issuer_authorization_not_before = cbor_unsigned(
        fields[18],
        "completion evidence issuer authorization not_before",
    )?;
    let issuer_authorization_expires_at = cbor_unsigned(
        fields[19],
        "completion evidence issuer authorization expires_at",
    )?;
    if issuer_authorization_not_before >= issuer_authorization_expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence issuer authorization validity is empty",
        ));
    }
    if issuer_authorization_not_before < issued_at
        || issuer_authorization_expires_at > expires_at
        || issuer_authorization_not_before < context.head_issued_at
        || issuer_authorization_expires_at > context.head_expires_at
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence issuer authorization validity escapes binding or catalog",
        ));
    }
    verify_signature(
        issuer_epk,
        COMPLETION_EVIDENCE_POP_DOMAIN,
        &encoded_unsigned_prefix(value, 20, "Catalog V2 completion evidence PoP")?,
        cbor_fixed(fields[20], "completion evidence PoP signature")?,
        "Catalog V2 completion evidence PoP",
    )?;
    verify_signature(
        verifier.public_key,
        COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
        &encoded_unsigned_prefix(value, 21, "Catalog V2 completion evidence authorization")?,
        cbor_fixed(
            fields[21],
            "completion evidence origin authorization signature",
        )?,
        "Catalog V2 completion evidence origin authorization",
    )?;
    let unsigned = encoded_unsigned_prefix(value, 22, "Catalog V2 verifier binding")?;
    Ok((
        CompletionEvidenceFacts {
            algorithm,
            purpose,
            issuer_epk,
            issuer_authorization_not_before,
            issuer_authorization_expires_at,
            issuer_authorization_digest: domain_digest(
                COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN,
                &unsigned,
            ),
        },
        unsigned,
    ))
}

pub(crate) fn validate_commitment_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    expected_index: u64,
    private_digest: [u8; 32],
    binding_digest: [u8; 32],
    evidence: &CompletionEvidenceFacts,
) -> Result<[u8; 32], ProtocolToolError> {
    let fields = numbered_fields(value, 12, "Catalog V2 leaf commitment")?;
    if cbor_unsigned(fields[0], "commitment version")? != 2
        || cbor_text(fields[1], "commitment catalog id")? != context.catalog_id
        || cbor_unsigned(fields[2], "commitment generation")? != context.generation
        || cbor_unsigned(fields[3], "commitment index")? != expected_index
        || cbor_fixed::<32>(fields[4], "commitment private digest")? != private_digest
        || cbor_fixed::<32>(fields[5], "commitment binding digest")? != binding_digest
        || cbor_unsigned(fields[6], "commitment evidence algorithm")? != evidence.algorithm
        || cbor_unsigned(fields[7], "commitment evidence purpose")? != evidence.purpose
        || cbor_fixed::<32>(fields[8], "commitment evidence issuer EPK")? != evidence.issuer_epk
        || cbor_unsigned(fields[9], "commitment authorization not_before")?
            != evidence.issuer_authorization_not_before
        || cbor_unsigned(fields[10], "commitment authorization expires_at")?
            != evidence.issuer_authorization_expires_at
        || cbor_fixed::<32>(fields[11], "commitment authorization digest")?
            != evidence.issuer_authorization_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 leaf commitment binding mismatch",
        ));
    }
    let exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode leaf commitment: {error}")))?;
    Ok(domain_digest(LEAF_COMMITMENT_DOMAIN, &exact))
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_opening_json_assertions(
    assertion: &Value,
    facts: &CatalogOpeningFacts,
    expected_index: u64,
) -> Result<(), ProtocolToolError> {
    require_json_keys(
        assertion,
        &[
            "issuer_authorization_expires_at_ms",
            "issuer_authorization_not_before_ms",
            "catalog_countersignature_hex",
            "completion_evidence_algorithm",
            "completion_evidence_issuer_authorization_digest_hex",
            "completion_evidence_issuer_epk_hex",
            "completion_evidence_issuer_origin_authorization_signature_hex",
            "completion_evidence_issuer_origin_authorization_unsigned_cbor_hex",
            "completion_evidence_issuer_pop_signature_hex",
            "completion_evidence_issuer_pop_unsigned_cbor_hex",
            "completion_evidence_purpose",
            "hiding_nonce_hex",
            "index",
            "leaf_commitment_cbor_hex",
            "leaf_digest_hex",
            "membership_receipt_digest_hex",
            "membership_receipt_hex",
            "opening_cbor_hex",
            "opening_digest_hex",
            "private_body_cbor_hex",
            "private_body_digest_hex",
            "recovery_scope_cbor_hex",
            "recovery_scope_digest_hex",
            "verifier_binding_digest_hex",
            "verifier_binding_signed_cbor_hex",
            "verifier_binding_unsigned_cbor_hex",
        ],
        "Catalog V2 opening assertion",
    )?;
    let fields = numbered_fields(&facts.value, 3, "Catalog V2 opening assertion source")?;
    let private_fields = numbered_fields(fields[0], 10, "Catalog V2 private assertion source")?;
    let binding_fields = numbered_fields(fields[1], 23, "Catalog V2 binding assertion source")?;
    let opening_exact = encode_deterministic_cbor(&facts.value)
        .map_err(|error| ProtocolToolError::new(format!("encode opening assertion: {error}")))?;
    let private_exact = encode_deterministic_cbor(fields[0])
        .map_err(|error| ProtocolToolError::new(format!("encode private assertion: {error}")))?;
    let binding_exact = encode_deterministic_cbor(fields[1])
        .map_err(|error| ProtocolToolError::new(format!("encode binding assertion: {error}")))?;
    let commitment_exact = encode_deterministic_cbor(fields[2])
        .map_err(|error| ProtocolToolError::new(format!("encode commitment assertion: {error}")))?;
    let scope_exact = encode_deterministic_cbor(private_fields[4])
        .map_err(|error| ProtocolToolError::new(format!("encode scope assertion: {error}")))?;
    if json_u64(assertion, "index")? != expected_index
        || decode_lower_hex(json_string(assertion, "hiding_nonce_hex")?)? != facts.nonce
        || decode_lower_hex(json_string(assertion, "membership_receipt_hex")?)?
            != cbor_bytes(private_fields[5], "asserted membership receipt")?
        || decode_json_fixed::<32>(assertion, "membership_receipt_digest_hex")?
            != cbor_fixed(private_fields[6], "asserted receipt digest")?
        || decode_lower_hex(json_string(assertion, "recovery_scope_cbor_hex")?)? != scope_exact
        || decode_json_fixed::<32>(assertion, "recovery_scope_digest_hex")?
            != cbor_fixed(private_fields[8], "asserted scope digest")?
        || decode_lower_hex(json_string(assertion, "private_body_cbor_hex")?)? != private_exact
        || decode_json_fixed::<32>(assertion, "private_body_digest_hex")? != facts.private_digest
        || decode_lower_hex(json_string(
            assertion,
            "verifier_binding_unsigned_cbor_hex",
        )?)? != encoded_unsigned_prefix(fields[1], 22, "binding assertion")?
        || decode_json_fixed::<64>(assertion, "catalog_countersignature_hex")?
            != cbor_fixed(binding_fields[22], "asserted catalog countersignature")?
        || json_u64(assertion, "completion_evidence_algorithm")? != facts.evidence.algorithm
        || json_u64(assertion, "completion_evidence_purpose")? != facts.evidence.purpose
        || decode_json_fixed::<32>(assertion, "completion_evidence_issuer_epk_hex")?
            != facts.evidence.issuer_epk
        || json_u64(assertion, "issuer_authorization_not_before_ms")?
            != facts.evidence.issuer_authorization_not_before
        || json_u64(assertion, "issuer_authorization_expires_at_ms")?
            != facts.evidence.issuer_authorization_expires_at
        || decode_lower_hex(json_string(
            assertion,
            "completion_evidence_issuer_pop_unsigned_cbor_hex",
        )?)? != encoded_unsigned_prefix(fields[1], 20, "completion evidence PoP assertion")?
        || decode_json_fixed::<64>(assertion, "completion_evidence_issuer_pop_signature_hex")?
            != cbor_fixed(binding_fields[20], "asserted completion evidence PoP")?
        || decode_lower_hex(json_string(
            assertion,
            "completion_evidence_issuer_origin_authorization_unsigned_cbor_hex",
        )?)? != encoded_unsigned_prefix(
            fields[1],
            21,
            "completion evidence authorization assertion",
        )?
        || decode_json_fixed::<64>(
            assertion,
            "completion_evidence_issuer_origin_authorization_signature_hex",
        )? != cbor_fixed(binding_fields[21], "asserted origin authorization")?
        || decode_json_fixed::<32>(
            assertion,
            "completion_evidence_issuer_authorization_digest_hex",
        )? != facts.evidence.issuer_authorization_digest
        || decode_lower_hex(json_string(assertion, "verifier_binding_signed_cbor_hex")?)?
            != binding_exact
        || decode_json_fixed::<32>(assertion, "verifier_binding_digest_hex")?
            != facts.binding_digest
        || decode_lower_hex(json_string(assertion, "leaf_commitment_cbor_hex")?)?
            != commitment_exact
        || decode_json_fixed::<32>(assertion, "leaf_digest_hex")? != facts.leaf_digest
        || decode_lower_hex(json_string(assertion, "opening_cbor_hex")?)? != opening_exact
        || decode_json_fixed::<32>(assertion, "opening_digest_hex")? != facts.opening_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 opening JSON derived assertion mismatch",
        ));
    }
    Ok(())
}
