use super::*;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CatalogVectorContext {
    pub(super) identity_id: String,
    pub(super) catalog_id: String,
    pub(super) generation: u64,
    pub(super) previous_head: [u8; 32],
    pub(super) identity_sequence: u64,
    pub(super) identity_head: [u8; 32],
    pub(super) authority_device_id: String,
    pub(super) authority_key_id: String,
    pub(super) authority_public_key: [u8; 32],
    pub(super) head_issued_at: u64,
    pub(super) head_expires_at: u64,
    pub(super) validation_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifierTuple {
    pub(super) origin: String,
    pub(super) key_id: String,
    pub(super) public_key: [u8; 32],
    pub(super) epoch: u64,
    pub(super) descriptor_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompletionEvidenceFacts {
    pub(super) algorithm: u64,
    pub(super) purpose: u64,
    pub(super) issuer_epk: [u8; 32],
    pub(super) issuer_authorization_not_before: u64,
    pub(super) issuer_authorization_expires_at: u64,
    pub(super) issuer_authorization_digest: [u8; 32],
}

pub(crate) struct BindingFacts {
    pub(super) digest: [u8; 32],
    pub(super) evidence: CompletionEvidenceFacts,
}

#[derive(Clone)]
pub(crate) struct CatalogOpeningFacts {
    pub(super) value: CanonicalValue,
    pub(super) opening_digest: [u8; 32],
    pub(super) private_digest: [u8; 32],
    pub(super) binding_digest: [u8; 32],
    pub(super) evidence: CompletionEvidenceFacts,
    pub(super) leaf_digest: [u8; 32],
    pub(super) scope_exact: Vec<u8>,
    pub(super) nonce: [u8; 32],
}

pub(crate) struct PrivateBodyFacts {
    pub(super) digest: [u8; 32],
    pub(super) scope_exact: Vec<u8>,
    pub(super) nonce: [u8; 32],
}

pub(crate) struct CatalogPositiveFacts {
    pub(super) context: CatalogVectorContext,
    pub(super) verifier: VerifierTuple,
    pub(super) openings: Vec<CatalogOpeningFacts>,
    pub(super) plaintext_exact: Vec<u8>,
    pub(super) merkle_root: [u8; 32],
    pub(super) signed_head: CanonicalValue,
}

/// The complete Catalog surface available to identity-server admission.
///
/// This deliberately contains exact signed/public data only. Candidate
/// plaintext, openings, recovery scopes, verifier descriptors, and decryption
/// material have no representation in this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CatalogServerProjection {
    pub(super) signed_head_exact: Vec<u8>,
    pub(super) signed_head_digest: [u8; 32],
    pub(super) identity_id: String,
    pub(super) catalog_id: String,
    pub(super) generation: u64,
    pub(super) previous_head_digest: [u8; 32],
    pub(super) leaf_count: u64,
    pub(super) merkle_root: [u8; 32],
    pub(super) identity_sequence: u64,
    pub(super) identity_head_digest: [u8; 32],
    pub(super) authority_device_id: String,
    pub(super) authority_key_id: String,
    pub(super) authority_public_key: [u8; 32],
    pub(super) head_issued_at: u64,
    pub(super) head_expires_at: u64,
    pub(super) validation_time: u64,
    pub(super) ciphertext: Vec<u8>,
    pub(super) ciphertext_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginActiveDevice {
    pub(super) device_id: String,
    pub(super) signing_public_key: [u8; 32],
    pub(super) encryption_public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginIdentityState {
    pub(super) sequence: u64,
    pub(super) head_digest: [u8; 32],
    pub(super) current_root_public_key: [u8; 32],
    pub(super) current_recovery_public_key: [u8; 32],
    pub(super) active_devices: Vec<OriginActiveDevice>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginAuthenticatedIdentityLog {
    pub(super) origin: String,
    pub(super) at_h: OriginIdentityState,
    pub(super) at_h_plus_1: OriginIdentityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginAuthenticatedCurrentIdentitySnapshot {
    pub(super) origin: String,
    pub(super) state: OriginIdentityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerVisibleHandoffInput {
    pub(super) preparation: Value,
    pub(super) origin_authenticated_identity_log: Value,
    pub(super) device_add: Value,
    pub(super) provider_response: Value,
    pub(super) public_aad: Value,
    pub(super) hpke_envelope: Value,
    pub(super) mutation_receipts: Value,
    pub(super) statuses: Value,
    pub(super) enrollment_candidate_recipient_public_key: [u8; 32],
    pub(super) response_capability: [u8; 32],
    pub(super) preparation_idempotency_key: Vec<u8>,
    pub(super) response_idempotency_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginAuthenticatedVerifierDescriptor {
    pub(super) origin: String,
    pub(super) key_id: String,
    pub(super) public_key: [u8; 32],
    pub(super) epoch: u64,
    pub(super) descriptor_digest: [u8; 32],
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    pub(super) signed_exact: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginAuthenticatedVerifierOracle {
    pub(super) by_origin: BTreeMap<String, OriginAuthenticatedVerifierDescriptor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IndependentAuthorityKind {
    ActiveDevice,
    CurrentRoot,
    CurrentRecovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerVisibleHandoffFacts {
    pub(super) request_id: String,
    pub(super) candidate_device_id: String,
    pub(super) candidate_signing_public_key: [u8; 32],
    pub(super) candidate_recipient_public_key: [u8; 32],
    pub(super) preparation_exact: Vec<u8>,
    pub(super) preparation_digest: [u8; 32],
    pub(super) identity_log: OriginAuthenticatedIdentityLog,
    pub(super) device_add_exact: Vec<u8>,
    pub(super) device_add_digest: [u8; 32],
    pub(super) public_aad_exact: Vec<u8>,
    pub(super) envelope_exact: Vec<u8>,
    pub(super) envelope_enc: [u8; 32],
    pub(super) envelope_ciphertext: Vec<u8>,
    pub(super) provider_response_exact: Vec<u8>,
    pub(super) provider_response_digest: [u8; 32],
    pub(super) independent_authority_kind: IndependentAuthorityKind,
    pub(super) independent_authority_key: [u8; 32],
    pub(super) preparation_receipt_exact: Vec<u8>,
    pub(super) provider_response_receipt_exact: Vec<u8>,
    pub(super) status_exact: [Vec<u8>; 5],
}

pub(crate) struct DecodedHandoffEnvelope {
    pub(super) exact: Vec<u8>,
    pub(super) enc: [u8; 32],
    pub(super) ciphertext: Vec<u8>,
}

pub(crate) fn validate_catalog_vector(
    root: &Path,
    cddl: &str,
    openapi: &str,
) -> Result<(), ProtocolToolError> {
    let vector = read_catalog_vector(root)?;
    validate_vector_metadata(&vector, cddl, openapi)?;
    let catalog_projection = validate_catalog_server_projection(&vector, cddl)?;
    let handoff_input = parse_server_visible_handoff_input(&vector)?;
    let server_visible =
        validate_server_visible_handoff(cddl, &catalog_projection, &handoff_input)?;
    let facts = validate_positive_vector(&vector, cddl)?;
    validate_candidate_handoff(&vector, cddl, &server_visible, &facts)?;
    validate_handoff_authority_variants(
        &vector,
        cddl,
        &catalog_projection,
        &server_visible,
        &facts,
    )?;
    validate_handoff_hpke_alternates(&vector, cddl, &server_visible)?;
    validate_handoff_signature_alternates(&vector, cddl, &server_visible)?;
    validate_handoff_b2b_families(&vector, cddl, &catalog_projection, &server_visible, &facts)?;
    validate_negative_vector_family(&vector, cddl, &facts)?;
    validate_completion_evidence_negative_vector_family(&vector, cddl, &facts)
}

pub(crate) fn read_catalog_vector(root: &Path) -> Result<Value, ProtocolToolError> {
    let path = root.join(VECTOR_PATH);
    let source = fs::read_to_string(&path).map_err(|error| {
        ProtocolToolError::new(format!(
            "read Recovery Scope Catalog V2 vector {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Recovery Scope Catalog V2 vector {}: {error}",
            path.display()
        ))
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "vector metadata must exactly cross-check JSON, CDDL, and OpenAPI in one gate"
)]
pub(crate) fn validate_vector_metadata(
    vector: &Value,
    cddl: &str,
    openapi: &str,
) -> Result<(), ProtocolToolError> {
    require_json_keys(
        vector,
        &[
            "baseline",
            "catalog",
            "catalog_authority_public_key_hex",
            "domains",
            "hpke_aad",
            "hpke_info",
            "handoff",
            "handoff_alternate_constructions",
            "handoff_authority_variants",
            "handoff_b2b",
            "limits",
            "media_types",
            "negative_cbor",
            "negative_completion_evidence",
            "origin_authenticated_completion_verifier_descriptors",
            "rotated_verifier_public_key_hex",
            "verifier_public_key_hex",
            "version",
            "wrong_authority_public_key_hex",
        ],
        "Catalog V2 vector",
    )?;
    if json_u64(vector, "version")? != 2 || json_u64(vector, "baseline")? != 42 {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector version or baseline drift",
        ));
    }
    let limits = json_field(vector, "limits", "Catalog V2 vector")?;
    require_json_keys(
        limits,
        &[
            "catalog_plaintext_ceiling_bytes",
            "consecutive_one_based_indices_required",
            "count_boundary_classification",
            "index_occurrences_per_opening",
            "indices_24_through_255_count",
            "indices_24_through_255_extra_bytes_per_opening",
            "indices_256_plus_extra_bytes_per_opening",
            "indices_256_through_1023_count",
            "max_catalog_upload_body_bytes",
            "max_ciphertext_bytes",
            "max_device_add_bytes",
            "max_envelope_bytes",
            "max_hpke_ciphertext_bytes",
            "max_hpke_encoded_envelope_bytes",
            "max_leaf_count",
            "max_leaf_count_minimum_bytes",
            "max_leaf_count_plus_one",
            "max_leaf_count_plus_one_minimum_bytes",
            "max_preparation_body_bytes",
            "max_proof_siblings",
            "max_provider_package_bytes",
            "max_provider_response_body_bytes",
            "max_signed_catalog_head_bytes",
            "max_status_body_bytes",
            "minimum_outer_plaintext_overhead_bytes",
            "minimum_valid_opening_bytes",
            "one_byte_index_maximum",
            "two_byte_index_maximum",
        ],
        "Catalog V2 limits",
    )?;
    let derived_maximum_bytes = MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
        + MAX_CATALOG_LEAVES * MIN_CATALOG_OPENING_BYTES
        + CATALOG_MIDDLE_INDEX_COUNT * CATALOG_MIDDLE_INDEX_EXTRA_BYTES
        + CATALOG_LARGE_INDEX_COUNT * CATALOG_LARGE_INDEX_EXTRA_BYTES;
    let derived_overflow_bytes = MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
        + (MAX_CATALOG_LEAVES + 1) * MIN_CATALOG_OPENING_BYTES
        + CATALOG_MIDDLE_INDEX_COUNT * CATALOG_MIDDLE_INDEX_EXTRA_BYTES
        + (CATALOG_LARGE_INDEX_COUNT + 1) * CATALOG_LARGE_INDEX_EXTRA_BYTES;
    if CATALOG_MIDDLE_INDEX_COUNT != CATALOG_TWO_BYTE_INDEX_MAXIMUM - CATALOG_ONE_BYTE_INDEX_MAXIMUM
        || CATALOG_LARGE_INDEX_COUNT != MAX_CATALOG_LEAVES - CATALOG_TWO_BYTE_INDEX_MAXIMUM
        || CATALOG_MIDDLE_INDEX_EXTRA_BYTES != CATALOG_INDEX_OCCURRENCES_PER_OPENING
        || CATALOG_LARGE_INDEX_EXTRA_BYTES != 2 * CATALOG_INDEX_OCCURRENCES_PER_OPENING
        || derived_maximum_bytes != MAX_MINIMAL_CATALOG_BYTES
        || derived_overflow_bytes != MIN_OVERFLOW_CATALOG_BYTES
        || limits
            .get("consecutive_one_based_indices_required")
            .and_then(Value::as_bool)
            != Some(true)
        || json_u64(limits, "index_occurrences_per_opening")?
            != u64::try_from(CATALOG_INDEX_OCCURRENCES_PER_OPENING)
                .expect("index occurrence count fits u64")
        || json_u64(limits, "one_byte_index_maximum")?
            != u64::try_from(CATALOG_ONE_BYTE_INDEX_MAXIMUM)
                .expect("one-byte index maximum fits u64")
        || json_u64(limits, "two_byte_index_maximum")?
            != u64::try_from(CATALOG_TWO_BYTE_INDEX_MAXIMUM)
                .expect("two-byte index maximum fits u64")
        || json_u64(limits, "indices_24_through_255_count")?
            != u64::try_from(CATALOG_MIDDLE_INDEX_COUNT).expect("middle index count fits u64")
        || json_u64(limits, "indices_24_through_255_extra_bytes_per_opening")?
            != u64::try_from(CATALOG_MIDDLE_INDEX_EXTRA_BYTES)
                .expect("middle index extra bytes fit u64")
        || json_u64(limits, "indices_256_through_1023_count")?
            != u64::try_from(CATALOG_LARGE_INDEX_COUNT).expect("large index count fits u64")
        || json_u64(limits, "indices_256_plus_extra_bytes_per_opening")?
            != u64::try_from(CATALOG_LARGE_INDEX_EXTRA_BYTES)
                .expect("large index extra bytes fit u64")
        || json_u64(limits, "max_leaf_count")?
            != u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits u64")
        || json_u64(limits, "max_leaf_count_plus_one")?
            != u64::try_from(MAX_CATALOG_LEAVES + 1).expect("catalog max+1 fits u64")
        || json_u64(limits, "catalog_plaintext_ceiling_bytes")?
            != u64::try_from(MAX_CIPHERTEXT_BYTES).expect("plaintext ceiling fits u64")
        || json_u64(limits, "minimum_valid_opening_bytes")?
            != u64::try_from(MIN_CATALOG_OPENING_BYTES).expect("opening minimum fits u64")
        || json_u64(limits, "minimum_outer_plaintext_overhead_bytes")?
            != u64::try_from(MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES)
                .expect("plaintext overhead fits u64")
        || json_u64(limits, "max_leaf_count_minimum_bytes")?
            != u64::try_from(MAX_MINIMAL_CATALOG_BYTES).expect("catalog maximum fits u64")
        || json_u64(limits, "max_leaf_count_plus_one_minimum_bytes")?
            != u64::try_from(MIN_OVERFLOW_CATALOG_BYTES).expect("catalog overflow fits u64")
        || json_string(limits, "count_boundary_classification")?
            != "structural_cddl_and_consecutive_index_semantic_size_model_not_1023_opening_full_crypto"
        || json_u64(limits, "max_ciphertext_bytes")?
            != u64::try_from(MAX_CIPHERTEXT_BYTES).expect("ciphertext limit fits u64")
        || json_u64(limits, "max_catalog_upload_body_bytes")?
            != u64::try_from(MAX_CATALOG_UPLOAD_BODY_BYTES)
                .expect("Catalog upload body limit fits u64")
        || json_u64(limits, "max_envelope_bytes")?
            != u64::try_from(MAX_ENVELOPE_BYTES).expect("envelope limit fits u64")
        || json_u64(limits, "max_proof_siblings")?
            != u64::try_from(MAX_PROOF_SIBLINGS).expect("proof sibling maximum fits u64")
        || json_u64(limits, "max_preparation_body_bytes")?
            != u64::try_from(MAX_PREPARATION_BODY_BYTES).expect("preparation limit fits u64")
        || json_u64(limits, "max_provider_package_bytes")?
            != u64::try_from(MAX_PROVIDER_PACKAGE_BYTES).expect("package limit fits u64")
        || json_u64(limits, "max_hpke_ciphertext_bytes")?
            != u64::try_from(MAX_HPKE_CIPHERTEXT_BYTES).expect("HPKE limit fits u64")
        || json_u64(limits, "max_hpke_encoded_envelope_bytes")?
            != u64::try_from(MAX_HPKE_ENCODED_ENVELOPE_BYTES).expect("HPKE envelope limit fits u64")
        || json_u64(limits, "max_device_add_bytes")?
            != u64::try_from(MAX_DEVICE_ADD_BYTES).expect("DeviceAdd limit fits u64")
        || json_u64(limits, "max_provider_response_body_bytes")?
            != u64::try_from(MAX_PROVIDER_RESPONSE_BODY_BYTES).expect("response limit fits u64")
        || json_u64(limits, "max_signed_catalog_head_bytes")?
            != u64::try_from(MAX_SIGNED_CATALOG_HEAD_BYTES)
                .expect("signed Catalog head limit fits u64")
        || json_u64(limits, "max_status_body_bytes")?
            != u64::try_from(MAX_STATUS_BODY_BYTES).expect("status limit fits u64")
    {
        return Err(ProtocolToolError::new("Catalog V2 vector limit drift"));
    }
    let media = json_field(vector, "media_types", "Catalog V2 vector")?;
    require_json_keys(
        media,
        &[
            "catalog_head",
            "catalog_upload",
            "preparation",
            "preparation_receipt",
            "provider_response",
            "provider_response_receipt",
            "status",
        ],
        "Catalog V2 media types",
    )?;
    if json_string(media, "catalog_upload")? != REQUEST_MEDIA
        || json_string(media, "catalog_head")? != RESPONSE_MEDIA
        || json_string(media, "preparation")? != PREPARATION_MEDIA
        || json_string(media, "preparation_receipt")? != PREPARATION_RECEIPT_MEDIA
        || json_string(media, "provider_response")? != PROVIDER_RESPONSE_MEDIA
        || json_string(media, "provider_response_receipt")? != PROVIDER_RESPONSE_RECEIPT_MEDIA
        || json_string(media, "status")? != STATUS_MEDIA
    {
        return Err(ProtocolToolError::new("Catalog V2 vector media type drift"));
    }
    let expected_domains = json!({
        "membership_receipt": String::from_utf8_lossy(MEMBERSHIP_RECEIPT_DOMAIN),
        "recovery_scope": String::from_utf8_lossy(RECOVERY_SCOPE_DOMAIN),
        "private_body": String::from_utf8_lossy(PRIVATE_BODY_DOMAIN),
        "opening": String::from_utf8_lossy(OPENING_DOMAIN),
        "verifier_binding": String::from_utf8_lossy(VERIFIER_BINDING_DOMAIN),
        "verifier_binding_signature": String::from_utf8_lossy(VERIFIER_BINDING_SIGNATURE_DOMAIN),
        "completion_verifier_descriptor": String::from_utf8_lossy(COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN),
        "completion_verifier_descriptor_signature": String::from_utf8_lossy(COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN),
        "completion_evidence_pop": String::from_utf8_lossy(COMPLETION_EVIDENCE_POP_DOMAIN),
        "completion_evidence_origin_authorization": String::from_utf8_lossy(COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN),
        "completion_evidence_authorization_digest": String::from_utf8_lossy(COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN),
        "leaf_commitment": String::from_utf8_lossy(LEAF_COMMITMENT_DOMAIN),
        "ciphertext": String::from_utf8_lossy(CIPHERTEXT_DOMAIN),
        "head": String::from_utf8_lossy(HEAD_DOMAIN),
        "head_signature": String::from_utf8_lossy(HEAD_SIGNATURE_DOMAIN),
        "merkle_node": String::from_utf8_lossy(MERKLE_NODE_DOMAIN),
        "response_capability": "dirextalk.recovery-response-capability.v1\0",
        "recipient_key": "dirextalk.recovery-recipient-key.v1\0",
        "device_history_authority_id": "dirextalk.device-history-authority-id.v1\0",
        "identity_device_add": "dirextalk.identity-device-add.v1\0",
        "preparation_idempotency": "dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\0",
        "response_idempotency": "dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\0",
        "preparation_signature": "dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\0",
        "preparation_digest": "dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0",
        "provider_package": "dirextalk.recovery-scope-catalog-handoff-provider-package.v2\0",
        "provider_aad": "dirextalk.recovery-scope-catalog-handoff-provider-aad.v2\0",
        "provider_envelope": "dirextalk.recovery-scope-catalog-handoff-provider-envelope.v2\0",
        "provider_signature": "dirextalk.recovery-scope-catalog-handoff-provider-signature.v2\0",
        "provider_authority_signature": "dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2\0",
        "provider_response": "dirextalk.recovery-scope-catalog-handoff-provider-response.v2\0",
    });
    if vector.get("domains") != Some(&expected_domains) {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector domain assertions drifted",
        ));
    }
    let cddl_domains = parse_crypto_domain_declarations(cddl)?;
    if json_string(vector, "hpke_info")? != HPKE_INFO {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE info metadata drifted",
        ));
    }
    let expected_hpke_aad = json!({
        "cddl_rule": "recovery-scope-catalog-provider-public-aad-v2",
        "input": "exact_deterministic_canonical_cbor_bytes",
        "forbidden_inputs": [
            "response_field_18_digest",
            "provider_aad_domain_prefixed",
            "json",
            "hex",
            "alternate_cbor_encoding",
        ],
        "deterministic_vector_required_in": "C1b-B",
    });
    if vector.get("hpke_aad") != Some(&expected_hpke_aad) {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE AAD byte-selection metadata drifted",
        ));
    }
    if cddl_domains.len() != 30
        || cddl_domains.values().any(|domain| {
            let actual = domain.replace("\\0", "\0");
            !expected_domains.as_object().is_some_and(|domains| {
                domains
                    .values()
                    .any(|value| value.as_str() == Some(&actual))
            })
        })
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector domains do not equal CDDL declarations",
        ));
    }
    let openapi_document = parse_openapi(openapi)?;
    let openapi_domains = openapi_document
        .pointer(&format!("{OPENAPI_OPERATION}/x-dirextalk-crypto-domains"))
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 OpenAPI crypto domains missing"))?;
    let openapi_handoff_domains = openapi_document
        .pointer("/x-dirextalk-handoff-crypto-domains")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProtocolToolError::new("Catalog V2 OpenAPI handoff crypto domains missing")
        })?;
    let openapi_domain_values = openapi_domains
        .values()
        .chain(openapi_handoff_domains.values())
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| ProtocolToolError::new("Catalog V2 OpenAPI domain must be a string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_domain_values = expected_domains
        .as_object()
        .expect("frozen domains are an object")
        .values()
        .map(|value| value.as_str().expect("frozen domain must be a string"))
        .collect::<BTreeSet<_>>();
    if openapi_domains.len() != 16
        || openapi_handoff_domains.len() != 14
        || openapi_domain_values != expected_domain_values
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector domains do not equal OpenAPI metadata",
        ));
    }
    if openapi_document.pointer("/x-dirextalk-handoff-hpke/info") != vector.get("hpke_info")
        || openapi_domain_values
            .iter()
            .any(|domain| *domain == HPKE_INFO)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE info must be exact and separate from hash domains",
        ));
    }
    let hpke_aad = vector
        .get("hpke_aad")
        .expect("frozen HPKE AAD metadata was validated");
    if openapi_document.pointer("/x-dirextalk-handoff-hpke/public-aad-cddl-rule")
        != hpke_aad.get("cddl_rule")
        || openapi_document
            .pointer("/x-dirextalk-handoff-hpke/deterministic-hpke-vector-required-in")
            != hpke_aad.get("deterministic_vector_required_in")
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE AAD metadata does not match OpenAPI",
        ));
    }
    for field in [
        "catalog_authority_public_key_hex",
        "wrong_authority_public_key_hex",
        "verifier_public_key_hex",
        "rotated_verifier_public_key_hex",
    ] {
        decode_json_fixed::<32>(vector, field)?;
    }
    Ok(())
}

pub(crate) fn validate_handoff_b2b_families(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let b2b = json_field(vector, "handoff_b2b", "Catalog V2 vector")?;
    require_json_keys(
        b2b,
        &[
            "classification",
            "currentness_drifts",
            "decoder_privacy_closure",
            "get_state_traces",
            "limitations",
            "recipient_bindings",
            "sealed_package_mismatches",
            "state_idempotency_traces",
            "time_boundaries",
            "verifier_rotation",
        ],
        "Catalog V2 C1b-B2b families",
    )?;
    require_handoff(
        json_string(b2b, "classification")?
            == "public-deterministic-authentic-handoff-boundary-fixtures-not-credentials",
        "B2b fixture classification drifted",
    )?;
    validate_b2b_recipient_bindings(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_sealed_package_mismatches(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_verifier_rotation(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_state_idempotency(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_get_states(vector, cddl, base, b2b)?;
    validate_b2b_currentness(vector, cddl, catalog_projection, base, b2b)?;
    validate_b2b_time_boundaries(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_decoder_privacy(vector, cddl, catalog_projection, b2b)?;
    validate_b2b_limitations(b2b)
}
