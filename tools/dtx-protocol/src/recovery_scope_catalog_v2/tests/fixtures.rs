fn cddl() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    super::read_cddl(&root).expect("Recovery Scope Catalog V2 CDDL must be readable")
}

fn openapi() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    super::read_openapi(&root).expect("Recovery Scope Catalog V2 OpenAPI must be readable")
}

fn openapi_document() -> Value {
    super::parse_openapi(&openapi()).expect("Recovery Scope Catalog V2 OpenAPI must parse")
}

fn vector() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    super::read_catalog_vector(&root).expect("Recovery Scope Catalog V2 vector must parse")
}

fn positive_handoff(
    value: &Value,
) -> (
    super::CatalogPositiveFacts,
    super::ServerVisibleHandoffFacts,
) {
    let cddl = cddl();
    let server =
        validate_server_handoff(value).expect("C1b-B1 server-visible fixture must validate");
    let catalog = super::validate_positive_vector(value, &cddl)
        .expect("Catalog V2 core positive fixture must validate");
    (catalog, server)
}

fn validate_server_handoff(
    value: &Value,
) -> Result<super::ServerVisibleHandoffFacts, super::ProtocolToolError> {
    let cddl = cddl();
    let catalog = super::validate_catalog_server_projection(value, &cddl)?;
    let input = super::parse_server_visible_handoff_input(value)?;
    super::validate_server_visible_handoff(&cddl, &catalog, &input)
}

fn assert_openapi_document_rejected(label: &str, document: &Value) {
    assert!(
        super::validate_openapi_document(document).is_err(),
        "OpenAPI validator must reject {label}"
    );
}

fn replace_openapi_value(document: &mut Value, pointer: &str, replacement: Value) {
    *document
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("mutation pointer must exist: {pointer}")) = replacement;
}

fn mutate_cddl_rule(source: &str, rule: &str, mutation: impl FnOnce(&str) -> String) -> String {
    let declaration = format!("{rule} = {{");
    let declaration_start = source
        .find(&declaration)
        .unwrap_or_else(|| panic!("rule declaration must exist: {rule}"));
    let body =
        super::rule_body(source, rule).unwrap_or_else(|_| panic!("rule body must exist: {rule}"));
    let body_offset = source[declaration_start..]
        .find(body)
        .expect("rule body must follow its declaration")
        + declaration_start;
    let mut mutated = source.to_owned();
    mutated.replace_range(body_offset..body_offset + body.len(), &mutation(body));
    mutated
}

fn independent_digest(domain: &[u8], exact: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(exact);
    hasher.finalize().into()
}

fn canonical_map(
    fields: impl IntoIterator<Item = (u64, dtx_wire::CanonicalValue)>,
) -> dtx_wire::CanonicalValue {
    dtx_wire::CanonicalValue::Map(
        fields
            .into_iter()
            .map(|(key, value)| (dtx_wire::CanonicalValue::Unsigned(key), value))
            .collect(),
    )
}

fn minimum_structural_catalog_opening(index: u64) -> dtx_wire::CanonicalValue {
    use dtx_wire::CanonicalValue::{Bytes, Text, Unsigned};

    let identity = Text("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la".to_owned());
    let catalog_id = Text("0190f2a5-7b1c-7abc-8def-0123456789a2".to_owned());
    let private_body = canonical_map([
        (1, Unsigned(2)),
        (2, catalog_id.clone()),
        (3, Unsigned(1)),
        (4, Unsigned(index)),
        (
            5,
            canonical_map([(1, Unsigned(1)), (2, catalog_id.clone())]),
        ),
        (6, Bytes(vec![0; 1])),
        (7, Bytes(vec![0; 32])),
        (8, Bytes(vec![0; 32])),
        (9, Bytes(vec![0; 32])),
        (10, Bytes(vec![0; 32])),
    ]);
    let binding = canonical_map([
        (1, Unsigned(1)),
        (2, identity),
        (3, catalog_id.clone()),
        (4, Unsigned(1)),
        (5, Unsigned(index)),
        (6, Bytes(vec![0; 32])),
        (7, Text("https://a".to_owned())),
        (8, catalog_id.clone()),
        (9, Bytes(vec![0; 32])),
        (10, Unsigned(1)),
        (11, Bytes(vec![0; 32])),
        (12, Unsigned(0)),
        (13, Unsigned(1)),
        (14, catalog_id.clone()),
        (15, catalog_id.clone()),
        (16, Unsigned(1)),
        (17, Unsigned(1)),
        (18, Bytes(vec![0; 32])),
        (19, Unsigned(0)),
        (20, Unsigned(1)),
        (21, Bytes(vec![0; 64])),
        (22, Bytes(vec![0; 64])),
        (23, Bytes(vec![0; 64])),
    ]);
    let leaf = canonical_map([
        (1, Unsigned(2)),
        (2, catalog_id),
        (3, Unsigned(1)),
        (4, Unsigned(index)),
        (5, Bytes(vec![0; 32])),
        (6, Bytes(vec![0; 32])),
        (7, Unsigned(1)),
        (8, Unsigned(1)),
        (9, Bytes(vec![0; 32])),
        (10, Unsigned(0)),
        (11, Unsigned(1)),
        (12, Bytes(vec![0; 32])),
    ]);
    canonical_map([(1, private_body), (2, binding), (3, leaf)])
}

fn structural_opening_indices(value: &dtx_wire::CanonicalValue) -> [u64; 3] {
    let opening = super::numbered_fields(value, 3, "structural opening")
        .expect("structural opening must contain three members");
    let private = super::numbered_fields(opening[0], 10, "structural private body")
        .expect("structural private body must contain ten fields");
    let binding = super::numbered_fields(opening[1], 23, "structural signed binding")
        .expect("structural signed binding must contain twenty-three fields");
    let leaf = super::numbered_fields(opening[2], 12, "structural public leaf")
        .expect("structural public leaf must contain twelve fields");
    [
        super::cbor_unsigned(private[3], "structural private index")
            .expect("structural private index must be unsigned"),
        super::cbor_unsigned(binding[4], "structural binding index")
            .expect("structural binding index must be unsigned"),
        super::cbor_unsigned(leaf[3], "structural leaf index")
            .expect("structural leaf index must be unsigned"),
    ]
}

fn consecutive_index_structural_catalog_plaintext_exact(count: usize) -> Vec<u8> {
    let count = u16::try_from(count).expect("Catalog structural boundary count fits u16");
    let mut exact = Vec::with_capacity(
        super::MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
            + usize::from(count) * (super::MIN_CATALOG_OPENING_BYTES + 6),
    );
    exact.extend_from_slice(&[0xa8, 0x01, 0x02, 0x02, 0x78, 0x39]);
    exact.extend_from_slice(b"dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la");
    exact.extend_from_slice(&[0x03, 0x78, 0x24]);
    exact.extend_from_slice(b"0190f2a5-7b1c-7abc-8def-0123456789a2");
    exact.extend_from_slice(&[0x04, 0x01, 0x05, 0xf6, 0x06, 0x00, 0x07, 0x58, 0x20]);
    exact.extend_from_slice(&[0; 32]);
    exact.extend_from_slice(&[0x08, 0x99]);
    exact.extend_from_slice(&count.to_be_bytes());
    for index in 1..=count {
        let index = u64::from(index);
        let opening = minimum_structural_catalog_opening(index);
        assert_eq!(structural_opening_indices(&opening), [index; 3]);
        exact.extend_from_slice(
            &dtx_wire::encode_deterministic_cbor(&opening)
                .expect("consecutive-index structural opening must encode"),
        );
    }
    exact
}

fn canonical_bstr_exact(bytes: &[u8]) -> Vec<u8> {
    let length = u32::try_from(bytes.len()).expect("Catalog structural boundary fits u32");
    let mut encoded = Vec::with_capacity(bytes.len() + 5);
    encoded.push(0x5a);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

fn proof_value(count: u64, index: u64, siblings: &[[u8; 32]]) -> dtx_wire::CanonicalValue {
    use dtx_wire::CanonicalValue::{Array, Bytes, Text, Unsigned};

    canonical_map([
        (1, Unsigned(2)),
        (2, Text("0190f2a5-7b1c-7abc-8def-0123456789a2".to_owned())),
        (3, Unsigned(8)),
        (4, Unsigned(count)),
        (5, Unsigned(index)),
        (
            6,
            Array(
                siblings
                    .iter()
                    .map(|sibling| Bytes(sibling.to_vec()))
                    .collect(),
            ),
        ),
    ])
}

fn independent_proof_root(
    mut count: u64,
    mut index: u64,
    mut current: [u8; 32],
    siblings: &[[u8; 32]],
) -> [u8; 32] {
    let mut sibling_index = 0;
    while count > 1 {
        let (left, right) = if count % 2 == 1 && index == count {
            (current, current)
        } else {
            let sibling = siblings[sibling_index];
            sibling_index += 1;
            if index % 2 == 1 {
                (current, sibling)
            } else {
                (sibling, current)
            }
        };
        let mut children = [0; 64];
        children[..32].copy_from_slice(&left);
        children[32..].copy_from_slice(&right);
        current = independent_digest(super::MERKLE_NODE_DOMAIN, &children);
        count = count.div_ceil(2);
        index = index.div_ceil(2);
    }
    assert_eq!(sibling_index, siblings.len());
    current
}

fn independent_unsigned_prefix(value: &dtx_wire::CanonicalValue, count: usize) -> Vec<u8> {
    let dtx_wire::CanonicalValue::Map(fields) = value else {
        panic!("signed fixture must be a map");
    };
    dtx_wire::encode_deterministic_cbor(&dtx_wire::CanonicalValue::Map(fields[..count].to_vec()))
        .expect("unsigned fixture must encode canonically")
}

fn independently_verifies(
    public_key: [u8; 32],
    domain: &[u8],
    unsigned: &[u8],
    signature: [u8; 64],
) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    let mut transcript = Vec::with_capacity(domain.len() + unsigned.len());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(unsigned);
    key.verify_strict(&transcript, &Signature::from_bytes(&signature))
        .is_ok()
}
