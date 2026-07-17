use dtx_domain::{DirectoryRegistrationId, IndexerId, TenantId};
use dtx_indexer::{IndexRegistrationRequestV1, IndexerError, PublicSearchCursorV1};
use serde::Deserialize;
use std::{fmt::Write as _, str::FromStr};

#[derive(Deserialize)]
struct IndexerVector {
    registration_id: String,
    indexer_id: String,
    registration_request_cbor_hex: String,
}
#[derive(Deserialize)]
struct DescriptorVector {
    descriptors: Vec<DescriptorEntry>,
}
#[derive(Deserialize)]
struct DescriptorEntry {
    descriptor: String,
    canonical_cbor_hex: String,
}
fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("byte"))
        .collect()
}
fn encode_hex(value: &[u8]) -> String {
    value.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("string");
        output
    })
}

#[test]
fn registration_request_vector_is_byte_exact() {
    let vector: IndexerVector = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/indexer/v1/indexer-v1.json"
    ))
    .expect("vector");
    let descriptors: DescriptorVector = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/public-descriptor/v1_2/public-descriptor-v1-2.json"
    ))
    .expect("descriptors");
    let descriptor = &descriptors
        .descriptors
        .iter()
        .find(|entry| entry.descriptor == "channel_genesis")
        .expect("channel")
        .canonical_cbor_hex;
    let request = IndexRegistrationRequestV1::new(
        DirectoryRegistrationId::from_str(&vector.registration_id).expect("registration"),
        IndexerId::from_str(&vector.indexer_id).expect("indexer"),
        decode_hex(descriptor),
    )
    .expect("request");
    assert_eq!(
        encode_hex(&request.encode().expect("encode")),
        vector.registration_request_cbor_hex
    );
    assert_eq!(
        IndexRegistrationRequestV1::decode(&request.encode().expect("encode")).expect("decode"),
        request
    );
}

#[test]
fn search_cursor_is_exactly_bound_and_stale_generations_fail_closed() {
    let tenant = TenantId::from_str("01890f00-0000-7000-8000-000000000001").expect("tenant");
    let indexer = IndexerId::from_str("01890f00-0000-7000-8000-000000000002").expect("indexer");
    let cursor = PublicSearchCursorV1::new(tenant, indexer, "secure agent", Some(2), 7, 25, 25)
        .expect("cursor");
    let encoded = cursor.encode().expect("encode");
    assert_eq!(
        encoded,
        "pQGiAaIBAQIAAqIBAQIAAlggB8yea17Xy1Snhz7nDyTLLkkGkDZci8KhawUnydWhSSkDBwQYGQUYGQ"
    );
    assert_eq!(
        PublicSearchCursorV1::decode_for(
            &encoded,
            tenant,
            indexer,
            "secure agent",
            Some(2),
            7,
            None,
        )
        .expect("decode"),
        cursor
    );
    for rejected in [
        PublicSearchCursorV1::decode_for(
            &encoded,
            tenant,
            indexer,
            "different",
            Some(2),
            7,
            Some(25),
        ),
        PublicSearchCursorV1::decode_for(
            &encoded,
            tenant,
            indexer,
            "secure agent",
            Some(1),
            7,
            Some(25),
        ),
        PublicSearchCursorV1::decode_for(
            &encoded,
            tenant,
            indexer,
            "secure agent",
            Some(2),
            8,
            Some(25),
        ),
        PublicSearchCursorV1::decode_for(
            &encoded,
            tenant,
            indexer,
            "secure agent",
            Some(2),
            7,
            Some(10),
        ),
        PublicSearchCursorV1::decode_for(
            &encoded,
            TenantId::from_str("01890f00-0000-7000-8000-000000000003").expect("tenant"),
            indexer,
            "secure agent",
            Some(2),
            7,
            Some(25),
        ),
        PublicSearchCursorV1::decode_for(
            &encoded,
            tenant,
            IndexerId::from_str("01890f00-0000-7000-8000-000000000004").expect("indexer"),
            "secure agent",
            Some(2),
            7,
            Some(25),
        ),
        PublicSearchCursorV1::decode_for(
            "25",
            tenant,
            indexer,
            "secure agent",
            Some(2),
            7,
            Some(25),
        ),
    ] {
        assert_eq!(rejected, Err(IndexerError::InvalidCursor));
    }
}
