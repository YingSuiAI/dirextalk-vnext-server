use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{DeviceId, IdentityId};
use dtx_group_node::GROUP_QUERY_PROOF_HEADER;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Sha256Digest, SigningPublicKey, UtcMillis,
    encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};

const BINDING_DOMAIN: &[u8] = b"dirextalk.group-query-binding.v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"dirextalk.group-query-signature.v1\0";

fn numbered_map(values: Vec<CanonicalValue>) -> CanonicalValue {
    CanonicalValue::Map(
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (CanonicalValue::Unsigned((index + 1) as u64), value))
            .collect(),
    )
}

fn proof(action: u64, target: &str) -> (String, String) {
    let device = SigningKey::from_bytes(&[9; 32]);
    let public = SigningPublicKey::try_from(device.verifying_key().to_bytes()).unwrap();
    let actor = IdentityId::derive(public.as_domain_key());
    let device_id = "0190f2a5-7b41-7abc-8def-0123456789ab"
        .parse::<DeviceId>()
        .unwrap();
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(target.to_owned()),
        numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text("0190f2a5-7b1d-7abc-8def-0123456789ab".to_owned()),
        ]),
        CanonicalValue::Text(actor.to_string()),
        CanonicalValue::Text(device_id.to_string()),
        UtcMillis::new(1_725_000_000_000)
            .unwrap()
            .to_canonical_value(),
        UtcMillis::new(1_725_000_120_000)
            .unwrap()
            .to_canonical_value(),
        CanonicalValue::Text("https://identity.example".to_owned()),
    ]);
    let binding_bytes = encode_deterministic_cbor(&binding).unwrap();
    let digest = Sha256Digest::hash_domain(BINDING_DOMAIN, &binding_bytes);
    let mut signature_input = SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    let canonical = encode_deterministic_cbor(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        binding,
        CanonicalValue::Bytes(device.sign(&signature_input).to_bytes().to_vec()),
    ]))
    .unwrap();
    (
        hex(&canonical),
        Base64UrlUnpadded::encode_string(&canonical),
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

#[test]
fn join_and_commit_feed_proofs_use_one_action_fenced_header_contract() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/group-query-proof/v1/group-query-proof-overlay-v1.json"
    ))
    .unwrap();
    assert_eq!(GROUP_QUERY_PROOF_HEADER, "dtx-group-query-proof");
    assert_eq!(
        vector["canonical_header"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase(),
        GROUP_QUERY_PROOF_HEADER
    );
    let scope = "0190f2a5-7b1d-7abc-8def-0123456789ab";
    let join = proof(
        1,
        &format!("/v1/groups/private_conversation/{scope}/join-requests?after=&limit=64"),
    );
    let feed = proof(
        2,
        &format!("/v1/groups/private_conversation/{scope}/mls-commits?after_epoch=7&limit=64"),
    );
    let proofs = vector["proofs"].as_array().unwrap();
    assert_eq!(join.0, proofs[0]["canonical_cbor_hex"].as_str().unwrap());
    assert_eq!(join.1, proofs[0]["header_base64url"].as_str().unwrap());
    assert_eq!(feed.0, proofs[1]["canonical_cbor_hex"].as_str().unwrap());
    assert_eq!(feed.1, proofs[1]["header_base64url"].as_str().unwrap());
    assert_ne!(join, feed);
}
