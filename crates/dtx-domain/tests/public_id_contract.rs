use std::str::FromStr;

use dtx_domain::{
    AgentId, AggregateId, ChannelId, Ed25519PublicKey, EventId, IdentityId, PublicSubjectId,
    RequestId, TenantId,
};
use serde::Deserialize;

const UUID_V7: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";

#[derive(Deserialize)]
struct PublicIdVector {
    version: u16,
    ed25519_public_key_hex: String,
    identity_id: String,
    channel_id: String,
    agent_id: String,
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("vector contains lowercase hex");
    }
    output
}

fn vector() -> PublicIdVector {
    serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/v1/public-ids.json"
    ))
    .expect("public ID vector is valid JSON")
}

#[test]
fn public_ids_match_the_independent_domain_separated_vector() {
    let vector = vector();
    assert_eq!(vector.version, 1);
    let key = Ed25519PublicKey::try_from(decode_hex_32(&vector.ed25519_public_key_hex))
        .expect("vector key is canonical and strong");

    let identity = IdentityId::derive(&key);
    let channel = ChannelId::derive(&key);
    let agent = AgentId::derive(&key);

    assert_eq!(identity.to_string(), vector.identity_id);
    assert_eq!(channel.to_string(), vector.channel_id);
    assert_eq!(agent.to_string(), vector.agent_id);
    identity
        .verify_subject_key(&key)
        .expect("derived identity must bind to its key");
}

#[test]
fn public_id_parsers_reject_noncanonical_text() {
    let valid = vector().identity_id;

    assert!(IdentityId::from_str(&valid.to_uppercase()).is_err());
    assert!(IdentityId::from_str(&(valid.clone() + "=")).is_err());
    assert!(IdentityId::from_str(&valid[..valid.len() - 1]).is_err());

    let mut nonzero_trailing_bits = valid.into_bytes();
    *nonzero_trailing_bits.last_mut().expect("non-empty ID") = b'b';
    let nonzero_trailing_bits = String::from_utf8(nonzero_trailing_bits).expect("ASCII ID");
    assert!(IdentityId::from_str(&nonzero_trailing_bits).is_err());
}

#[test]
fn public_id_kinds_are_not_interchangeable() {
    let vector = vector();

    assert!(IdentityId::from_str(&vector.channel_id).is_err());
    assert!(ChannelId::from_str(&vector.agent_id).is_err());
    assert!(AgentId::from_str(&vector.identity_id).is_err());
}

#[test]
fn public_subject_union_preserves_the_validated_concrete_kind() {
    let vector = vector();

    let identity: PublicSubjectId = vector.identity_id.parse().unwrap();
    let channel: PublicSubjectId = vector.channel_id.parse().unwrap();
    let agent: PublicSubjectId = vector.agent_id.parse().unwrap();

    assert!(matches!(identity, PublicSubjectId::Identity(_)));
    assert!(matches!(channel, PublicSubjectId::Channel(_)));
    assert!(matches!(agent, PublicSubjectId::Agent(_)));
    assert_eq!(
        serde_json::from_str::<PublicSubjectId>(&serde_json::to_string(&identity).unwrap())
            .unwrap(),
        identity
    );
}

#[test]
fn public_key_validation_rejects_invalid_and_weak_encodings() {
    assert!(Ed25519PublicKey::try_from([0xff; 32]).is_err());
    assert!(Ed25519PublicKey::try_from([0_u8; 32]).is_err());
}

#[test]
fn lifecycle_ids_require_canonical_uuid_v7_text_and_serde_round_trip() {
    let tenant: TenantId = UUID_V7.parse().expect("canonical tenant UUIDv7");
    let event: EventId = UUID_V7.parse().expect("canonical event UUIDv7");
    let request: RequestId = UUID_V7.parse().expect("canonical request UUIDv7");
    let aggregate: AggregateId = UUID_V7.parse().expect("canonical aggregate UUIDv7");

    assert_eq!(
        serde_json::to_string(&tenant).unwrap(),
        format!("\"{UUID_V7}\"")
    );
    assert_eq!(event.to_string(), UUID_V7);
    assert_eq!(request.to_string(), UUID_V7);
    assert_eq!(aggregate.to_string(), UUID_V7);

    assert!(UUID_V7.to_uppercase().parse::<TenantId>().is_err());
    assert!(UUID_V7.replace('-', "").parse::<TenantId>().is_err());
}

#[test]
fn lifecycle_id_deserialization_rejects_noncanonical_or_unknown_shapes() {
    let uppercase = format!("\"{}\"", UUID_V7.to_uppercase());
    assert!(serde_json::from_str::<TenantId>(&uppercase).is_err());
    assert!(serde_json::from_str::<TenantId>("{}").is_err());
}
