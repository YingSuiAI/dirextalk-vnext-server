use dtx_domain::{AgentId, ChannelId, IdentityId, PublicSubjectId};
use dtx_public_feed::{
    PublicAttachmentRefV1, PublicFeedError, PublicFeedHeadV1, PublicFeedPayloadV1,
    SignedPublicFeedEventV1, UnsignedPublicFeedEventV1,
};
use dtx_wire::{Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use std::fmt::Write as _;

#[derive(Deserialize)]
struct Vector {
    channel_post_cbor_hex: String,
    agent_post_cbor_hex: String,
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).expect("valid key")
}
fn event(
    subject: PublicSubjectId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    payload: PublicFeedPayloadV1,
) -> SignedPublicFeedEventV1 {
    let signing = key();
    let public = public(&signing);
    let unsigned = UnsignedPublicFeedEventV1::new(
        subject,
        IdentityId::derive(public.as_domain_key()),
        public,
        SafeUint::new(sequence).expect("safe sequence"),
        previous,
        UtcMillis::new(1_700_000_000_000 + i64::try_from(sequence).expect("small sequence"))
            .expect("time"),
        payload,
    )
    .expect("valid event");
    let input = unsigned.signature_input().expect("signature input");
    SignedPublicFeedEventV1::signed(
        unsigned,
        Ed25519Signature::from_bytes(signing.sign(&input).to_bytes()),
    )
    .expect("signed event")
}
fn post() -> PublicFeedPayloadV1 {
    PublicFeedPayloadV1::Post {
        body: "public hello".to_owned(),
        attachments: vec![
            PublicAttachmentRefV1::new(
                Sha256Digest::from_bytes([7; 32]),
                "image/png".to_owned(),
                SafeUint::new(4096).expect("size"),
            )
            .expect("attachment"),
        ],
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("write to string");
        output
    })
}

#[test]
fn channel_and_agent_vectors_are_exact_and_tombstone_is_permanent() {
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/public-feed/v1/public-feed-v1.json"
    ))
    .expect("vector");
    let public = public(&key());
    let channel = event(
        PublicSubjectId::Channel(ChannelId::derive(public.as_domain_key())),
        1,
        None,
        post(),
    );
    let agent = event(
        PublicSubjectId::Agent(AgentId::derive(public.as_domain_key())),
        1,
        None,
        post(),
    );
    assert_eq!(
        hex(&channel.to_deterministic_cbor().expect("encode")),
        vector.channel_post_cbor_hex
    );
    assert_eq!(
        hex(&agent.to_deterministic_cbor().expect("encode")),
        vector.agent_post_cbor_hex
    );
    assert_eq!(
        SignedPublicFeedEventV1::decode_and_verify(
            &channel.to_deterministic_cbor().expect("encode")
        )
        .expect("decode"),
        channel
    );

    let mut head = PublicFeedHeadV1::bootstrap(&channel).expect("head");
    let second = event(channel.subject_id(), 2, Some(head.hash()), post());
    head.append(&second).expect("append");
    let tombstone = event(
        channel.subject_id(),
        3,
        Some(head.hash()),
        PublicFeedPayloadV1::Tombstone,
    );
    head.append(&tombstone).expect("tombstone");
    assert!(head.is_tombstoned());
    let resurrection = event(channel.subject_id(), 4, Some(head.hash()), post());
    assert_eq!(head.append(&resurrection), Err(PublicFeedError::Tombstoned));
}
