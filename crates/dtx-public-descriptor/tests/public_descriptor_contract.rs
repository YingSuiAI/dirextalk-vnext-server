use dtx_domain::{AgentId, ChannelId, IdentityId, PublicSubjectId};
use dtx_public_descriptor::{
    DescriptorHeadV1, PUBLIC_DESCRIPTOR_WIRE_VERSION, PublicDescriptorError,
    PublicDescriptorKindV1, PublicDescriptorPayloadV1, SignedPublicDescriptorV1,
    UnsignedPublicDescriptorV1,
};
use dtx_wire::{Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct PublicDescriptorVector {
    version: u16,
    wire_version: String,
    descriptors: Vec<PublicDescriptorVectorEntry>,
}

#[derive(Deserialize)]
struct PublicDescriptorVectorEntry {
    descriptor: String,
    subject_id: String,
    publisher_identity_id: String,
    tombstone: bool,
    canonical_cbor_hex: String,
    entry_hash: String,
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).expect("test key is canonical")
}

fn utc(value: i64) -> UtcMillis {
    UtcMillis::new(value).expect("test timestamp is valid")
}

fn unsigned_channel(
    sequence: u64,
    previous_descriptor_hash: Option<Sha256Digest>,
    issued_at: i64,
    expires_at: i64,
    tombstone: bool,
) -> (UnsignedPublicDescriptorV1, SigningKey) {
    let publisher = key(22);
    let publisher_key = public(&publisher);
    let subject_key = publisher_key;
    let subject_id = ChannelId::derive(subject_key.as_domain_key());
    let publisher_identity_id = IdentityId::derive(publisher_key.as_domain_key());
    let payload = if tombstone {
        PublicDescriptorPayloadV1::Tombstone
    } else {
        PublicDescriptorPayloadV1::Channel {
            feed_endpoint: "https://feed.example/channel".to_owned(),
            capability_digest: Sha256Digest::from_bytes([33; 32]),
        }
    };
    (
        UnsignedPublicDescriptorV1::new(
            PUBLIC_DESCRIPTOR_WIRE_VERSION,
            PublicDescriptorKindV1::Channel,
            PublicSubjectId::Channel(subject_id),
            subject_key,
            publisher_identity_id,
            publisher_key,
            SafeUint::new(sequence).expect("test sequence is safe"),
            previous_descriptor_hash,
            utc(issued_at),
            utc(expires_at),
            payload,
        )
        .expect("well-formed unsigned channel descriptor"),
        publisher,
    )
}

fn sign(unsigned: UnsignedPublicDescriptorV1, publisher: &SigningKey) -> SignedPublicDescriptorV1 {
    let input = unsigned.signature_input().expect("canonical signing input");
    SignedPublicDescriptorV1::signed(
        unsigned,
        Ed25519Signature::from_bytes(publisher.sign(&input).to_bytes()),
    )
    .expect("valid signature")
}

#[test]
fn stable_ids_are_self_certifying_and_kind_specific() {
    let subject = public(&key(41));
    let channel = ChannelId::derive(subject.as_domain_key());
    let agent = AgentId::derive(subject.as_domain_key());
    assert_ne!(channel.to_string(), agent.to_string());
    assert!(channel.verify_subject_key(subject.as_domain_key()).is_ok());
    assert!(agent.verify_subject_key(subject.as_domain_key()).is_ok());
}

#[test]
fn rejects_a_subject_id_that_does_not_bind_the_declared_genesis_key() {
    let expected_subject = public(&key(51));
    let declared_subject = public(&key(52));
    let publisher = public(&key(22));
    let result = UnsignedPublicDescriptorV1::new(
        PUBLIC_DESCRIPTOR_WIRE_VERSION,
        PublicDescriptorKindV1::Channel,
        PublicSubjectId::Channel(ChannelId::derive(expected_subject.as_domain_key())),
        declared_subject,
        IdentityId::derive(publisher.as_domain_key()),
        publisher,
        SafeUint::new(1).expect("sequence"),
        None,
        utc(1_700_000_000_000),
        utc(1_700_000_100_000),
        PublicDescriptorPayloadV1::Channel {
            feed_endpoint: "https://feed.example/channel".to_owned(),
            capability_digest: Sha256Digest::from_bytes([33; 32]),
        },
    );
    assert_eq!(
        result.unwrap_err(),
        PublicDescriptorError::InvalidSubjectBinding
    );
}

#[test]
fn rejects_a_publisher_that_does_not_control_the_subject_genesis_key() {
    let subject = public(&key(51));
    let publisher = public(&key(22));
    let result = UnsignedPublicDescriptorV1::new(
        PUBLIC_DESCRIPTOR_WIRE_VERSION,
        PublicDescriptorKindV1::Channel,
        PublicSubjectId::Channel(ChannelId::derive(subject.as_domain_key())),
        subject,
        IdentityId::derive(publisher.as_domain_key()),
        publisher,
        SafeUint::new(1).expect("sequence"),
        None,
        utc(1_700_000_000_000),
        utc(1_700_000_100_000),
        PublicDescriptorPayloadV1::Channel {
            feed_endpoint: "https://feed.example/channel".to_owned(),
            capability_digest: Sha256Digest::from_bytes([33; 32]),
        },
    );
    assert_eq!(
        result.unwrap_err(),
        PublicDescriptorError::SubjectPublisherBindingMismatch
    );
}

#[test]
fn rejects_a_signature_from_a_key_not_bound_to_the_publisher_identity() {
    let (unsigned, _publisher) =
        unsigned_channel(1, None, 1_700_000_000_000, 1_700_000_100_000, false);
    let wrong = key(23);
    let input = unsigned.signature_input().expect("canonical signing input");
    let result = SignedPublicDescriptorV1::signed(
        unsigned,
        Ed25519Signature::from_bytes(wrong.sign(&input).to_bytes()),
    );
    assert_eq!(result.unwrap_err(), PublicDescriptorError::InvalidSignature);
}

#[test]
fn rejects_an_unknown_even_if_the_extra_cbor_field_is_canonical() {
    let (unsigned, publisher) =
        unsigned_channel(1, None, 1_700_000_000_000, 1_700_000_100_000, false);
    let descriptor = sign(unsigned, &publisher);
    let mut bytes = descriptor.to_deterministic_cbor().expect("canonical bytes");
    assert_eq!(bytes[0], 0xad, "V1 descriptor has thirteen map fields");
    bytes[0] = 0xae;
    bytes.extend([0x0e, 0xf6]);
    assert_eq!(
        SignedPublicDescriptorV1::decode_and_verify(&bytes),
        Err(PublicDescriptorError::InvalidCanonical)
    );
}

#[test]
fn reducer_rejects_replay_and_same_sequence_equivocation() {
    let (genesis_unsigned, publisher) =
        unsigned_channel(1, None, 1_700_000_000_000, 1_700_000_100_000, false);
    let genesis = sign(genesis_unsigned, &publisher);
    let mut head =
        DescriptorHeadV1::bootstrap_at(&genesis, utc(1_700_000_000_001)).expect("live genesis");

    assert_eq!(
        head.append_at(&genesis, utc(1_700_000_000_002)),
        Err(PublicDescriptorError::Replay)
    );

    let (fork_unsigned, fork_publisher) = unsigned_channel(
        2,
        Some(Sha256Digest::from_bytes([99; 32])),
        1_700_000_000_010,
        1_700_000_100_000,
        false,
    );
    let fork = sign(fork_unsigned, &fork_publisher);
    assert_eq!(
        head.append_at(&fork, utc(1_700_000_000_011)),
        Err(PublicDescriptorError::Equivocation)
    );
}

#[test]
fn reducer_fails_closed_for_an_expired_live_descriptor_and_for_tombstoned_subjects() {
    let (expired_unsigned, expired_publisher) =
        unsigned_channel(1, None, 1_700_000_000_000, 1_700_000_000_010, false);
    let expired = sign(expired_unsigned, &expired_publisher);
    assert_eq!(
        DescriptorHeadV1::bootstrap_at(&expired, utc(1_700_000_000_010)),
        Err(PublicDescriptorError::Expired)
    );

    let (genesis_unsigned, publisher) =
        unsigned_channel(1, None, 1_700_000_000_000, 1_700_000_100_000, false);
    let genesis = sign(genesis_unsigned, &publisher);
    let mut head =
        DescriptorHeadV1::bootstrap_at(&genesis, utc(1_700_000_000_001)).expect("live genesis");
    let (tombstone_unsigned, tombstone_publisher) = unsigned_channel(
        2,
        Some(genesis.entry_hash().expect("hash")),
        1_700_000_000_010,
        1_700_000_000_010,
        true,
    );
    let tombstone = sign(tombstone_unsigned, &tombstone_publisher);
    head.append_at(&tombstone, utc(1_700_000_000_011))
        .expect("tombstone is accepted");
    assert!(head.active_descriptor_at(utc(1_700_000_000_011)).is_none());

    let (later_unsigned, later_publisher) = unsigned_channel(
        3,
        Some(tombstone.entry_hash().expect("hash")),
        1_700_000_000_020,
        1_700_000_100_000,
        false,
    );
    let later = sign(later_unsigned, &later_publisher);
    assert_eq!(
        head.append_at(&later, utc(1_700_000_000_021)),
        Err(PublicDescriptorError::Tombstoned)
    );
}

#[test]
fn frozen_public_vector_is_byte_exact_and_reduces_to_the_expected_heads() {
    let vector: PublicDescriptorVector = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/public-descriptor/v1/public-descriptor-v1.json"
    ))
    .expect("public descriptor vector is valid JSON");
    assert_eq!(vector.version, 1);
    assert_eq!(vector.wire_version, "1.0");

    let mut channel_genesis = None;
    let mut channel_tombstone = None;
    let mut agent_genesis = None;
    for entry in vector.descriptors {
        let bytes = decode_hex(&entry.canonical_cbor_hex);
        let descriptor =
            SignedPublicDescriptorV1::decode_and_verify(&bytes).unwrap_or_else(|error| {
                panic!("{} vector proof is invalid: {error:?}", entry.descriptor)
            });
        assert_eq!(descriptor.subject_id().to_string(), entry.subject_id);
        assert_eq!(
            descriptor.publisher_identity_id().to_string(),
            entry.publisher_identity_id
        );
        assert_eq!(descriptor.is_tombstone(), entry.tombstone);
        assert_eq!(
            descriptor.entry_hash().expect("entry hash").to_string(),
            entry.entry_hash
        );
        assert_eq!(
            descriptor.to_deterministic_cbor().expect("canonical CBOR"),
            bytes
        );
        match entry.descriptor.as_str() {
            "channel_genesis" => channel_genesis = Some(descriptor),
            "channel_tombstone" => channel_tombstone = Some(descriptor),
            "agent_genesis" => agent_genesis = Some(descriptor),
            other => panic!("unexpected public descriptor vector entry: {other}"),
        }
    }

    let channel_genesis = channel_genesis.expect("channel genesis vector");
    let channel_tombstone = channel_tombstone.expect("channel tombstone vector");
    let mut channel_head = DescriptorHeadV1::bootstrap_at(&channel_genesis, utc(1_700_000_000_001))
        .expect("channel vector genesis is live");
    channel_head
        .append_at(&channel_tombstone, utc(1_700_000_000_011))
        .expect("channel vector tombstone is accepted");
    assert!(
        channel_head
            .active_descriptor_at(utc(1_700_000_000_011))
            .is_none()
    );

    let agent_genesis = agent_genesis.expect("agent genesis vector");
    DescriptorHeadV1::bootstrap_at(&agent_genesis, utc(1_700_000_000_001))
        .expect("agent vector genesis is live");
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex"))
        .collect()
}
