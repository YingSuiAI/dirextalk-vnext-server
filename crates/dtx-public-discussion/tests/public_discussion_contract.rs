use dtx_domain::{ChannelId, DeviceId, EventId, IdentityId, PublicSubjectId};
use dtx_public_discussion::{
    CommentCursorV1, CommentPageV1, CommentReceiptV1, DiscussionAcceptancePolicyV1, ReactionKindV1,
    ReactionProjectionV1, ReactionReceiptV1, ReactionTargetKindV1, SignedCommentEventV1,
    SignedDiscussionPolicyV1, SignedReactionEventV1, UnsignedCommentEventV1,
    UnsignedDiscussionPolicyV1, UnsignedReactionEventV1,
};
use dtx_wire::{Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis};
use ed25519_dalek::{Signer, SigningKey};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
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
#[allow(
    clippy::too_many_lines,
    reason = "one shared V36 golden-vector test keeps every linked public discussion byte exact"
)]
fn policy_comment_reply_and_like_are_exact_and_target_bound() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/public-discussion/v1/public-discussion-v1.json"
    ))
    .unwrap();
    let owner = key(7);
    let owner_public = public(&owner);
    let owner_identity = IdentityId::derive(owner_public.as_domain_key());
    let channel = PublicSubjectId::Channel(ChannelId::derive(owner_public.as_domain_key()));
    let policy_unsigned = UnsignedDiscussionPolicyV1::new(
        channel,
        owner_identity,
        owner_public,
        SafeUint::new(1).unwrap(),
        None,
        DiscussionAcceptancePolicyV1::VerifiedIdentity,
        UtcMillis::new(1_725_000_000_000).unwrap(),
    )
    .unwrap();
    let policy = SignedDiscussionPolicyV1::signed(
        policy_unsigned.clone(),
        Ed25519Signature::from_bytes(
            owner
                .sign(&policy_unsigned.signature_input().unwrap())
                .to_bytes(),
        ),
    )
    .unwrap();
    let policy_bytes = policy.to_deterministic_cbor().unwrap();
    assert_eq!(
        hex(&policy_bytes),
        vector["policy"]["canonical_cbor_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(policy.policy_digest().unwrap().as_bytes()),
        vector["policy"]["policy_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        SignedDiscussionPolicyV1::decode_and_verify(&policy_bytes).unwrap(),
        policy
    );

    let actor = key(9);
    let actor_public = public(&actor);
    let post = Sha256Digest::from_bytes([3; 32]);
    let unsigned = UnsignedCommentEventV1::new(
        "0190f2a5-7b40-7abc-8def-0123456789ab"
            .parse::<EventId>()
            .unwrap(),
        channel,
        post,
        None,
        "A public comment".to_owned(),
        IdentityId::derive(actor_public.as_domain_key()),
        "0190f2a5-7b41-7abc-8def-0123456789ab"
            .parse::<DeviceId>()
            .unwrap(),
        "https://identity.example".to_owned(),
        SafeUint::new(1).unwrap(),
        policy.policy_digest().unwrap(),
        UtcMillis::new(1_725_000_000_001).unwrap(),
    )
    .unwrap();
    let comment = SignedCommentEventV1::signed(
        unsigned.clone(),
        Ed25519Signature::from_bytes(actor.sign(&unsigned.signature_input().unwrap()).to_bytes()),
        actor_public,
    )
    .unwrap();
    let exact = comment.to_deterministic_cbor().unwrap();
    assert_eq!(
        hex(&exact),
        vector["comment"]["canonical_cbor_hex"].as_str().unwrap()
    );
    let decoded = SignedCommentEventV1::decode(&exact).unwrap();
    decoded.verify_with_key(actor_public).unwrap();
    let receipt = CommentReceiptV1::new(SafeUint::new(1).unwrap(), None, exact).unwrap();
    assert_eq!(
        hex(decoded.event_hash().unwrap().as_bytes()),
        vector["comment"]["event_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&receipt.encode().unwrap()),
        vector["comment_receipt"]["canonical_cbor_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        CommentReceiptV1::decode(&receipt.encode().unwrap()).unwrap(),
        receipt
    );
    let cursor = CommentCursorV1::new(
        channel,
        post,
        SafeUint::new(1).unwrap(),
        SafeUint::new(1).unwrap(),
        receipt.thread_entry_hash(),
    )
    .unwrap();
    let page = CommentPageV1::new(
        channel,
        post,
        vec![receipt.encode().unwrap()],
        Some(cursor.encode().unwrap()),
        SafeUint::new(1).unwrap(),
        receipt.thread_entry_hash(),
    )
    .unwrap();
    assert_eq!(
        cursor.encode().unwrap(),
        vector["comment_cursor"]["base64url"].as_str().unwrap()
    );
    assert_eq!(
        hex(&page.encode().unwrap()),
        vector["comment_page_canonical_cbor_hex"].as_str().unwrap()
    );

    let reaction_unsigned = UnsignedReactionEventV1::new(
        "0190f2a5-7b42-7abc-8def-0123456789ab"
            .parse::<EventId>()
            .unwrap(),
        channel,
        post,
        ReactionTargetKindV1::Comment,
        receipt.thread_entry_hash(),
        ReactionKindV1::Like,
        true,
        SafeUint::new(1).unwrap(),
        None,
        decoded.actor_identity_id(),
        decoded.actor_device_id(),
        decoded.actor_identity_origin().to_owned(),
        SafeUint::new(1).unwrap(),
        policy.policy_digest().unwrap(),
        UtcMillis::new(1_725_000_000_002).unwrap(),
    )
    .unwrap();
    let reaction = SignedReactionEventV1::signed(
        reaction_unsigned.clone(),
        Ed25519Signature::from_bytes(
            actor
                .sign(&reaction_unsigned.signature_input().unwrap())
                .to_bytes(),
        ),
        actor_public,
    )
    .unwrap();
    let reaction_bytes = reaction.to_deterministic_cbor().unwrap();
    assert_eq!(
        hex(&reaction_bytes),
        vector["reaction"]["canonical_cbor_hex"].as_str().unwrap()
    );
    SignedReactionEventV1::decode(&reaction_bytes)
        .unwrap()
        .verify_with_key(actor_public)
        .unwrap();
    let reaction_receipt = ReactionReceiptV1::new(
        reaction.event_id(),
        reaction.event_digest().unwrap(),
        reaction.actor_revision(),
        UtcMillis::new(1_725_000_000_003).unwrap(),
    )
    .unwrap();
    let projection = ReactionProjectionV1::new(
        channel,
        post,
        ReactionTargetKindV1::Comment,
        receipt.thread_entry_hash(),
        ReactionKindV1::Like,
        vec![reaction_bytes.clone()],
    )
    .unwrap();
    assert_eq!(
        hex(reaction.event_digest().unwrap().as_bytes()),
        vector["reaction"]["event_digest_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&reaction_receipt.encode().unwrap()),
        vector["reaction_receipt_canonical_cbor_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        hex(&projection.encode().unwrap()),
        vector["reaction_projection_canonical_cbor_hex"]
            .as_str()
            .unwrap()
    );

    assert!(
        UnsignedReactionEventV1::new(
            reaction.event_id(),
            channel,
            post,
            ReactionTargetKindV1::Post,
            Sha256Digest::from_bytes([4; 32]),
            ReactionKindV1::Like,
            true,
            SafeUint::new(1).unwrap(),
            None,
            reaction.actor_identity_id(),
            reaction.actor_device_id(),
            reaction.actor_identity_origin().to_owned(),
            reaction.policy_revision(),
            reaction.policy_digest(),
            reaction.created_at(),
        )
        .is_err(),
        "a post reaction cannot substitute a cross-target digest",
    );
}
