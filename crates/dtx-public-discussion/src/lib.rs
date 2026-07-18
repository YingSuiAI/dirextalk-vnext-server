#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    reason = "the frozen V36 CDDL and OpenAPI define rejection semantics for this first-validation codec"
)]

//! Device-authenticated public Channel discussion facts.
//!
//! Public Discussion V1 is deliberately disjoint from the publisher-signed
//! Public Feed V1. A V24 feed entry hash is the immutable post identifier;
//! comments and actor-state reactions bind to it without changing its bytes.

use std::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{DeviceId, EventId, IdentityId, PublicSubjectId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};

pub const POLICY_EVENT_DIGEST_DOMAIN: &[u8] = b"dirextalk.public-discussion-policy-event.v1\0";
pub const POLICY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.public-discussion-policy-signature.v1\0";
pub const POLICY_ENTRY_DOMAIN: &[u8] = b"dirextalk.public-discussion-policy-entry.v1\0";
pub const COMMENT_EVENT_DIGEST_DOMAIN: &[u8] = b"dirextalk.public-comment-event.v1\0";
pub const COMMENT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.public-comment-signature.v1\0";
pub const COMMENT_EVENT_ENTRY_DOMAIN: &[u8] = b"dirextalk.public-comment-event-entry.v1\0";
pub const COMMENT_THREAD_ENTRY_DOMAIN: &[u8] = b"dirextalk.public-comment-thread-entry.v1\0";
pub const REACTION_EVENT_DIGEST_DOMAIN: &[u8] = b"dirextalk.public-reaction-event.v1\0";
pub const REACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.public-reaction-signature.v1\0";
pub const REACTION_EVENT_ENTRY_DOMAIN: &[u8] = b"dirextalk.public-reaction-event-entry.v1\0";
pub const REACTION_PROJECTION_DOMAIN: &[u8] = b"dirextalk.public-reaction-projection.v1\0";

const MAX_COMMENT_BODY_BYTES: usize = 4_096;
const MAX_IDENTITY_ORIGIN_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicDiscussionError {
    InvalidCanonical,
    InvalidWireVersion,
    InvalidChannel,
    InvalidAuthority,
    InvalidSignature,
    InvalidPolicy,
    InvalidEvent,
    InvalidTarget,
    InvalidReaction,
    InvalidCursor,
    InvalidPage,
}

impl fmt::Display for PublicDiscussionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCanonical => "public discussion bytes are not exact canonical CBOR",
            Self::InvalidWireVersion => "unsupported public discussion wire version",
            Self::InvalidChannel => "public discussion subject is not a Channel",
            Self::InvalidAuthority => "public discussion actor authority is invalid",
            Self::InvalidSignature => "public discussion signature is invalid",
            Self::InvalidPolicy => "public discussion policy is invalid",
            Self::InvalidEvent => "public discussion event is invalid",
            Self::InvalidTarget => "public discussion target is invalid",
            Self::InvalidReaction => "public discussion reaction state is invalid",
            Self::InvalidCursor => "public discussion cursor is invalid",
            Self::InvalidPage => "public discussion page is invalid",
        })
    }
}
impl Error for PublicDiscussionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DiscussionAcceptancePolicyV1 {
    VerifiedIdentity = 1,
}

impl DiscussionAcceptancePolicyV1 {
    fn decode(value: u64) -> Result<Self, PublicDiscussionError> {
        match value {
            1 => Ok(Self::VerifiedIdentity),
            _ => Err(PublicDiscussionError::InvalidPolicy),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedDiscussionPolicyV1 {
    channel_id: PublicSubjectId,
    owner_identity_id: IdentityId,
    owner_signing_key: SigningPublicKey,
    revision: SafeUint,
    previous_policy_digest: Option<Sha256Digest>,
    acceptance_policy: DiscussionAcceptancePolicyV1,
    issued_at: UtcMillis,
}

impl UnsignedDiscussionPolicyV1 {
    /// Creates an owner policy. V1 intentionally accepts only `verified_identity`.
    pub fn new(
        channel_id: PublicSubjectId,
        owner_identity_id: IdentityId,
        owner_signing_key: SigningPublicKey,
        revision: SafeUint,
        previous_policy_digest: Option<Sha256Digest>,
        acceptance_policy: DiscussionAcceptancePolicyV1,
        issued_at: UtcMillis,
    ) -> Result<Self, PublicDiscussionError> {
        require_channel(channel_id)?;
        owner_identity_id
            .verify_subject_key(owner_signing_key.as_domain_key())
            .map_err(|_| PublicDiscussionError::InvalidAuthority)?;
        if revision.get() == 0 || (revision.get() == 1) != previous_policy_digest.is_none() {
            return Err(PublicDiscussionError::InvalidPolicy);
        }
        Ok(Self {
            channel_id,
            owner_identity_id,
            owner_signing_key,
            revision,
            previous_policy_digest,
            acceptance_policy,
            issued_at,
        })
    }

    pub fn signature_input(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        Ok(signature_input(
            POLICY_EVENT_DIGEST_DOMAIN,
            POLICY_SIGNATURE_DOMAIN,
            &encode_deterministic_cbor(self)
                .map_err(|_| PublicDiscussionError::InvalidCanonical)?,
        ))
    }
}

impl CanonicalEncode for UnsignedDiscussionPolicyV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.channel_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.owner_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.owner_signing_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.revision.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                optional_digest_value(self.previous_policy_digest),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Unsigned(self.acceptance_policy as u64),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.issued_at.to_canonical_value(),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedDiscussionPolicyV1 {
    unsigned: UnsignedDiscussionPolicyV1,
    signature: Ed25519Signature,
}

impl SignedDiscussionPolicyV1 {
    pub fn signed(
        unsigned: UnsignedDiscussionPolicyV1,
        signature: Ed25519Signature,
    ) -> Result<Self, PublicDiscussionError> {
        let value = Self {
            unsigned,
            signature,
        };
        value.verify()?;
        Ok(value)
    }

    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, PublicDiscussionError> {
        let root = decode_deterministic_cbor(bytes)
            .map_err(|_| PublicDiscussionError::InvalidCanonical)?;
        let fields = exact_map(&root, 9)?;
        decode_wire(field(fields, 1)?)?;
        let value = Self::signed(
            UnsignedDiscussionPolicyV1::new(
                parse_channel(field(fields, 2)?)?,
                parse_identity(field(fields, 3)?)?,
                parse_signing_key(field(fields, 4)?)?,
                positive_safe_uint(field(fields, 5)?)
                    .map_err(|_| PublicDiscussionError::InvalidPolicy)?,
                optional_digest(field(fields, 6)?)?,
                DiscussionAcceptancePolicyV1::decode(unsigned(field(fields, 7)?)?)?,
                parse_time(field(fields, 8)?)?,
            )?,
            Ed25519Signature::from_bytes(bytes64(field(fields, 9)?)?),
        )?;
        require_exact(bytes, &value)?;
        Ok(value)
    }

    pub fn verify(&self) -> Result<(), PublicDiscussionError> {
        verify_signature(
            self.unsigned.owner_signing_key,
            self.signature,
            &self.unsigned.signature_input()?,
        )
    }

    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCanonical)
    }

    pub fn policy_digest(&self) -> Result<Sha256Digest, PublicDiscussionError> {
        Ok(Sha256Digest::hash_domain(
            POLICY_ENTRY_DOMAIN,
            &self.to_deterministic_cbor()?,
        ))
    }

    #[must_use]
    pub const fn channel_id(&self) -> PublicSubjectId {
        self.unsigned.channel_id
    }
    #[must_use]
    pub const fn owner_identity_id(&self) -> IdentityId {
        self.unsigned.owner_identity_id
    }
    #[must_use]
    pub const fn owner_signing_key(&self) -> SigningPublicKey {
        self.unsigned.owner_signing_key
    }
    #[must_use]
    pub const fn revision(&self) -> SafeUint {
        self.unsigned.revision
    }
    #[must_use]
    pub const fn previous_policy_digest(&self) -> Option<Sha256Digest> {
        self.unsigned.previous_policy_digest
    }
    #[must_use]
    pub const fn acceptance_policy(&self) -> DiscussionAcceptancePolicyV1 {
        self.unsigned.acceptance_policy
    }
    #[must_use]
    pub const fn issued_at(&self) -> UtcMillis {
        self.unsigned.issued_at
    }
}

impl CanonicalEncode for SignedDiscussionPolicyV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        append_signature(self.unsigned.to_canonical_value(), 9, self.signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedCommentEventV1 {
    event_id: EventId,
    channel_id: PublicSubjectId,
    post_hash: Sha256Digest,
    parent_comment_entry_hash: Option<Sha256Digest>,
    body: String,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    actor_identity_origin: String,
    policy_revision: SafeUint,
    policy_digest: Sha256Digest,
    created_at: UtcMillis,
}

impl UnsignedCommentEventV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: EventId,
        channel_id: PublicSubjectId,
        post_hash: Sha256Digest,
        parent_comment_entry_hash: Option<Sha256Digest>,
        body: String,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        actor_identity_origin: String,
        policy_revision: SafeUint,
        policy_digest: Sha256Digest,
        created_at: UtcMillis,
    ) -> Result<Self, PublicDiscussionError> {
        require_channel(channel_id)?;
        if !valid_body(&body)
            || !valid_identity_origin(&actor_identity_origin)
            || policy_revision.get() == 0
        {
            return Err(PublicDiscussionError::InvalidEvent);
        }
        Ok(Self {
            event_id,
            channel_id,
            post_hash,
            parent_comment_entry_hash,
            body,
            actor_identity_id,
            actor_device_id,
            actor_identity_origin,
            policy_revision,
            policy_digest,
            created_at,
        })
    }

    pub fn signature_input(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        Ok(signature_input(
            COMMENT_EVENT_DIGEST_DOMAIN,
            COMMENT_SIGNATURE_DOMAIN,
            &encode_deterministic_cbor(self)
                .map_err(|_| PublicDiscussionError::InvalidCanonical)?,
        ))
    }
}

impl CanonicalEncode for UnsignedCommentEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.event_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.channel_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.post_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                optional_digest_value(self.parent_comment_entry_hash),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(self.body.clone()),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text(self.actor_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Text(self.actor_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Text(self.actor_identity_origin.clone()),
            ),
            (
                CanonicalValue::Unsigned(10),
                self.policy_revision.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(11),
                self.policy_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(12),
                self.created_at.to_canonical_value(),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCommentEventV1 {
    unsigned: UnsignedCommentEventV1,
    signature: Ed25519Signature,
}

impl SignedCommentEventV1 {
    pub fn signed(
        unsigned: UnsignedCommentEventV1,
        signature: Ed25519Signature,
        device_signing_key: SigningPublicKey,
    ) -> Result<Self, PublicDiscussionError> {
        let value = Self {
            unsigned,
            signature,
        };
        value.verify_with_key(device_signing_key)?;
        Ok(value)
    }

    /// Decodes static bounds without trusting an actor-controlled key.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicDiscussionError> {
        let root = decode_deterministic_cbor(bytes)
            .map_err(|_| PublicDiscussionError::InvalidCanonical)?;
        let fields = exact_map(&root, 13)?;
        decode_wire(field(fields, 1)?)?;
        let value = Self {
            unsigned: UnsignedCommentEventV1::new(
                parse_event_id(field(fields, 2)?)?,
                parse_channel(field(fields, 3)?)?,
                digest(field(fields, 4)?)?,
                optional_digest(field(fields, 5)?)?,
                text(field(fields, 6)?)?.to_owned(),
                parse_identity(field(fields, 7)?)?,
                parse_device_id(field(fields, 8)?)?,
                text(field(fields, 9)?)?.to_owned(),
                positive_safe_uint(field(fields, 10)?)?,
                digest(field(fields, 11)?)?,
                parse_time(field(fields, 12)?)?,
            )?,
            signature: Ed25519Signature::from_bytes(bytes64(field(fields, 13)?)?),
        };
        require_exact(bytes, &value)?;
        Ok(value)
    }

    pub fn verify_with_key(
        &self,
        device_signing_key: SigningPublicKey,
    ) -> Result<(), PublicDiscussionError> {
        verify_signature(
            device_signing_key,
            self.signature,
            &self.unsigned.signature_input()?,
        )
    }

    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCanonical)
    }

    pub fn event_hash(&self) -> Result<Sha256Digest, PublicDiscussionError> {
        Ok(Sha256Digest::hash_domain(
            COMMENT_EVENT_ENTRY_DOMAIN,
            &self.to_deterministic_cbor()?,
        ))
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.unsigned.event_id
    }
    #[must_use]
    pub const fn channel_id(&self) -> PublicSubjectId {
        self.unsigned.channel_id
    }
    #[must_use]
    pub const fn post_hash(&self) -> Sha256Digest {
        self.unsigned.post_hash
    }
    #[must_use]
    pub const fn parent_comment_entry_hash(&self) -> Option<Sha256Digest> {
        self.unsigned.parent_comment_entry_hash
    }
    #[must_use]
    pub fn body(&self) -> &str {
        &self.unsigned.body
    }
    #[must_use]
    pub const fn actor_identity_id(&self) -> IdentityId {
        self.unsigned.actor_identity_id
    }
    #[must_use]
    pub const fn actor_device_id(&self) -> DeviceId {
        self.unsigned.actor_device_id
    }
    #[must_use]
    pub fn actor_identity_origin(&self) -> &str {
        &self.unsigned.actor_identity_origin
    }
    #[must_use]
    pub const fn policy_revision(&self) -> SafeUint {
        self.unsigned.policy_revision
    }
    #[must_use]
    pub const fn policy_digest(&self) -> Sha256Digest {
        self.unsigned.policy_digest
    }
    #[must_use]
    pub const fn created_at(&self) -> UtcMillis {
        self.unsigned.created_at
    }
}

impl CanonicalEncode for SignedCommentEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        append_signature(self.unsigned.to_canonical_value(), 13, self.signature)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReactionTargetKindV1 {
    Post = 1,
    Comment = 2,
}
impl ReactionTargetKindV1 {
    fn decode(value: u64) -> Result<Self, PublicDiscussionError> {
        match value {
            1 => Ok(Self::Post),
            2 => Ok(Self::Comment),
            _ => Err(PublicDiscussionError::InvalidTarget),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReactionKindV1 {
    Like = 1,
}
impl ReactionKindV1 {
    fn decode(value: u64) -> Result<Self, PublicDiscussionError> {
        match value {
            1 => Ok(Self::Like),
            _ => Err(PublicDiscussionError::InvalidReaction),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedReactionEventV1 {
    event_id: EventId,
    channel_id: PublicSubjectId,
    post_hash: Sha256Digest,
    target_kind: ReactionTargetKindV1,
    target_hash: Sha256Digest,
    reaction_kind: ReactionKindV1,
    active: bool,
    actor_revision: SafeUint,
    expected_previous_digest: Option<Sha256Digest>,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    actor_identity_origin: String,
    policy_revision: SafeUint,
    policy_digest: Sha256Digest,
    created_at: UtcMillis,
}

impl UnsignedReactionEventV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: EventId,
        channel_id: PublicSubjectId,
        post_hash: Sha256Digest,
        target_kind: ReactionTargetKindV1,
        target_hash: Sha256Digest,
        reaction_kind: ReactionKindV1,
        active: bool,
        actor_revision: SafeUint,
        expected_previous_digest: Option<Sha256Digest>,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        actor_identity_origin: String,
        policy_revision: SafeUint,
        policy_digest: Sha256Digest,
        created_at: UtcMillis,
    ) -> Result<Self, PublicDiscussionError> {
        require_channel(channel_id)?;
        if (target_kind == ReactionTargetKindV1::Post && target_hash != post_hash)
            || actor_revision.get() == 0
            || (actor_revision.get() == 1) != expected_previous_digest.is_none()
            || policy_revision.get() == 0
            || !valid_identity_origin(&actor_identity_origin)
        {
            return Err(PublicDiscussionError::InvalidReaction);
        }
        Ok(Self {
            event_id,
            channel_id,
            post_hash,
            target_kind,
            target_hash,
            reaction_kind,
            active,
            actor_revision,
            expected_previous_digest,
            actor_identity_id,
            actor_device_id,
            actor_identity_origin,
            policy_revision,
            policy_digest,
            created_at,
        })
    }

    pub fn signature_input(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        Ok(signature_input(
            REACTION_EVENT_DIGEST_DOMAIN,
            REACTION_SIGNATURE_DOMAIN,
            &encode_deterministic_cbor(self)
                .map_err(|_| PublicDiscussionError::InvalidCanonical)?,
        ))
    }
}

impl CanonicalEncode for UnsignedReactionEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.event_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.channel_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.post_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Unsigned(self.target_kind as u64),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.target_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Unsigned(self.reaction_kind as u64),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Bool(self.active),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.actor_revision.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(10),
                optional_digest_value(self.expected_previous_digest),
            ),
            (
                CanonicalValue::Unsigned(11),
                CanonicalValue::Text(self.actor_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(12),
                CanonicalValue::Text(self.actor_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(13),
                CanonicalValue::Text(self.actor_identity_origin.clone()),
            ),
            (
                CanonicalValue::Unsigned(14),
                self.policy_revision.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(15),
                self.policy_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(16),
                self.created_at.to_canonical_value(),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedReactionEventV1 {
    unsigned: UnsignedReactionEventV1,
    signature: Ed25519Signature,
}

impl SignedReactionEventV1 {
    pub fn signed(
        unsigned: UnsignedReactionEventV1,
        signature: Ed25519Signature,
        device_signing_key: SigningPublicKey,
    ) -> Result<Self, PublicDiscussionError> {
        let value = Self {
            unsigned,
            signature,
        };
        value.verify_with_key(device_signing_key)?;
        Ok(value)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PublicDiscussionError> {
        let root = decode_deterministic_cbor(bytes)
            .map_err(|_| PublicDiscussionError::InvalidCanonical)?;
        let fields = exact_map(&root, 17)?;
        decode_wire(field(fields, 1)?)?;
        let value = Self {
            unsigned: UnsignedReactionEventV1::new(
                parse_event_id(field(fields, 2)?)?,
                parse_channel(field(fields, 3)?)?,
                digest(field(fields, 4)?)?,
                ReactionTargetKindV1::decode(unsigned(field(fields, 5)?)?)?,
                digest(field(fields, 6)?)?,
                ReactionKindV1::decode(unsigned(field(fields, 7)?)?)?,
                boolean(field(fields, 8)?)?,
                positive_safe_uint(field(fields, 9)?)?,
                optional_digest(field(fields, 10)?)?,
                parse_identity(field(fields, 11)?)?,
                parse_device_id(field(fields, 12)?)?,
                text(field(fields, 13)?)?.to_owned(),
                positive_safe_uint(field(fields, 14)?)?,
                digest(field(fields, 15)?)?,
                parse_time(field(fields, 16)?)?,
            )?,
            signature: Ed25519Signature::from_bytes(bytes64(field(fields, 17)?)?),
        };
        require_exact(bytes, &value)?;
        Ok(value)
    }

    pub fn verify_with_key(
        &self,
        device_signing_key: SigningPublicKey,
    ) -> Result<(), PublicDiscussionError> {
        verify_signature(
            device_signing_key,
            self.signature,
            &self.unsigned.signature_input()?,
        )
    }

    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCanonical)
    }

    pub fn event_digest(&self) -> Result<Sha256Digest, PublicDiscussionError> {
        Ok(Sha256Digest::hash_domain(
            REACTION_EVENT_ENTRY_DOMAIN,
            &self.to_deterministic_cbor()?,
        ))
    }

    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.unsigned.event_id
    }
    #[must_use]
    pub const fn channel_id(&self) -> PublicSubjectId {
        self.unsigned.channel_id
    }
    #[must_use]
    pub const fn post_hash(&self) -> Sha256Digest {
        self.unsigned.post_hash
    }
    #[must_use]
    pub const fn target_kind(&self) -> ReactionTargetKindV1 {
        self.unsigned.target_kind
    }
    #[must_use]
    pub const fn target_hash(&self) -> Sha256Digest {
        self.unsigned.target_hash
    }
    #[must_use]
    pub const fn reaction_kind(&self) -> ReactionKindV1 {
        self.unsigned.reaction_kind
    }
    #[must_use]
    pub const fn active(&self) -> bool {
        self.unsigned.active
    }
    #[must_use]
    pub const fn actor_revision(&self) -> SafeUint {
        self.unsigned.actor_revision
    }
    #[must_use]
    pub const fn expected_previous_digest(&self) -> Option<Sha256Digest> {
        self.unsigned.expected_previous_digest
    }
    #[must_use]
    pub const fn actor_identity_id(&self) -> IdentityId {
        self.unsigned.actor_identity_id
    }
    #[must_use]
    pub const fn actor_device_id(&self) -> DeviceId {
        self.unsigned.actor_device_id
    }
    #[must_use]
    pub fn actor_identity_origin(&self) -> &str {
        &self.unsigned.actor_identity_origin
    }
    #[must_use]
    pub const fn policy_revision(&self) -> SafeUint {
        self.unsigned.policy_revision
    }
    #[must_use]
    pub const fn policy_digest(&self) -> Sha256Digest {
        self.unsigned.policy_digest
    }
    #[must_use]
    pub const fn created_at(&self) -> UtcMillis {
        self.unsigned.created_at
    }
}

impl CanonicalEncode for SignedReactionEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        append_signature(self.unsigned.to_canonical_value(), 17, self.signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommentReceiptV1 {
    sequence: SafeUint,
    previous_thread_entry_hash: Option<Sha256Digest>,
    thread_entry_hash: Sha256Digest,
    exact_signed_comment: Vec<u8>,
}

impl CommentReceiptV1 {
    pub fn new(
        sequence: SafeUint,
        previous_thread_entry_hash: Option<Sha256Digest>,
        exact_signed_comment: Vec<u8>,
    ) -> Result<Self, PublicDiscussionError> {
        let event = SignedCommentEventV1::decode(&exact_signed_comment)?;
        if sequence.get() == 0 || (sequence.get() == 1) != previous_thread_entry_hash.is_none() {
            return Err(PublicDiscussionError::InvalidPage);
        }
        let thread_entry_hash =
            comment_thread_entry_hash(sequence, previous_thread_entry_hash, event.event_hash()?);
        Ok(Self {
            sequence,
            previous_thread_entry_hash,
            thread_entry_hash,
            exact_signed_comment,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PublicDiscussionError> {
        let root = decode_deterministic_cbor(bytes)
            .map_err(|_| PublicDiscussionError::InvalidCanonical)?;
        let fields = exact_map(&root, 5)?;
        decode_wire(field(fields, 1)?)?;
        let value = Self::new(
            positive_safe_uint(field(fields, 2)?)?,
            optional_digest(field(fields, 3)?)?,
            byte_string(field(fields, 5)?)?.to_vec(),
        )?;
        if value.thread_entry_hash != digest(field(fields, 4)?)? {
            return Err(PublicDiscussionError::InvalidPage);
        }
        require_exact(bytes, &value)?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCanonical)
    }

    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.sequence
    }
    #[must_use]
    pub const fn previous_thread_entry_hash(&self) -> Option<Sha256Digest> {
        self.previous_thread_entry_hash
    }
    #[must_use]
    pub const fn thread_entry_hash(&self) -> Sha256Digest {
        self.thread_entry_hash
    }
    #[must_use]
    pub fn exact_signed_comment(&self) -> &[u8] {
        &self.exact_signed_comment
    }
}

impl CanonicalEncode for CommentReceiptV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                self.sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(3),
                optional_digest_value(self.previous_thread_entry_hash),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.thread_entry_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Bytes(self.exact_signed_comment.clone()),
            ),
        ])
    }
}

#[must_use]
pub fn comment_thread_entry_hash(
    sequence: SafeUint,
    previous: Option<Sha256Digest>,
    event_hash: Sha256Digest,
) -> Sha256Digest {
    let mut material = Vec::with_capacity(8 + 32 + 32);
    material.extend_from_slice(&sequence.get().to_be_bytes());
    let previous_bytes = previous.map_or([0_u8; 32], |digest| *digest.as_bytes());
    material.extend_from_slice(&previous_bytes);
    material.extend_from_slice(event_hash.as_bytes());
    Sha256Digest::hash_domain(COMMENT_THREAD_ENTRY_DOMAIN, &material)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommentCursorV1 {
    channel_id: PublicSubjectId,
    post_hash: Sha256Digest,
    after_sequence: SafeUint,
    snapshot_sequence: SafeUint,
    snapshot_hash: Sha256Digest,
}

impl CommentCursorV1 {
    pub fn new(
        channel_id: PublicSubjectId,
        post_hash: Sha256Digest,
        after_sequence: SafeUint,
        snapshot_sequence: SafeUint,
        snapshot_hash: Sha256Digest,
    ) -> Result<Self, PublicDiscussionError> {
        require_channel(channel_id)?;
        if snapshot_sequence.get() == 0 || after_sequence.get() > snapshot_sequence.get() {
            return Err(PublicDiscussionError::InvalidCursor);
        }
        Ok(Self {
            channel_id,
            post_hash,
            after_sequence,
            snapshot_sequence,
            snapshot_hash,
        })
    }

    pub fn encode(&self) -> Result<String, PublicDiscussionError> {
        Ok(Base64UrlUnpadded::encode_string(
            &encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCursor)?,
        ))
    }

    pub fn decode(value: &str) -> Result<Self, PublicDiscussionError> {
        let bytes = Base64UrlUnpadded::decode_vec(value)
            .map_err(|_| PublicDiscussionError::InvalidCursor)?;
        let root =
            decode_deterministic_cbor(&bytes).map_err(|_| PublicDiscussionError::InvalidCursor)?;
        let fields = exact_map(&root, 5)?;
        Self::new(
            parse_channel(field(fields, 1)?)?,
            digest(field(fields, 2)?)?,
            safe_uint(field(fields, 3)?)?,
            positive_safe_uint(field(fields, 4)?)?,
            digest(field(fields, 5)?)?,
        )
    }

    #[must_use]
    pub const fn channel_id(&self) -> PublicSubjectId {
        self.channel_id
    }
    #[must_use]
    pub const fn post_hash(&self) -> Sha256Digest {
        self.post_hash
    }
    #[must_use]
    pub const fn after_sequence(&self) -> SafeUint {
        self.after_sequence
    }
    #[must_use]
    pub const fn snapshot_sequence(&self) -> SafeUint {
        self.snapshot_sequence
    }
    #[must_use]
    pub const fn snapshot_hash(&self) -> Sha256Digest {
        self.snapshot_hash
    }
}

impl CanonicalEncode for CommentCursorV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Text(self.channel_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(2),
                self.post_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.after_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.snapshot_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.snapshot_hash.to_canonical_value(),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommentPageV1 {
    channel_id: PublicSubjectId,
    post_hash: Sha256Digest,
    exact_receipts: Vec<Vec<u8>>,
    next_cursor: Option<String>,
    snapshot_sequence: SafeUint,
    snapshot_hash: Sha256Digest,
}

impl CommentPageV1 {
    pub fn new(
        channel_id: PublicSubjectId,
        post_hash: Sha256Digest,
        exact_receipts: Vec<Vec<u8>>,
        next_cursor: Option<String>,
        snapshot_sequence: SafeUint,
        snapshot_hash: Sha256Digest,
    ) -> Result<Self, PublicDiscussionError> {
        require_channel(channel_id)?;
        if exact_receipts.is_empty() || snapshot_sequence.get() == 0 {
            return Err(PublicDiscussionError::InvalidPage);
        }
        for exact in &exact_receipts {
            let receipt = CommentReceiptV1::decode(exact)?;
            let comment = SignedCommentEventV1::decode(receipt.exact_signed_comment())?;
            if comment.channel_id() != channel_id || comment.post_hash() != post_hash {
                return Err(PublicDiscussionError::InvalidPage);
            }
        }
        if let Some(cursor) = &next_cursor {
            let cursor = CommentCursorV1::decode(cursor)?;
            if cursor.channel_id != channel_id
                || cursor.post_hash != post_hash
                || cursor.snapshot_sequence != snapshot_sequence
                || cursor.snapshot_hash != snapshot_hash
            {
                return Err(PublicDiscussionError::InvalidPage);
            }
        }
        Ok(Self {
            channel_id,
            post_hash,
            exact_receipts,
            next_cursor,
            snapshot_sequence,
            snapshot_hash,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCanonical)
    }
}

impl CanonicalEncode for CommentPageV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.channel_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.post_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Array(
                    self.exact_receipts
                        .iter()
                        .cloned()
                        .map(CanonicalValue::Bytes)
                        .collect(),
                ),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.next_cursor
                    .clone()
                    .map_or(CanonicalValue::Null, CanonicalValue::Text),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.snapshot_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.snapshot_hash.to_canonical_value(),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactionReceiptV1 {
    event_id: EventId,
    event_digest: Sha256Digest,
    actor_revision: SafeUint,
    accepted_at: UtcMillis,
}

impl ReactionReceiptV1 {
    pub fn new(
        event_id: EventId,
        event_digest: Sha256Digest,
        actor_revision: SafeUint,
        accepted_at: UtcMillis,
    ) -> Result<Self, PublicDiscussionError> {
        if actor_revision.get() == 0 {
            return Err(PublicDiscussionError::InvalidReaction);
        }
        Ok(Self {
            event_id,
            event_digest,
            actor_revision,
            accepted_at,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCanonical)
    }
}

impl CanonicalEncode for ReactionReceiptV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.event_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.event_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.actor_revision.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.accepted_at.to_canonical_value(),
            ),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactionProjectionV1 {
    channel_id: PublicSubjectId,
    post_hash: Sha256Digest,
    target_kind: ReactionTargetKindV1,
    target_hash: Sha256Digest,
    reaction_kind: ReactionKindV1,
    exact_current_events: Vec<Vec<u8>>,
    projection_digest: Sha256Digest,
}

impl ReactionProjectionV1 {
    pub fn new(
        channel_id: PublicSubjectId,
        post_hash: Sha256Digest,
        target_kind: ReactionTargetKindV1,
        target_hash: Sha256Digest,
        reaction_kind: ReactionKindV1,
        exact_current_events: Vec<Vec<u8>>,
    ) -> Result<Self, PublicDiscussionError> {
        require_channel(channel_id)?;
        if target_kind == ReactionTargetKindV1::Post && target_hash != post_hash {
            return Err(PublicDiscussionError::InvalidTarget);
        }
        let mut previous_actor = None;
        for exact in &exact_current_events {
            let event = SignedReactionEventV1::decode(exact)?;
            if event.channel_id() != channel_id
                || event.post_hash() != post_hash
                || event.target_kind() != target_kind
                || event.target_hash() != target_hash
                || event.reaction_kind() != reaction_kind
                || previous_actor.is_some_and(|actor| actor >= event.actor_identity_id())
            {
                return Err(PublicDiscussionError::InvalidReaction);
            }
            previous_actor = Some(event.actor_identity_id());
        }
        let mut material = Vec::new();
        for exact in &exact_current_events {
            material.extend_from_slice(&(exact.len() as u64).to_be_bytes());
            material.extend_from_slice(exact);
        }
        let projection_digest = Sha256Digest::hash_domain(REACTION_PROJECTION_DOMAIN, &material);
        Ok(Self {
            channel_id,
            post_hash,
            target_kind,
            target_hash,
            reaction_kind,
            exact_current_events,
            projection_digest,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PublicDiscussionError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDiscussionError::InvalidCanonical)
    }
}

impl CanonicalEncode for ReactionProjectionV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), wire_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.channel_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.post_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Unsigned(self.target_kind as u64),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.target_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Unsigned(self.reaction_kind as u64),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Array(
                    self.exact_current_events
                        .iter()
                        .cloned()
                        .map(CanonicalValue::Bytes)
                        .collect(),
                ),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.projection_digest.to_canonical_value(),
            ),
        ])
    }
}

fn signature_input(digest_domain: &[u8], signature_domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let digest = Sha256Digest::hash_domain(digest_domain, bytes);
    [signature_domain, digest.as_bytes()].concat()
}

fn verify_signature(
    key: SigningPublicKey,
    signature: Ed25519Signature,
    input: &[u8],
) -> Result<(), PublicDiscussionError> {
    VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| PublicDiscussionError::InvalidSignature)?
        .verify_strict(input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| PublicDiscussionError::InvalidSignature)
}

fn append_signature(
    unsigned: CanonicalValue,
    key: u64,
    signature: Ed25519Signature,
) -> CanonicalValue {
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!();
    };
    fields.push((
        CanonicalValue::Unsigned(key),
        signature.to_canonical_value(),
    ));
    CanonicalValue::Map(fields)
}

fn wire_value() -> CanonicalValue {
    WireVersion::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0)).to_canonical_value()
}

fn require_channel(value: PublicSubjectId) -> Result<(), PublicDiscussionError> {
    if matches!(value, PublicSubjectId::Channel(_)) {
        Ok(())
    } else {
        Err(PublicDiscussionError::InvalidChannel)
    }
}

fn valid_body(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COMMENT_BODY_BYTES
        && value.chars().all(|character| {
            (!character.is_control() || matches!(character, '\n' | '\t'))
                && !matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
        })
}

fn valid_identity_origin(value: &str) -> bool {
    if !(10..=MAX_IDENTITY_ORIGIN_BYTES).contains(&value.len())
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    authority.is_some_and(|authority| {
        !authority.is_empty()
            && !authority.ends_with('.')
            && !authority.contains(['/', '@', '?', '#', '\\'])
            && authority.bytes().all(|byte| byte.is_ascii_graphic())
    })
}

fn optional_digest_value(value: Option<Sha256Digest>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, |digest| digest.to_canonical_value())
}

fn require_exact<T: CanonicalEncode>(bytes: &[u8], value: &T) -> Result<(), PublicDiscussionError> {
    if encode_deterministic_cbor(value).map_err(|_| PublicDiscussionError::InvalidCanonical)?
        == bytes
    {
        Ok(())
    } else {
        Err(PublicDiscussionError::InvalidCanonical)
    }
}

fn exact_map(
    value: &CanonicalValue,
    length: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], PublicDiscussionError> {
    match value {
        CanonicalValue::Map(fields) if fields.len() == length => Ok(fields),
        _ => Err(PublicDiscussionError::InvalidCanonical),
    }
}
fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: u64,
) -> Result<&CanonicalValue, PublicDiscussionError> {
    fields
        .iter()
        .find_map(|(candidate, value)| {
            (*candidate == CanonicalValue::Unsigned(key)).then_some(value)
        })
        .ok_or(PublicDiscussionError::InvalidCanonical)
}
fn unsigned(value: &CanonicalValue) -> Result<u64, PublicDiscussionError> {
    match value {
        CanonicalValue::Unsigned(value) => Ok(*value),
        _ => Err(PublicDiscussionError::InvalidCanonical),
    }
}
fn boolean(value: &CanonicalValue) -> Result<bool, PublicDiscussionError> {
    match value {
        CanonicalValue::Bool(value) => Ok(*value),
        _ => Err(PublicDiscussionError::InvalidCanonical),
    }
}
fn text(value: &CanonicalValue) -> Result<&str, PublicDiscussionError> {
    match value {
        CanonicalValue::Text(value) => Ok(value),
        _ => Err(PublicDiscussionError::InvalidCanonical),
    }
}
fn byte_string(value: &CanonicalValue) -> Result<&[u8], PublicDiscussionError> {
    match value {
        CanonicalValue::Bytes(value) => Ok(value),
        _ => Err(PublicDiscussionError::InvalidCanonical),
    }
}
fn bytes32(value: &CanonicalValue) -> Result<[u8; 32], PublicDiscussionError> {
    byte_string(value)?
        .try_into()
        .map_err(|_| PublicDiscussionError::InvalidCanonical)
}
fn bytes64(value: &CanonicalValue) -> Result<[u8; 64], PublicDiscussionError> {
    byte_string(value)?
        .try_into()
        .map_err(|_| PublicDiscussionError::InvalidCanonical)
}
fn digest(value: &CanonicalValue) -> Result<Sha256Digest, PublicDiscussionError> {
    Ok(Sha256Digest::from_bytes(bytes32(value)?))
}
fn optional_digest(value: &CanonicalValue) -> Result<Option<Sha256Digest>, PublicDiscussionError> {
    match value {
        CanonicalValue::Null => Ok(None),
        _ => digest(value).map(Some),
    }
}
fn safe_uint(value: &CanonicalValue) -> Result<SafeUint, PublicDiscussionError> {
    SafeUint::new(unsigned(value)?).map_err(|_| PublicDiscussionError::InvalidCanonical)
}
fn positive_safe_uint(value: &CanonicalValue) -> Result<SafeUint, PublicDiscussionError> {
    let value = safe_uint(value)?;
    if value.get() == 0 {
        Err(PublicDiscussionError::InvalidCanonical)
    } else {
        Ok(value)
    }
}
fn parse_time(value: &CanonicalValue) -> Result<UtcMillis, PublicDiscussionError> {
    let raw = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| PublicDiscussionError::InvalidCanonical)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(PublicDiscussionError::InvalidCanonical),
    };
    UtcMillis::new(raw).map_err(|_| PublicDiscussionError::InvalidCanonical)
}
fn parse_channel(value: &CanonicalValue) -> Result<PublicSubjectId, PublicDiscussionError> {
    let channel = text(value)?
        .parse()
        .map_err(|_| PublicDiscussionError::InvalidChannel)?;
    require_channel(channel)?;
    Ok(channel)
}
fn parse_identity(value: &CanonicalValue) -> Result<IdentityId, PublicDiscussionError> {
    text(value)?
        .parse()
        .map_err(|_| PublicDiscussionError::InvalidAuthority)
}
fn parse_event_id(value: &CanonicalValue) -> Result<EventId, PublicDiscussionError> {
    text(value)?
        .parse()
        .map_err(|_| PublicDiscussionError::InvalidEvent)
}
fn parse_device_id(value: &CanonicalValue) -> Result<DeviceId, PublicDiscussionError> {
    text(value)?
        .parse()
        .map_err(|_| PublicDiscussionError::InvalidAuthority)
}
fn parse_signing_key(value: &CanonicalValue) -> Result<SigningPublicKey, PublicDiscussionError> {
    SigningPublicKey::try_from(bytes32(value)?).map_err(|_| PublicDiscussionError::InvalidAuthority)
}
fn decode_wire(value: &CanonicalValue) -> Result<(), PublicDiscussionError> {
    let fields = exact_map(value, 2)?;
    for key in [1_u64, 2] {
        let version = exact_map(field(fields, key)?, 2)?;
        if unsigned(field(version, 1)?)? != 1 || unsigned(field(version, 2)?)? != 0 {
            return Err(PublicDiscussionError::InvalidWireVersion);
        }
    }
    Ok(())
}
