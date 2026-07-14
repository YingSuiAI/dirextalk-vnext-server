#![forbid(unsafe_code)]

//! Signed public Channel and Agent descriptor primitives.
//!
//! Current V1.2 descriptors expose only a canonical DNS HTTPS `feed_origin`;
//! clients derive the fixed subject path themselves. Frozen V1.0/V1.1 bytes can
//! be decoded only through their explicit historical wrappers. This crate is
//! deliberately a pure protocol/reducer boundary. It has no tenant, database,
//! Matrix, HTTP, indexer, mailbox, token, or private-key dependency.
//! Public `dtxc1`/`dtxa1` subject IDs are self-certifying values derived from a
//! descriptor subject genesis key; they are never an internal control-plane
//! UUID, alias, or endpoint.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    str::FromStr,
};

use dtx_domain::{IdentityId, PublicSubjectId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};

/// Frozen public-descriptor `1.0` protocol version retained only for history reads.
pub const PUBLIC_DESCRIPTOR_V1_0_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
/// Exact frozen public-descriptor `1.0` wire version.
pub const PUBLIC_DESCRIPTOR_V1_0_WIRE_VERSION: WireVersion = WireVersion::new(
    PUBLIC_DESCRIPTOR_V1_0_PROTOCOL_VERSION,
    PUBLIC_DESCRIPTOR_V1_0_PROTOCOL_VERSION,
);
/// Frozen public-descriptor `1.1` protocol version retained only for history reads.
pub const PUBLIC_DESCRIPTOR_V1_1_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 1);
/// Exact frozen public-descriptor `1.1` wire version.
pub const PUBLIC_DESCRIPTOR_V1_1_WIRE_VERSION: WireVersion = WireVersion::new(
    PUBLIC_DESCRIPTOR_V1_1_PROTOCOL_VERSION,
    PUBLIC_DESCRIPTOR_V1_1_PROTOCOL_VERSION,
);
/// Current writable public-descriptor protocol version.
pub const PUBLIC_DESCRIPTOR_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 2);
/// Exact current writer and reader version for public signed descriptors.
pub const PUBLIC_DESCRIPTOR_WIRE_VERSION: WireVersion = WireVersion::new(
    PUBLIC_DESCRIPTOR_PROTOCOL_VERSION,
    PUBLIC_DESCRIPTOR_PROTOCOL_VERSION,
);

/// Domain separator for the deterministic unsigned descriptor digest.
pub const PUBLIC_DESCRIPTOR_HASH_DOMAIN: &[u8] = b"dirextalk.public-descriptor.v1\0";
/// Domain separator for an Ed25519 signature over a descriptor digest.
pub const PUBLIC_DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.public-descriptor-signature.v1\0";
/// Domain separator for the complete signed descriptor head hash.
pub const PUBLIC_DESCRIPTOR_ENTRY_HASH_DOMAIN: &[u8] = b"dirextalk.public-descriptor-entry.v1\0";

const MAX_FEED_ENDPOINT_BYTES: usize = 512;
/// Fixed public feed document root. V1.2 derives a subject-specific path under it.
pub const PUBLIC_FEED_WELL_KNOWN_PATH_PREFIX: &str = "/.well-known/dirextalk/public/v1/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicDescriptorWireLine {
    FrozenV1_0,
    FrozenV1_1,
    CurrentV1_2,
}

/// Public descriptor admission or reduction failed without exposing a secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicDescriptorError {
    /// A descriptor used a schema or minimum-reader version outside V1.
    InvalidWireVersion,
    /// Bytes or typed fields did not use the exact canonical V1 shape.
    InvalidCanonical,
    /// The Ed25519 proof did not authenticate the bound publisher key.
    InvalidSignature,
    /// The declared Channel or Agent ID does not derive from its genesis key.
    InvalidSubjectBinding,
    /// The publisher identity ID does not derive from its genesis signing key.
    InvalidPublisherBinding,
    /// The publisher does not control the self-certifying subject genesis key.
    SubjectPublisherBindingMismatch,
    /// The sequence, predecessor, expiry relation, or tombstone shape is invalid.
    InvalidDescriptorShape,
    /// A frozen V1.0 feed endpoint is malformed for historical verification.
    InvalidFeedEndpoint,
    /// A current V1.2 public feed origin is unsafe, ambiguous, or outside bounds.
    InvalidFeedOrigin,
    /// A live descriptor is expired at the caller's trusted clock.
    Expired,
    /// A descriptor starts after the caller's trusted clock.
    NotYetValid,
    /// The exact already accepted signed descriptor was submitted again.
    Replay,
    /// A candidate conflicts with the accepted descriptor chain at a sequence or head.
    Equivocation,
    /// A candidate leaves a sequence gap after the accepted head.
    SequenceMismatch,
    /// A candidate belongs to a different self-certifying Channel or Agent subject.
    SubjectMismatch,
    /// A candidate changes the immutable publisher identity binding.
    PublisherMismatch,
    /// A descriptor was appended after a permanent tombstone.
    Tombstoned,
}

impl fmt::Display for PublicDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWireVersion => "public descriptor uses an unsupported wire version",
            Self::InvalidCanonical => "public descriptor bytes do not match the canonical contract",
            Self::InvalidSignature => "public descriptor signature is invalid",
            Self::InvalidSubjectBinding => {
                "public descriptor subject ID does not bind its genesis key"
            }
            Self::InvalidPublisherBinding => {
                "public descriptor publisher identity does not bind its genesis key"
            }
            Self::SubjectPublisherBindingMismatch => {
                "public descriptor publisher does not control the subject genesis key"
            }
            Self::InvalidDescriptorShape => "public descriptor has an invalid shape",
            Self::InvalidFeedEndpoint => "historical public descriptor feed endpoint is invalid",
            Self::InvalidFeedOrigin => "public descriptor feed origin is invalid",
            Self::Expired => "public descriptor is expired",
            Self::NotYetValid => "public descriptor is not active yet",
            Self::Replay => "public descriptor was already accepted",
            Self::Equivocation => "public descriptor conflicts with the accepted head",
            Self::SequenceMismatch => "public descriptor sequence leaves a gap",
            Self::SubjectMismatch => "public descriptor belongs to another subject",
            Self::PublisherMismatch => "public descriptor changes its publisher binding",
            Self::Tombstoned => "public descriptor subject is permanently tombstoned",
        })
    }
}

impl Error for PublicDescriptorError {}

/// Kind of self-certifying public subject described by a V1 descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicDescriptorKindV1 {
    /// A public Channel with a signed append-only public feed.
    Channel,
    /// A discoverable Agent definition with a signed manifest reference.
    Agent,
}

impl PublicDescriptorKindV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Channel => 1,
            Self::Agent => 2,
        }
    }

    fn from_code(value: u64) -> Result<Self, PublicDescriptorError> {
        match value {
            1 => Ok(Self::Channel),
            2 => Ok(Self::Agent),
            _ => Err(PublicDescriptorError::InvalidCanonical),
        }
    }
}

/// Mutable public content carried by a signed descriptor chain entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicDescriptorPayloadV1 {
    /// A live public Channel descriptor.
    Channel {
        /// HTTPS authority-only origin of the Channel's signed public feed.
        feed_origin: String,
        /// SHA-256 digest of the Channel capability declaration.
        capability_digest: Sha256Digest,
    },
    /// A live discoverable Agent descriptor.
    Agent {
        /// HTTPS authority-only origin of the Agent's signed public feed.
        feed_origin: String,
        /// SHA-256 digest of the Agent capability declaration.
        capability_digest: Sha256Digest,
        /// SHA-256 digest of the Agent manifest or provenance document.
        manifest_digest: Sha256Digest,
    },
    /// Permanent public subject revocation with no live endpoint or artifact reference.
    Tombstone,
    /// Frozen V1.0 Channel payload, available only to the historical decoder.
    #[doc(hidden)]
    LegacyChannelV1_0 {
        /// Exact historical endpoint bytes, never accepted by the current writer.
        feed_endpoint: String,
        /// SHA-256 digest of the historical Channel capability declaration.
        capability_digest: Sha256Digest,
    },
    /// Frozen V1.0 Agent payload, available only to the historical decoder.
    #[doc(hidden)]
    LegacyAgentV1_0 {
        /// Exact historical endpoint bytes, never accepted by the current writer.
        feed_endpoint: String,
        /// SHA-256 digest of the historical Agent capability declaration.
        capability_digest: Sha256Digest,
        /// SHA-256 digest of the historical Agent manifest or provenance document.
        manifest_digest: Sha256Digest,
    },
    /// Frozen V1.1 Channel payload, available only to the historical decoder.
    #[doc(hidden)]
    LegacyChannelV1_1 {
        /// Exact historical origin bytes, never accepted by the current writer.
        feed_origin: String,
        /// SHA-256 digest of the historical Channel capability declaration.
        capability_digest: Sha256Digest,
    },
    /// Frozen V1.1 Agent payload, available only to the historical decoder.
    #[doc(hidden)]
    LegacyAgentV1_1 {
        /// Exact historical origin bytes, never accepted by the current writer.
        feed_origin: String,
        /// SHA-256 digest of the historical Agent capability declaration.
        capability_digest: Sha256Digest,
        /// SHA-256 digest of the historical Agent manifest or provenance document.
        manifest_digest: Sha256Digest,
    },
}

impl PublicDescriptorPayloadV1 {
    const fn code(&self) -> u64 {
        match self {
            Self::Channel { .. }
            | Self::LegacyChannelV1_0 { .. }
            | Self::LegacyChannelV1_1 { .. } => 1,
            Self::Agent { .. } | Self::LegacyAgentV1_0 { .. } | Self::LegacyAgentV1_1 { .. } => 2,
            Self::Tombstone => 3,
        }
    }

    fn to_canonical_value(&self) -> CanonicalValue {
        match self {
            Self::Channel {
                feed_origin,
                capability_digest,
            }
            | Self::LegacyChannelV1_1 {
                feed_origin,
                capability_digest,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text(feed_origin.clone()),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    capability_digest.to_canonical_value(),
                ),
            ]),
            Self::Agent {
                feed_origin,
                capability_digest,
                manifest_digest,
            }
            | Self::LegacyAgentV1_1 {
                feed_origin,
                capability_digest,
                manifest_digest,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text(feed_origin.clone()),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    capability_digest.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    manifest_digest.to_canonical_value(),
                ),
            ]),
            Self::Tombstone => CanonicalValue::Map(Vec::new()),
            Self::LegacyChannelV1_0 {
                feed_endpoint,
                capability_digest,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text(feed_endpoint.clone()),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    capability_digest.to_canonical_value(),
                ),
            ]),
            Self::LegacyAgentV1_0 {
                feed_endpoint,
                capability_digest,
                manifest_digest,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text(feed_endpoint.clone()),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    capability_digest.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    manifest_digest.to_canonical_value(),
                ),
            ]),
        }
    }

    const fn is_tombstone(&self) -> bool {
        matches!(self, Self::Tombstone)
    }

    fn feed_origin(&self) -> Option<&str> {
        match self {
            Self::Channel { feed_origin, .. } | Self::Agent { feed_origin, .. } => {
                Some(feed_origin)
            }
            Self::Tombstone
            | Self::LegacyChannelV1_0 { .. }
            | Self::LegacyAgentV1_0 { .. }
            | Self::LegacyChannelV1_1 { .. }
            | Self::LegacyAgentV1_1 { .. } => None,
        }
    }
}

/// Exact unsigned fields authenticated by a publisher identity genesis key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedPublicDescriptorV1 {
    wire: WireVersion,
    kind: PublicDescriptorKindV1,
    subject_id: PublicSubjectId,
    subject_genesis_signing_key: SigningPublicKey,
    publisher_identity_id: IdentityId,
    publisher_identity_genesis_signing_key: SigningPublicKey,
    sequence: SafeUint,
    previous_descriptor_hash: Option<Sha256Digest>,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    payload: PublicDescriptorPayloadV1,
}

impl UnsignedPublicDescriptorV1 {
    /// Creates strictly validated current V1.2 unsigned descriptor content.
    ///
    /// `subject_id` must be `dtxc1` for Channel or `dtxa1` for Agent and must
    /// derive from `subject_genesis_signing_key`. The publisher identity is
    /// independently self-certifying; V1 requires its genesis key to equal
    /// the subject genesis key, and that one key signs the descriptor.
    ///
    /// # Errors
    ///
    /// Returns a descriptor error for an unsupported wire line, mismatched
    /// self-certifying ID, invalid sequence or expiry shape, or invalid public
    /// payload origin. Frozen V1.0/V1.1 are deliberately not writer inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wire: WireVersion,
        kind: PublicDescriptorKindV1,
        subject_id: PublicSubjectId,
        subject_genesis_signing_key: SigningPublicKey,
        publisher_identity_id: IdentityId,
        publisher_identity_genesis_signing_key: SigningPublicKey,
        sequence: SafeUint,
        previous_descriptor_hash: Option<Sha256Digest>,
        issued_at: UtcMillis,
        expires_at: UtcMillis,
        payload: PublicDescriptorPayloadV1,
    ) -> Result<Self, PublicDescriptorError> {
        if wire != PUBLIC_DESCRIPTOR_WIRE_VERSION {
            return Err(PublicDescriptorError::InvalidWireVersion);
        }
        let descriptor = Self {
            wire,
            kind,
            subject_id,
            subject_genesis_signing_key,
            publisher_identity_id,
            publisher_identity_genesis_signing_key,
            sequence,
            previous_descriptor_hash,
            issued_at,
            expires_at,
            payload,
        };
        descriptor.validate_static_current()?;
        Ok(descriptor)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_decoded(
        wire: WireVersion,
        kind: PublicDescriptorKindV1,
        subject_id: PublicSubjectId,
        subject_genesis_signing_key: SigningPublicKey,
        publisher_identity_id: IdentityId,
        publisher_identity_genesis_signing_key: SigningPublicKey,
        sequence: SafeUint,
        previous_descriptor_hash: Option<Sha256Digest>,
        issued_at: UtcMillis,
        expires_at: UtcMillis,
        payload: PublicDescriptorPayloadV1,
    ) -> Result<Self, PublicDescriptorError> {
        let descriptor = Self {
            wire,
            kind,
            subject_id,
            subject_genesis_signing_key,
            publisher_identity_id,
            publisher_identity_genesis_signing_key,
            sequence,
            previous_descriptor_hash,
            issued_at,
            expires_at,
            payload,
        };
        descriptor.validate_static_any()?;
        Ok(descriptor)
    }

    /// Computes the canonical descriptor digest authenticated by the publisher.
    ///
    /// # Errors
    ///
    /// Returns [`PublicDescriptorError::InvalidCanonical`] if deterministic
    /// CBOR cannot encode the bounded descriptor shape.
    pub fn signing_digest(&self) -> Result<Sha256Digest, PublicDescriptorError> {
        canonical_hash(PUBLIC_DESCRIPTOR_HASH_DOMAIN, self)
    }

    /// Returns the exact domain-separated bytes to sign with the publisher key.
    ///
    /// # Errors
    ///
    /// Returns [`PublicDescriptorError::InvalidCanonical`] when the descriptor
    /// cannot be represented in deterministic CBOR.
    pub fn signature_input(&self) -> Result<Vec<u8>, PublicDescriptorError> {
        Ok(signature_input(
            PUBLIC_DESCRIPTOR_SIGNATURE_DOMAIN,
            self.signing_digest()?,
        ))
    }

    fn validate_static_current(&self) -> Result<(), PublicDescriptorError> {
        if public_descriptor_wire_line(self.wire)? != PublicDescriptorWireLine::CurrentV1_2 {
            return Err(PublicDescriptorError::InvalidWireVersion);
        }
        self.validate_static_any()
    }

    fn validate_static_any(&self) -> Result<(), PublicDescriptorError> {
        let wire_line = public_descriptor_wire_line(self.wire)?;
        match (self.kind, self.subject_id) {
            (PublicDescriptorKindV1::Channel, PublicSubjectId::Channel(id)) => id
                .verify_subject_key(self.subject_genesis_signing_key.as_domain_key())
                .map_err(|_| PublicDescriptorError::InvalidSubjectBinding)?,
            (PublicDescriptorKindV1::Agent, PublicSubjectId::Agent(id)) => id
                .verify_subject_key(self.subject_genesis_signing_key.as_domain_key())
                .map_err(|_| PublicDescriptorError::InvalidSubjectBinding)?,
            (
                PublicDescriptorKindV1::Channel | PublicDescriptorKindV1::Agent,
                PublicSubjectId::Identity(_),
            )
            | (PublicDescriptorKindV1::Channel, PublicSubjectId::Agent(_))
            | (PublicDescriptorKindV1::Agent, PublicSubjectId::Channel(_)) => {
                return Err(PublicDescriptorError::InvalidSubjectBinding);
            }
        }
        self.publisher_identity_id
            .verify_subject_key(self.publisher_identity_genesis_signing_key.as_domain_key())
            .map_err(|_| PublicDescriptorError::InvalidPublisherBinding)?;
        if self.subject_genesis_signing_key != self.publisher_identity_genesis_signing_key {
            return Err(PublicDescriptorError::SubjectPublisherBindingMismatch);
        }
        if self.sequence.get() == 0
            || (self.sequence.get() == 1 && self.previous_descriptor_hash.is_some())
            || (self.sequence.get() > 1 && self.previous_descriptor_hash.is_none())
        {
            return Err(PublicDescriptorError::InvalidDescriptorShape);
        }
        match (wire_line, &self.kind, &self.payload) {
            (
                PublicDescriptorWireLine::CurrentV1_2,
                PublicDescriptorKindV1::Channel,
                PublicDescriptorPayloadV1::Channel { feed_origin, .. },
            )
            | (
                PublicDescriptorWireLine::CurrentV1_2,
                PublicDescriptorKindV1::Agent,
                PublicDescriptorPayloadV1::Agent { feed_origin, .. },
            ) => {
                if self.expires_at <= self.issued_at {
                    return Err(PublicDescriptorError::InvalidDescriptorShape);
                }
                if valid_public_feed_origin(feed_origin) {
                    Ok(())
                } else {
                    Err(PublicDescriptorError::InvalidFeedOrigin)
                }
            }
            (
                PublicDescriptorWireLine::FrozenV1_1,
                PublicDescriptorKindV1::Channel,
                PublicDescriptorPayloadV1::LegacyChannelV1_1 { feed_origin, .. },
            )
            | (
                PublicDescriptorWireLine::FrozenV1_1,
                PublicDescriptorKindV1::Agent,
                PublicDescriptorPayloadV1::LegacyAgentV1_1 { feed_origin, .. },
            ) => {
                if self.expires_at <= self.issued_at {
                    return Err(PublicDescriptorError::InvalidDescriptorShape);
                }
                if valid_historical_feed_origin(feed_origin) {
                    Ok(())
                } else {
                    Err(PublicDescriptorError::InvalidFeedOrigin)
                }
            }
            (
                PublicDescriptorWireLine::FrozenV1_0,
                PublicDescriptorKindV1::Channel,
                PublicDescriptorPayloadV1::LegacyChannelV1_0 { feed_endpoint, .. },
            )
            | (
                PublicDescriptorWireLine::FrozenV1_0,
                PublicDescriptorKindV1::Agent,
                PublicDescriptorPayloadV1::LegacyAgentV1_0 { feed_endpoint, .. },
            ) => {
                if self.expires_at <= self.issued_at {
                    return Err(PublicDescriptorError::InvalidDescriptorShape);
                }
                if valid_historical_feed_endpoint(feed_endpoint) {
                    Ok(())
                } else {
                    Err(PublicDescriptorError::InvalidFeedEndpoint)
                }
            }
            (_, _, PublicDescriptorPayloadV1::Tombstone) => {
                if self.sequence.get() == 1 || self.expires_at != self.issued_at {
                    Err(PublicDescriptorError::InvalidDescriptorShape)
                } else {
                    Ok(())
                }
            }
            _ => Err(PublicDescriptorError::InvalidDescriptorShape),
        }
    }
}

impl CanonicalEncode for UnsignedPublicDescriptorV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), self.wire.to_canonical_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(self.kind.code()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.subject_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.subject_genesis_signing_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(self.publisher_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.publisher_identity_genesis_signing_key
                    .to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.previous_descriptor_hash
                    .map_or(CanonicalValue::Null, |hash| hash.to_canonical_value()),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.issued_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(10),
                self.expires_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(11),
                CanonicalValue::Unsigned(self.payload.code()),
            ),
            (
                CanonicalValue::Unsigned(12),
                self.payload.to_canonical_value(),
            ),
        ])
    }
}

/// A complete signed public descriptor chain entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPublicDescriptorV1 {
    unsigned: UnsignedPublicDescriptorV1,
    signature: Ed25519Signature,
}

impl SignedPublicDescriptorV1 {
    /// Attaches and strictly verifies a publisher identity signature.
    ///
    /// # Errors
    ///
    /// Returns a descriptor error for static validation or signature failure.
    pub fn signed(
        unsigned: UnsignedPublicDescriptorV1,
        signature: Ed25519Signature,
    ) -> Result<Self, PublicDescriptorError> {
        let descriptor = Self {
            unsigned,
            signature,
        };
        descriptor.verify()?;
        Ok(descriptor)
    }

    /// Decodes one exact canonical current V1.2 CBOR descriptor and verifies its signature.
    ///
    /// Unknown fields, non-preferred CBOR, malformed IDs, noncanonical public
    /// keys, and a decode/re-encode mismatch are all rejected.
    ///
    /// # Errors
    ///
    /// Returns a descriptor error when bytes or their cryptographic proof are
    /// not exactly valid current V1.2 descriptor data. Frozen V1.0/V1.1 bytes
    /// must use their explicit historical wrappers.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, PublicDescriptorError> {
        Self::decode_and_verify_for_line(bytes, PublicDescriptorWireLine::CurrentV1_2)
    }

    fn decode_and_verify_for_line(
        bytes: &[u8],
        expected_wire_line: PublicDescriptorWireLine,
    ) -> Result<Self, PublicDescriptorError> {
        let value = decode_deterministic_cbor(bytes)
            .map_err(|_| PublicDescriptorError::InvalidCanonical)?;
        let fields = exact_fields(&value, 13)?;
        let wire = decode_wire_version(field(fields, 1)?)?;
        let wire_line = public_descriptor_wire_line(wire)?;
        if wire_line != expected_wire_line {
            return Err(PublicDescriptorError::InvalidWireVersion);
        }
        let kind = PublicDescriptorKindV1::from_code(decode_unsigned(field(fields, 2)?)?)?;
        let subject_id = decode_subject_id(field(fields, 3)?)?;
        let subject_genesis_signing_key = decode_signing_key(field(fields, 4)?)?;
        let publisher_identity_id = decode_identity_id(field(fields, 5)?)?;
        let publisher_identity_genesis_signing_key = decode_signing_key(field(fields, 6)?)?;
        let sequence = decode_safe_uint(field(fields, 7)?)?;
        let previous_descriptor_hash = decode_optional_digest(field(fields, 8)?)?;
        let issued_at = decode_utc_millis(field(fields, 9)?)?;
        let expires_at = decode_utc_millis(field(fields, 10)?)?;
        let payload_code = decode_unsigned(field(fields, 11)?)?;
        let payload = decode_payload(wire_line, kind, payload_code, field(fields, 12)?)?;
        let signature = decode_signature(field(fields, 13)?)?;
        let unsigned = UnsignedPublicDescriptorV1::from_decoded(
            wire,
            kind,
            subject_id,
            subject_genesis_signing_key,
            publisher_identity_id,
            publisher_identity_genesis_signing_key,
            sequence,
            previous_descriptor_hash,
            issued_at,
            expires_at,
            payload,
        )?;
        let descriptor = Self {
            unsigned,
            signature,
        };
        descriptor.verify_any()?;
        if descriptor.to_deterministic_cbor()? != bytes {
            return Err(PublicDescriptorError::InvalidCanonical);
        }
        Ok(descriptor)
    }

    /// Re-verifies current V1.2 constraints and the strict Ed25519 proof.
    ///
    /// # Errors
    ///
    /// Returns an error when any exact binding or the publisher signature is invalid.
    pub fn verify(&self) -> Result<(), PublicDescriptorError> {
        self.unsigned.validate_static_current()?;
        self.verify_signature()
    }

    fn verify_any(&self) -> Result<(), PublicDescriptorError> {
        self.unsigned.validate_static_any()?;
        self.verify_signature()
    }

    fn verify_signature(&self) -> Result<(), PublicDescriptorError> {
        verify_signature(
            self.unsigned.publisher_identity_genesis_signing_key,
            &self.unsigned.signature_input()?,
            self.signature,
        )
    }

    /// Encodes this complete signed entry with deterministic canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error only if the bounded deterministic profile cannot encode it.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, PublicDescriptorError> {
        encode_deterministic_cbor(self).map_err(|_| PublicDescriptorError::InvalidCanonical)
    }

    /// Computes the durable hash of this exact complete signed descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical encoding cannot represent this descriptor.
    pub fn entry_hash(&self) -> Result<Sha256Digest, PublicDescriptorError> {
        canonical_hash(PUBLIC_DESCRIPTOR_ENTRY_HASH_DOMAIN, self)
    }

    /// Returns the exact descriptor wire version.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.unsigned.wire
    }

    /// Returns the stable public Channel or Agent subject ID.
    #[must_use]
    pub const fn subject_id(&self) -> PublicSubjectId {
        self.unsigned.subject_id
    }

    /// Returns the immutable subject kind.
    #[must_use]
    pub const fn kind(&self) -> PublicDescriptorKindV1 {
        self.unsigned.kind
    }

    /// Returns the immutable descriptor subject genesis signing key.
    #[must_use]
    pub const fn subject_genesis_signing_key(&self) -> SigningPublicKey {
        self.unsigned.subject_genesis_signing_key
    }

    /// Returns the self-certifying publisher identity ID.
    #[must_use]
    pub const fn publisher_identity_id(&self) -> IdentityId {
        self.unsigned.publisher_identity_id
    }

    /// Returns the publisher identity genesis key that authenticated V1.
    #[must_use]
    pub const fn publisher_identity_genesis_signing_key(&self) -> SigningPublicKey {
        self.unsigned.publisher_identity_genesis_signing_key
    }

    /// Returns the append-only sequence.
    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.unsigned.sequence
    }

    /// Returns the exact predecessor hash, absent only for genesis.
    #[must_use]
    pub const fn previous_descriptor_hash(&self) -> Option<Sha256Digest> {
        self.unsigned.previous_descriptor_hash
    }

    /// Returns publisher-declared issue time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcMillis {
        self.unsigned.issued_at
    }

    /// Returns expiration time; a tombstone uses the same value as issue time.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.unsigned.expires_at
    }

    /// Returns the immutable public payload.
    #[must_use]
    pub const fn payload(&self) -> &PublicDescriptorPayloadV1 {
        &self.unsigned.payload
    }

    /// Returns the V1.2 canonical DNS HTTPS feed origin for a live descriptor.
    #[must_use]
    pub fn feed_origin(&self) -> Option<&str> {
        self.unsigned.payload.feed_origin()
    }

    /// Returns the fixed subject-specific public feed path for a live descriptor.
    #[must_use]
    pub fn public_feed_path(&self) -> Option<String> {
        self.feed_origin()
            .map(|_| format!("{PUBLIC_FEED_WELL_KNOWN_PATH_PREFIX}{}", self.subject_id()))
    }

    /// Returns the fixed subject-specific public feed URL for a live descriptor.
    #[must_use]
    pub fn public_feed_url(&self) -> Option<String> {
        self.feed_origin().map(|origin| {
            format!(
                "{}{PUBLIC_FEED_WELL_KNOWN_PATH_PREFIX}{}",
                origin.trim_end_matches('/'),
                self.subject_id()
            )
        })
    }

    /// Returns whether this entry is a permanent tombstone.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.unsigned.payload.is_tombstone()
    }

    fn live_at(&self, now: UtcMillis) -> Result<(), PublicDescriptorError> {
        if self.issued_at() > now {
            Err(PublicDescriptorError::NotYetValid)
        } else if !self.is_tombstone() && self.expires_at() <= now {
            Err(PublicDescriptorError::Expired)
        } else {
            Ok(())
        }
    }
}

impl CanonicalEncode for SignedPublicDescriptorV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        let CanonicalValue::Map(mut fields) = self.unsigned.to_canonical_value() else {
            unreachable!("unsigned public descriptor is always a map");
        };
        fields.push((
            CanonicalValue::Unsigned(13),
            self.signature.to_canonical_value(),
        ));
        CanonicalValue::Map(fields)
    }
}

/// Read-only verified wrapper for frozen public-descriptor wire `1.0` bytes.
///
/// V1.0 allowed an arbitrary endpoint path and is therefore never returned by
/// the current decoder, writer, or reducer. This wrapper is intentionally only
/// for exact historical inspection and migration diagnostics; it exposes no
/// payload endpoint, write constructor, or append operation.
#[derive(Clone, Eq, PartialEq)]
pub struct HistoricalPublicDescriptorV1_0 {
    descriptor: SignedPublicDescriptorV1,
}

impl HistoricalPublicDescriptorV1_0 {
    /// Decodes and strictly verifies one frozen V1.0 descriptor for history reads.
    ///
    /// # Errors
    ///
    /// Returns [`PublicDescriptorError::InvalidWireVersion`] for current or
    /// unknown bytes, and the relevant strict canonical or signature error for
    /// an invalid historical descriptor.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, PublicDescriptorError> {
        let descriptor = SignedPublicDescriptorV1::decode_and_verify_for_line(
            bytes,
            PublicDescriptorWireLine::FrozenV1_0,
        )?;
        if descriptor.wire() != PUBLIC_DESCRIPTOR_V1_0_WIRE_VERSION {
            return Err(PublicDescriptorError::InvalidWireVersion);
        }
        Ok(Self { descriptor })
    }

    /// Returns the frozen historical wire version.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.descriptor.wire()
    }

    /// Returns the stable historical public Channel or Agent subject ID.
    #[must_use]
    pub const fn subject_id(&self) -> PublicSubjectId {
        self.descriptor.subject_id()
    }

    /// Returns the self-certifying historical publisher identity ID.
    #[must_use]
    pub const fn publisher_identity_id(&self) -> IdentityId {
        self.descriptor.publisher_identity_id()
    }

    /// Returns the historical descriptor sequence.
    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.descriptor.sequence()
    }

    /// Returns whether the historical entry is a tombstone.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.descriptor.is_tombstone()
    }

    /// Returns exact deterministic historical descriptor bytes.
    ///
    /// # Errors
    ///
    /// Returns an error only if the bounded deterministic profile cannot encode
    /// this already verified historical descriptor.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, PublicDescriptorError> {
        self.descriptor.to_deterministic_cbor()
    }

    /// Returns the complete historical descriptor hash.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical encoding cannot represent the entry.
    pub fn entry_hash(&self) -> Result<Sha256Digest, PublicDescriptorError> {
        self.descriptor.entry_hash()
    }
}

/// Read-only verified wrapper for frozen public-descriptor wire `1.1` bytes.
///
/// V1.1 is superseded by the canonical-DNS origin rules in V1.2 and is never
/// returned by the current decoder, writer, or reducer. This wrapper is only
/// for exact historical inspection and migration diagnostics; it exposes no
/// payload origin, write constructor, append operation, or current feed URL.
#[derive(Clone, Eq, PartialEq)]
pub struct HistoricalPublicDescriptorV1_1 {
    descriptor: SignedPublicDescriptorV1,
}

impl HistoricalPublicDescriptorV1_1 {
    /// Decodes and strictly verifies one frozen V1.1 descriptor for history reads.
    ///
    /// # Errors
    ///
    /// Returns [`PublicDescriptorError::InvalidWireVersion`] for current,
    /// V1.0, or unknown bytes, and the relevant strict canonical or signature
    /// error for an invalid historical descriptor.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, PublicDescriptorError> {
        let descriptor = SignedPublicDescriptorV1::decode_and_verify_for_line(
            bytes,
            PublicDescriptorWireLine::FrozenV1_1,
        )?;
        if descriptor.wire() != PUBLIC_DESCRIPTOR_V1_1_WIRE_VERSION {
            return Err(PublicDescriptorError::InvalidWireVersion);
        }
        Ok(Self { descriptor })
    }

    /// Returns the frozen historical wire version.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.descriptor.wire()
    }

    /// Returns the stable historical public Channel or Agent subject ID.
    #[must_use]
    pub const fn subject_id(&self) -> PublicSubjectId {
        self.descriptor.subject_id()
    }

    /// Returns the self-certifying historical publisher identity ID.
    #[must_use]
    pub const fn publisher_identity_id(&self) -> IdentityId {
        self.descriptor.publisher_identity_id()
    }

    /// Returns the historical descriptor sequence.
    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.descriptor.sequence()
    }

    /// Returns whether the historical entry is a tombstone.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.descriptor.is_tombstone()
    }

    /// Returns exact deterministic historical descriptor bytes.
    ///
    /// # Errors
    ///
    /// Returns an error only if the bounded deterministic profile cannot encode
    /// this already verified historical descriptor.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, PublicDescriptorError> {
        self.descriptor.to_deterministic_cbor()
    }

    /// Returns the complete historical descriptor hash.
    ///
    /// # Errors
    ///
    /// Returns an error only if canonical encoding cannot represent the entry.
    pub fn entry_hash(&self) -> Result<Sha256Digest, PublicDescriptorError> {
        self.descriptor.entry_hash()
    }
}

/// Current externally visible status at a trusted clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicDescriptorStatusV1 {
    /// The current descriptor is live and may be consumed.
    Active,
    /// The current descriptor is not live because its expiry passed.
    Expired,
    /// The current descriptor permanently revokes the public subject.
    Tombstoned,
}

/// In-memory fail-closed reducer for one public descriptor subject.
///
/// Persistence and indexers must use a compare-and-swap on both
/// `head_sequence` and `head_hash`, persist exact descriptor bytes, and retain
/// the unique full entry hash. This pure reducer owns no database or network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorHeadV1 {
    kind: PublicDescriptorKindV1,
    subject_id: PublicSubjectId,
    subject_genesis_signing_key: SigningPublicKey,
    publisher_identity_id: IdentityId,
    publisher_identity_genesis_signing_key: SigningPublicKey,
    descriptor: SignedPublicDescriptorV1,
    head_sequence: SafeUint,
    head_hash: Sha256Digest,
    accepted_by_sequence: BTreeMap<SafeUint, Sha256Digest>,
    seen_entry_hashes: BTreeSet<Sha256Digest>,
    tombstoned: bool,
}

impl DescriptorHeadV1 {
    /// Bootstraps a verified live sequence-one descriptor at a trusted clock.
    ///
    /// # Errors
    ///
    /// Returns an error for non-genesis descriptors, tombstone genesis,
    /// invalid proof, future issue time, or expired descriptor.
    pub fn bootstrap_at(
        descriptor: &SignedPublicDescriptorV1,
        now: UtcMillis,
    ) -> Result<Self, PublicDescriptorError> {
        descriptor.verify()?;
        if descriptor.sequence().get() != 1 || descriptor.previous_descriptor_hash().is_some() {
            return Err(PublicDescriptorError::InvalidDescriptorShape);
        }
        if descriptor.is_tombstone() {
            return Err(PublicDescriptorError::InvalidDescriptorShape);
        }
        descriptor.live_at(now)?;
        let head_hash = descriptor.entry_hash()?;
        Ok(Self {
            kind: descriptor.kind(),
            subject_id: descriptor.subject_id(),
            subject_genesis_signing_key: descriptor.subject_genesis_signing_key(),
            publisher_identity_id: descriptor.publisher_identity_id(),
            publisher_identity_genesis_signing_key: descriptor
                .publisher_identity_genesis_signing_key(),
            descriptor: descriptor.clone(),
            head_sequence: descriptor.sequence(),
            head_hash,
            accepted_by_sequence: BTreeMap::from([(descriptor.sequence(), head_hash)]),
            seen_entry_hashes: BTreeSet::from([head_hash]),
            tombstoned: false,
        })
    }

    /// Atomically admits the exact next descriptor or leaves the head unchanged.
    ///
    /// A candidate with a known hash is replay. A different candidate at an
    /// accepted sequence or the expected sequence with a different predecessor
    /// is equivocation. The trusted `now` makes expired/future live entries fail
    /// closed, while a valid tombstone may always permanently close the chain.
    ///
    /// # Errors
    ///
    /// Returns a descriptor error without changing this projection.
    pub fn append_at(
        &mut self,
        descriptor: &SignedPublicDescriptorV1,
        now: UtcMillis,
    ) -> Result<(), PublicDescriptorError> {
        descriptor.verify()?;
        let entry_hash = descriptor.entry_hash()?;
        if self.seen_entry_hashes.contains(&entry_hash) {
            return Err(PublicDescriptorError::Replay);
        }
        if descriptor.kind() != self.kind
            || descriptor.subject_id() != self.subject_id
            || descriptor.subject_genesis_signing_key() != self.subject_genesis_signing_key
        {
            return Err(PublicDescriptorError::SubjectMismatch);
        }
        if descriptor.publisher_identity_id() != self.publisher_identity_id
            || descriptor.publisher_identity_genesis_signing_key()
                != self.publisher_identity_genesis_signing_key
        {
            return Err(PublicDescriptorError::PublisherMismatch);
        }
        if self.tombstoned {
            return Err(PublicDescriptorError::Tombstoned);
        }
        descriptor.live_at(now)?;
        if self
            .accepted_by_sequence
            .contains_key(&descriptor.sequence())
        {
            return Err(PublicDescriptorError::Equivocation);
        }
        let expected = self
            .head_sequence
            .get()
            .checked_add(1)
            .and_then(|sequence| SafeUint::new(sequence).ok())
            .ok_or(PublicDescriptorError::SequenceMismatch)?;
        if descriptor.sequence() < expected {
            return Err(PublicDescriptorError::Equivocation);
        }
        if descriptor.sequence() > expected {
            return Err(PublicDescriptorError::SequenceMismatch);
        }
        if descriptor.previous_descriptor_hash() != Some(self.head_hash) {
            return Err(PublicDescriptorError::Equivocation);
        }

        let mut next = self.clone();
        next.descriptor = descriptor.clone();
        next.head_sequence = descriptor.sequence();
        next.head_hash = entry_hash;
        next.accepted_by_sequence
            .insert(descriptor.sequence(), entry_hash);
        next.seen_entry_hashes.insert(entry_hash);
        next.tombstoned = descriptor.is_tombstone();
        *self = next;
        Ok(())
    }

    /// Returns the stable self-certifying subject ID.
    #[must_use]
    pub const fn subject_id(&self) -> PublicSubjectId {
        self.subject_id
    }

    /// Returns the accepted contiguous sequence head.
    #[must_use]
    pub const fn head_sequence(&self) -> SafeUint {
        self.head_sequence
    }

    /// Returns the complete signed descriptor hash at the accepted head.
    #[must_use]
    pub const fn head_hash(&self) -> Sha256Digest {
        self.head_hash
    }

    /// Returns the exact current signed descriptor, including expired history.
    #[must_use]
    pub const fn current_descriptor(&self) -> &SignedPublicDescriptorV1 {
        &self.descriptor
    }

    /// Returns the current descriptor only when it is active at trusted `now`.
    #[must_use]
    pub fn active_descriptor_at(&self, now: UtcMillis) -> Option<&SignedPublicDescriptorV1> {
        if self.status_at(now) == PublicDescriptorStatusV1::Active {
            Some(&self.descriptor)
        } else {
            None
        }
    }

    /// Returns the visible descriptor status at a trusted clock.
    #[must_use]
    pub fn status_at(&self, now: UtcMillis) -> PublicDescriptorStatusV1 {
        if self.tombstoned {
            PublicDescriptorStatusV1::Tombstoned
        } else if self.descriptor.live_at(now).is_ok() {
            PublicDescriptorStatusV1::Active
        } else {
            PublicDescriptorStatusV1::Expired
        }
    }
}

fn canonical_hash<T>(domain: &[u8], value: &T) -> Result<Sha256Digest, PublicDescriptorError>
where
    T: CanonicalEncode + ?Sized,
{
    let bytes =
        encode_deterministic_cbor(value).map_err(|_| PublicDescriptorError::InvalidCanonical)?;
    Ok(Sha256Digest::hash_domain(domain, &bytes))
}

fn signature_input(domain: &[u8], digest: Sha256Digest) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + digest.as_bytes().len());
    input.extend_from_slice(domain);
    input.extend_from_slice(digest.as_bytes());
    input
}

fn verify_signature(
    signer: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), PublicDescriptorError> {
    let key = VerifyingKey::from_bytes(signer.as_bytes())
        .map_err(|_| PublicDescriptorError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    key.verify_strict(input, &signature)
        .map_err(|_| PublicDescriptorError::InvalidSignature)
}

fn valid_historical_feed_endpoint(value: &str) -> bool {
    if value.len() > MAX_FEED_ENDPOINT_BYTES
        || !value.is_ascii()
        || !value.starts_with("https://")
        || value.contains(['@', '?', '#', '\\'])
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return false;
    }
    let authority_and_path = &value["https://".len()..];
    let authority = authority_and_path
        .split_once('/')
        .map_or(authority_and_path, |(authority, _)| authority);
    !authority.is_empty()
        && !authority.ends_with('.')
        && authority.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
        && authority.bytes().any(|byte| byte.is_ascii_alphanumeric())
}

/// V1.1 accepted an HTTPS origin with a broader authority grammar. Keep that
/// exact admission boundary only for authenticating frozen historical bytes;
/// current V1.2 writes use [`valid_public_feed_origin`] below.
fn valid_historical_feed_origin(value: &str) -> bool {
    if value.len() > MAX_FEED_ENDPOINT_BYTES
        || !value.is_ascii()
        || !value.starts_with("https://")
        || value.contains(['@', '?', '#', '\\'])
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return false;
    }
    let authority_and_root = &value["https://".len()..];
    let authority = if let Some(authority) = authority_and_root.strip_suffix('/') {
        authority
    } else {
        authority_and_root
    };
    !authority.is_empty() && !authority.contains('/') && valid_historical_feed_authority(authority)
}

fn valid_historical_feed_authority(authority: &str) -> bool {
    if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((host, suffix)) = ipv6.split_once(']') else {
            return false;
        };
        if host.is_empty()
            || !host.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b':' | b'.')
            })
            || std::net::Ipv6Addr::from_str(host).is_err()
        {
            return false;
        }
        return suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .is_some_and(valid_historical_feed_port);
    }

    if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    valid_historical_feed_host(host) && port.is_none_or(valid_historical_feed_port)
}

fn valid_historical_feed_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
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

fn valid_historical_feed_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|parsed| parsed != 0)
}

/// V1.2 requires one canonical lower-case ASCII DNS origin. In particular,
/// it deliberately never accepts an IP literal or a WHATWG IPv4-looking host
/// whose URL interpretation could vary between clients.
fn valid_public_feed_origin(value: &str) -> bool {
    let Some(authority) = feed_origin_authority(value) else {
        return false;
    };
    valid_canonical_dns_authority(authority)
}

fn feed_origin_authority(value: &str) -> Option<&str> {
    if value.len() > MAX_FEED_ENDPOINT_BYTES
        || !value.is_ascii()
        || !value.starts_with("https://")
        || value.contains(['@', '?', '#', '\\'])
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return None;
    }
    let authority_and_root = &value["https://".len()..];
    let authority = authority_and_root
        .strip_suffix('/')
        .unwrap_or(authority_and_root);
    (!authority.is_empty() && !authority.contains('/')).then_some(authority)
}

fn valid_canonical_dns_authority(authority: &str) -> bool {
    if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    valid_canonical_dns_host(host) && port.is_none_or(valid_canonical_dns_port)
}

fn valid_canonical_dns_host(host: &str) -> bool {
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

fn looks_like_whatwg_ipv4_host(host: &str) -> bool {
    host.split('.').all(|part| {
        !part.is_empty()
            && (part.bytes().all(|byte| byte.is_ascii_digit())
                || part.strip_prefix("0x").is_some_and(|hex| {
                    !hex.is_empty()
                        && hex
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }))
    })
}

fn valid_canonical_dns_port(port: &str) -> bool {
    !port.is_empty()
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port
            .parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed != 443)
}

fn exact_fields(
    value: &CanonicalValue,
    count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], PublicDescriptorError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(PublicDescriptorError::InvalidCanonical);
    };
    if fields.len() != count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .is_none_or(|expected| key != &CanonicalValue::Unsigned(expected))
        })
    {
        Err(PublicDescriptorError::InvalidCanonical)
    } else {
        Ok(fields)
    }
}

fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, PublicDescriptorError> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(PublicDescriptorError::InvalidCanonical)?,
        )
        .map(|(_, value)| value)
        .ok_or(PublicDescriptorError::InvalidCanonical)
}

fn decode_wire_version(value: &CanonicalValue) -> Result<WireVersion, PublicDescriptorError> {
    let fields = exact_fields(value, 2)?;
    let wire = WireVersion::new(
        decode_protocol_version(field(fields, 1)?)?,
        decode_protocol_version(field(fields, 2)?)?,
    );
    public_descriptor_wire_line(wire).map(|_| wire)
}

fn public_descriptor_wire_line(
    wire: WireVersion,
) -> Result<PublicDescriptorWireLine, PublicDescriptorError> {
    if wire == PUBLIC_DESCRIPTOR_V1_0_WIRE_VERSION {
        Ok(PublicDescriptorWireLine::FrozenV1_0)
    } else if wire == PUBLIC_DESCRIPTOR_V1_1_WIRE_VERSION {
        Ok(PublicDescriptorWireLine::FrozenV1_1)
    } else if wire == PUBLIC_DESCRIPTOR_WIRE_VERSION {
        Ok(PublicDescriptorWireLine::CurrentV1_2)
    } else {
        Err(PublicDescriptorError::InvalidWireVersion)
    }
}

fn decode_protocol_version(
    value: &CanonicalValue,
) -> Result<ProtocolVersion, PublicDescriptorError> {
    let fields = exact_fields(value, 2)?;
    Ok(ProtocolVersion::new(
        decode_u16(field(fields, 1)?)?,
        decode_u16(field(fields, 2)?)?,
    ))
}

fn decode_u16(value: &CanonicalValue) -> Result<u16, PublicDescriptorError> {
    u16::try_from(decode_unsigned(value)?).map_err(|_| PublicDescriptorError::InvalidCanonical)
}

fn decode_unsigned(value: &CanonicalValue) -> Result<u64, PublicDescriptorError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(PublicDescriptorError::InvalidCanonical);
    };
    Ok(*value)
}

fn decode_safe_uint(value: &CanonicalValue) -> Result<SafeUint, PublicDescriptorError> {
    SafeUint::new(decode_unsigned(value)?).map_err(|_| PublicDescriptorError::InvalidCanonical)
}

fn decode_optional_digest(
    value: &CanonicalValue,
) -> Result<Option<Sha256Digest>, PublicDescriptorError> {
    if value == &CanonicalValue::Null {
        Ok(None)
    } else {
        decode_digest(value).map(Some)
    }
}

fn decode_digest(value: &CanonicalValue) -> Result<Sha256Digest, PublicDescriptorError> {
    Ok(Sha256Digest::from_bytes(decode_exact_bytes::<32>(value)?))
}

fn decode_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, PublicDescriptorError> {
    let raw = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| PublicDescriptorError::InvalidCanonical)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(PublicDescriptorError::InvalidCanonical),
    };
    UtcMillis::new(raw).map_err(|_| PublicDescriptorError::InvalidCanonical)
}

fn decode_subject_id(value: &CanonicalValue) -> Result<PublicSubjectId, PublicDescriptorError> {
    let CanonicalValue::Text(value) = value else {
        return Err(PublicDescriptorError::InvalidCanonical);
    };
    PublicSubjectId::from_str(value).map_err(|_| PublicDescriptorError::InvalidCanonical)
}

fn decode_identity_id(value: &CanonicalValue) -> Result<IdentityId, PublicDescriptorError> {
    let CanonicalValue::Text(value) = value else {
        return Err(PublicDescriptorError::InvalidCanonical);
    };
    IdentityId::from_str(value).map_err(|_| PublicDescriptorError::InvalidCanonical)
}

fn decode_signing_key(value: &CanonicalValue) -> Result<SigningPublicKey, PublicDescriptorError> {
    SigningPublicKey::try_from(decode_exact_bytes::<32>(value)?)
        .map_err(|_| PublicDescriptorError::InvalidCanonical)
}

fn decode_signature(value: &CanonicalValue) -> Result<Ed25519Signature, PublicDescriptorError> {
    Ok(Ed25519Signature::from_bytes(decode_exact_bytes::<64>(
        value,
    )?))
}

fn decode_payload(
    wire_line: PublicDescriptorWireLine,
    kind: PublicDescriptorKindV1,
    code: u64,
    value: &CanonicalValue,
) -> Result<PublicDescriptorPayloadV1, PublicDescriptorError> {
    match (wire_line, kind, code) {
        (PublicDescriptorWireLine::CurrentV1_2, PublicDescriptorKindV1::Channel, 1) => {
            let fields = exact_fields(value, 2)?;
            Ok(PublicDescriptorPayloadV1::Channel {
                feed_origin: decode_text(field(fields, 1)?)?,
                capability_digest: decode_digest(field(fields, 2)?)?,
            })
        }
        (PublicDescriptorWireLine::CurrentV1_2, PublicDescriptorKindV1::Agent, 2) => {
            let fields = exact_fields(value, 3)?;
            Ok(PublicDescriptorPayloadV1::Agent {
                feed_origin: decode_text(field(fields, 1)?)?,
                capability_digest: decode_digest(field(fields, 2)?)?,
                manifest_digest: decode_digest(field(fields, 3)?)?,
            })
        }
        (PublicDescriptorWireLine::FrozenV1_0, PublicDescriptorKindV1::Channel, 1) => {
            let fields = exact_fields(value, 2)?;
            Ok(PublicDescriptorPayloadV1::LegacyChannelV1_0 {
                feed_endpoint: decode_text(field(fields, 1)?)?,
                capability_digest: decode_digest(field(fields, 2)?)?,
            })
        }
        (PublicDescriptorWireLine::FrozenV1_0, PublicDescriptorKindV1::Agent, 2) => {
            let fields = exact_fields(value, 3)?;
            Ok(PublicDescriptorPayloadV1::LegacyAgentV1_0 {
                feed_endpoint: decode_text(field(fields, 1)?)?,
                capability_digest: decode_digest(field(fields, 2)?)?,
                manifest_digest: decode_digest(field(fields, 3)?)?,
            })
        }
        (PublicDescriptorWireLine::FrozenV1_1, PublicDescriptorKindV1::Channel, 1) => {
            let fields = exact_fields(value, 2)?;
            Ok(PublicDescriptorPayloadV1::LegacyChannelV1_1 {
                feed_origin: decode_text(field(fields, 1)?)?,
                capability_digest: decode_digest(field(fields, 2)?)?,
            })
        }
        (PublicDescriptorWireLine::FrozenV1_1, PublicDescriptorKindV1::Agent, 2) => {
            let fields = exact_fields(value, 3)?;
            Ok(PublicDescriptorPayloadV1::LegacyAgentV1_1 {
                feed_origin: decode_text(field(fields, 1)?)?,
                capability_digest: decode_digest(field(fields, 2)?)?,
                manifest_digest: decode_digest(field(fields, 3)?)?,
            })
        }
        (_, _, 3) => {
            exact_fields(value, 0)?;
            Ok(PublicDescriptorPayloadV1::Tombstone)
        }
        _ => Err(PublicDescriptorError::InvalidCanonical),
    }
}

fn decode_text(value: &CanonicalValue) -> Result<String, PublicDescriptorError> {
    let CanonicalValue::Text(value) = value else {
        return Err(PublicDescriptorError::InvalidCanonical);
    };
    Ok(value.clone())
}

fn decode_exact_bytes<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], PublicDescriptorError> {
    let CanonicalValue::Bytes(bytes) = value else {
        return Err(PublicDescriptorError::InvalidCanonical);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| PublicDescriptorError::InvalidCanonical)
}
