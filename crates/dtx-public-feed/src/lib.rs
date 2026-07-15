#![forbid(unsafe_code)]

//! Publisher-authenticated append-only public Channel and Agent feeds.
//! This is deliberately independent from private MLS and mailbox timelines.

use std::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{IdentityId, PublicSubjectId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};

const EVENT_DIGEST_DOMAIN: &[u8] = b"dirextalk.public-feed-event.v1\0";
const EVENT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.public-feed-signature.v1\0";
const EVENT_ENTRY_DOMAIN: &[u8] = b"dirextalk.public-feed-entry.v1\0";
const MAX_BODY_BYTES: usize = 32_768;
const MAX_ATTACHMENTS: usize = 16;
const MAX_MEDIA_TYPE_BYTES: usize = 127;

/// Stable public-feed V1 errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicFeedError {
    InvalidCanonical,
    InvalidWireVersion,
    InvalidSubject,
    InvalidPublisher,
    InvalidSignature,
    InvalidSequence,
    InvalidPayload,
    Replay,
    Equivocation,
    Gap,
    Tombstoned,
    InvalidCursor,
}

impl fmt::Display for PublicFeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCanonical => "public feed event is not exact canonical CBOR",
            Self::InvalidWireVersion => "unsupported public feed wire version",
            Self::InvalidSubject => "invalid public Channel or Agent subject",
            Self::InvalidPublisher => "public feed publisher does not match descriptor authority",
            Self::InvalidSignature => "public feed signature is invalid",
            Self::InvalidSequence => "public feed sequence must be positive",
            Self::InvalidPayload => "public feed payload violates its public bounds",
            Self::Replay => "public feed event is an exact replay",
            Self::Equivocation => "public feed history conflicts with the accepted history",
            Self::Gap => "public feed event leaves a sequence gap",
            Self::Tombstoned => "public feed is permanently tombstoned",
            Self::InvalidCursor => "public feed cursor is invalid",
        })
    }
}
impl Error for PublicFeedError {}

/// An attachment is only a public digest reference; bytes, URLs, keys and capabilities are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAttachmentRefV1 {
    digest: Sha256Digest,
    media_type: String,
    size_bytes: SafeUint,
}

impl PublicAttachmentRefV1 {
    /// Creates a bounded digest-only public attachment reference.
    ///
    /// # Errors
    /// Returns `InvalidPayload` for an invalid media type or zero size.
    pub fn new(
        digest: Sha256Digest,
        media_type: String,
        size_bytes: SafeUint,
    ) -> Result<Self, PublicFeedError> {
        if media_type.is_empty()
            || media_type.len() > MAX_MEDIA_TYPE_BYTES
            || !media_type.is_ascii()
            || !media_type.bytes().all(|b| matches!(b, 0x21..=0x7e))
            || !media_type.contains('/')
            || size_bytes.get() == 0
        {
            return Err(PublicFeedError::InvalidPayload);
        }
        Ok(Self {
            digest,
            media_type,
            size_bytes,
        })
    }
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    #[must_use]
    pub const fn size_bytes(&self) -> SafeUint {
        self.size_bytes
    }
}

impl CanonicalEncode for PublicAttachmentRefV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                self.digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.media_type.clone()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.size_bytes.to_canonical_value(),
            ),
        ])
    }
}

/// Public event content. Moderation labels are intentionally not representable here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicFeedPayloadV1 {
    Post {
        body: String,
        attachments: Vec<PublicAttachmentRefV1>,
    },
    Tombstone,
}

impl PublicFeedPayloadV1 {
    fn code(&self) -> u64 {
        match self {
            Self::Post { .. } => 1,
            Self::Tombstone => 2,
        }
    }
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        matches!(self, Self::Tombstone)
    }
    fn validate(&self) -> Result<(), PublicFeedError> {
        match self {
            Self::Post { body, attachments }
                if !body.is_empty()
                    && body.len() <= MAX_BODY_BYTES
                    && attachments.len() <= MAX_ATTACHMENTS =>
            {
                Ok(())
            }
            Self::Tombstone => Ok(()),
            Self::Post { .. } => Err(PublicFeedError::InvalidPayload),
        }
    }
    fn canonical(&self) -> CanonicalValue {
        match self {
            Self::Post { body, attachments } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text(body.clone()),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    CanonicalValue::Array(
                        attachments
                            .iter()
                            .map(CanonicalEncode::to_canonical_value)
                            .collect(),
                    ),
                ),
            ]),
            Self::Tombstone => CanonicalValue::Map(vec![]),
        }
    }
}

/// Exact unsigned fields authenticated by the descriptor publisher key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedPublicFeedEventV1 {
    subject_id: PublicSubjectId,
    publisher_identity_id: IdentityId,
    publisher_key: SigningPublicKey,
    sequence: SafeUint,
    previous_entry_hash: Option<Sha256Digest>,
    published_at: UtcMillis,
    payload: PublicFeedPayloadV1,
}

impl UnsignedPublicFeedEventV1 {
    /// Creates the exact unsigned event fields.
    ///
    /// # Errors
    /// Returns an error for an invalid subject, publisher, sequence, or payload.
    pub fn new(
        subject_id: PublicSubjectId,
        publisher_identity_id: IdentityId,
        publisher_key: SigningPublicKey,
        sequence: SafeUint,
        previous_entry_hash: Option<Sha256Digest>,
        published_at: UtcMillis,
        payload: PublicFeedPayloadV1,
    ) -> Result<Self, PublicFeedError> {
        if matches!(subject_id, PublicSubjectId::Identity(_)) {
            return Err(PublicFeedError::InvalidSubject);
        }
        if sequence.get() == 0 || (sequence.get() == 1) != previous_entry_hash.is_none() {
            return Err(PublicFeedError::InvalidSequence);
        }
        publisher_identity_id
            .verify_subject_key(publisher_key.as_domain_key())
            .map_err(|_| PublicFeedError::InvalidPublisher)?;
        payload.validate()?;
        Ok(Self {
            subject_id,
            publisher_identity_id,
            publisher_key,
            sequence,
            previous_entry_hash,
            published_at,
            payload,
        })
    }
    /// Returns the domain-separated publisher signature transcript.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn signature_input(&self) -> Result<Vec<u8>, PublicFeedError> {
        let bytes =
            encode_deterministic_cbor(self).map_err(|_| PublicFeedError::InvalidCanonical)?;
        let digest = Sha256Digest::hash_domain(EVENT_DIGEST_DOMAIN, &bytes);
        Ok([EVENT_SIGNATURE_DOMAIN, digest.as_bytes()].concat())
    }
}

impl CanonicalEncode for UnsignedPublicFeedEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                WireVersion::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0))
                    .to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.subject_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.publisher_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.publisher_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.previous_entry_hash
                    .map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.published_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Unsigned(self.payload.code()),
            ),
            (CanonicalValue::Unsigned(9), self.payload.canonical()),
        ])
    }
}

/// Complete signed event retained byte-exactly by relays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPublicFeedEventV1 {
    unsigned: UnsignedPublicFeedEventV1,
    signature: Ed25519Signature,
}

impl SignedPublicFeedEventV1 {
    /// Attaches and verifies a publisher signature.
    ///
    /// # Errors
    /// Returns `InvalidSignature` or a static event validation error.
    pub fn signed(
        unsigned: UnsignedPublicFeedEventV1,
        signature: Ed25519Signature,
    ) -> Result<Self, PublicFeedError> {
        let value = Self {
            unsigned,
            signature,
        };
        value.verify()?;
        Ok(value)
    }
    /// Decodes exact canonical CBOR and verifies its publisher signature.
    ///
    /// # Errors
    /// Returns an error for any noncanonical, malformed, or unauthenticated event.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, PublicFeedError> {
        let root =
            decode_deterministic_cbor(bytes).map_err(|_| PublicFeedError::InvalidCanonical)?;
        let fields = exact_map(&root, 10)?;
        decode_wire(field(fields, 1)?)?;
        let subject_id = text(field(fields, 2)?)?
            .parse()
            .map_err(|_| PublicFeedError::InvalidSubject)?;
        let publisher_identity_id = text(field(fields, 3)?)?
            .parse()
            .map_err(|_| PublicFeedError::InvalidPublisher)?;
        let publisher_key = SigningPublicKey::try_from(bytes32(field(fields, 4)?)?)
            .map_err(|_| PublicFeedError::InvalidPublisher)?;
        let sequence = SafeUint::new(unsigned(field(fields, 5)?)?)
            .map_err(|_| PublicFeedError::InvalidSequence)?;
        let previous = optional_digest(field(fields, 6)?)?;
        let published_at = UtcMillis::new(signed_int(field(fields, 7)?)?)
            .map_err(|_| PublicFeedError::InvalidPayload)?;
        let payload = decode_payload(unsigned(field(fields, 8)?)?, field(fields, 9)?)?;
        let signature = Ed25519Signature::from_bytes(bytes64(field(fields, 10)?)?);
        let value = Self::signed(
            UnsignedPublicFeedEventV1::new(
                subject_id,
                publisher_identity_id,
                publisher_key,
                sequence,
                previous,
                published_at,
                payload,
            )?,
            signature,
        )?;
        if value.to_deterministic_cbor()? != bytes {
            return Err(PublicFeedError::InvalidCanonical);
        }
        Ok(value)
    }
    /// Re-verifies static bounds and the strict Ed25519 proof.
    ///
    /// # Errors
    /// Returns an error when the payload or signature is invalid.
    pub fn verify(&self) -> Result<(), PublicFeedError> {
        self.unsigned.payload.validate()?;
        let key = VerifyingKey::from_bytes(self.unsigned.publisher_key.as_bytes())
            .map_err(|_| PublicFeedError::InvalidSignature)?;
        key.verify_strict(
            &self.unsigned.signature_input()?,
            &Signature::from_bytes(self.signature.as_bytes()),
        )
        .map_err(|_| PublicFeedError::InvalidSignature)
    }
    /// Encodes the exact signed event.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, PublicFeedError> {
        encode_deterministic_cbor(self).map_err(|_| PublicFeedError::InvalidCanonical)
    }
    /// Computes the domain-separated complete-entry hash.
    ///
    /// # Errors
    /// Returns an error if canonical encoding fails.
    pub fn entry_hash(&self) -> Result<Sha256Digest, PublicFeedError> {
        Ok(Sha256Digest::hash_domain(
            EVENT_ENTRY_DOMAIN,
            &self.to_deterministic_cbor()?,
        ))
    }
    #[must_use]
    pub const fn subject_id(&self) -> PublicSubjectId {
        self.unsigned.subject_id
    }
    #[must_use]
    pub const fn publisher_identity_id(&self) -> IdentityId {
        self.unsigned.publisher_identity_id
    }
    #[must_use]
    pub const fn publisher_key(&self) -> SigningPublicKey {
        self.unsigned.publisher_key
    }
    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.unsigned.sequence
    }
    #[must_use]
    pub const fn previous_entry_hash(&self) -> Option<Sha256Digest> {
        self.unsigned.previous_entry_hash
    }
    #[must_use]
    pub const fn published_at(&self) -> UtcMillis {
        self.unsigned.published_at
    }
    #[must_use]
    pub const fn payload(&self) -> &PublicFeedPayloadV1 {
        &self.unsigned.payload
    }
}
impl CanonicalEncode for SignedPublicFeedEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        let CanonicalValue::Map(mut fields) = self.unsigned.to_canonical_value() else {
            unreachable!()
        };
        fields.push((
            CanonicalValue::Unsigned(10),
            self.signature.to_canonical_value(),
        ));
        CanonicalValue::Map(fields)
    }
}

/// Deterministic reducer used before a storage CAS.
#[derive(Clone, Debug)]
pub struct PublicFeedHeadV1 {
    subject_id: PublicSubjectId,
    publisher_id: IdentityId,
    publisher_key: SigningPublicKey,
    sequence: SafeUint,
    hash: Sha256Digest,
    tombstoned: bool,
}
impl PublicFeedHeadV1 {
    /// Starts a feed at an authenticated genesis event.
    ///
    /// # Errors
    /// Returns an error when the event is not a valid genesis.
    pub fn bootstrap(event: &SignedPublicFeedEventV1) -> Result<Self, PublicFeedError> {
        event.verify()?;
        if event.sequence().get() != 1 || event.previous_entry_hash().is_some() {
            return Err(PublicFeedError::InvalidSequence);
        }
        Ok(Self {
            subject_id: event.subject_id(),
            publisher_id: event.publisher_identity_id(),
            publisher_key: event.publisher_key(),
            sequence: event.sequence(),
            hash: event.entry_hash()?,
            tombstoned: event.payload().is_tombstone(),
        })
    }
    /// Applies the exact next event without mutating state on failure.
    ///
    /// # Errors
    /// Returns replay, equivocation, gap, authority, or tombstone errors.
    pub fn append(&mut self, event: &SignedPublicFeedEventV1) -> Result<(), PublicFeedError> {
        event.verify()?;
        let hash = event.entry_hash()?;
        if event.subject_id() != self.subject_id
            || event.publisher_identity_id() != self.publisher_id
            || event.publisher_key() != self.publisher_key
        {
            return Err(PublicFeedError::InvalidPublisher);
        }
        if event.sequence() == self.sequence {
            return if hash == self.hash {
                Err(PublicFeedError::Replay)
            } else {
                Err(PublicFeedError::Equivocation)
            };
        }
        if self.tombstoned {
            return Err(PublicFeedError::Tombstoned);
        }
        if event.sequence().get() != self.sequence.get() + 1 {
            return Err(if event.sequence().get() < self.sequence.get() {
                PublicFeedError::Equivocation
            } else {
                PublicFeedError::Gap
            });
        }
        if event.previous_entry_hash() != Some(self.hash) {
            return Err(PublicFeedError::Equivocation);
        }
        self.sequence = event.sequence();
        self.hash = hash;
        self.tombstoned = event.payload().is_tombstone();
        Ok(())
    }
    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.sequence
    }
    #[must_use]
    pub const fn hash(&self) -> Sha256Digest {
        self.hash
    }
    #[must_use]
    pub const fn is_tombstoned(&self) -> bool {
        self.tombstoned
    }
}

/// Opaque, subject-bound snapshot cursor. It carries no authority and is validated against the feed head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicFeedCursorV1 {
    subject_id: PublicSubjectId,
    after_sequence: SafeUint,
    snapshot_sequence: SafeUint,
    snapshot_hash: Sha256Digest,
}
impl PublicFeedCursorV1 {
    /// Creates a subject-bound stable-snapshot cursor.
    ///
    /// # Errors
    /// Returns `InvalidCursor` when the bounds or subject are invalid.
    pub fn new(
        subject_id: PublicSubjectId,
        after_sequence: SafeUint,
        snapshot_sequence: SafeUint,
        snapshot_hash: Sha256Digest,
    ) -> Result<Self, PublicFeedError> {
        if after_sequence.get() > snapshot_sequence.get()
            || matches!(subject_id, PublicSubjectId::Identity(_))
        {
            return Err(PublicFeedError::InvalidCursor);
        }
        Ok(Self {
            subject_id,
            after_sequence,
            snapshot_sequence,
            snapshot_hash,
        })
    }
    /// Encodes canonical CBOR as unpadded base64url.
    ///
    /// # Errors
    /// Returns `InvalidCursor` if canonical encoding fails.
    pub fn encode(&self) -> Result<String, PublicFeedError> {
        Ok(Base64UrlUnpadded::encode_string(
            &encode_deterministic_cbor(self).map_err(|_| PublicFeedError::InvalidCursor)?,
        ))
    }
    /// Decodes and strictly validates an opaque cursor.
    ///
    /// # Errors
    /// Returns `InvalidCursor` for malformed or noncanonical input.
    pub fn decode(value: &str) -> Result<Self, PublicFeedError> {
        let bytes =
            Base64UrlUnpadded::decode_vec(value).map_err(|_| PublicFeedError::InvalidCursor)?;
        let root = decode_deterministic_cbor(&bytes).map_err(|_| PublicFeedError::InvalidCursor)?;
        let fields = exact_map(&root, 4)?;
        let subject_id = text(field(fields, 1)?)?
            .parse()
            .map_err(|_| PublicFeedError::InvalidCursor)?;
        Self::new(
            subject_id,
            SafeUint::new(unsigned(field(fields, 2)?)?)
                .map_err(|_| PublicFeedError::InvalidCursor)?,
            SafeUint::new(unsigned(field(fields, 3)?)?)
                .map_err(|_| PublicFeedError::InvalidCursor)?,
            Sha256Digest::from_bytes(bytes32(field(fields, 4)?)?),
        )
    }
    #[must_use]
    pub const fn subject_id(&self) -> PublicSubjectId {
        self.subject_id
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
impl CanonicalEncode for PublicFeedCursorV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Text(self.subject_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(2),
                self.after_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.snapshot_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.snapshot_hash.to_canonical_value(),
            ),
        ])
    }
}

fn decode_payload(
    code: u64,
    value: &CanonicalValue,
) -> Result<PublicFeedPayloadV1, PublicFeedError> {
    match code {
        1 => {
            let fields = exact_map(value, 2)?;
            let body = text(field(fields, 1)?)?.to_owned();
            let attachments = match field(fields, 2)? {
                CanonicalValue::Array(v) if v.len() <= MAX_ATTACHMENTS => v
                    .iter()
                    .map(decode_attachment)
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(PublicFeedError::InvalidPayload),
            };
            let payload = PublicFeedPayloadV1::Post { body, attachments };
            payload.validate()?;
            Ok(payload)
        }
        2 if exact_map(value, 0).is_ok() => Ok(PublicFeedPayloadV1::Tombstone),
        _ => Err(PublicFeedError::InvalidPayload),
    }
}
fn decode_attachment(value: &CanonicalValue) -> Result<PublicAttachmentRefV1, PublicFeedError> {
    let f = exact_map(value, 3)?;
    PublicAttachmentRefV1::new(
        Sha256Digest::from_bytes(bytes32(field(f, 1)?)?),
        text(field(f, 2)?)?.to_owned(),
        SafeUint::new(unsigned(field(f, 3)?)?).map_err(|_| PublicFeedError::InvalidPayload)?,
    )
}
fn exact_map(
    value: &CanonicalValue,
    len: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], PublicFeedError> {
    match value {
        CanonicalValue::Map(v) if v.len() == len => Ok(v),
        _ => Err(PublicFeedError::InvalidCanonical),
    }
}
fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: u64,
) -> Result<&CanonicalValue, PublicFeedError> {
    fields
        .iter()
        .find_map(|(k, v)| (*k == CanonicalValue::Unsigned(key)).then_some(v))
        .ok_or(PublicFeedError::InvalidCanonical)
}
fn unsigned(v: &CanonicalValue) -> Result<u64, PublicFeedError> {
    if let CanonicalValue::Unsigned(v) = v {
        Ok(*v)
    } else {
        Err(PublicFeedError::InvalidCanonical)
    }
}
fn signed_int(v: &CanonicalValue) -> Result<i64, PublicFeedError> {
    match v {
        CanonicalValue::Unsigned(v) => {
            i64::try_from(*v).map_err(|_| PublicFeedError::InvalidCanonical)
        }
        CanonicalValue::Negative(v) => Ok(*v),
        _ => Err(PublicFeedError::InvalidCanonical),
    }
}
fn text(v: &CanonicalValue) -> Result<&str, PublicFeedError> {
    if let CanonicalValue::Text(v) = v {
        Ok(v)
    } else {
        Err(PublicFeedError::InvalidCanonical)
    }
}
fn bytes32(v: &CanonicalValue) -> Result<[u8; 32], PublicFeedError> {
    match v {
        CanonicalValue::Bytes(v) => v
            .as_slice()
            .try_into()
            .map_err(|_| PublicFeedError::InvalidCanonical),
        _ => Err(PublicFeedError::InvalidCanonical),
    }
}
fn bytes64(v: &CanonicalValue) -> Result<[u8; 64], PublicFeedError> {
    match v {
        CanonicalValue::Bytes(v) => v
            .as_slice()
            .try_into()
            .map_err(|_| PublicFeedError::InvalidCanonical),
        _ => Err(PublicFeedError::InvalidCanonical),
    }
}
fn optional_digest(v: &CanonicalValue) -> Result<Option<Sha256Digest>, PublicFeedError> {
    if *v == CanonicalValue::Null {
        Ok(None)
    } else {
        Ok(Some(Sha256Digest::from_bytes(bytes32(v)?)))
    }
}
fn decode_wire(v: &CanonicalValue) -> Result<(), PublicFeedError> {
    let f = exact_map(v, 2)?;
    for k in [1, 2] {
        let version = exact_map(field(f, k)?, 2)?;
        if unsigned(field(version, 1)?)? != 1 || unsigned(field(version, 2)?)? != 0 {
            return Err(PublicFeedError::InvalidWireVersion);
        }
    }
    Ok(())
}
