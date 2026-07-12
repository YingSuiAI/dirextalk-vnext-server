use std::{error::Error, fmt, str::FromStr};

use dtx_domain::{AggregateId, EventId, TenantId};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    CanonicalCborError, CanonicalDecode, CanonicalDecodeError, CanonicalEncode, CanonicalValue,
    Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest, SigningPublicKey, StableCode,
    UtcMillis, VersionError, WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
    ensure_readable,
};

/// Domain separator for the hash of an unsigned v1 event envelope.
pub const EVENT_HASH_DOMAIN: &[u8] = b"dirextalk.event.v1\0";
/// Domain separator for the Ed25519 input that authenticates an event digest.
pub const EVENT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.event-signature.v1\0";
const EVENT_PROTOCOL_MAJOR: u16 = 1;

/// A generated event payload's immutable registry metadata.
pub trait RegisteredEventPayload: CanonicalEncode + CanonicalDecode {
    /// Stable dotted event type.
    const EVENT_TYPE: &'static str;
    /// Payload schema version.
    const SCHEMA_VERSION: u16;
    /// Aggregate family.
    const AGGREGATE_TYPE: &'static str;
    /// Capability that makes the event required, or `None` for optional events.
    const REQUIRED_READER_CAPABILITY: Option<&'static str>;
    /// Cursor behavior for an unknown payload version.
    const UNKNOWN_VERSION_POLICY: UnknownVersionPolicy;
}

/// Registry policy for a client that does not understand an event version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownVersionPolicy {
    /// Keep the original canonical bytes and skip only the non-critical projection.
    PreserveAndSkip,
    /// Stop before advancing the cursor and require an upgraded reader.
    StopCursor,
}

/// The unsigned fields whose deterministic bytes participate in event integrity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedEventEnvelopeV1<T> {
    protocol_version: ProtocolVersion,
    minimum_reader_version: ProtocolVersion,
    event_id: EventId,
    tenant_id: TenantId,
    aggregate_type: StableCode,
    aggregate_id: AggregateId,
    aggregate_revision: SafeUint,
    stream_sequence: SafeUint,
    occurred_at: UtcMillis,
    schema_version: u16,
    event_type: StableCode,
    required_reader_capability: Option<StableCode>,
    payload: T,
}

impl<T> UnsignedEventEnvelopeV1<T>
where
    T: RegisteredEventPayload,
{
    /// Builds an unsigned envelope from registry-owned metadata and caller-owned IDs.
    ///
    /// # Errors
    ///
    /// Returns [`EventIntegrityError::ContractMismatch`] if generated metadata is
    /// invalid or a sequence/revision is zero, and returns a version error for an
    /// internally invalid writer/minimum-reader range.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wire: WireVersion,
        event_id: EventId,
        tenant_id: TenantId,
        aggregate_id: AggregateId,
        aggregate_revision: SafeUint,
        stream_sequence: SafeUint,
        occurred_at: UtcMillis,
        payload: T,
    ) -> Result<Self, EventIntegrityError> {
        if wire.protocol.major() != EVENT_PROTOCOL_MAJOR {
            return Err(EventIntegrityError::ContractMismatch);
        }
        ensure_readable(wire.protocol, wire)?;
        if aggregate_revision.get() == 0 || stream_sequence.get() == 0 || T::SCHEMA_VERSION == 0 {
            return Err(EventIntegrityError::ContractMismatch);
        }
        let aggregate_type = StableCode::parse(T::AGGREGATE_TYPE)
            .map_err(|_| EventIntegrityError::ContractMismatch)?;
        let event_type =
            StableCode::parse(T::EVENT_TYPE).map_err(|_| EventIntegrityError::ContractMismatch)?;
        let required_reader_capability = T::REQUIRED_READER_CAPABILITY
            .map(StableCode::parse)
            .transpose()
            .map_err(|_| EventIntegrityError::ContractMismatch)?;
        if T::UNKNOWN_VERSION_POLICY == UnknownVersionPolicy::PreserveAndSkip
            && required_reader_capability.is_some()
        {
            return Err(EventIntegrityError::ContractMismatch);
        }
        Ok(Self {
            protocol_version: wire.protocol,
            minimum_reader_version: wire.minimum_reader,
            event_id,
            tenant_id,
            aggregate_type,
            aggregate_id,
            aggregate_revision,
            stream_sequence,
            occurred_at,
            schema_version: T::SCHEMA_VERSION,
            event_type,
            required_reader_capability,
            payload,
        })
    }
}

impl<T> CanonicalEncode for UnsignedEventEnvelopeV1<T>
where
    T: CanonicalEncode,
{
    fn to_canonical_value(&self) -> CanonicalValue {
        unsigned_value(
            self.protocol_version,
            self.minimum_reader_version,
            self.event_id,
            self.tenant_id,
            &self.aggregate_type,
            self.aggregate_id,
            self.aggregate_revision,
            self.stream_sequence,
            self.occurred_at,
            self.schema_version,
            &self.event_type,
            self.required_reader_capability.as_ref(),
            &self.payload,
        )
    }
}

/// Integrity metadata appended after the unsigned event fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "algorithm", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventIntegrityV1 {
    /// Corruption-detecting hash without origin authentication.
    Sha256 {
        /// Digest of the unsigned envelope.
        digest: Sha256Digest,
    },
    /// Strict Ed25519 signature over the domain-separated digest input.
    Ed25519 {
        /// Digest of the unsigned envelope.
        digest: Sha256Digest,
        /// Public signer key; its authorization is checked by outer policy.
        signer: SigningPublicKey,
        /// Signature over the v1 event signature input.
        signature: Ed25519Signature,
    },
}

impl EventIntegrityV1 {
    fn digest(&self) -> Sha256Digest {
        match self {
            Self::Sha256 { digest } | Self::Ed25519 { digest, .. } => *digest,
        }
    }
}

impl CanonicalEncode for EventIntegrityV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        match self {
            Self::Sha256 { digest } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text("sha256".to_owned()),
                ),
                (CanonicalValue::Unsigned(2), digest.to_canonical_value()),
            ]),
            Self::Ed25519 {
                digest,
                signer,
                signature,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text("ed25519".to_owned()),
                ),
                (CanonicalValue::Unsigned(2), digest.to_canonical_value()),
                (CanonicalValue::Unsigned(3), signer.to_canonical_value()),
                (CanonicalValue::Unsigned(4), signature.to_canonical_value()),
            ]),
        }
    }
}

/// A complete durable v1 event envelope awaiting explicit verification.
///
/// Semantic getters intentionally exist only on [`VerifiedEventEnvelope`].
/// Code cannot project a deserialized payload before checking its integrity:
///
/// ```compile_fail,E0599
/// use dtx_wire::{AgentInstallationChangedV1, EventEnvelopeV1};
///
/// fn bypass_verification(event: &EventEnvelopeV1<AgentInstallationChangedV1>) {
///     let _ = event.payload();
/// }
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelopeV1<T> {
    protocol_version: ProtocolVersion,
    minimum_reader_version: ProtocolVersion,
    event_id: EventId,
    tenant_id: TenantId,
    aggregate_type: StableCode,
    aggregate_id: AggregateId,
    aggregate_revision: SafeUint,
    stream_sequence: SafeUint,
    occurred_at: UtcMillis,
    schema_version: u16,
    event_type: StableCode,
    required_reader_capability: Option<StableCode>,
    payload: T,
    integrity: EventIntegrityV1,
}

impl<T> EventEnvelopeV1<T>
where
    T: RegisteredEventPayload,
{
    /// Creates an envelope whose hash detects corruption but does not authenticate origin.
    ///
    /// # Errors
    ///
    /// Returns [`EventIntegrityError`] when canonical encoding fails.
    pub fn hash_only(unsigned: UnsignedEventEnvelopeV1<T>) -> Result<Self, EventIntegrityError> {
        let digest = event_digest(&unsigned)?;
        Ok(Self::from_unsigned(
            unsigned,
            EventIntegrityV1::Sha256 { digest },
        ))
    }

    /// Creates and verifies a strictly signed event.
    ///
    /// # Errors
    ///
    /// Returns [`EventIntegrityError::InvalidSignature`] if the supplied public
    /// key and signature do not authenticate this exact unsigned envelope.
    pub fn signed(
        unsigned: UnsignedEventEnvelopeV1<T>,
        signer: SigningPublicKey,
        signature: Ed25519Signature,
    ) -> Result<Self, EventIntegrityError> {
        let digest = event_digest(&unsigned)?;
        verify_event_signature(digest, signer, signature)?;
        Ok(Self::from_unsigned(
            unsigned,
            EventIntegrityV1::Ed25519 {
                digest,
                signer,
                signature,
            },
        ))
    }

    /// Decodes exact deterministic bytes and verifies the typed v1 event before use.
    ///
    /// Envelope and payload maps reject missing, extra, or differently typed
    /// fields. Successful return is the same distinct verification wrapper used
    /// by in-memory envelopes.
    ///
    /// # Errors
    ///
    /// Returns [`EventIntegrityError`] for malformed canonical CBOR, unreadable
    /// versions, registry metadata mismatch, invalid payload fields, digest
    /// mismatch, or a failed strict Ed25519 signature.
    pub fn decode_and_verify(
        bytes: &[u8],
        reader: ProtocolVersion,
    ) -> Result<VerifiedEventEnvelope<T>, EventIntegrityError> {
        let parsed = parse_and_verify_event(bytes, reader)?;
        if parsed.schema_version != T::SCHEMA_VERSION
            || parsed.event_type.as_str() != T::EVENT_TYPE
            || parsed.aggregate_type.as_str() != T::AGGREGATE_TYPE
            || parsed
                .required_reader_capability
                .as_ref()
                .map(StableCode::as_str)
                != T::REQUIRED_READER_CAPABILITY
            || (T::UNKNOWN_VERSION_POLICY == UnknownVersionPolicy::PreserveAndSkip
                && parsed.required_reader_capability.is_some())
        {
            return Err(EventIntegrityError::ContractMismatch);
        }
        let payload = T::decode_canonical(&parsed.payload)?;
        if payload.to_canonical_value() != parsed.payload {
            return Err(EventIntegrityError::PayloadDecode(
                CanonicalDecodeError::RoundTripMismatch,
            ));
        }
        let envelope = Self {
            protocol_version: parsed.protocol_version,
            minimum_reader_version: parsed.minimum_reader_version,
            event_id: parsed.event_id,
            tenant_id: parsed.tenant_id,
            aggregate_type: parsed.aggregate_type,
            aggregate_id: parsed.aggregate_id,
            aggregate_revision: parsed.aggregate_revision,
            stream_sequence: parsed.stream_sequence,
            occurred_at: parsed.occurred_at,
            schema_version: parsed.schema_version,
            event_type: parsed.event_type,
            required_reader_capability: parsed.required_reader_capability,
            payload,
            integrity: parsed.integrity,
        };
        Ok(VerifiedEventEnvelope {
            envelope,
            verification: parsed.verification,
        })
    }

    /// Recomputes and validates version, registry metadata, digest, and signature.
    ///
    /// # Errors
    ///
    /// Returns [`EventIntegrityError`] before the event may enter a projection.
    pub fn verify(
        self,
        reader: ProtocolVersion,
    ) -> Result<VerifiedEventEnvelope<T>, EventIntegrityError> {
        self.validate_contract(reader)?;
        let digest = event_digest(&unsigned_value(
            self.protocol_version,
            self.minimum_reader_version,
            self.event_id,
            self.tenant_id,
            &self.aggregate_type,
            self.aggregate_id,
            self.aggregate_revision,
            self.stream_sequence,
            self.occurred_at,
            self.schema_version,
            &self.event_type,
            self.required_reader_capability.as_ref(),
            &self.payload,
        ))?;
        if digest != self.integrity.digest() {
            return Err(EventIntegrityError::DigestMismatch);
        }
        let verification = match &self.integrity {
            EventIntegrityV1::Sha256 { .. } => IntegrityVerification::HashOnly,
            EventIntegrityV1::Ed25519 {
                signer, signature, ..
            } => {
                verify_event_signature(digest, *signer, *signature)?;
                IntegrityVerification::Signed { signer: *signer }
            }
        };
        Ok(VerifiedEventEnvelope {
            envelope: self,
            verification,
        })
    }

    /// Encodes the full envelope using the deterministic CBOR profile.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalCborError`] for a profile limit or duplicate payload key.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, CanonicalCborError> {
        encode_deterministic_cbor(self)
    }

    fn from_unsigned(unsigned: UnsignedEventEnvelopeV1<T>, integrity: EventIntegrityV1) -> Self {
        Self {
            protocol_version: unsigned.protocol_version,
            minimum_reader_version: unsigned.minimum_reader_version,
            event_id: unsigned.event_id,
            tenant_id: unsigned.tenant_id,
            aggregate_type: unsigned.aggregate_type,
            aggregate_id: unsigned.aggregate_id,
            aggregate_revision: unsigned.aggregate_revision,
            stream_sequence: unsigned.stream_sequence,
            occurred_at: unsigned.occurred_at,
            schema_version: unsigned.schema_version,
            event_type: unsigned.event_type,
            required_reader_capability: unsigned.required_reader_capability,
            payload: unsigned.payload,
            integrity,
        }
    }

    fn validate_contract(&self, reader: ProtocolVersion) -> Result<(), EventIntegrityError> {
        if self.protocol_version.major() != EVENT_PROTOCOL_MAJOR {
            return Err(EventIntegrityError::ContractMismatch);
        }
        ensure_readable(
            reader,
            WireVersion::new(self.protocol_version, self.minimum_reader_version),
        )?;
        if self.aggregate_revision.get() == 0
            || self.stream_sequence.get() == 0
            || self.schema_version != T::SCHEMA_VERSION
            || self.event_type.as_str() != T::EVENT_TYPE
            || self.aggregate_type.as_str() != T::AGGREGATE_TYPE
            || self
                .required_reader_capability
                .as_ref()
                .map(StableCode::as_str)
                != T::REQUIRED_READER_CAPABILITY
            || (T::UNKNOWN_VERSION_POLICY == UnknownVersionPolicy::PreserveAndSkip
                && self.required_reader_capability.is_some())
        {
            return Err(EventIntegrityError::ContractMismatch);
        }
        Ok(())
    }
}

impl<T> CanonicalEncode for EventEnvelopeV1<T>
where
    T: CanonicalEncode,
{
    fn to_canonical_value(&self) -> CanonicalValue {
        let CanonicalValue::Map(mut entries) = unsigned_value(
            self.protocol_version,
            self.minimum_reader_version,
            self.event_id,
            self.tenant_id,
            &self.aggregate_type,
            self.aggregate_id,
            self.aggregate_revision,
            self.stream_sequence,
            self.occurred_at,
            self.schema_version,
            &self.event_type,
            self.required_reader_capability.as_ref(),
            &self.payload,
        ) else {
            unreachable!("unsigned event is always a map")
        };
        entries.push((
            CanonicalValue::Unsigned(14),
            self.integrity.to_canonical_value(),
        ));
        CanonicalValue::Map(entries)
    }
}

#[allow(clippy::too_many_arguments)]
fn unsigned_value<T>(
    protocol_version: ProtocolVersion,
    minimum_reader_version: ProtocolVersion,
    event_id: EventId,
    tenant_id: TenantId,
    aggregate_type: &StableCode,
    aggregate_id: AggregateId,
    aggregate_revision: SafeUint,
    stream_sequence: SafeUint,
    occurred_at: UtcMillis,
    schema_version: u16,
    event_type: &StableCode,
    required_reader_capability: Option<&StableCode>,
    payload: &T,
) -> CanonicalValue
where
    T: CanonicalEncode,
{
    CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            protocol_version.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(2),
            minimum_reader_version.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(event_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            aggregate_type.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(aggregate_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            aggregate_revision.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(8),
            stream_sequence.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(9),
            occurred_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Unsigned(u64::from(schema_version)),
        ),
        (
            CanonicalValue::Unsigned(11),
            event_type.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(12),
            required_reader_capability
                .map_or(CanonicalValue::Null, CanonicalEncode::to_canonical_value),
        ),
        (CanonicalValue::Unsigned(13), payload.to_canonical_value()),
    ])
}

fn event_digest<T>(event: &T) -> Result<Sha256Digest, EventIntegrityError>
where
    T: CanonicalEncode + ?Sized,
{
    let bytes = encode_deterministic_cbor(event)?;
    Ok(Sha256Digest::hash_domain(EVENT_HASH_DOMAIN, &bytes))
}

/// Returns the exact bytes an Ed25519 event signer must sign.
#[must_use]
pub fn event_signature_input(digest: Sha256Digest) -> Vec<u8> {
    let mut input = Vec::with_capacity(EVENT_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
    input.extend_from_slice(EVENT_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    input
}

fn verify_event_signature(
    digest: Sha256Digest,
    signer: SigningPublicKey,
    signature: Ed25519Signature,
) -> Result<(), EventIntegrityError> {
    let key = VerifyingKey::from_bytes(signer.as_bytes())
        .map_err(|_| EventIntegrityError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    key.verify_strict(&event_signature_input(digest), &signature)
        .map_err(|_| EventIntegrityError::InvalidSignature)
}

/// Result of successful event integrity verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityVerification {
    /// Digest consistency only; origin is unauthenticated.
    HashOnly,
    /// Strict signature verified; outer policy must still authorize the key.
    Signed {
        /// Verified signer key.
        signer: SigningPublicKey,
    },
}

/// An event that passed version, contract, digest, and optional signature checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEventEnvelope<T> {
    envelope: EventEnvelopeV1<T>,
    verification: IntegrityVerification,
}

impl<T> VerifiedEventEnvelope<T> {
    /// Returns the checked envelope.
    #[must_use]
    pub const fn envelope(&self) -> &EventEnvelopeV1<T> {
        &self.envelope
    }

    /// Returns the integrity-checked registered event type.
    #[must_use]
    pub const fn event_type(&self) -> &StableCode {
        &self.envelope.event_type
    }

    /// Returns the integrity-checked aggregate family.
    #[must_use]
    pub const fn aggregate_type(&self) -> &StableCode {
        &self.envelope.aggregate_type
    }

    /// Returns the integrity-checked typed payload.
    #[must_use]
    pub const fn payload(&self) -> &T {
        &self.envelope.payload
    }

    /// Returns the achieved integrity level.
    #[must_use]
    pub const fn verification(&self) -> IntegrityVerification {
        self.verification
    }

    /// Consumes the proof wrapper and returns the checked typed payload.
    #[must_use]
    pub fn into_payload(self) -> T {
        self.envelope.payload
    }
}

/// An unknown event's safe cursor behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownEventAction {
    /// Preserve exact canonical bytes and skip only an optional projection.
    PreserveAndSkip,
    /// Stop before advancing the cursor.
    StopCursor,
}

/// Integrity-verified metadata used only to select a generated typed decoder.
///
/// The payload remains untyped; it must still pass
/// [`EventEnvelopeV1::decode_and_verify`] before projection or domain use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEventDispatchMetadata {
    event_type: StableCode,
    schema_version: u16,
    verification: IntegrityVerification,
}

impl VerifiedEventDispatchMetadata {
    /// Returns the integrity-checked event type dispatch key.
    #[must_use]
    pub const fn event_type(&self) -> &StableCode {
        &self.event_type
    }

    /// Returns the integrity-checked payload schema dispatch key.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the integrity level established before dispatch.
    #[must_use]
    pub const fn verification(&self) -> IntegrityVerification {
        self.verification
    }
}

/// Verifies a complete envelope and returns only safe generated-dispatch keys.
///
/// This helper does not decode the payload. A matching generated dispatcher must
/// immediately call [`EventEnvelopeV1::decode_and_verify`] for the selected type.
///
/// # Errors
///
/// Returns [`EventIntegrityError`] for any envelope, primitive, digest, or
/// signature failure.
pub fn peek_verified_event_dispatch_metadata(
    bytes: &[u8],
    reader: ProtocolVersion,
) -> Result<VerifiedEventDispatchMetadata, EventIntegrityError> {
    let parsed = parse_and_verify_event(bytes, reader)?;
    Ok(VerifiedEventDispatchMetadata {
        event_type: parsed.event_type,
        schema_version: parsed.schema_version,
        verification: parsed.verification,
    })
}

/// Exact validated bytes for an event version this reader does not understand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueCanonicalEvent {
    bytes: Vec<u8>,
    event_type: StableCode,
    schema_version: u16,
    verification: IntegrityVerification,
    action: UnknownEventAction,
}

impl OpaqueCanonicalEvent {
    /// Admits exact deterministic bytes for an event payload version this reader
    /// does not understand.
    ///
    /// Admission validates the complete envelope, all metadata primitives, the
    /// version range, and hash/signature integrity. Cursor behavior comes only
    /// from the compiled event registry; envelope claims cannot relax it.
    ///
    /// # Errors
    ///
    /// Returns [`EventIntegrityError`] unless `bytes` are one complete, readable,
    /// integrity-checked v1 envelope for an unknown event type or unknown schema
    /// version. Known schema versions must use their typed decoder.
    pub fn admit(bytes: Vec<u8>, reader: ProtocolVersion) -> Result<Self, EventIntegrityError> {
        let parsed = parse_and_verify_event(&bytes, reader)?;

        if crate::event_registry_metadata(parsed.event_type.as_str()).is_some() {
            // An exact locally registered type/schema must pass its generated
            // typed decoder; opaque admission would bypass payload validation.
            return Err(EventIntegrityError::ContractMismatch);
        }

        let action =
            match crate::event_family_metadata(parsed.event_type.as_str(), parsed.schema_version) {
                None => UnknownEventAction::StopCursor,
                Some(metadata) => {
                    if parsed.aggregate_type.as_str() != metadata.aggregate_type {
                        return Err(EventIntegrityError::ContractMismatch);
                    }
                    if parsed.required_reader_capability.is_some()
                        || metadata.required_reader_capability.is_some()
                        || metadata.unknown_version_policy == UnknownVersionPolicy::StopCursor
                    {
                        UnknownEventAction::StopCursor
                    } else {
                        UnknownEventAction::PreserveAndSkip
                    }
                }
            };

        Ok(Self {
            bytes,
            event_type: parsed.event_type,
            schema_version: parsed.schema_version,
            verification: parsed.verification,
            action,
        })
    }

    /// Returns the cursor action without discarding the event bytes.
    #[must_use]
    pub const fn action(&self) -> UnknownEventAction {
        self.action
    }

    /// Returns the exact canonical bytes for durable storage/forwarding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the validated event type carried by the envelope.
    #[must_use]
    pub const fn event_type(&self) -> &StableCode {
        &self.event_type
    }

    /// Returns the positive payload schema version carried by the envelope.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the integrity level established during admission.
    #[must_use]
    pub const fn verification(&self) -> IntegrityVerification {
        self.verification
    }
}

struct ParsedCanonicalEvent {
    protocol_version: ProtocolVersion,
    minimum_reader_version: ProtocolVersion,
    event_id: EventId,
    tenant_id: TenantId,
    aggregate_type: StableCode,
    aggregate_id: AggregateId,
    aggregate_revision: SafeUint,
    stream_sequence: SafeUint,
    occurred_at: UtcMillis,
    schema_version: u16,
    event_type: StableCode,
    required_reader_capability: Option<StableCode>,
    payload: CanonicalValue,
    integrity: EventIntegrityV1,
    verification: IntegrityVerification,
}

fn parse_and_verify_event(
    bytes: &[u8],
    reader: ProtocolVersion,
) -> Result<ParsedCanonicalEvent, EventIntegrityError> {
    let decoded = decode_deterministic_cbor(bytes)?;
    let CanonicalValue::Map(entries) = decoded else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    validate_envelope_keys(&entries)?;

    let protocol_version = parse_protocol_version(&entries[0].1)?;
    let minimum_reader_version = parse_protocol_version(&entries[1].1)?;
    if protocol_version.major() != EVENT_PROTOCOL_MAJOR {
        return Err(EventIntegrityError::ContractMismatch);
    }
    ensure_readable(
        reader,
        WireVersion::new(protocol_version, minimum_reader_version),
    )?;
    let event_id = parse_text_primitive(&entries[2].1)?;
    let tenant_id = parse_text_primitive(&entries[3].1)?;
    let aggregate_type = parse_stable_code(&entries[4].1)?;
    let aggregate_id = parse_text_primitive(&entries[5].1)?;
    let aggregate_revision = parse_positive_safe_uint(&entries[6].1)?;
    let stream_sequence = parse_positive_safe_uint(&entries[7].1)?;
    let occurred_at = parse_utc_millis(&entries[8].1)?;
    let schema_version = parse_positive_u16(&entries[9].1)?;
    let event_type = parse_stable_code(&entries[10].1)?;
    if event_type_version(event_type.as_str()) != Some(schema_version) {
        return Err(EventIntegrityError::ContractMismatch);
    }
    let required_reader_capability = parse_optional_stable_code(&entries[11].1)?;
    let payload = entries[12].1.clone();

    let unsigned = CanonicalValue::Map(entries[..13].to_vec());
    let digest = event_digest(&unsigned)?;
    let integrity = parse_integrity(&entries[13].1)?;
    if digest != integrity.digest() {
        return Err(EventIntegrityError::DigestMismatch);
    }
    let verification = match &integrity {
        EventIntegrityV1::Sha256 { .. } => IntegrityVerification::HashOnly,
        EventIntegrityV1::Ed25519 {
            signer, signature, ..
        } => {
            verify_event_signature(digest, *signer, *signature)?;
            IntegrityVerification::Signed { signer: *signer }
        }
    };

    Ok(ParsedCanonicalEvent {
        protocol_version,
        minimum_reader_version,
        event_id,
        tenant_id,
        aggregate_type,
        aggregate_id,
        aggregate_revision,
        stream_sequence,
        occurred_at,
        schema_version,
        event_type,
        required_reader_capability,
        payload,
        integrity,
        verification,
    })
}

fn event_type_version(event_type: &str) -> Option<u16> {
    let (family, version) = event_type.rsplit_once(".v")?;
    if family.is_empty()
        || version.is_empty()
        || (version.len() > 1 && version.starts_with('0'))
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let version = version.parse().ok()?;
    (version > 0).then_some(version)
}

fn validate_envelope_keys(
    entries: &[(CanonicalValue, CanonicalValue)],
) -> Result<(), EventIntegrityError> {
    if entries.len() != 14
        || entries.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).expect("index fits u64"))
        })
    {
        Err(EventIntegrityError::ContractMismatch)
    } else {
        Ok(())
    }
}

fn parse_protocol_version(value: &CanonicalValue) -> Result<ProtocolVersion, EventIntegrityError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    if entries.len() != 2
        || entries[0].0 != CanonicalValue::Unsigned(1)
        || entries[1].0 != CanonicalValue::Unsigned(2)
    {
        return Err(EventIntegrityError::ContractMismatch);
    }
    Ok(ProtocolVersion::new(
        parse_u16(&entries[0].1)?,
        parse_u16(&entries[1].1)?,
    ))
}

fn parse_u16(value: &CanonicalValue) -> Result<u16, EventIntegrityError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    u16::try_from(*value).map_err(|_| EventIntegrityError::ContractMismatch)
}

fn parse_positive_u16(value: &CanonicalValue) -> Result<u16, EventIntegrityError> {
    let value = parse_u16(value)?;
    if value == 0 {
        Err(EventIntegrityError::ContractMismatch)
    } else {
        Ok(value)
    }
}

fn parse_positive_safe_uint(value: &CanonicalValue) -> Result<SafeUint, EventIntegrityError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    if *value == 0 {
        Err(EventIntegrityError::ContractMismatch)
    } else {
        SafeUint::new(*value).map_err(|_| EventIntegrityError::ContractMismatch)
    }
}

fn parse_text_primitive<T>(value: &CanonicalValue) -> Result<T, EventIntegrityError>
where
    T: FromStr,
{
    let CanonicalValue::Text(value) = value else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    value
        .parse()
        .map_err(|_| EventIntegrityError::ContractMismatch)
}

fn parse_stable_code(value: &CanonicalValue) -> Result<StableCode, EventIntegrityError> {
    parse_text_primitive(value)
}

fn parse_optional_stable_code(
    value: &CanonicalValue,
) -> Result<Option<StableCode>, EventIntegrityError> {
    match value {
        CanonicalValue::Null => Ok(None),
        CanonicalValue::Text(_) => parse_stable_code(value).map(Some),
        _ => Err(EventIntegrityError::ContractMismatch),
    }
}

fn parse_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, EventIntegrityError> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| EventIntegrityError::ContractMismatch)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(EventIntegrityError::ContractMismatch),
    };
    UtcMillis::new(value).map_err(|_| EventIntegrityError::ContractMismatch)
}

fn parse_integrity(value: &CanonicalValue) -> Result<EventIntegrityV1, EventIntegrityError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    if entries.len() < 2
        || entries[0].0 != CanonicalValue::Unsigned(1)
        || entries[1].0 != CanonicalValue::Unsigned(2)
    {
        return Err(EventIntegrityError::ContractMismatch);
    }
    let CanonicalValue::Text(algorithm) = &entries[0].1 else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    let digest = Sha256Digest::from_bytes(parse_fixed_bytes(&entries[1].1)?);
    match algorithm.as_str() {
        "sha256" if entries.len() == 2 => Ok(EventIntegrityV1::Sha256 { digest }),
        "ed25519"
            if entries.len() == 4
                && entries[2].0 == CanonicalValue::Unsigned(3)
                && entries[3].0 == CanonicalValue::Unsigned(4) =>
        {
            let signer = SigningPublicKey::try_from(parse_fixed_bytes(&entries[2].1)?)
                .map_err(|_| EventIntegrityError::InvalidSignature)?;
            let signature = Ed25519Signature::from_bytes(parse_fixed_bytes(&entries[3].1)?);
            Ok(EventIntegrityV1::Ed25519 {
                digest,
                signer,
                signature,
            })
        }
        _ => Err(EventIntegrityError::ContractMismatch),
    }
}

fn parse_fixed_bytes<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], EventIntegrityError> {
    let CanonicalValue::Bytes(bytes) = value else {
        return Err(EventIntegrityError::ContractMismatch);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| EventIntegrityError::ContractMismatch)
}

/// Event construction or integrity verification failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventIntegrityError {
    /// Registry constants or envelope metadata do not agree.
    ContractMismatch,
    /// Reader/writer version compatibility failed.
    Version(VersionError),
    /// Deterministic CBOR encoding or decoding failed.
    CanonicalCbor(CanonicalCborError),
    /// The deterministic payload did not match its generated typed schema.
    PayloadDecode(CanonicalDecodeError),
    /// Stored digest differs from the unsigned envelope digest.
    DigestMismatch,
    /// Strict Ed25519 verification failed.
    InvalidSignature,
}

impl fmt::Display for EventIntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContractMismatch => "event metadata does not match its registered payload",
            Self::Version(_) => "event protocol version is not readable",
            Self::CanonicalCbor(_) => "event is not valid deterministic CBOR",
            Self::PayloadDecode(_) => "event payload does not match its registered schema",
            Self::DigestMismatch => "event digest mismatch",
            Self::InvalidSignature => "event signature verification failed",
        })
    }
}

impl Error for EventIntegrityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Version(error) => Some(error),
            Self::CanonicalCbor(error) => Some(error),
            Self::PayloadDecode(error) => Some(error),
            Self::ContractMismatch | Self::DigestMismatch | Self::InvalidSignature => None,
        }
    }
}

impl From<VersionError> for EventIntegrityError {
    fn from(value: VersionError) -> Self {
        Self::Version(value)
    }
}

impl From<CanonicalCborError> for EventIntegrityError {
    fn from(value: CanonicalCborError) -> Self {
        Self::CanonicalCbor(value)
    }
}

impl From<CanonicalDecodeError> for EventIntegrityError {
    fn from(value: CanonicalDecodeError) -> Self {
        Self::PayloadDecode(value)
    }
}
