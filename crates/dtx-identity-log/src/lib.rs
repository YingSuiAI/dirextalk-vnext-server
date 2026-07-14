#![forbid(unsafe_code)]

//! Self-certifying identity and device-log primitives.
//!
//! This crate deliberately owns only canonical bytes, signatures, and the
//! in-memory authorization projection. HTTP admission, storage, recovery UI,
//! and directory discovery are separate boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    str::FromStr,
};

use dtx_domain::{DeviceId, IdentityId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};

/// Frozen original identity-log writer version retained for replay-only reads.
pub const IDENTITY_LOG_V1_0_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);
/// Exact frozen original identity-log wire version.
pub const IDENTITY_LOG_V1_0_WIRE_VERSION: WireVersion = WireVersion::new(
    IDENTITY_LOG_V1_0_PROTOCOL_VERSION,
    IDENTITY_LOG_V1_0_PROTOCOL_VERSION,
);
/// The current writable identity-log wire version.
pub const IDENTITY_LOG_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 1);
/// Exact current identity-log writer and minimum-reader version.
pub const IDENTITY_LOG_WIRE_VERSION: WireVersion =
    WireVersion::new(IDENTITY_LOG_PROTOCOL_VERSION, IDENTITY_LOG_PROTOCOL_VERSION);

/// Domain separator for an unsigned identity-log event digest.
pub const IDENTITY_LOG_EVENT_HASH_DOMAIN: &[u8] = b"dirextalk.identity-log-event.v1\0";
/// Domain separator for the Ed25519 input authenticating an identity-log event.
pub const IDENTITY_LOG_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.identity-log-signature.v1\0";
/// Domain separator for the durable chain hash of a complete signed event.
pub const IDENTITY_LOG_ENTRY_HASH_DOMAIN: &[u8] = b"dirextalk.identity-log-entry.v1\0";
/// Domain separator for a root-signed device certificate digest.
pub const DEVICE_CERTIFICATE_HASH_DOMAIN: &[u8] = b"dirextalk.device-certificate.v1\0";
/// Domain separator for the Ed25519 input authenticating a device certificate.
pub const DEVICE_CERTIFICATE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.device-certificate-signature.v1\0";
/// Domain separator proving the genesis recovery key is controlled by its holder.
pub const GENESIS_RECOVERY_ACCEPTANCE_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-log-genesis-recovery-acceptance.v1\0";
/// Domain separator for the genesis recovery-key acceptance signature.
pub const GENESIS_RECOVERY_ACCEPTANCE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.identity-log-genesis-recovery-acceptance-signature.v1\0";
/// Domain separator proving a successor root or recovery key is controlled.
pub const KEY_ROTATION_ACCEPTANCE_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-log-key-acceptance.v1\0";
/// Domain separator for successor root or recovery key acceptance signatures.
pub const KEY_ROTATION_ACCEPTANCE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.identity-log-key-acceptance-signature.v1\0";
/// Domain separator for current-recovery authorization of a recovery rotation.
pub const RECOVERY_ROTATION_AUTHORIZATION_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-log-recovery-rotation-authorization.v1\0";
/// Domain separator for the current-recovery authorization signature.
pub const RECOVERY_ROTATION_AUTHORIZATION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.identity-log-recovery-rotation-authorization-signature.v1\0";

const MAX_RELAY_URLS: usize = 8;
const MAX_RELAY_URL_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityLogWireLine {
    FrozenV1_0,
    CurrentV1_1,
}

/// Identity-log admission failed without revealing private key or storage state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityLogError {
    /// A writer or embedded contract used a different wire version.
    InvalidWireVersion,
    /// Deterministic bytes did not have the exact declared type shape.
    InvalidCanonical,
    /// An Ed25519 proof did not authenticate its declared public key.
    InvalidSignature,
    /// The immutable genesis event did not bind the identity and its keys.
    InvalidGenesis,
    /// An event cannot occupy its declared sequence or parent position.
    InvalidEventShape,
    /// The event belongs to a different self-certifying identity.
    IdentityMismatch,
    /// The event sequence is not the next contiguous log sequence.
    SequenceMismatch,
    /// The event predecessor hash is not the current log head.
    PreviousHashMismatch,
    /// A previously accepted complete event was submitted again.
    Replay,
    /// The verified signer is not authorized for this transition.
    UnauthorizedSigner,
    /// A device certificate is malformed, stale, or not issued by the current root.
    InvalidDeviceCertificate,
    /// A device ID or device key was already used in this identity log.
    DeviceAlreadyExists,
    /// The named device does not exist in this identity log.
    DeviceNotFound,
    /// The named device was already revoked.
    DeviceAlreadyRevoked,
    /// A root or recovery key succession proof is invalid.
    InvalidRotation,
    /// A relay descriptor is malformed, expired, or not canonical.
    InvalidRelayDescriptor,
}

impl fmt::Display for IdentityLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWireVersion => "identity log uses an unsupported wire version",
            Self::InvalidCanonical => "identity log bytes do not match the canonical contract",
            Self::InvalidSignature => "identity log signature is invalid",
            Self::InvalidGenesis => "identity log genesis is invalid",
            Self::InvalidEventShape => "identity log event has an invalid position or shape",
            Self::IdentityMismatch => "identity log event belongs to another identity",
            Self::SequenceMismatch => "identity log event sequence is not contiguous",
            Self::PreviousHashMismatch => "identity log event predecessor does not match",
            Self::Replay => "identity log event was already accepted",
            Self::UnauthorizedSigner => "identity log signer is not authorized",
            Self::InvalidDeviceCertificate => "device certificate is invalid",
            Self::DeviceAlreadyExists => "device ID or key was already used",
            Self::DeviceNotFound => "device does not exist",
            Self::DeviceAlreadyRevoked => "device is already revoked",
            Self::InvalidRotation => "key rotation proof is invalid",
            Self::InvalidRelayDescriptor => "relay descriptor is invalid",
        })
    }
}

impl Error for IdentityLogError {}

/// An X25519-compatible device encryption public key.
///
/// X25519 public encodings are opaque 32-byte strings. The all-zero value is
/// rejected because it can produce an all-zero shared secret in a later MLS or
/// mailbox implementation. This crate deliberately does not perform X25519.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceEncryptionPublicKey([u8; 32]);

impl DeviceEncryptionPublicKey {
    /// Returns the exact wire encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A device encryption key used the forbidden all-zero encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceEncryptionPublicKeyError;

impl fmt::Display for DeviceEncryptionPublicKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("device encryption public key must not be all zero")
    }
}

impl Error for DeviceEncryptionPublicKeyError {}

impl TryFrom<[u8; 32]> for DeviceEncryptionPublicKey {
    type Error = DeviceEncryptionPublicKeyError;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        if value.iter().all(|byte| *byte == 0) {
            Err(DeviceEncryptionPublicKeyError)
        } else {
            Ok(Self(value))
        }
    }
}

impl CanonicalEncode for DeviceEncryptionPublicKey {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Bytes(self.0.to_vec())
    }
}

/// The exact transition for which a successor key must prove possession.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAcceptancePurposeV1 {
    /// Proof for a root-key rotation authored by the current root.
    RootRotate,
    /// Proof for a recovery-key rotation authored by the current root.
    RecoveryRotate,
    /// Root-key proof inside a recovery restore authored by current recovery.
    RecoveryRestoreRoot,
    /// Recovery-key proof inside a recovery restore authored by current recovery.
    RecoveryRestoreRecovery,
}

impl KeyAcceptancePurposeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::RootRotate => 1,
            Self::RecoveryRotate => 2,
            Self::RecoveryRestoreRoot => 3,
            Self::RecoveryRestoreRecovery => 4,
        }
    }
}

/// The unsigned root-issued content of a device certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedDeviceCertificateV1 {
    wire: WireVersion,
    identity_id: IdentityId,
    device_id: DeviceId,
    device_signing_key: SigningPublicKey,
    device_encryption_key: DeviceEncryptionPublicKey,
    issuer_root_key: SigningPublicKey,
    issued_at: UtcMillis,
}

impl UnsignedDeviceCertificateV1 {
    /// Creates exact unsigned certificate content for an identity device.
    ///
    /// The caller obtains the root signature externally, then passes it to
    /// [`DeviceCertificateV1::signed`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidWireVersion`] for a non-v1 wire
    /// value and [`IdentityLogError::InvalidDeviceCertificate`] when keys
    /// overlap an invalid certificate role.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wire: WireVersion,
        identity_id: IdentityId,
        device_id: DeviceId,
        device_signing_key: SigningPublicKey,
        device_encryption_key: DeviceEncryptionPublicKey,
        issuer_root_key: SigningPublicKey,
        issued_at: UtcMillis,
    ) -> Result<Self, IdentityLogError> {
        validate_wire_version(wire)?;
        if device_signing_key.as_bytes() == device_encryption_key.as_bytes()
            || device_signing_key == issuer_root_key
        {
            return Err(IdentityLogError::InvalidDeviceCertificate);
        }
        Ok(Self {
            wire,
            identity_id,
            device_id,
            device_signing_key,
            device_encryption_key,
            issuer_root_key,
            issued_at,
        })
    }

    /// Returns the domain-separated digest the issuer must authenticate.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidCanonical`] if deterministic CBOR
    /// encoding cannot satisfy the bounded wire profile.
    pub fn signing_digest(&self) -> Result<Sha256Digest, IdentityLogError> {
        canonical_hash(DEVICE_CERTIFICATE_HASH_DOMAIN, self)
    }
}

impl CanonicalEncode for UnsignedDeviceCertificateV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), self.wire.to_canonical_value()),
            (
                CanonicalValue::Unsigned(2),
                identity_value(self.identity_id),
            ),
            (CanonicalValue::Unsigned(3), device_id_value(self.device_id)),
            (
                CanonicalValue::Unsigned(4),
                self.device_signing_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.device_encryption_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.issuer_root_key.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.issued_at.to_canonical_value(),
            ),
        ])
    }
}

/// A root-signed certificate binding one device's signing and encryption keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCertificateV1 {
    unsigned: UnsignedDeviceCertificateV1,
    signature: Ed25519Signature,
}

impl DeviceCertificateV1 {
    /// Attaches and verifies the root signature over an unsigned certificate.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidDeviceCertificate`] if the issuer
    /// proof does not authenticate the exact unsigned certificate.
    pub fn signed(
        unsigned: UnsignedDeviceCertificateV1,
        signature: Ed25519Signature,
    ) -> Result<Self, IdentityLogError> {
        let certificate = Self {
            unsigned,
            signature,
        };
        certificate.verify()?;
        Ok(certificate)
    }

    /// Re-verifies the issuer proof before a certificate enters the log.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidDeviceCertificate`] when the root
    /// proof is malformed or does not verify strictly.
    pub fn verify(&self) -> Result<(), IdentityLogError> {
        let digest = self.unsigned.signing_digest()?;
        verify_signature(
            self.unsigned.issuer_root_key,
            &device_certificate_signature_input(digest),
            self.signature,
        )
        .map_err(|_| IdentityLogError::InvalidDeviceCertificate)
    }

    /// Encodes the full certificate using deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidCanonical`] if encoding exceeds the
    /// deterministic CBOR profile.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, IdentityLogError> {
        encode_deterministic_cbor(self).map_err(|_| IdentityLogError::InvalidCanonical)
    }

    /// Returns the exact wire version authenticated by this certificate.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.unsigned.wire
    }

    /// Returns the identity named by this certificate.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.unsigned.identity_id
    }

    /// Returns the immutable device ID.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.unsigned.device_id
    }

    /// Returns the device signing key.
    #[must_use]
    pub const fn device_signing_key(&self) -> SigningPublicKey {
        self.unsigned.device_signing_key
    }

    /// Returns the device encryption key.
    #[must_use]
    pub const fn device_encryption_key(&self) -> DeviceEncryptionPublicKey {
        self.unsigned.device_encryption_key
    }

    /// Returns the root key that issued this certificate.
    #[must_use]
    pub const fn issuer_root_key(&self) -> SigningPublicKey {
        self.unsigned.issuer_root_key
    }

    /// Returns the certificate issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UtcMillis {
        self.unsigned.issued_at
    }
}

impl CanonicalEncode for DeviceCertificateV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        let CanonicalValue::Map(mut fields) = self.unsigned.to_canonical_value() else {
            unreachable!("unsigned device certificate is always a map");
        };
        fields.push((
            CanonicalValue::Unsigned(8),
            self.signature.to_canonical_value(),
        ));
        CanonicalValue::Map(fields)
    }
}

/// Returns the exact bytes a device root key must sign for `digest`.
#[must_use]
pub fn device_certificate_signature_input(digest: Sha256Digest) -> Vec<u8> {
    signature_input(DEVICE_CERTIFICATE_SIGNATURE_DOMAIN, digest)
}

/// A bounded ordered relay descriptor that is signed by its containing log event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayDescriptorV1 {
    wire: WireVersion,
    relay_urls: Vec<String>,
    expires_at: UtcMillis,
}

impl RelayDescriptorV1 {
    /// Builds a canonical literal relay descriptor.
    ///
    /// URLs are intentionally literal, ASCII HTTPS endpoints rather than a
    /// guessed URL normalization algorithm. They must be strictly increasing
    /// bytewise, unique, bounded, credential-free, and contain no query or
    /// fragment component.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidWireVersion`] for a non-v1 wire
    /// value or [`IdentityLogError::InvalidRelayDescriptor`] for an unordered,
    /// unsafe, empty, or oversized descriptor.
    pub fn new(
        wire: WireVersion,
        relay_urls: Vec<String>,
        expires_at: UtcMillis,
    ) -> Result<Self, IdentityLogError> {
        validate_wire_version(wire)?;
        validate_relay_urls(&relay_urls)?;
        Ok(Self {
            wire,
            relay_urls,
            expires_at,
        })
    }

    /// Returns the ordered literal relay URLs.
    #[must_use]
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    /// Returns the exact wire version carried by this descriptor.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.wire
    }

    /// Returns the descriptor expiration timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    fn validate_for_event(&self, occurred_at: UtcMillis) -> Result<(), IdentityLogError> {
        if self.expires_at <= occurred_at {
            Err(IdentityLogError::InvalidRelayDescriptor)
        } else {
            Ok(())
        }
    }
}

impl CanonicalEncode for RelayDescriptorV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), self.wire.to_canonical_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Array(
                    self.relay_urls
                        .iter()
                        .cloned()
                        .map(CanonicalValue::Text)
                        .collect(),
                ),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }
}

/// The immutable transition encoded by an identity-log event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityLogEventPayloadV1 {
    /// Establishes the genesis root and independent recovery key.
    Genesis {
        /// Root signing key from which `identity_id` derives.
        root_signing_key: SigningPublicKey,
        /// Independent recovery signing key.
        recovery_signing_key: SigningPublicKey,
        /// Proof of possession by `recovery_signing_key`.
        recovery_acceptance_signature: Ed25519Signature,
    },
    /// Adds one root-certified device. An active device may co-authorize it.
    DeviceAdd {
        /// The root-signed device certificate.
        certificate: DeviceCertificateV1,
    },
    /// Permanently revokes one enrolled device ID.
    DeviceRevoke {
        /// Device to revoke.
        device_id: DeviceId,
    },
    /// Rotates the online root signing key.
    RootRotate {
        /// Proposed successor root key.
        new_root_signing_key: SigningPublicKey,
        /// Proof of possession by the successor key.
        acceptance_signature: Ed25519Signature,
    },
    /// Rotates the offline recovery signing key.
    RecoveryRotate {
        /// Proposed successor recovery key.
        new_recovery_signing_key: SigningPublicKey,
        /// Proof of possession by the successor key.
        acceptance_signature: Ed25519Signature,
        /// Authorization by the current recovery key, required by wire `1.1`.
        recovery_authorization_signature: Option<Ed25519Signature>,
    },
    /// Uses recovery to rotate both authority keys and revoke all devices.
    RecoveryRestore {
        /// Successor root key.
        new_root_signing_key: SigningPublicKey,
        /// Successor recovery key.
        new_recovery_signing_key: SigningPublicKey,
        /// Proof of possession by the successor root key.
        root_acceptance_signature: Ed25519Signature,
        /// Proof of possession by the successor recovery key.
        recovery_acceptance_signature: Ed25519Signature,
    },
    /// Publishes a current relay descriptor through the signed append-only log.
    RelayDescriptor {
        /// Bounded relay descriptor.
        descriptor: RelayDescriptorV1,
    },
}

impl IdentityLogEventPayloadV1 {
    const fn kind(&self) -> IdentityLogEventKindV1 {
        match self {
            Self::Genesis { .. } => IdentityLogEventKindV1::Genesis,
            Self::DeviceAdd { .. } => IdentityLogEventKindV1::DeviceAdd,
            Self::DeviceRevoke { .. } => IdentityLogEventKindV1::DeviceRevoke,
            Self::RootRotate { .. } => IdentityLogEventKindV1::RootRotate,
            Self::RecoveryRotate { .. } => IdentityLogEventKindV1::RecoveryRotate,
            Self::RecoveryRestore { .. } => IdentityLogEventKindV1::RecoveryRestore,
            Self::RelayDescriptor { .. } => IdentityLogEventKindV1::RelayDescriptor,
        }
    }

    fn to_canonical_value_for_wire(&self, wire: WireVersion) -> CanonicalValue {
        let line = identity_log_wire_line(wire)
            .expect("identity-log events are constructed only with a supported wire version");
        match self {
            Self::Genesis {
                root_signing_key,
                recovery_signing_key,
                recovery_acceptance_signature,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    root_signing_key.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    recovery_signing_key.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    recovery_acceptance_signature.to_canonical_value(),
                ),
            ]),
            Self::DeviceAdd { certificate } => CanonicalValue::Map(vec![(
                CanonicalValue::Unsigned(1),
                certificate.to_canonical_value(),
            )]),
            Self::DeviceRevoke { device_id } => CanonicalValue::Map(vec![(
                CanonicalValue::Unsigned(1),
                device_id_value(*device_id),
            )]),
            Self::RootRotate {
                new_root_signing_key,
                acceptance_signature,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    new_root_signing_key.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    acceptance_signature.to_canonical_value(),
                ),
            ]),
            Self::RecoveryRotate {
                new_recovery_signing_key,
                acceptance_signature,
                recovery_authorization_signature,
            } => {
                let mut fields = vec![
                    (
                        CanonicalValue::Unsigned(1),
                        new_recovery_signing_key.to_canonical_value(),
                    ),
                    (
                        CanonicalValue::Unsigned(2),
                        acceptance_signature.to_canonical_value(),
                    ),
                ];
                if line == IdentityLogWireLine::CurrentV1_1 {
                    fields.push((
                        CanonicalValue::Unsigned(3),
                        recovery_authorization_signature
                            .expect("current recovery rotation requires a recovery signature")
                            .to_canonical_value(),
                    ));
                }
                CanonicalValue::Map(fields)
            }
            Self::RecoveryRestore {
                new_root_signing_key,
                new_recovery_signing_key,
                root_acceptance_signature,
                recovery_acceptance_signature,
            } => CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    new_root_signing_key.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    new_recovery_signing_key.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    root_acceptance_signature.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(4),
                    recovery_acceptance_signature.to_canonical_value(),
                ),
            ]),
            Self::RelayDescriptor { descriptor } => CanonicalValue::Map(vec![(
                CanonicalValue::Unsigned(1),
                descriptor.to_canonical_value(),
            )]),
        }
    }
}

/// The stable type discriminator for [`IdentityLogEventPayloadV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityLogEventKindV1 {
    Genesis,
    DeviceAdd,
    DeviceRevoke,
    RootRotate,
    RecoveryRotate,
    RecoveryRestore,
    RelayDescriptor,
}

impl IdentityLogEventKindV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Genesis => 1,
            Self::DeviceAdd => 2,
            Self::DeviceRevoke => 3,
            Self::RootRotate => 4,
            Self::RecoveryRotate => 5,
            Self::RecoveryRestore => 6,
            Self::RelayDescriptor => 7,
        }
    }

    fn from_code(value: u64) -> Result<Self, IdentityLogError> {
        match value {
            1 => Ok(Self::Genesis),
            2 => Ok(Self::DeviceAdd),
            3 => Ok(Self::DeviceRevoke),
            4 => Ok(Self::RootRotate),
            5 => Ok(Self::RecoveryRotate),
            6 => Ok(Self::RecoveryRestore),
            7 => Ok(Self::RelayDescriptor),
            _ => Err(IdentityLogError::InvalidCanonical),
        }
    }
}

/// The unsigned, deterministic fields that an identity-log signer authenticates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedIdentityLogEventV1 {
    wire: WireVersion,
    identity_id: IdentityId,
    sequence: SafeUint,
    previous_event_hash: Option<Sha256Digest>,
    occurred_at: UtcMillis,
    payload: IdentityLogEventPayloadV1,
    signer: SigningPublicKey,
}

impl UnsignedIdentityLogEventV1 {
    /// Creates unsigned event content after enforcing its static v1 invariants.
    ///
    /// # Errors
    ///
    /// Returns an identity-log error when the version, genesis binding,
    /// predecessor shape, certificate proof, or relay expiry is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wire: WireVersion,
        identity_id: IdentityId,
        sequence: SafeUint,
        previous_event_hash: Option<Sha256Digest>,
        occurred_at: UtcMillis,
        payload: IdentityLogEventPayloadV1,
        signer: SigningPublicKey,
    ) -> Result<Self, IdentityLogError> {
        let unsigned = Self {
            wire,
            identity_id,
            sequence,
            previous_event_hash,
            occurred_at,
            payload,
            signer,
        };
        unsigned.validate_static()?;
        Ok(unsigned)
    }

    /// Returns the domain-separated digest the event signer must authenticate.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidCanonical`] if deterministic CBOR
    /// encoding cannot satisfy the bounded wire profile.
    pub fn signing_digest(&self) -> Result<Sha256Digest, IdentityLogError> {
        canonical_hash(IDENTITY_LOG_EVENT_HASH_DOMAIN, self)
    }

    fn validate_static(&self) -> Result<(), IdentityLogError> {
        let wire_line = identity_log_wire_line(self.wire)?;
        if self.sequence.get() == 0 {
            return Err(IdentityLogError::InvalidEventShape);
        }
        match &self.payload {
            IdentityLogEventPayloadV1::Genesis {
                root_signing_key,
                recovery_signing_key,
                recovery_acceptance_signature,
            } => {
                if self.sequence.get() != 1
                    || self.previous_event_hash.is_some()
                    || self.signer != *root_signing_key
                    || root_signing_key == recovery_signing_key
                    || self
                        .identity_id
                        .verify_subject_key(root_signing_key.as_domain_key())
                        .is_err()
                {
                    return Err(IdentityLogError::InvalidGenesis);
                }
                verify_signature(
                    *recovery_signing_key,
                    &genesis_recovery_acceptance_input(
                        self.identity_id,
                        *root_signing_key,
                        *recovery_signing_key,
                    )?,
                    *recovery_acceptance_signature,
                )
                .map_err(|_| IdentityLogError::InvalidGenesis)
            }
            IdentityLogEventPayloadV1::RelayDescriptor { descriptor } => {
                if self.sequence.get() == 1 || self.previous_event_hash.is_none() {
                    return Err(IdentityLogError::InvalidEventShape);
                }
                if descriptor.wire() != self.wire {
                    return Err(IdentityLogError::InvalidWireVersion);
                }
                descriptor.validate_for_event(self.occurred_at)
            }
            IdentityLogEventPayloadV1::DeviceAdd { certificate } => {
                if self.sequence.get() == 1 || self.previous_event_hash.is_none() {
                    return Err(IdentityLogError::InvalidEventShape);
                }
                if certificate.wire() != self.wire {
                    return Err(IdentityLogError::InvalidWireVersion);
                }
                certificate.verify()
            }
            IdentityLogEventPayloadV1::RecoveryRotate {
                recovery_authorization_signature,
                ..
            } => {
                if self.sequence.get() == 1 || self.previous_event_hash.is_none() {
                    return Err(IdentityLogError::InvalidEventShape);
                }
                match (wire_line, recovery_authorization_signature.is_some()) {
                    (IdentityLogWireLine::FrozenV1_0, false)
                    | (IdentityLogWireLine::CurrentV1_1, true) => Ok(()),
                    (IdentityLogWireLine::FrozenV1_0, true) => {
                        Err(IdentityLogError::InvalidCanonical)
                    }
                    (IdentityLogWireLine::CurrentV1_1, false) => {
                        Err(IdentityLogError::InvalidRotation)
                    }
                }
            }
            IdentityLogEventPayloadV1::DeviceRevoke { .. }
            | IdentityLogEventPayloadV1::RootRotate { .. }
            | IdentityLogEventPayloadV1::RecoveryRestore { .. } => {
                if self.sequence.get() == 1 || self.previous_event_hash.is_none() {
                    return Err(IdentityLogError::InvalidEventShape);
                }
                Ok(())
            }
        }
    }
}

impl CanonicalEncode for UnsignedIdentityLogEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), self.wire.to_canonical_value()),
            (
                CanonicalValue::Unsigned(2),
                identity_value(self.identity_id),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.previous_event_hash
                    .map_or(CanonicalValue::Null, |value| value.to_canonical_value()),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.occurred_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Unsigned(self.payload.kind().code()),
            ),
            (
                CanonicalValue::Unsigned(7),
                self.payload.to_canonical_value_for_wire(self.wire),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.signer.to_canonical_value(),
            ),
        ])
    }
}

/// A complete signed append-only identity-log event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityLogEventV1 {
    unsigned: UnsignedIdentityLogEventV1,
    signature: Ed25519Signature,
}

impl IdentityLogEventV1 {
    /// Attaches and verifies the event signature over exact unsigned content.
    ///
    /// # Errors
    ///
    /// Returns an identity-log error if static invariants or the strict Ed25519
    /// signature do not verify.
    pub fn signed(
        unsigned: UnsignedIdentityLogEventV1,
        signature: Ed25519Signature,
    ) -> Result<Self, IdentityLogError> {
        let event = Self {
            unsigned,
            signature,
        };
        event.verify()?;
        Ok(event)
    }

    /// Decodes deterministic CBOR, rejects unknown fields, and verifies the signature.
    ///
    /// # Errors
    ///
    /// Returns an identity-log error for noncanonical bytes, unknown fields or
    /// kinds, a non-v1 version, invalid typed values, or an invalid signature.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, IdentityLogError> {
        let value =
            decode_deterministic_cbor(bytes).map_err(|_| IdentityLogError::InvalidCanonical)?;
        let fields = exact_fields(&value, 9)?;
        let wire = decode_wire_version(field(fields, 1)?)?;
        let identity_id = decode_identity_id(field(fields, 2)?)?;
        let sequence = decode_safe_uint(field(fields, 3)?)?;
        let previous_event_hash = decode_optional_digest(field(fields, 4)?)?;
        let occurred_at = decode_utc_millis(field(fields, 5)?)?;
        let kind = IdentityLogEventKindV1::from_code(decode_unsigned(field(fields, 6)?)?)?;
        let payload = decode_payload(kind, field(fields, 7)?, wire)?;
        let signer = decode_signing_key(field(fields, 8)?)?;
        let signature = decode_signature(field(fields, 9)?)?;
        let unsigned = UnsignedIdentityLogEventV1::new(
            wire,
            identity_id,
            sequence,
            previous_event_hash,
            occurred_at,
            payload,
            signer,
        )?;
        let event = Self::signed(unsigned, signature)?;
        if event.to_deterministic_cbor()? != bytes {
            return Err(IdentityLogError::InvalidCanonical);
        }
        Ok(event)
    }

    /// Re-verifies static invariants and the signer proof.
    ///
    /// # Errors
    ///
    /// Returns an identity-log error when static shape validation or strict
    /// Ed25519 signature verification fails.
    pub fn verify(&self) -> Result<(), IdentityLogError> {
        self.unsigned.validate_static()?;
        verify_signature(
            self.unsigned.signer,
            &identity_log_signature_input(self.unsigned.signing_digest()?),
            self.signature,
        )
    }

    /// Encodes the complete event using deterministic CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidCanonical`] if encoding exceeds the
    /// deterministic CBOR profile.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, IdentityLogError> {
        encode_deterministic_cbor(self).map_err(|_| IdentityLogError::InvalidCanonical)
    }

    /// Computes the durable predecessor hash of this complete signed event.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidCanonical`] if deterministic CBOR
    /// encoding cannot satisfy the bounded wire profile.
    pub fn entry_hash(&self) -> Result<Sha256Digest, IdentityLogError> {
        canonical_hash(IDENTITY_LOG_ENTRY_HASH_DOMAIN, self)
    }

    /// Returns the self-certifying identity ID.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.unsigned.identity_id
    }

    /// Returns the exact wire version of this event.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.unsigned.wire
    }

    /// Returns the immutable log sequence.
    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.unsigned.sequence
    }

    /// Returns the predecessor hash, or `None` for genesis.
    #[must_use]
    pub const fn previous_event_hash(&self) -> Option<Sha256Digest> {
        self.unsigned.previous_event_hash
    }

    /// Returns the event timestamp.
    #[must_use]
    pub const fn occurred_at(&self) -> UtcMillis {
        self.unsigned.occurred_at
    }

    /// Returns the verified signer public key.
    #[must_use]
    pub const fn signer(&self) -> SigningPublicKey {
        self.unsigned.signer
    }

    /// Returns the immutable typed transition.
    #[must_use]
    pub const fn payload(&self) -> &IdentityLogEventPayloadV1 {
        &self.unsigned.payload
    }
}

impl CanonicalEncode for IdentityLogEventV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        let CanonicalValue::Map(mut fields) = self.unsigned.to_canonical_value() else {
            unreachable!("unsigned identity log event is always a map");
        };
        fields.push((
            CanonicalValue::Unsigned(9),
            self.signature.to_canonical_value(),
        ));
        CanonicalValue::Map(fields)
    }
}

/// Returns the exact bytes an identity-log signer must sign for `digest`.
#[must_use]
pub fn identity_log_signature_input(digest: Sha256Digest) -> Vec<u8> {
    signature_input(IDENTITY_LOG_SIGNATURE_DOMAIN, digest)
}

/// Returns the exact proof-of-possession bytes for a genesis recovery key.
///
/// # Errors
///
/// Returns [`IdentityLogError::InvalidCanonical`] if the bounded deterministic
/// input cannot be encoded.
pub fn genesis_recovery_acceptance_input(
    identity_id: IdentityId,
    root_signing_key: SigningPublicKey,
    recovery_signing_key: SigningPublicKey,
) -> Result<Vec<u8>, IdentityLogError> {
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), identity_value(identity_id)),
        (
            CanonicalValue::Unsigned(2),
            root_signing_key.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            recovery_signing_key.to_canonical_value(),
        ),
    ]);
    let digest = canonical_hash(GENESIS_RECOVERY_ACCEPTANCE_HASH_DOMAIN, &value)?;
    Ok(signature_input(
        GENESIS_RECOVERY_ACCEPTANCE_SIGNATURE_DOMAIN,
        digest,
    ))
}

/// Returns the exact proof-of-possession bytes for a successor authority key.
///
/// # Errors
///
/// Returns [`IdentityLogError::InvalidRotation`] for sequence zero and
/// [`IdentityLogError::InvalidCanonical`] if the bounded deterministic input
/// cannot be encoded.
pub fn key_rotation_acceptance_input(
    identity_id: IdentityId,
    sequence: SafeUint,
    previous_event_hash: Option<Sha256Digest>,
    purpose: KeyAcceptancePurposeV1,
    successor_key: SigningPublicKey,
) -> Result<Vec<u8>, IdentityLogError> {
    if sequence.get() == 0 {
        return Err(IdentityLogError::InvalidRotation);
    }
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), identity_value(identity_id)),
        (CanonicalValue::Unsigned(2), sequence.to_canonical_value()),
        (
            CanonicalValue::Unsigned(3),
            previous_event_hash.map_or(CanonicalValue::Null, |value| value.to_canonical_value()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Unsigned(purpose.code()),
        ),
        (
            CanonicalValue::Unsigned(5),
            successor_key.to_canonical_value(),
        ),
    ]);
    let digest = canonical_hash(KEY_ROTATION_ACCEPTANCE_HASH_DOMAIN, &value)?;
    Ok(signature_input(
        KEY_ROTATION_ACCEPTANCE_SIGNATURE_DOMAIN,
        digest,
    ))
}

/// Returns the exact bytes the current recovery key signs for a recovery rotation.
///
/// # Errors
///
/// Returns [`IdentityLogError::InvalidWireVersion`] unless `wire` is current
/// identity-log `1.1`, or [`IdentityLogError::InvalidCanonical`] if the bounded
/// deterministic input cannot be encoded.
#[allow(clippy::too_many_arguments)]
pub fn recovery_rotation_authorization_input(
    wire: WireVersion,
    identity_id: IdentityId,
    sequence: SafeUint,
    previous_event_hash: Option<Sha256Digest>,
    occurred_at: UtcMillis,
    root_signer: SigningPublicKey,
    successor_key: SigningPublicKey,
    successor_acceptance_signature: Ed25519Signature,
) -> Result<Vec<u8>, IdentityLogError> {
    if identity_log_wire_line(wire)? != IdentityLogWireLine::CurrentV1_1 {
        return Err(IdentityLogError::InvalidWireVersion);
    }
    if sequence.get() == 0 {
        return Err(IdentityLogError::InvalidRotation);
    }
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), wire.to_canonical_value()),
        (CanonicalValue::Unsigned(2), identity_value(identity_id)),
        (CanonicalValue::Unsigned(3), sequence.to_canonical_value()),
        (
            CanonicalValue::Unsigned(4),
            previous_event_hash.map_or(CanonicalValue::Null, |value| value.to_canonical_value()),
        ),
        (
            CanonicalValue::Unsigned(5),
            occurred_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            root_signer.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(7),
            successor_key.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(8),
            successor_acceptance_signature.to_canonical_value(),
        ),
    ]);
    let digest = canonical_hash(RECOVERY_ROTATION_AUTHORIZATION_HASH_DOMAIN, &value)?;
    Ok(signature_input(
        RECOVERY_ROTATION_AUTHORIZATION_SIGNATURE_DOMAIN,
        digest,
    ))
}

/// Current enrollment status for a device certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStatusV1 {
    /// Device can co-authorize a root-certified enrollment event.
    Active,
    /// Device can no longer authorize any event.
    Revoked,
}

#[derive(Clone, Debug)]
struct DeviceRecordV1 {
    certificate: DeviceCertificateV1,
    status: DeviceStatusV1,
}

/// In-memory writable projection of a verified current identity log.
///
/// Persistence must use a compare-and-swap on `head_sequence` and `head_hash`,
/// a unique entry hash, and exact event bytes. This pure projection makes those
/// storage semantics testable before the HTTP and `PostgreSQL` layers arrive.
#[derive(Clone, Debug)]
pub struct IdentityLogV1 {
    wire: WireVersion,
    identity_id: IdentityId,
    current_root_key: SigningPublicKey,
    current_recovery_key: SigningPublicKey,
    devices: BTreeMap<DeviceId, DeviceRecordV1>,
    relay_descriptor: Option<RelayDescriptorV1>,
    head_sequence: SafeUint,
    head_hash: Sha256Digest,
    seen_entry_hashes: BTreeSet<Sha256Digest>,
}

impl IdentityLogV1 {
    /// Creates the current writable projection from its immutable genesis event.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidWireVersion`] unless genesis is
    /// current wire `1.1`, [`IdentityLogError::InvalidGenesis`] for a
    /// non-genesis event, or any error from strict event verification.
    pub fn bootstrap(genesis: &IdentityLogEventV1) -> Result<Self, IdentityLogError> {
        if genesis.wire() != IDENTITY_LOG_WIRE_VERSION {
            return Err(IdentityLogError::InvalidWireVersion);
        }
        Self::bootstrap_projection(genesis)
    }

    fn bootstrap_projection(genesis: &IdentityLogEventV1) -> Result<Self, IdentityLogError> {
        genesis.verify()?;
        let IdentityLogEventPayloadV1::Genesis {
            root_signing_key,
            recovery_signing_key,
            ..
        } = genesis.payload()
        else {
            return Err(IdentityLogError::InvalidGenesis);
        };
        let entry_hash = genesis.entry_hash()?;
        Ok(Self {
            wire: genesis.wire(),
            identity_id: genesis.identity_id(),
            current_root_key: *root_signing_key,
            current_recovery_key: *recovery_signing_key,
            devices: BTreeMap::new(),
            relay_descriptor: None,
            head_sequence: genesis.sequence(),
            head_hash: entry_hash,
            seen_entry_hashes: BTreeSet::from([entry_hash]),
        })
    }

    /// Atomically admits the exact next current-wire authorized event, or leaves state unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidWireVersion`] for a non-current
    /// event or projection, or an identity-log error for an invalid signature,
    /// identity, sequence, predecessor, replay, authorization, certificate,
    /// rotation, or relay transition. No state is changed on error.
    pub fn append(&mut self, event: &IdentityLogEventV1) -> Result<(), IdentityLogError> {
        if self.wire != IDENTITY_LOG_WIRE_VERSION || event.wire() != IDENTITY_LOG_WIRE_VERSION {
            return Err(IdentityLogError::InvalidWireVersion);
        }
        self.append_projection(event)
    }

    fn append_projection(&mut self, event: &IdentityLogEventV1) -> Result<(), IdentityLogError> {
        event.verify()?;
        if event.identity_id() != self.identity_id {
            return Err(IdentityLogError::IdentityMismatch);
        }
        if event.wire() != self.wire {
            return Err(IdentityLogError::InvalidWireVersion);
        }
        let entry_hash = event.entry_hash()?;
        if self.seen_entry_hashes.contains(&entry_hash) {
            return Err(IdentityLogError::Replay);
        }
        let next_sequence = self
            .head_sequence
            .get()
            .checked_add(1)
            .and_then(|value| SafeUint::new(value).ok())
            .ok_or(IdentityLogError::SequenceMismatch)?;
        if event.sequence() != next_sequence {
            return Err(IdentityLogError::SequenceMismatch);
        }
        if event.previous_event_hash() != Some(self.head_hash) {
            return Err(IdentityLogError::PreviousHashMismatch);
        }

        let mut next = self.clone();
        next.apply_authorized(event)?;
        next.head_sequence = event.sequence();
        next.head_hash = entry_hash;
        next.seen_entry_hashes.insert(entry_hash);
        *self = next;
        Ok(())
    }

    /// Returns the permanent public identity ID.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the immutable wire version established by genesis.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.wire
    }

    /// Returns the current root signing key.
    #[must_use]
    pub const fn current_root_key(&self) -> SigningPublicKey {
        self.current_root_key
    }

    /// Returns the current recovery signing key.
    #[must_use]
    pub const fn current_recovery_key(&self) -> SigningPublicKey {
        self.current_recovery_key
    }

    /// Returns the contiguous log head sequence.
    #[must_use]
    pub const fn head_sequence(&self) -> SafeUint {
        self.head_sequence
    }

    /// Returns the chain hash of the exact current head event bytes.
    #[must_use]
    pub const fn head_hash(&self) -> Sha256Digest {
        self.head_hash
    }

    /// Returns a device's enrollment status, if it was ever enrolled.
    #[must_use]
    pub fn device_status(&self, device_id: DeviceId) -> Option<DeviceStatusV1> {
        self.devices.get(&device_id).map(|record| record.status)
    }

    /// Returns the device certificate retained for audit and verification.
    #[must_use]
    pub fn device_certificate(&self, device_id: DeviceId) -> Option<&DeviceCertificateV1> {
        self.devices
            .get(&device_id)
            .map(|record| &record.certificate)
    }

    /// Returns the latest signed relay descriptor, including expired history.
    #[must_use]
    pub fn latest_relay_descriptor(&self) -> Option<&RelayDescriptorV1> {
        self.relay_descriptor.as_ref()
    }

    /// Returns the latest descriptor only when it is active at trusted `now`.
    ///
    /// Callers must obtain `now` from their trusted clock rather than the event
    /// timestamp, which is signer-provided historical metadata.
    #[must_use]
    pub fn active_relay_descriptor(&self, now: UtcMillis) -> Option<&RelayDescriptorV1> {
        self.relay_descriptor
            .as_ref()
            .filter(|descriptor| descriptor.expires_at() > now)
    }

    fn apply_authorized(&mut self, event: &IdentityLogEventV1) -> Result<(), IdentityLogError> {
        match event.payload() {
            IdentityLogEventPayloadV1::Genesis { .. } => Err(IdentityLogError::InvalidGenesis),
            IdentityLogEventPayloadV1::DeviceAdd { certificate } => {
                self.apply_device_add(event, certificate)
            }
            IdentityLogEventPayloadV1::DeviceRevoke { device_id } => {
                if event.signer() != self.current_root_key {
                    return Err(IdentityLogError::UnauthorizedSigner);
                }
                let record = self
                    .devices
                    .get_mut(device_id)
                    .ok_or(IdentityLogError::DeviceNotFound)?;
                if record.status == DeviceStatusV1::Revoked {
                    return Err(IdentityLogError::DeviceAlreadyRevoked);
                }
                record.status = DeviceStatusV1::Revoked;
                Ok(())
            }
            IdentityLogEventPayloadV1::RootRotate {
                new_root_signing_key,
                acceptance_signature,
            } => self.apply_root_rotation(event, *new_root_signing_key, *acceptance_signature),
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key,
                acceptance_signature,
                recovery_authorization_signature,
            } => self.apply_recovery_rotation(
                event,
                *new_recovery_signing_key,
                *acceptance_signature,
                *recovery_authorization_signature,
            ),
            IdentityLogEventPayloadV1::RecoveryRestore {
                new_root_signing_key,
                new_recovery_signing_key,
                root_acceptance_signature,
                recovery_acceptance_signature,
            } => self.apply_recovery_restore(
                event,
                *new_root_signing_key,
                *new_recovery_signing_key,
                *root_acceptance_signature,
                *recovery_acceptance_signature,
            ),
            IdentityLogEventPayloadV1::RelayDescriptor { descriptor } => {
                if event.signer() != self.current_root_key {
                    return Err(IdentityLogError::UnauthorizedSigner);
                }
                descriptor.validate_for_event(event.occurred_at())?;
                self.relay_descriptor = Some(descriptor.clone());
                Ok(())
            }
        }
    }

    fn apply_device_add(
        &mut self,
        event: &IdentityLogEventV1,
        certificate: &DeviceCertificateV1,
    ) -> Result<(), IdentityLogError> {
        let signer_is_active_device = self.devices.values().any(|record| {
            record.status == DeviceStatusV1::Active
                && record.certificate.device_signing_key() == event.signer()
        });
        if event.signer() != self.current_root_key && !signer_is_active_device {
            return Err(IdentityLogError::UnauthorizedSigner);
        }
        certificate.verify()?;
        if certificate.identity_id() != self.identity_id
            || certificate.issuer_root_key() != self.current_root_key
            || certificate.issued_at() > event.occurred_at()
            || certificate.device_signing_key() == self.current_root_key
            || certificate.device_signing_key() == self.current_recovery_key
        {
            return Err(IdentityLogError::InvalidDeviceCertificate);
        }
        if self.devices.contains_key(&certificate.device_id())
            || self.devices.values().any(|record| {
                record.certificate.device_signing_key() == certificate.device_signing_key()
                    || record.certificate.device_encryption_key()
                        == certificate.device_encryption_key()
            })
        {
            return Err(IdentityLogError::DeviceAlreadyExists);
        }
        self.devices.insert(
            certificate.device_id(),
            DeviceRecordV1 {
                certificate: certificate.clone(),
                status: DeviceStatusV1::Active,
            },
        );
        Ok(())
    }

    fn apply_root_rotation(
        &mut self,
        event: &IdentityLogEventV1,
        successor: SigningPublicKey,
        acceptance_signature: Ed25519Signature,
    ) -> Result<(), IdentityLogError> {
        if event.signer() != self.current_root_key {
            return Err(IdentityLogError::UnauthorizedSigner);
        }
        if successor == self.current_root_key
            || successor == self.current_recovery_key
            || self.device_signing_key_is_used(successor)
        {
            return Err(IdentityLogError::InvalidRotation);
        }
        self.verify_rotation_acceptance(
            event,
            KeyAcceptancePurposeV1::RootRotate,
            successor,
            acceptance_signature,
        )?;
        self.current_root_key = successor;
        Ok(())
    }

    fn apply_recovery_rotation(
        &mut self,
        event: &IdentityLogEventV1,
        successor: SigningPublicKey,
        acceptance_signature: Ed25519Signature,
        recovery_authorization_signature: Option<Ed25519Signature>,
    ) -> Result<(), IdentityLogError> {
        if event.signer() != self.current_root_key {
            return Err(IdentityLogError::UnauthorizedSigner);
        }
        if successor == self.current_root_key
            || successor == self.current_recovery_key
            || self.device_signing_key_is_used(successor)
        {
            return Err(IdentityLogError::InvalidRotation);
        }
        self.verify_rotation_acceptance(
            event,
            KeyAcceptancePurposeV1::RecoveryRotate,
            successor,
            acceptance_signature,
        )?;
        match (
            identity_log_wire_line(event.wire())?,
            recovery_authorization_signature,
        ) {
            (IdentityLogWireLine::FrozenV1_0, None) => {}
            (IdentityLogWireLine::CurrentV1_1, Some(signature)) => {
                let authorization_input = recovery_rotation_authorization_input(
                    event.wire(),
                    self.identity_id,
                    event.sequence(),
                    event.previous_event_hash(),
                    event.occurred_at(),
                    event.signer(),
                    successor,
                    acceptance_signature,
                )?;
                verify_signature(self.current_recovery_key, &authorization_input, signature)
                    .map_err(|_| IdentityLogError::InvalidRotation)?;
            }
            (IdentityLogWireLine::FrozenV1_0, Some(_)) => {
                return Err(IdentityLogError::InvalidCanonical);
            }
            (IdentityLogWireLine::CurrentV1_1, None) => {
                return Err(IdentityLogError::InvalidRotation);
            }
        }
        self.current_recovery_key = successor;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_recovery_restore(
        &mut self,
        event: &IdentityLogEventV1,
        new_root: SigningPublicKey,
        new_recovery: SigningPublicKey,
        root_acceptance_signature: Ed25519Signature,
        recovery_acceptance_signature: Ed25519Signature,
    ) -> Result<(), IdentityLogError> {
        if event.signer() != self.current_recovery_key {
            return Err(IdentityLogError::UnauthorizedSigner);
        }
        if new_root == new_recovery
            || new_root == self.current_root_key
            || new_root == self.current_recovery_key
            || new_recovery == self.current_root_key
            || new_recovery == self.current_recovery_key
            || self.device_signing_key_is_used(new_root)
            || self.device_signing_key_is_used(new_recovery)
        {
            return Err(IdentityLogError::InvalidRotation);
        }
        self.verify_rotation_acceptance(
            event,
            KeyAcceptancePurposeV1::RecoveryRestoreRoot,
            new_root,
            root_acceptance_signature,
        )?;
        self.verify_rotation_acceptance(
            event,
            KeyAcceptancePurposeV1::RecoveryRestoreRecovery,
            new_recovery,
            recovery_acceptance_signature,
        )?;
        self.current_root_key = new_root;
        self.current_recovery_key = new_recovery;
        for record in self.devices.values_mut() {
            record.status = DeviceStatusV1::Revoked;
        }
        Ok(())
    }

    fn verify_rotation_acceptance(
        &self,
        event: &IdentityLogEventV1,
        purpose: KeyAcceptancePurposeV1,
        successor: SigningPublicKey,
        signature: Ed25519Signature,
    ) -> Result<(), IdentityLogError> {
        let input = key_rotation_acceptance_input(
            self.identity_id,
            event.sequence(),
            event.previous_event_hash(),
            purpose,
            successor,
        )?;
        verify_signature(successor, &input, signature)
            .map_err(|_| IdentityLogError::InvalidRotation)
    }

    fn device_signing_key_is_used(&self, key: SigningPublicKey) -> bool {
        self.devices
            .values()
            .any(|record| record.certificate.device_signing_key() == key)
    }
}

/// Read-only verified projection of a frozen identity-log `1.0` history.
///
/// This type intentionally exposes no append operation and does not reveal its
/// internal writable projection. Current callers must use [`IdentityLogV1`]
/// for wire `1.1`; this import path exists only to validate and inspect exact
/// historical records.
#[derive(Debug)]
pub struct HistoricalIdentityLogV1 {
    projection: IdentityLogV1,
}

impl HistoricalIdentityLogV1 {
    /// Verifies and imports one complete frozen wire `1.0` history.
    ///
    /// The first event must be the matching `1.0` genesis, and each remaining
    /// event must be the exact next event in that same historical wire line.
    /// The returned projection is read-only.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityLogError::InvalidWireVersion`] for a non-`1.0`
    /// history, [`IdentityLogError::InvalidGenesis`] for an empty or invalid
    /// genesis history, or the relevant identity-log error for an invalid
    /// subsequent historical event.
    pub fn import_v1_0(events: &[IdentityLogEventV1]) -> Result<Self, IdentityLogError> {
        let (genesis, rest) = events
            .split_first()
            .ok_or(IdentityLogError::InvalidGenesis)?;
        if genesis.wire() != IDENTITY_LOG_V1_0_WIRE_VERSION {
            return Err(IdentityLogError::InvalidWireVersion);
        }
        let mut projection = IdentityLogV1::bootstrap_projection(genesis)?;
        for event in rest {
            if event.wire() != IDENTITY_LOG_V1_0_WIRE_VERSION {
                return Err(IdentityLogError::InvalidWireVersion);
            }
            projection.append_projection(event)?;
        }
        Ok(Self { projection })
    }

    /// Returns the permanent public identity ID.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.projection.identity_id()
    }

    /// Returns the immutable historical wire version.
    #[must_use]
    pub const fn wire(&self) -> WireVersion {
        self.projection.wire()
    }

    /// Returns the historical root signing key at the imported head.
    #[must_use]
    pub const fn current_root_key(&self) -> SigningPublicKey {
        self.projection.current_root_key()
    }

    /// Returns the historical recovery signing key at the imported head.
    #[must_use]
    pub const fn current_recovery_key(&self) -> SigningPublicKey {
        self.projection.current_recovery_key()
    }

    /// Returns the contiguous imported head sequence.
    #[must_use]
    pub const fn head_sequence(&self) -> SafeUint {
        self.projection.head_sequence()
    }

    /// Returns the exact imported head event hash.
    #[must_use]
    pub const fn head_hash(&self) -> Sha256Digest {
        self.projection.head_hash()
    }
}

fn identity_log_wire_line(wire: WireVersion) -> Result<IdentityLogWireLine, IdentityLogError> {
    if wire == IDENTITY_LOG_V1_0_WIRE_VERSION {
        Ok(IdentityLogWireLine::FrozenV1_0)
    } else if wire == IDENTITY_LOG_WIRE_VERSION {
        Ok(IdentityLogWireLine::CurrentV1_1)
    } else {
        Err(IdentityLogError::InvalidWireVersion)
    }
}

fn validate_wire_version(wire: WireVersion) -> Result<(), IdentityLogError> {
    identity_log_wire_line(wire).map(|_| ())
}

fn identity_value(identity_id: IdentityId) -> CanonicalValue {
    CanonicalValue::Text(identity_id.to_string())
}

fn device_id_value(device_id: DeviceId) -> CanonicalValue {
    CanonicalValue::Text(device_id.to_string())
}

fn signature_input(domain: &[u8], digest: Sha256Digest) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + digest.as_bytes().len());
    input.extend_from_slice(domain);
    input.extend_from_slice(digest.as_bytes());
    input
}

fn canonical_hash<T>(domain: &[u8], value: &T) -> Result<Sha256Digest, IdentityLogError>
where
    T: CanonicalEncode + ?Sized,
{
    let bytes = encode_deterministic_cbor(value).map_err(|_| IdentityLogError::InvalidCanonical)?;
    Ok(Sha256Digest::hash_domain(domain, &bytes))
}

fn verify_signature(
    signer: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), IdentityLogError> {
    let key = VerifyingKey::from_bytes(signer.as_bytes())
        .map_err(|_| IdentityLogError::InvalidSignature)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    key.verify_strict(input, &signature)
        .map_err(|_| IdentityLogError::InvalidSignature)
}

fn validate_relay_urls(relay_urls: &[String]) -> Result<(), IdentityLogError> {
    if relay_urls.is_empty() || relay_urls.len() > MAX_RELAY_URLS {
        return Err(IdentityLogError::InvalidRelayDescriptor);
    }
    if relay_urls
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(IdentityLogError::InvalidRelayDescriptor);
    }
    if relay_urls.iter().all(|url| valid_relay_url(url)) {
        Ok(())
    } else {
        Err(IdentityLogError::InvalidRelayDescriptor)
    }
}

fn valid_relay_url(value: &str) -> bool {
    if value.len() > MAX_RELAY_URL_BYTES
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

fn exact_fields(
    value: &CanonicalValue,
    count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], IdentityLogError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    if fields.len() != count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(IdentityLogError::InvalidCanonical)
    } else {
        Ok(fields)
    }
}

fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, IdentityLogError> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(IdentityLogError::InvalidCanonical)?,
        )
        .map(|(_, value)| value)
        .ok_or(IdentityLogError::InvalidCanonical)
}

fn decode_payload(
    kind: IdentityLogEventKindV1,
    value: &CanonicalValue,
    wire: WireVersion,
) -> Result<IdentityLogEventPayloadV1, IdentityLogError> {
    match kind {
        IdentityLogEventKindV1::Genesis => {
            let fields = exact_fields(value, 3)?;
            Ok(IdentityLogEventPayloadV1::Genesis {
                root_signing_key: decode_signing_key(field(fields, 1)?)?,
                recovery_signing_key: decode_signing_key(field(fields, 2)?)?,
                recovery_acceptance_signature: decode_signature(field(fields, 3)?)?,
            })
        }
        IdentityLogEventKindV1::DeviceAdd => {
            let fields = exact_fields(value, 1)?;
            Ok(IdentityLogEventPayloadV1::DeviceAdd {
                certificate: decode_device_certificate(field(fields, 1)?)?,
            })
        }
        IdentityLogEventKindV1::DeviceRevoke => {
            let fields = exact_fields(value, 1)?;
            Ok(IdentityLogEventPayloadV1::DeviceRevoke {
                device_id: decode_device_id(field(fields, 1)?)?,
            })
        }
        IdentityLogEventKindV1::RootRotate => {
            let fields = exact_fields(value, 2)?;
            Ok(IdentityLogEventPayloadV1::RootRotate {
                new_root_signing_key: decode_signing_key(field(fields, 1)?)?,
                acceptance_signature: decode_signature(field(fields, 2)?)?,
            })
        }
        IdentityLogEventKindV1::RecoveryRotate => {
            let wire_line = identity_log_wire_line(wire)?;
            let fields = exact_fields(
                value,
                match wire_line {
                    IdentityLogWireLine::FrozenV1_0 => 2,
                    IdentityLogWireLine::CurrentV1_1 => 3,
                },
            )?;
            Ok(IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: decode_signing_key(field(fields, 1)?)?,
                acceptance_signature: decode_signature(field(fields, 2)?)?,
                recovery_authorization_signature: match wire_line {
                    IdentityLogWireLine::FrozenV1_0 => None,
                    IdentityLogWireLine::CurrentV1_1 => Some(decode_signature(field(fields, 3)?)?),
                },
            })
        }
        IdentityLogEventKindV1::RecoveryRestore => {
            let fields = exact_fields(value, 4)?;
            Ok(IdentityLogEventPayloadV1::RecoveryRestore {
                new_root_signing_key: decode_signing_key(field(fields, 1)?)?,
                new_recovery_signing_key: decode_signing_key(field(fields, 2)?)?,
                root_acceptance_signature: decode_signature(field(fields, 3)?)?,
                recovery_acceptance_signature: decode_signature(field(fields, 4)?)?,
            })
        }
        IdentityLogEventKindV1::RelayDescriptor => {
            let fields = exact_fields(value, 1)?;
            Ok(IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: decode_relay_descriptor(field(fields, 1)?)?,
            })
        }
    }
}

fn decode_device_certificate(
    value: &CanonicalValue,
) -> Result<DeviceCertificateV1, IdentityLogError> {
    let fields = exact_fields(value, 8)?;
    let wire = decode_wire_version(field(fields, 1)?)?;
    let identity_id = decode_identity_id(field(fields, 2)?)?;
    let device_id = decode_device_id(field(fields, 3)?)?;
    let device_signing_key = decode_signing_key(field(fields, 4)?)?;
    let device_encryption_key = decode_encryption_key(field(fields, 5)?)?;
    let issuer_root_key = decode_signing_key(field(fields, 6)?)?;
    let issued_at = decode_utc_millis(field(fields, 7)?)?;
    let signature = decode_signature(field(fields, 8)?)?;
    let unsigned = UnsignedDeviceCertificateV1::new(
        wire,
        identity_id,
        device_id,
        device_signing_key,
        device_encryption_key,
        issuer_root_key,
        issued_at,
    )?;
    DeviceCertificateV1::signed(unsigned, signature)
}

fn decode_relay_descriptor(value: &CanonicalValue) -> Result<RelayDescriptorV1, IdentityLogError> {
    let fields = exact_fields(value, 3)?;
    let wire = decode_wire_version(field(fields, 1)?)?;
    let CanonicalValue::Array(urls) = field(fields, 2)? else {
        return Err(IdentityLogError::InvalidRelayDescriptor);
    };
    let relay_urls = urls
        .iter()
        .map(|url| match url {
            CanonicalValue::Text(value) => Ok(value.clone()),
            _ => Err(IdentityLogError::InvalidRelayDescriptor),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expires_at = decode_utc_millis(field(fields, 3)?)?;
    RelayDescriptorV1::new(wire, relay_urls, expires_at)
}

fn decode_wire_version(value: &CanonicalValue) -> Result<WireVersion, IdentityLogError> {
    let fields = exact_fields(value, 2)?;
    let wire = WireVersion::new(
        decode_protocol_version(field(fields, 1)?)?,
        decode_protocol_version(field(fields, 2)?)?,
    );
    validate_wire_version(wire)?;
    Ok(wire)
}

fn decode_protocol_version(value: &CanonicalValue) -> Result<ProtocolVersion, IdentityLogError> {
    let fields = exact_fields(value, 2)?;
    Ok(ProtocolVersion::new(
        decode_u16(field(fields, 1)?)?,
        decode_u16(field(fields, 2)?)?,
    ))
}

fn decode_u16(value: &CanonicalValue) -> Result<u16, IdentityLogError> {
    u16::try_from(decode_unsigned(value)?).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_unsigned(value: &CanonicalValue) -> Result<u64, IdentityLogError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    Ok(*value)
}

fn decode_safe_uint(value: &CanonicalValue) -> Result<SafeUint, IdentityLogError> {
    SafeUint::new(decode_unsigned(value)?).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_optional_digest(
    value: &CanonicalValue,
) -> Result<Option<Sha256Digest>, IdentityLogError> {
    if value == &CanonicalValue::Null {
        Ok(None)
    } else {
        decode_digest(value).map(Some)
    }
}

fn decode_digest(value: &CanonicalValue) -> Result<Sha256Digest, IdentityLogError> {
    let bytes = decode_exact_bytes::<32>(value)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn decode_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, IdentityLogError> {
    let raw = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| IdentityLogError::InvalidCanonical)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(IdentityLogError::InvalidCanonical),
    };
    UtcMillis::new(raw).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_identity_id(value: &CanonicalValue) -> Result<IdentityId, IdentityLogError> {
    let CanonicalValue::Text(value) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    IdentityId::from_str(value).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_device_id(value: &CanonicalValue) -> Result<DeviceId, IdentityLogError> {
    let CanonicalValue::Text(value) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    DeviceId::from_str(value).map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_signing_key(value: &CanonicalValue) -> Result<SigningPublicKey, IdentityLogError> {
    SigningPublicKey::try_from(decode_exact_bytes::<32>(value)?)
        .map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_encryption_key(
    value: &CanonicalValue,
) -> Result<DeviceEncryptionPublicKey, IdentityLogError> {
    DeviceEncryptionPublicKey::try_from(decode_exact_bytes::<32>(value)?)
        .map_err(|_| IdentityLogError::InvalidCanonical)
}

fn decode_signature(value: &CanonicalValue) -> Result<Ed25519Signature, IdentityLogError> {
    Ok(Ed25519Signature::from_bytes(decode_exact_bytes::<64>(
        value,
    )?))
}

fn decode_exact_bytes<const N: usize>(value: &CanonicalValue) -> Result<[u8; N], IdentityLogError> {
    let CanonicalValue::Bytes(bytes) = value else {
        return Err(IdentityLogError::InvalidCanonical);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| IdentityLogError::InvalidCanonical)
}

#[cfg(test)]
mod tests {
    use std::{fmt::Write as _, str::FromStr};

    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    const DEVICE_A: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";
    const DEVICE_B: &str = "0190f2a5-7b1c-7abc-8def-0123456789ac";
    const DEVICE_C: &str = "0190f2a5-7b1c-7abc-8def-0123456789ad";

    #[derive(Deserialize)]
    struct IdentityLogVector {
        version: u16,
        identity_id: String,
        canonical_cbor_hex: String,
        entry_hash: String,
    }

    #[derive(Deserialize)]
    struct IdentityLogV1_1Vector {
        version: u16,
        wire_version: String,
        identity_id: String,
        events: Vec<IdentityLogVectorEvent>,
    }

    #[derive(Deserialize)]
    struct IdentityLogVectorEvent {
        event: String,
        canonical_cbor_hex: String,
        entry_hash: String,
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_key(key: &SigningKey) -> SigningPublicKey {
        SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
    }

    fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
        Ed25519Signature::from_bytes(key.sign(input).to_bytes())
    }

    fn safe(value: u64) -> SafeUint {
        SafeUint::new(value).unwrap()
    }

    fn timestamp(value: i64) -> UtcMillis {
        UtcMillis::new(value).unwrap()
    }

    fn device_id(value: &str) -> DeviceId {
        DeviceId::from_str(value).unwrap()
    }

    fn signed_event(
        signer: &SigningKey,
        identity_id: IdentityId,
        sequence: u64,
        previous_event_hash: Option<Sha256Digest>,
        occurred_at: i64,
        payload: IdentityLogEventPayloadV1,
    ) -> IdentityLogEventV1 {
        signed_event_with_wire(
            IDENTITY_LOG_WIRE_VERSION,
            signer,
            identity_id,
            sequence,
            previous_event_hash,
            occurred_at,
            payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_event_with_wire(
        wire: WireVersion,
        signer: &SigningKey,
        identity_id: IdentityId,
        sequence: u64,
        previous_event_hash: Option<Sha256Digest>,
        occurred_at: i64,
        payload: IdentityLogEventPayloadV1,
    ) -> IdentityLogEventV1 {
        let unsigned = UnsignedIdentityLogEventV1::new(
            wire,
            identity_id,
            safe(sequence),
            previous_event_hash,
            timestamp(occurred_at),
            payload,
            public_key(signer),
        )
        .unwrap();
        IdentityLogEventV1::signed(
            unsigned.clone(),
            signature(
                signer,
                &identity_log_signature_input(unsigned.signing_digest().unwrap()),
            ),
        )
        .unwrap()
    }

    fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
        genesis_with_wire(IDENTITY_LOG_WIRE_VERSION, root, recovery)
    }

    fn genesis_with_wire(
        wire: WireVersion,
        root: &SigningKey,
        recovery: &SigningKey,
    ) -> IdentityLogEventV1 {
        let root_key = public_key(root);
        let recovery_key = public_key(recovery);
        let identity_id = IdentityId::derive(root_key.as_domain_key());
        let recovery_acceptance_signature = signature(
            recovery,
            &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key).unwrap(),
        );
        signed_event_with_wire(
            wire,
            root,
            identity_id,
            1,
            None,
            1_000,
            IdentityLogEventPayloadV1::Genesis {
                root_signing_key: root_key,
                recovery_signing_key: recovery_key,
                recovery_acceptance_signature,
            },
        )
    }

    fn device_certificate(
        root: &SigningKey,
        identity_id: IdentityId,
        device: &SigningKey,
        device_id: DeviceId,
        encryption_seed: u8,
        issued_at: i64,
    ) -> DeviceCertificateV1 {
        let unsigned = UnsignedDeviceCertificateV1::new(
            IDENTITY_LOG_WIRE_VERSION,
            identity_id,
            device_id,
            public_key(device),
            DeviceEncryptionPublicKey::try_from([encryption_seed; 32]).unwrap(),
            public_key(root),
            timestamp(issued_at),
        )
        .unwrap();
        DeviceCertificateV1::signed(
            unsigned.clone(),
            signature(
                root,
                &device_certificate_signature_input(unsigned.signing_digest().unwrap()),
            ),
        )
        .unwrap()
    }

    fn descriptor(expires_at: i64) -> RelayDescriptorV1 {
        RelayDescriptorV1::new(
            IDENTITY_LOG_WIRE_VERSION,
            vec![
                "https://relay-a.example/v1".to_owned(),
                "https://relay-b.example/v1".to_owned(),
            ],
            timestamp(expires_at),
        )
        .unwrap()
    }

    fn frozen_v1_0_root_only_recovery_chain()
    -> (IdentityLogEventV1, IdentityLogEventV1, IdentityLogEventV1) {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let legacy_genesis = genesis_with_wire(IDENTITY_LOG_V1_0_WIRE_VERSION, &root, &recovery);
        let identity_id = legacy_genesis.identity_id();
        let legacy_head = legacy_genesis.entry_hash().unwrap();
        let successor = signing_key(3);
        let rotation = signed_event_with_wire(
            IDENTITY_LOG_V1_0_WIRE_VERSION,
            &root,
            identity_id,
            2,
            Some(legacy_head),
            1_100,
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: public_key(&successor),
                acceptance_signature: signature(
                    &successor,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(2),
                        Some(legacy_head),
                        KeyAcceptancePurposeV1::RecoveryRotate,
                        public_key(&successor),
                    )
                    .unwrap(),
                ),
                recovery_authorization_signature: None,
            },
        );
        (legacy_genesis, genesis(&root, &recovery), rotation)
    }

    #[allow(clippy::too_many_lines)]
    fn current_v1_1_chain() -> Vec<(&'static str, IdentityLogEventV1)> {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let genesis = genesis(&root, &recovery);
        let identity_id = genesis.identity_id();
        let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();
        let mut events = vec![("genesis", genesis)];

        let first_device = signing_key(3);
        let first_certificate = device_certificate(
            &root,
            identity_id,
            &first_device,
            device_id(DEVICE_A),
            31,
            1_050,
        );
        let device_add = signed_event(
            &root,
            identity_id,
            2,
            Some(log.head_hash()),
            1_100,
            IdentityLogEventPayloadV1::DeviceAdd {
                certificate: first_certificate,
            },
        );
        log.append(&device_add).unwrap();
        events.push(("device_add", device_add));

        let relay_descriptor = signed_event(
            &root,
            identity_id,
            3,
            Some(log.head_hash()),
            1_200,
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(2_000),
            },
        );
        log.append(&relay_descriptor).unwrap();
        events.push(("relay_descriptor", relay_descriptor));

        let next_root = signing_key(4);
        let root_acceptance_signature = signature(
            &next_root,
            &key_rotation_acceptance_input(
                identity_id,
                safe(4),
                Some(log.head_hash()),
                KeyAcceptancePurposeV1::RootRotate,
                public_key(&next_root),
            )
            .unwrap(),
        );
        let root_rotate = signed_event(
            &root,
            identity_id,
            4,
            Some(log.head_hash()),
            1_300,
            IdentityLogEventPayloadV1::RootRotate {
                new_root_signing_key: public_key(&next_root),
                acceptance_signature: root_acceptance_signature,
            },
        );
        log.append(&root_rotate).unwrap();
        events.push(("root_rotate", root_rotate));

        let next_recovery = signing_key(5);
        let recovery_acceptance_signature = signature(
            &next_recovery,
            &key_rotation_acceptance_input(
                identity_id,
                safe(5),
                Some(log.head_hash()),
                KeyAcceptancePurposeV1::RecoveryRotate,
                public_key(&next_recovery),
            )
            .unwrap(),
        );
        let recovery_rotation_authorization_signature = signature(
            &recovery,
            &recovery_rotation_authorization_input(
                IDENTITY_LOG_WIRE_VERSION,
                identity_id,
                safe(5),
                Some(log.head_hash()),
                timestamp(1_400),
                public_key(&next_root),
                public_key(&next_recovery),
                recovery_acceptance_signature,
            )
            .unwrap(),
        );
        let recovery_rotate = signed_event(
            &next_root,
            identity_id,
            5,
            Some(log.head_hash()),
            1_400,
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: public_key(&next_recovery),
                acceptance_signature: recovery_acceptance_signature,
                recovery_authorization_signature: Some(recovery_rotation_authorization_signature),
            },
        );
        log.append(&recovery_rotate).unwrap();
        events.push(("recovery_rotate", recovery_rotate));

        let device_revoke = signed_event(
            &next_root,
            identity_id,
            6,
            Some(log.head_hash()),
            1_500,
            IdentityLogEventPayloadV1::DeviceRevoke {
                device_id: device_id(DEVICE_A),
            },
        );
        log.append(&device_revoke).unwrap();
        events.push(("device_revoke", device_revoke));

        let restored_root = signing_key(6);
        let restored_recovery = signing_key(7);
        let recovery_restore = signed_event(
            &next_recovery,
            identity_id,
            7,
            Some(log.head_hash()),
            1_600,
            IdentityLogEventPayloadV1::RecoveryRestore {
                new_root_signing_key: public_key(&restored_root),
                new_recovery_signing_key: public_key(&restored_recovery),
                root_acceptance_signature: signature(
                    &restored_root,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(7),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RecoveryRestoreRoot,
                        public_key(&restored_root),
                    )
                    .unwrap(),
                ),
                recovery_acceptance_signature: signature(
                    &restored_recovery,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(7),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RecoveryRestoreRecovery,
                        public_key(&restored_recovery),
                    )
                    .unwrap(),
                ),
            },
        );
        log.append(&recovery_restore).unwrap();
        events.push(("recovery_restore", recovery_restore));
        events
    }

    fn render_current_v1_1_vector() -> String {
        let events = current_v1_1_chain();
        let identity_id = events[0].1.identity_id().to_string();
        let events = events
            .into_iter()
            .map(|(event, value)| {
                json!({
                    "event": event,
                    "canonical_cbor_hex": encode_hex(&value.to_deterministic_cbor().unwrap()),
                    "entry_hash": value.entry_hash().unwrap().to_string(),
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string_pretty(&json!({
            "version": 1,
            "wire_version": "1.1",
            "identity_id": identity_id,
            "events": events,
        }))
        .unwrap()
            + "\n"
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn encode_hex(value: &[u8]) -> String {
        let mut output = String::with_capacity(value.len() * 2);
        for byte in value {
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
        }
        output
    }

    fn vector() -> IdentityLogVector {
        serde_json::from_str(include_str!(
            "../../../protocol/test-vectors/identity-log/v1/identity-log-v1.json"
        ))
        .unwrap()
    }

    fn current_v1_1_vector() -> IdentityLogV1_1Vector {
        serde_json::from_str(include_str!(
            "../../../protocol/test-vectors/identity-log/v1_1/identity-log-v1_1.json"
        ))
        .unwrap()
    }

    #[test]
    fn canonical_genesis_vector_is_exact_and_independently_verifiable() {
        let vector = vector();
        assert_eq!(vector.version, 1);
        let root = signing_key(1);
        let recovery = signing_key(2);
        let expected = genesis_with_wire(IDENTITY_LOG_V1_0_WIRE_VERSION, &root, &recovery);
        assert_eq!(expected.identity_id().to_string(), vector.identity_id);
        assert_eq!(
            encode_hex(&expected.to_deterministic_cbor().unwrap()),
            vector.canonical_cbor_hex
        );
        assert_eq!(
            expected.entry_hash().unwrap().to_string(),
            vector.entry_hash
        );

        let bytes = decode_hex(&vector.canonical_cbor_hex);
        let decoded = IdentityLogEventV1::decode_and_verify(&bytes).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.to_deterministic_cbor().unwrap(), bytes);
    }

    #[test]
    fn canonical_v1_1_vector_is_full_replayable_contract() {
        let vector = current_v1_1_vector();
        let expected = current_v1_1_chain();
        let expected_event_names = [
            "genesis",
            "device_add",
            "relay_descriptor",
            "root_rotate",
            "recovery_rotate",
            "device_revoke",
            "recovery_restore",
        ];

        assert_eq!(vector.version, 1);
        assert_eq!(vector.wire_version, "1.1");
        assert_eq!(
            vector
                .events
                .iter()
                .map(|event| event.event.as_str())
                .collect::<Vec<_>>(),
            expected_event_names
        );
        assert_eq!(expected.len(), expected_event_names.len());
        assert_eq!(vector.identity_id, expected[0].1.identity_id().to_string());
        assert_eq!(
            render_current_v1_1_vector(),
            include_str!("../../../protocol/test-vectors/identity-log/v1_1/identity-log-v1_1.json")
        );

        let decoded = vector
            .events
            .iter()
            .zip(expected.iter())
            .map(|(fixture, (expected_name, expected_event))| {
                assert_eq!(fixture.event, *expected_name);
                let bytes = decode_hex(&fixture.canonical_cbor_hex);
                let decoded = IdentityLogEventV1::decode_and_verify(&bytes).unwrap();
                assert_eq!(&decoded, expected_event);
                assert_eq!(decoded.to_deterministic_cbor().unwrap(), bytes);
                assert_eq!(
                    decoded.entry_hash().unwrap().to_string(),
                    fixture.entry_hash
                );
                decoded
            })
            .collect::<Vec<_>>();

        let mut log = IdentityLogV1::bootstrap(&decoded[0]).unwrap();
        assert_eq!(log.wire(), IDENTITY_LOG_WIRE_VERSION);
        for event in decoded.iter().skip(1) {
            log.append(event).unwrap();
        }
        assert_eq!(log.head_sequence(), safe(7));
        assert_eq!(
            log.device_status(device_id(DEVICE_A)),
            Some(DeviceStatusV1::Revoked)
        );
        assert!(log.active_relay_descriptor(timestamp(1_999)).is_some());
        assert!(log.active_relay_descriptor(timestamp(2_000)).is_none());
    }

    #[test]
    fn root_and_active_device_can_enroll_then_root_can_revoke_devices() {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let genesis = genesis(&root, &recovery);
        let identity_id = genesis.identity_id();
        let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();

        let first_device = signing_key(3);
        let first_certificate = device_certificate(
            &root,
            identity_id,
            &first_device,
            device_id(DEVICE_A),
            31,
            1_050,
        );
        let first_add = signed_event(
            &root,
            identity_id,
            2,
            Some(log.head_hash()),
            1_100,
            IdentityLogEventPayloadV1::DeviceAdd {
                certificate: first_certificate,
            },
        );
        log.append(&first_add).unwrap();
        assert_eq!(
            log.device_status(device_id(DEVICE_A)),
            Some(DeviceStatusV1::Active)
        );

        let second_device = signing_key(4);
        let second_certificate = device_certificate(
            &root,
            identity_id,
            &second_device,
            device_id(DEVICE_B),
            41,
            1_150,
        );
        let second_add = signed_event(
            &first_device,
            identity_id,
            3,
            Some(log.head_hash()),
            1_200,
            IdentityLogEventPayloadV1::DeviceAdd {
                certificate: second_certificate,
            },
        );
        log.append(&second_add).unwrap();

        let relay_update = signed_event(
            &root,
            identity_id,
            4,
            Some(log.head_hash()),
            1_300,
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(2_000),
            },
        );
        log.append(&relay_update).unwrap();
        assert_eq!(
            log.latest_relay_descriptor().unwrap().relay_urls(),
            ["https://relay-a.example/v1", "https://relay-b.example/v1"]
        );

        let revoke = signed_event(
            &root,
            identity_id,
            5,
            Some(log.head_hash()),
            1_400,
            IdentityLogEventPayloadV1::DeviceRevoke {
                device_id: device_id(DEVICE_A),
            },
        );
        log.append(&revoke).unwrap();
        assert_eq!(
            log.device_status(device_id(DEVICE_A)),
            Some(DeviceStatusV1::Revoked)
        );
        assert_eq!(
            log.device_status(device_id(DEVICE_B)),
            Some(DeviceStatusV1::Active)
        );
    }

    #[test]
    fn replay_fork_and_tampering_fail_without_advancing_state() {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let genesis = genesis(&root, &recovery);
        let identity_id = genesis.identity_id();
        let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();

        let update = signed_event(
            &root,
            identity_id,
            2,
            Some(log.head_hash()),
            1_100,
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(2_000),
            },
        );
        log.append(&update).unwrap();
        let head_before = (log.head_sequence(), log.head_hash());

        let skipped_sequence = signed_event(
            &root,
            identity_id,
            4,
            Some(log.head_hash()),
            1_200,
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(2_100),
            },
        );
        let fork = signed_event(
            &root,
            identity_id,
            3,
            Some(Sha256Digest::from_bytes([9; 32])),
            1_200,
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(2_100),
            },
        );
        for (candidate, expected_error) in [
            (update.clone(), IdentityLogError::Replay),
            (skipped_sequence, IdentityLogError::SequenceMismatch),
            (fork, IdentityLogError::PreviousHashMismatch),
        ] {
            assert_eq!(log.append(&candidate), Err(expected_error));
            assert_eq!((log.head_sequence(), log.head_hash()), head_before);
        }

        let signed_bytes = update.to_deterministic_cbor().unwrap();
        let mut tampered = signed_bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let mut trailing = signed_bytes;
        trailing.push(0);
        for (bytes, expected_error) in [
            (tampered, IdentityLogError::InvalidSignature),
            (trailing, IdentityLogError::InvalidCanonical),
        ] {
            assert_eq!(
                IdentityLogEventV1::decode_and_verify(&bytes),
                Err(expected_error)
            );
        }
    }

    #[test]
    fn recovery_rotation_rejects_a_root_only_authorization() {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let genesis = genesis(&root, &recovery);
        let identity_id = genesis.identity_id();
        let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();
        let successor = signing_key(3);
        let root_only_rotation = UnsignedIdentityLogEventV1::new(
            IDENTITY_LOG_WIRE_VERSION,
            identity_id,
            safe(2),
            Some(log.head_hash()),
            timestamp(1_100),
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: public_key(&successor),
                acceptance_signature: signature(
                    &successor,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(2),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RecoveryRotate,
                        public_key(&successor),
                    )
                    .unwrap(),
                ),
                recovery_authorization_signature: None,
            },
            public_key(&root),
        );

        assert_eq!(root_only_rotation, Err(IdentityLogError::InvalidRotation));

        let successor_acceptance_signature = signature(
            &successor,
            &key_rotation_acceptance_input(
                identity_id,
                safe(2),
                Some(log.head_hash()),
                KeyAcceptancePurposeV1::RecoveryRotate,
                public_key(&successor),
            )
            .unwrap(),
        );
        let forged_recovery_authorization = signed_event(
            &root,
            identity_id,
            2,
            Some(log.head_hash()),
            1_100,
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: public_key(&successor),
                acceptance_signature: successor_acceptance_signature,
                recovery_authorization_signature: Some(signature(
                    &root,
                    &recovery_rotation_authorization_input(
                        IDENTITY_LOG_WIRE_VERSION,
                        identity_id,
                        safe(2),
                        Some(log.head_hash()),
                        timestamp(1_100),
                        public_key(&root),
                        public_key(&successor),
                        successor_acceptance_signature,
                    )
                    .unwrap(),
                )),
            },
        );
        assert_eq!(
            log.append(&forged_recovery_authorization),
            Err(IdentityLogError::InvalidRotation)
        );
        assert_eq!(log.current_recovery_key(), public_key(&recovery));
    }

    #[test]
    fn current_write_entry_rejects_v1_0_root_only_recovery_chain() {
        let (legacy_genesis, current_genesis, rotation) = frozen_v1_0_root_only_recovery_chain();

        rotation.verify().unwrap();
        assert!(matches!(
            IdentityLogV1::bootstrap(&legacy_genesis),
            Err(IdentityLogError::InvalidWireVersion)
        ));

        let mut current_log = IdentityLogV1::bootstrap(&current_genesis).unwrap();
        assert_eq!(
            current_log.append(&rotation),
            Err(IdentityLogError::InvalidWireVersion)
        );
    }

    #[test]
    fn historical_v1_0_chain_is_verified_without_current_append_access() {
        let (legacy_genesis, _, rotation) = frozen_v1_0_root_only_recovery_chain();
        let expected_recovery = match rotation.payload() {
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key,
                ..
            } => *new_recovery_signing_key,
            _ => unreachable!("fixture contains a recovery rotation"),
        };
        let historical = HistoricalIdentityLogV1::import_v1_0(&[legacy_genesis, rotation]).unwrap();

        assert_eq!(historical.wire(), IDENTITY_LOG_V1_0_WIRE_VERSION);
        assert_eq!(historical.head_sequence(), safe(2));
        assert_eq!(historical.current_recovery_key(), expected_recovery);
    }

    #[test]
    fn relay_history_replays_but_active_lookup_uses_trusted_now() {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let genesis = genesis(&root, &recovery);
        let identity_id = genesis.identity_id();
        let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();

        let backdated_descriptor = signed_event(
            &root,
            identity_id,
            2,
            Some(log.head_hash()),
            1_050,
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(1_100),
            },
        );
        log.append(&backdated_descriptor).unwrap();
        assert!(log.latest_relay_descriptor().is_some());
        assert!(log.active_relay_descriptor(timestamp(1_099)).is_some());
        assert!(log.active_relay_descriptor(timestamp(1_100)).is_none());
        assert!(log.active_relay_descriptor(timestamp(1_500)).is_none());

        let already_expired_at_event_time = UnsignedIdentityLogEventV1::new(
            IDENTITY_LOG_WIRE_VERSION,
            identity_id,
            safe(3),
            Some(log.head_hash()),
            timestamp(1_200),
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(1_100),
            },
            public_key(&root),
        );
        assert_eq!(
            already_expired_at_event_time,
            Err(IdentityLogError::InvalidRelayDescriptor)
        );
    }

    #[test]
    fn current_wire_rejects_legacy_embedded_contracts() {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let genesis = genesis(&root, &recovery);
        let identity_id = genesis.identity_id();
        let legacy_device = signing_key(3);
        let legacy_certificate_unsigned = UnsignedDeviceCertificateV1::new(
            IDENTITY_LOG_V1_0_WIRE_VERSION,
            identity_id,
            device_id(DEVICE_A),
            public_key(&legacy_device),
            DeviceEncryptionPublicKey::try_from([31; 32]).unwrap(),
            public_key(&root),
            timestamp(1_050),
        )
        .unwrap();
        let legacy_certificate = DeviceCertificateV1::signed(
            legacy_certificate_unsigned.clone(),
            signature(
                &root,
                &device_certificate_signature_input(
                    legacy_certificate_unsigned.signing_digest().unwrap(),
                ),
            ),
        )
        .unwrap();

        let device_add = UnsignedIdentityLogEventV1::new(
            IDENTITY_LOG_WIRE_VERSION,
            identity_id,
            safe(2),
            Some(genesis.entry_hash().unwrap()),
            timestamp(1_100),
            IdentityLogEventPayloadV1::DeviceAdd {
                certificate: legacy_certificate,
            },
            public_key(&root),
        );
        assert_eq!(device_add, Err(IdentityLogError::InvalidWireVersion));

        let relay_update = UnsignedIdentityLogEventV1::new(
            IDENTITY_LOG_WIRE_VERSION,
            identity_id,
            safe(2),
            Some(genesis.entry_hash().unwrap()),
            timestamp(1_100),
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: RelayDescriptorV1::new(
                    IDENTITY_LOG_V1_0_WIRE_VERSION,
                    vec!["https://relay-a.example/v1".to_owned()],
                    timestamp(2_000),
                )
                .unwrap(),
            },
            public_key(&root),
        );
        assert_eq!(relay_update, Err(IdentityLogError::InvalidWireVersion));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn root_recovery_rotation_and_restore_fence_old_authorities() {
        let root = signing_key(1);
        let recovery = signing_key(2);
        let genesis = genesis(&root, &recovery);
        let identity_id = genesis.identity_id();
        let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();

        let first_device = signing_key(3);
        let first_certificate = device_certificate(
            &root,
            identity_id,
            &first_device,
            device_id(DEVICE_A),
            31,
            1_050,
        );
        let add = signed_event(
            &root,
            identity_id,
            2,
            Some(log.head_hash()),
            1_100,
            IdentityLogEventPayloadV1::DeviceAdd {
                certificate: first_certificate,
            },
        );
        log.append(&add).unwrap();

        let device_key_as_root = signed_event(
            &root,
            identity_id,
            3,
            Some(log.head_hash()),
            1_150,
            IdentityLogEventPayloadV1::RootRotate {
                new_root_signing_key: public_key(&first_device),
                acceptance_signature: signature(
                    &first_device,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(3),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RootRotate,
                        public_key(&first_device),
                    )
                    .unwrap(),
                ),
            },
        );
        assert_eq!(
            log.append(&device_key_as_root),
            Err(IdentityLogError::InvalidRotation)
        );

        let next_root = signing_key(4);
        let wrong_purpose_rotation = signed_event(
            &root,
            identity_id,
            3,
            Some(log.head_hash()),
            1_175,
            IdentityLogEventPayloadV1::RootRotate {
                new_root_signing_key: public_key(&next_root),
                acceptance_signature: signature(
                    &next_root,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(3),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RecoveryRestoreRoot,
                        public_key(&next_root),
                    )
                    .unwrap(),
                ),
            },
        );
        assert_eq!(
            log.append(&wrong_purpose_rotation),
            Err(IdentityLogError::InvalidRotation)
        );

        let root_rotation = signed_event(
            &root,
            identity_id,
            3,
            Some(log.head_hash()),
            1_200,
            IdentityLogEventPayloadV1::RootRotate {
                new_root_signing_key: public_key(&next_root),
                acceptance_signature: signature(
                    &next_root,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(3),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RootRotate,
                        public_key(&next_root),
                    )
                    .unwrap(),
                ),
            },
        );
        log.append(&root_rotation).unwrap();
        assert_eq!(log.current_root_key(), public_key(&next_root));

        let old_root_update = signed_event(
            &root,
            identity_id,
            4,
            Some(log.head_hash()),
            1_250,
            IdentityLogEventPayloadV1::RelayDescriptor {
                descriptor: descriptor(2_500),
            },
        );
        assert_eq!(
            log.append(&old_root_update),
            Err(IdentityLogError::UnauthorizedSigner)
        );

        let next_recovery = signing_key(5);
        let recovery_successor_acceptance_signature = signature(
            &next_recovery,
            &key_rotation_acceptance_input(
                identity_id,
                safe(4),
                Some(log.head_hash()),
                KeyAcceptancePurposeV1::RecoveryRotate,
                public_key(&next_recovery),
            )
            .unwrap(),
        );
        let old_root_recovery_rotation = signed_event(
            &root,
            identity_id,
            4,
            Some(log.head_hash()),
            1_300,
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: public_key(&next_recovery),
                acceptance_signature: recovery_successor_acceptance_signature,
                recovery_authorization_signature: Some(signature(
                    &recovery,
                    &recovery_rotation_authorization_input(
                        IDENTITY_LOG_WIRE_VERSION,
                        identity_id,
                        safe(4),
                        Some(log.head_hash()),
                        timestamp(1_300),
                        public_key(&root),
                        public_key(&next_recovery),
                        recovery_successor_acceptance_signature,
                    )
                    .unwrap(),
                )),
            },
        );
        assert_eq!(
            log.append(&old_root_recovery_rotation),
            Err(IdentityLogError::UnauthorizedSigner)
        );
        assert_eq!(log.current_recovery_key(), public_key(&recovery));

        let recovery_rotation = signed_event(
            &next_root,
            identity_id,
            4,
            Some(log.head_hash()),
            1_300,
            IdentityLogEventPayloadV1::RecoveryRotate {
                new_recovery_signing_key: public_key(&next_recovery),
                acceptance_signature: recovery_successor_acceptance_signature,
                recovery_authorization_signature: Some(signature(
                    &recovery,
                    &recovery_rotation_authorization_input(
                        IDENTITY_LOG_WIRE_VERSION,
                        identity_id,
                        safe(4),
                        Some(log.head_hash()),
                        timestamp(1_300),
                        public_key(&next_root),
                        public_key(&next_recovery),
                        recovery_successor_acceptance_signature,
                    )
                    .unwrap(),
                )),
            },
        );
        log.append(&recovery_rotation).unwrap();
        assert_eq!(log.current_recovery_key(), public_key(&next_recovery));

        let restored_root = signing_key(6);
        let restored_recovery = signing_key(7);
        let recovery_restore = signed_event(
            &next_recovery,
            identity_id,
            5,
            Some(log.head_hash()),
            1_400,
            IdentityLogEventPayloadV1::RecoveryRestore {
                new_root_signing_key: public_key(&restored_root),
                new_recovery_signing_key: public_key(&restored_recovery),
                root_acceptance_signature: signature(
                    &restored_root,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(5),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RecoveryRestoreRoot,
                        public_key(&restored_root),
                    )
                    .unwrap(),
                ),
                recovery_acceptance_signature: signature(
                    &restored_recovery,
                    &key_rotation_acceptance_input(
                        identity_id,
                        safe(5),
                        Some(log.head_hash()),
                        KeyAcceptancePurposeV1::RecoveryRestoreRecovery,
                        public_key(&restored_recovery),
                    )
                    .unwrap(),
                ),
            },
        );
        log.append(&recovery_restore).unwrap();
        assert_eq!(log.current_root_key(), public_key(&restored_root));
        assert_eq!(log.current_recovery_key(), public_key(&restored_recovery));
        assert_eq!(
            log.device_status(device_id(DEVICE_A)),
            Some(DeviceStatusV1::Revoked)
        );

        let new_device = signing_key(8);
        let new_certificate = device_certificate(
            &restored_root,
            identity_id,
            &new_device,
            device_id(DEVICE_C),
            81,
            1_450,
        );
        let revoked_device_attempt = signed_event(
            &first_device,
            identity_id,
            6,
            Some(log.head_hash()),
            1_500,
            IdentityLogEventPayloadV1::DeviceAdd {
                certificate: new_certificate.clone(),
            },
        );
        assert_eq!(
            log.append(&revoked_device_attempt),
            Err(IdentityLogError::UnauthorizedSigner)
        );

        let root_device_add = signed_event(
            &restored_root,
            identity_id,
            6,
            Some(log.head_hash()),
            1_500,
            IdentityLogEventPayloadV1::DeviceAdd {
                certificate: new_certificate,
            },
        );
        log.append(&root_device_add).unwrap();
        assert_eq!(
            log.device_status(device_id(DEVICE_C)),
            Some(DeviceStatusV1::Active)
        );
    }
}
