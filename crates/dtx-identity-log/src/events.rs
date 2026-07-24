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
