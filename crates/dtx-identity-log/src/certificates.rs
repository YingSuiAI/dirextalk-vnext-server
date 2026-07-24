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
