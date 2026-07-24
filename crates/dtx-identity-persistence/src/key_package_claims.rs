/// One exact request to atomically receive one package from a target active
/// device. It intentionally does not name a package ID, preventing a caller
/// from probing directory contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPackageClaimCommand {
    idempotency_key_hash: Sha256Digest,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    exact_claim_bytes: Vec<u8>,
    history_recovery_scope: Option<HistoryRecoveryKeyPackageScope>,
}

impl KeyPackageClaimCommand {
    /// Builds a claim command from its exact deterministic-CBOR body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds its bound or is not the exact
    /// canonical request representation.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        target_identity_id: IdentityId,
        target_device_id: DeviceId,
        exact_claim_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_claim_bytes.is_empty() || exact_claim_bytes.len() > 16_384 {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim byte length",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            target_identity_id,
            target_device_id,
            exact_claim_bytes,
            history_recovery_scope: None,
        };
        let expected = encode_deterministic_cbor(&command.to_canonical_value())
            .map_err(|_| IdentityPersistenceError::InvalidCommand("key package claim encoding"))?;
        if expected != command.exact_claim_bytes {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim canonical bytes",
            ));
        }
        Ok(command)
    }

    /// Builds a same-identity claim restricted to one exact recovery scope.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact claim is empty, oversized, or not the
    /// canonical representation of the supplied public fields.
    pub fn new_history_recovery_v2(
        idempotency_key_hash: Sha256Digest,
        target_identity_id: IdentityId,
        target_device_id: DeviceId,
        scope: HistoryRecoveryKeyPackageScope,
        exact_claim_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_claim_bytes.is_empty() || exact_claim_bytes.len() > 16_384 {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim byte length",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            target_identity_id,
            target_device_id,
            exact_claim_bytes,
            history_recovery_scope: Some(scope),
        };
        let expected = encode_deterministic_cbor(&command.to_canonical_value())
            .map_err(|_| IdentityPersistenceError::InvalidCommand("key package claim encoding"))?;
        if expected != command.exact_claim_bytes {
            return Err(IdentityPersistenceError::InvalidCommand(
                "key package claim canonical bytes",
            ));
        }
        Ok(command)
    }

    /// Returns the optional exact history-recovery scope.
    #[must_use]
    pub const fn history_recovery_scope(&self) -> Option<HistoryRecoveryKeyPackageScope> {
        self.history_recovery_scope
    }

    /// Returns the target self-certifying identity.
    #[must_use]
    pub const fn target_identity_id(&self) -> IdentityId {
        self.target_identity_id
    }

    /// Returns the target active device.
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    /// Returns the scoped HTTP idempotency-key digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(
            KEY_PACKAGE_CLAIM_REQUEST_HASH_DOMAIN,
            &self.exact_claim_bytes,
        )
    }
}

impl CanonicalEncode for KeyPackageClaimCommand {
    fn to_canonical_value(&self) -> CanonicalValue {
        let mut fields = vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(if self.history_recovery_scope.is_some() {
                    2
                } else {
                    1
                }),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.target_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.target_device_id.to_string()),
            ),
        ];
        if let Some(scope) = self.history_recovery_scope {
            fields.push((
                CanonicalValue::Unsigned(4),
                scope.request_digest().to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(5),
                scope.scope_digest().to_canonical_value(),
            ));
            fields.push((CanonicalValue::Unsigned(6), CanonicalValue::Unsigned(1)));
        }
        CanonicalValue::Map(fields)
    }
}

/// Parsed V2 proof fields which become authoritative only after the target
/// node resolves the requester's current identity log and verifies this proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedKeyPackageClaimProof {
    requester_identity_origin: String,
    requester_identity_id: IdentityId,
    requester_device_id: DeviceId,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    method: String,
    path: String,
    body_digest: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    nonce: [u8; 32],
    idempotency_key_hash: Sha256Digest,
    signature: Ed25519Signature,
}

impl FederatedKeyPackageClaimProof {
    /// Builds a parsed proof while retaining every signed coordinate.
    /// Cryptographic and current-device verification happens in [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns an invalid-command error when the requester origin or nonce is
    /// not suitable for a signed federated request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_identity_origin: impl Into<String>,
        requester_identity_id: IdentityId,
        requester_device_id: DeviceId,
        target_identity_id: IdentityId,
        target_device_id: DeviceId,
        method: impl Into<String>,
        path: impl Into<String>,
        body_digest: Sha256Digest,
        issued_at: UtcMillis,
        expires_at: UtcMillis,
        nonce: [u8; 32],
        idempotency_key_hash: Sha256Digest,
        signature: Ed25519Signature,
    ) -> Result<Self, IdentityPersistenceError> {
        let proof = Self {
            requester_identity_origin: requester_identity_origin.into(),
            requester_identity_id,
            requester_device_id,
            target_identity_id,
            target_device_id,
            method: method.into(),
            path: path.into(),
            body_digest,
            issued_at,
            expires_at,
            nonce,
            idempotency_key_hash,
            signature,
        };
        if !(8..=512).contains(&proof.requester_identity_origin.len())
            || !proof
                .requester_identity_origin
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || proof.nonce.iter().all(|byte| *byte == 0)
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "federated key package claim proof",
            ));
        }
        Ok(proof)
    }

    /// Returns the signed requester origin used for remote log resolution.
    #[must_use]
    pub fn requester_identity_origin(&self) -> &str {
        &self.requester_identity_origin
    }

    /// Returns the signed requester identity.
    #[must_use]
    pub const fn requester_identity_id(&self) -> IdentityId {
        self.requester_identity_id
    }

    /// Returns the signed requester device.
    #[must_use]
    pub const fn requester_device_id(&self) -> DeviceId {
        self.requester_device_id
    }

    /// Verifies all HTTP, target, body, time, nonce and idempotency bindings
    /// using the current active-device key fetched from the requester origin.
    ///
    /// # Errors
    ///
    /// Returns a uniform authentication rejection for any mismatch or invalid
    /// remote signature.
    pub fn verify(
        &self,
        command: &KeyPackageClaimCommand,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<VerifiedFederatedKeyPackageClaimant, IdentityPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(IdentityPersistenceError::DeviceAuthenticationRejected)?;
        if self.target_identity_id != command.target_identity_id()
            || self.target_device_id != command.target_device_id()
            || self.method != FEDERATED_KEY_PACKAGE_CLAIM_METHOD
            || self.path != FEDERATED_KEY_PACKAGE_CLAIM_PATH
            || self.body_digest != federated_key_package_claim_body_digest(command)
            || self.idempotency_key_hash != command.idempotency_key_hash()
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=FEDERATED_KEY_PACKAGE_CLAIM_PROOF_MAX_LIFETIME_MILLIS).contains(&lifetime)
        {
            return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
        }
        let signature_input = federated_key_package_claim_signature_input(
            &self.requester_identity_origin,
            self.requester_identity_id,
            self.requester_device_id,
            self.target_identity_id,
            self.target_device_id,
            &self.method,
            &self.path,
            self.body_digest,
            self.issued_at,
            self.expires_at,
            self.nonce,
            self.idempotency_key_hash,
        )?;
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        verifying_key
            .verify_strict(
                &signature_input,
                &Signature::from_bytes(self.signature.as_bytes()),
            )
            .map_err(|_| IdentityPersistenceError::DeviceAuthenticationRejected)?;
        Ok(VerifiedFederatedKeyPackageClaimant {
            identity_origin: self.requester_identity_origin.clone(),
            identity_id: self.requester_identity_id,
            device_id: self.requester_device_id,
        })
    }
}

/// Remote claimant identity that can only be produced by a complete V2 proof
/// verification against a freshly resolved active-device key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFederatedKeyPackageClaimant {
    identity_origin: String,
    identity_id: IdentityId,
    device_id: DeviceId,
}

/// Computes the exact signed body digest for a federated V2 claim.
#[must_use]
pub fn federated_key_package_claim_body_digest(command: &KeyPackageClaimCommand) -> Sha256Digest {
    Sha256Digest::hash_domain(
        FEDERATED_KEY_PACKAGE_CLAIM_BODY_HASH_DOMAIN,
        &command.exact_claim_bytes,
    )
}

/// Builds the canonical V2 remote-device signature input.
///
/// # Errors
///
/// Returns an error only when deterministic CBOR encoding fails.
#[allow(clippy::too_many_arguments)]
pub fn federated_key_package_claim_signature_input(
    requester_identity_origin: &str,
    requester_identity_id: IdentityId,
    requester_device_id: DeviceId,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    method: &str,
    path: &str,
    body_digest: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    nonce: [u8; 32],
    idempotency_key_hash: Sha256Digest,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let binding = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(requester_identity_origin.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(requester_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(requester_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(target_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(target_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(method.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(path.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(9),
            body_digest.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(10), issued_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(11),
            expires_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(12),
            CanonicalValue::Bytes(nonce.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(13),
            idempotency_key_hash.to_canonical_value(),
        ),
    ]))
    .map_err(|_| {
        IdentityPersistenceError::InvalidCommand("federated key package claim encoding")
    })?;
    let digest =
        Sha256Digest::hash_domain(FEDERATED_KEY_PACKAGE_CLAIM_BINDING_HASH_DOMAIN, &binding);
    let mut input = Vec::with_capacity(
        FEDERATED_KEY_PACKAGE_CLAIM_SIGNATURE_DOMAIN.len() + digest.as_bytes().len(),
    );
    input.extend_from_slice(FEDERATED_KEY_PACKAGE_CLAIM_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Builds the canonical unsigned binding that an active device signs before a
/// `KeyPackage` is uploaded. The MLS signer key remains inside the opaque MLS
/// package; the outer signature binds the currently active Dirextalk device.
///
/// # Errors
///
/// Returns an error when canonical encoding cannot represent the binding.
#[allow(clippy::too_many_arguments)]
pub fn key_package_publish_binding_canonical_bytes(
    identity_id: IdentityId,
    device_id: DeviceId,
    package_id: KeyPackageId,
    published_head_sequence: SafeUint,
    published_head_hash: Sha256Digest,
    expires_at: UtcMillis,
    package_digest: Sha256Digest,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(package_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            published_head_sequence.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            published_head_hash.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(7), expires_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(8),
            package_digest.to_canonical_value(),
        ),
    ]))
    .map_err(|_| IdentityPersistenceError::InvalidCommand("key package binding encoding"))
}

/// Returns the exact detached-signature input for a `KeyPackage` publish
/// envelope. It hashes the canonical binding and prefixes a distinct domain,
/// so this signature cannot be replayed as an MLS or identity-log signature.
///
/// # Errors
///
/// Returns an error when the opaque payload is outside its bound or canonical
/// encoding cannot represent the binding.
#[allow(clippy::too_many_arguments)]
pub fn key_package_publish_signature_input(
    identity_id: IdentityId,
    device_id: DeviceId,
    package_id: KeyPackageId,
    published_head_sequence: SafeUint,
    published_head_hash: Sha256Digest,
    expires_at: UtcMillis,
    opaque_key_package: &[u8],
) -> Result<Vec<u8>, IdentityPersistenceError> {
    if opaque_key_package.is_empty() || opaque_key_package.len() > MAX_KEY_PACKAGE_BYTES {
        return Err(IdentityPersistenceError::InvalidCommand(
            "key package byte length",
        ));
    }
    let package_digest =
        Sha256Digest::hash_domain(KEY_PACKAGE_BYTES_HASH_DOMAIN, opaque_key_package);
    let canonical = key_package_publish_binding_canonical_bytes(
        identity_id,
        device_id,
        package_id,
        published_head_sequence,
        published_head_hash,
        expires_at,
        package_digest,
    )?;
    let digest = Sha256Digest::hash_domain(KEY_PACKAGE_PUBLISH_BINDING_HASH_DOMAIN, &canonical);
    let mut input = Vec::with_capacity(KEY_PACKAGE_PUBLISH_SIGNATURE_DOMAIN.len() + 32);
    input.extend_from_slice(KEY_PACKAGE_PUBLISH_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Exact immutable publish receipt returned after successful persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPackagePublishReceipt {
    package_id: KeyPackageId,
    package_digest: Sha256Digest,
    expires_at: UtcMillis,
    exact_bytes: Vec<u8>,
}

impl KeyPackagePublishReceipt {
    fn new(
        package_id: KeyPackageId,
        package_digest: Sha256Digest,
        expires_at: UtcMillis,
    ) -> Result<Self, IdentityPersistenceError> {
        let receipt = Self {
            package_id,
            package_digest,
            expires_at,
            exact_bytes: Vec::new(),
        };
        let exact_bytes = encode_deterministic_cbor(&receipt).map_err(|_| {
            IdentityPersistenceError::InvalidCommand("key package publish receipt encoding")
        })?;
        Ok(Self {
            exact_bytes,
            ..receipt
        })
    }

    /// Returns the durable public package ID.
    #[must_use]
    pub const fn package_id(&self) -> KeyPackageId {
        self.package_id
    }

    /// Returns the opaque package digest bound to the device signature.
    #[must_use]
    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }

    /// Returns the package expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the exact receipt bytes replayed after response loss.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    fn receipt_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(KEY_PACKAGE_PUBLISH_RECEIPT_HASH_DOMAIN, &self.exact_bytes)
    }

    fn verify_exact_bytes(
        &self,
        stored_bytes: &[u8],
        stored_digest: Sha256Digest,
    ) -> Result<(), IdentityPersistenceError> {
        if self.exact_bytes != stored_bytes || self.receipt_digest() != stored_digest {
            return Err(IdentityPersistenceError::ReceiptIntegrity);
        }
        Ok(())
    }
}

impl CanonicalEncode for KeyPackagePublishReceipt {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.package_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.package_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }
}

/// The exact original publish envelope returned by an atomic claim.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyPackageClaimReceipt {
    exact_publish_bytes: Vec<u8>,
}

impl fmt::Debug for KeyPackageClaimReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyPackageClaimReceipt")
            .field("exact_publish_bytes", &"[OPAQUE]")
            .finish()
    }
}

impl KeyPackageClaimReceipt {
    fn new(exact_publish_bytes: Vec<u8>) -> Result<Self, IdentityPersistenceError> {
        if exact_publish_bytes.is_empty()
            || exact_publish_bytes.len() > MAX_KEY_PACKAGE_PUBLISH_BYTES
        {
            return Err(IdentityPersistenceError::CorruptData(
                "key package claim receipt byte length",
            ));
        }
        Ok(Self {
            exact_publish_bytes,
        })
    }

    /// Returns the original exact publish envelope, including the publisher's
    /// active-device signature and opaque MLS bytes.
    #[must_use]
    pub fn exact_publish_bytes(&self) -> &[u8] {
        &self.exact_publish_bytes
    }

    fn receipt_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(
            KEY_PACKAGE_CLAIM_RECEIPT_HASH_DOMAIN,
            &self.exact_publish_bytes,
        )
    }

    fn verify_exact_bytes(
        &self,
        stored_bytes: &[u8],
        stored_digest: Sha256Digest,
    ) -> Result<(), IdentityPersistenceError> {
        if self.exact_publish_bytes != stored_bytes || self.receipt_digest() != stored_digest {
            return Err(IdentityPersistenceError::ReceiptIntegrity);
        }
        Ok(())
    }
}

/// Durable result of a publish request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyPackagePublishOutcome {
    /// A fresh opaque `KeyPackage` was persisted and made claimable.
    Published(KeyPackagePublishReceipt),
    /// The exact publish receipt was returned after response loss.
    Replayed(KeyPackagePublishReceipt),
}

impl KeyPackagePublishOutcome {
    /// Returns the immutable receipt in either outcome.
    #[must_use]
    pub const fn receipt(&self) -> &KeyPackagePublishReceipt {
        match self {
            Self::Published(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}

/// Durable result of a one-time claim request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyPackageClaimOutcome {
    /// One available package was atomically consumed.
    Claimed(KeyPackageClaimReceipt),
    /// The exact original envelope was returned after response loss.
    Replayed(KeyPackageClaimReceipt),
}

impl KeyPackageClaimOutcome {
    /// Returns the exact opaque publish envelope in either outcome.
    #[must_use]
    pub const fn receipt(&self) -> &KeyPackageClaimReceipt {
        match self {
            Self::Claimed(receipt) | Self::Replayed(receipt) => receipt,
        }
    }
}
