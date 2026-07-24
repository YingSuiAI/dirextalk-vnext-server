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
    initial_device_id: Option<DeviceId>,
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
            initial_device_id: None,
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

    /// Returns the immutable first device enrolled directly after genesis.
    ///
    /// Later devices cannot acquire bootstrap authority by owning service
    /// resources. A projection without an exact sequence-two device has no
    /// bootstrap device.
    #[must_use]
    pub const fn initial_device_id(&self) -> Option<DeviceId> {
        self.initial_device_id
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
        if self.head_sequence.get() == 1 {
            self.initial_device_id = Some(certificate.device_id());
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
