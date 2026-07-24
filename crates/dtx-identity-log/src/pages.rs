/// One bounded, read-only page of exact signed identity-log events.
///
/// The page is transport metadata, not a second signature layer. Consumers
/// still reduce each embedded event with their locally trusted projection
/// before trusting device keys or relay descriptors. This type proves the
/// page itself is canonical, contiguous, and internally bound to its terminal
/// advertised head when that head is present in the page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityLogPageV1 {
    identity_id: IdentityId,
    advertised_head_sequence: SafeUint,
    advertised_head_hash: Sha256Digest,
    requested_after_sequence: u64,
    exact_events: Vec<Vec<u8>>,
    next_after_sequence: u64,
    has_more: bool,
}

impl IdentityLogPageV1 {
    /// Creates a bounded canonical identity-log page from exact signed events.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when the cursor range, exact event bytes,
    /// contiguous event chain, advertised terminal head, or response bounds
    /// are inconsistent.
    pub fn new(
        identity_id: IdentityId,
        advertised_head_sequence: SafeUint,
        advertised_head_hash: Sha256Digest,
        requested_after_sequence: u64,
        exact_events: Vec<Vec<u8>>,
        next_after_sequence: u64,
        has_more: bool,
    ) -> Result<Self, IdentityLogPageError> {
        if SafeUint::new(requested_after_sequence).is_err()
            || SafeUint::new(next_after_sequence).is_err()
            || advertised_head_sequence.get() == 0
            || requested_after_sequence > advertised_head_sequence.get()
            || next_after_sequence > advertised_head_sequence.get()
        {
            return Err(IdentityLogPageError::InvalidCursor);
        }
        if exact_events.len() > MAX_IDENTITY_LOG_PAGE_EVENTS {
            return Err(IdentityLogPageError::EventLimitExceeded);
        }

        let mut previous_hash = None;
        for (index, exact_bytes) in exact_events.iter().enumerate() {
            if exact_bytes.is_empty() || exact_bytes.len() > MAX_IDENTITY_LOG_PAGE_EVENT_BYTES {
                return Err(IdentityLogPageError::PageTooLarge);
            }
            let event = IdentityLogEventV1::decode_and_verify(exact_bytes)
                .map_err(IdentityLogPageError::InvalidEvent)?;
            if event.identity_id() != identity_id || event.wire() != IDENTITY_LOG_WIRE_VERSION {
                return Err(IdentityLogPageError::IdentityMismatch);
            }
            let event_offset =
                u64::try_from(index).map_err(|_| IdentityLogPageError::SequenceMismatch)?;
            let expected_sequence = requested_after_sequence
                .checked_add(event_offset)
                .and_then(|value| value.checked_add(1))
                .ok_or(IdentityLogPageError::SequenceMismatch)?;
            if event.sequence().get() != expected_sequence {
                return Err(IdentityLogPageError::SequenceMismatch);
            }
            if let Some(previous_hash) = previous_hash {
                if event.previous_event_hash() != Some(previous_hash) {
                    return Err(IdentityLogPageError::PreviousHashMismatch);
                }
            } else if expected_sequence == 1 && event.previous_event_hash().is_some() {
                return Err(IdentityLogPageError::PreviousHashMismatch);
            }
            previous_hash = Some(
                event
                    .entry_hash()
                    .map_err(IdentityLogPageError::InvalidEvent)?,
            );
        }

        let expected_next = requested_after_sequence
            .checked_add(
                u64::try_from(exact_events.len())
                    .map_err(|_| IdentityLogPageError::NextCursorMismatch)?,
            )
            .ok_or(IdentityLogPageError::NextCursorMismatch)?;
        if next_after_sequence != expected_next {
            return Err(IdentityLogPageError::NextCursorMismatch);
        }
        let terminal = next_after_sequence == advertised_head_sequence.get();
        if has_more == terminal || (has_more && exact_events.is_empty()) {
            return Err(IdentityLogPageError::PaginationMismatch);
        }
        if terminal && !exact_events.is_empty() && previous_hash != Some(advertised_head_hash) {
            return Err(IdentityLogPageError::AdvertisedHeadMismatch);
        }

        let page = Self {
            identity_id,
            advertised_head_sequence,
            advertised_head_hash,
            requested_after_sequence,
            exact_events,
            next_after_sequence,
            has_more,
        };
        if page
            .to_deterministic_cbor()
            .map_err(|_| IdentityLogPageError::InvalidCanonical)?
            .len()
            > MAX_IDENTITY_LOG_PAGE_BYTES
        {
            return Err(IdentityLogPageError::PageTooLarge);
        }
        Ok(page)
    }

    /// Decodes a deterministic-CBOR page and revalidates every exact event.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for noncanonical CBOR, unknown fields,
    /// malformed exact events, inconsistent cursors, or a mismatched head.
    pub fn decode_and_verify(bytes: &[u8]) -> Result<Self, IdentityLogPageError> {
        if bytes.is_empty() || bytes.len() > MAX_IDENTITY_LOG_PAGE_BYTES {
            return Err(IdentityLogPageError::PageTooLarge);
        }
        let value =
            decode_deterministic_cbor(bytes).map_err(|_| IdentityLogPageError::InvalidCanonical)?;
        let fields = page_exact_fields(&value, 8)?;
        decode_page_wire(page_field(fields, 1)?)?;
        let identity_id = page_decode_identity_id(page_field(fields, 2)?)?;
        let advertised_head_sequence = page_decode_safe_uint(page_field(fields, 3)?)?;
        let advertised_head_hash = page_decode_digest(page_field(fields, 4)?)?;
        let requested_after_sequence = page_decode_safe_uint(page_field(fields, 5)?)?.get();
        let CanonicalValue::Array(events) = page_field(fields, 6)? else {
            return Err(IdentityLogPageError::InvalidCanonical);
        };
        let exact_events = events
            .iter()
            .map(page_decode_event_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let next_after_sequence = page_decode_safe_uint(page_field(fields, 7)?)?.get();
        let CanonicalValue::Bool(has_more) = page_field(fields, 8)? else {
            return Err(IdentityLogPageError::InvalidCanonical);
        };
        let page = Self::new(
            identity_id,
            advertised_head_sequence,
            advertised_head_hash,
            requested_after_sequence,
            exact_events,
            next_after_sequence,
            *has_more,
        )?;
        if page.to_deterministic_cbor()? != bytes {
            return Err(IdentityLogPageError::InvalidCanonical);
        }
        Ok(page)
    }

    /// Encodes the exact deterministic-CBOR page payload.
    ///
    /// # Errors
    ///
    /// Returns an error only if deterministic encoding fails unexpectedly.
    pub fn to_deterministic_cbor(&self) -> Result<Vec<u8>, IdentityLogPageError> {
        encode_deterministic_cbor(self).map_err(|_| IdentityLogPageError::InvalidCanonical)
    }

    /// Returns the self-certifying identity that owns this event stream.
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Returns the source's immutable advertised head sequence.
    #[must_use]
    pub const fn advertised_head_sequence(&self) -> SafeUint {
        self.advertised_head_sequence
    }

    /// Returns the source's immutable advertised head event hash.
    #[must_use]
    pub const fn advertised_head_hash(&self) -> Sha256Digest {
        self.advertised_head_hash
    }

    /// Returns the caller's requested last verified sequence.
    #[must_use]
    pub const fn requested_after_sequence(&self) -> u64 {
        self.requested_after_sequence
    }

    /// Returns the original exact signed event bytes in response order.
    #[must_use]
    pub fn exact_events(&self) -> &[Vec<u8>] {
        &self.exact_events
    }

    /// Returns the last sequence advanced by bytes in this response.
    #[must_use]
    pub const fn next_after_sequence(&self) -> u64 {
        self.next_after_sequence
    }

    /// Returns whether a contiguous successor page is required to reach head.
    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

impl CanonicalEncode for IdentityLogPageV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Map(vec![
                    (
                        CanonicalValue::Unsigned(1),
                        CanonicalValue::Unsigned(IDENTITY_LOG_PAGE_WIRE_MAJOR),
                    ),
                    (
                        CanonicalValue::Unsigned(2),
                        CanonicalValue::Unsigned(IDENTITY_LOG_PAGE_WIRE_MINOR),
                    ),
                ]),
            ),
            (
                CanonicalValue::Unsigned(2),
                identity_value(self.identity_id),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.advertised_head_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.advertised_head_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Unsigned(self.requested_after_sequence),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Array(
                    self.exact_events
                        .iter()
                        .cloned()
                        .map(CanonicalValue::Bytes)
                        .collect(),
                ),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Unsigned(self.next_after_sequence),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Bool(self.has_more),
            ),
        ])
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
