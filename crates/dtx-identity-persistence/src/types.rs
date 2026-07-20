use dtx_domain::{DeviceId, IdentityId};
use dtx_identity_log::IdentityLogV1;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, WireVersion,
    encode_deterministic_cbor,
};

use crate::IdentityPersistenceError;

/// Domain separator for a canonical identity-log append request digest.
pub const IDENTITY_APPEND_REQUEST_HASH_DOMAIN: &[u8] = b"dirextalk.identity-append-request.v1\0";
/// Domain separator for an immutable exact identity-log append receipt digest.
pub const IDENTITY_APPEND_RECEIPT_HASH_DOMAIN: &[u8] = b"dirextalk.identity-append-receipt.v1\0";

const MAX_IDENTITY_EVENT_BYTES: usize = 1024 * 1024;

/// Public, self-certifying durable identity-log head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityLogHead {
    identity_id: IdentityId,
    wire: WireVersion,
    sequence: SafeUint,
    hash: Sha256Digest,
}

impl IdentityLogHead {
    pub(crate) const fn new(
        identity_id: IdentityId,
        wire: WireVersion,
        sequence: SafeUint,
        hash: Sha256Digest,
    ) -> Self {
        Self {
            identity_id,
            wire,
            sequence,
            hash,
        }
    }

    /// Builds an externally observed current head for an exact recovery
    /// request; persistence still rechecks it against the locked log head.
    ///
    /// # Errors
    ///
    /// Returns an error when the observed sequence is zero.
    pub fn observed(
        identity_id: IdentityId,
        sequence: SafeUint,
        hash: Sha256Digest,
    ) -> Result<Self, IdentityPersistenceError> {
        if sequence.get() == 0 {
            return Err(IdentityPersistenceError::InvalidCommand(
                "observed identity head sequence",
            ));
        }
        Ok(Self::new(
            identity_id,
            dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
            sequence,
            hash,
        ))
    }

    /// Returns the permanent self-certifying public ID.
    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    /// Returns the exact established wire line.
    #[must_use]
    pub const fn wire(self) -> WireVersion {
        self.wire
    }

    /// Returns the contiguous durable event sequence.
    #[must_use]
    pub const fn sequence(self) -> SafeUint {
        self.sequence
    }

    /// Returns the exact complete-event hash at the head.
    #[must_use]
    pub const fn hash(self) -> Sha256Digest {
        self.hash
    }
}

/// One canonical append command. The idempotency key is already hashed at the
/// authenticated transport boundary; raw keys never enter durable storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityAppendCommand {
    idempotency_key_hash: Sha256Digest,
    expected_head: Option<IdentityLogHead>,
    exact_event_bytes: Vec<u8>,
}

impl IdentityAppendCommand {
    /// Creates a bounded append command over exact canonical signed event bytes.
    ///
    /// Event canonicality and reducer authorization are intentionally checked
    /// by the repository immediately before it claims durable idempotency.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact event byte length is outside the durable
    /// bounded input contract.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        expected_head: Option<IdentityLogHead>,
        exact_event_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_event_bytes.is_empty() || exact_event_bytes.len() > MAX_IDENTITY_EVENT_BYTES {
            return Err(IdentityPersistenceError::InvalidCommand(
                "identity event byte length",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            expected_head,
            exact_event_bytes,
        })
    }

    /// Returns the non-secret digest of the caller's idempotency key.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    /// Returns the caller's observed predecessor, or `None` only for genesis.
    #[must_use]
    pub const fn expected_head(&self) -> Option<IdentityLogHead> {
        self.expected_head
    }

    /// Returns the original exact signed bytes. They are not reserialized.
    #[must_use]
    pub fn exact_event_bytes(&self) -> &[u8] {
        &self.exact_event_bytes
    }
}

/// One dedicated request to revoke another device from an identity log.
///
/// The authenticated session is supplied separately so its secret never
/// becomes part of durable command state or an idempotency digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRevokeCommand {
    idempotency_key_hash: Sha256Digest,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    expected_head_hash: Sha256Digest,
    exact_event_bytes: Vec<u8>,
}

impl DeviceRevokeCommand {
    /// Builds a bounded transport command over one exact signed event.
    ///
    /// Event canonicality, V1.1 shape, route/body binding, and root authority
    /// are checked by the repository inside the durable revoke boundary.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized event before opening a transaction.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        identity_id: IdentityId,
        target_device_id: DeviceId,
        expected_head_hash: Sha256Digest,
        exact_event_bytes: Vec<u8>,
    ) -> Result<Self, IdentityPersistenceError> {
        if exact_event_bytes.is_empty() || exact_event_bytes.len() > MAX_IDENTITY_EVENT_BYTES {
            return Err(IdentityPersistenceError::InvalidCommand(
                "device revoke event byte length",
            ));
        }
        Ok(Self {
            idempotency_key_hash,
            identity_id,
            target_device_id,
            expected_head_hash,
            exact_event_bytes,
        })
    }

    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }

    #[must_use]
    pub const fn expected_head_hash(&self) -> Sha256Digest {
        self.expected_head_hash
    }

    #[must_use]
    pub fn exact_event_bytes(&self) -> &[u8] {
        &self.exact_event_bytes
    }
}

/// Stable lifecycle envelope for a durable identity command resolution.
///
/// `Pending` exists only inside an open database transaction. `IM1b` returns
/// `Committed` for a canonical append and `Reconciling` for a verified fork;
/// a later membership command still needs its own durable reconciliation facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityCommandPhase {
    /// The command has been accepted but lacks a durable authorization result.
    Pending,
    /// The exact identity event, head, receipt, and outbox record committed atomically.
    Committed,
    /// A verified identity fork needs deterministic manual reconciliation.
    Reconciling,
}

/// Immutable proof that a verified signed candidate diverged from the
/// canonical durable identity chain. The candidate is deliberately retained
/// outside the canonical entry sequence so fork detection never chooses a
/// winner by overwriting history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityForkEvidence {
    observed_head: IdentityLogHead,
    candidate: IdentityLogHead,
    exact_candidate_event_bytes: Vec<u8>,
}

impl IdentityForkEvidence {
    pub(crate) fn new(
        observed_head: IdentityLogHead,
        candidate: IdentityLogHead,
        exact_candidate_event_bytes: Vec<u8>,
    ) -> Self {
        Self {
            observed_head,
            candidate,
            exact_candidate_event_bytes,
        }
    }

    /// Returns the canonical head observed when the divergence was verified.
    #[must_use]
    pub const fn observed_head(&self) -> IdentityLogHead {
        self.observed_head
    }

    /// Returns the signed competing candidate's identity, sequence, and hash.
    #[must_use]
    pub const fn candidate(&self) -> IdentityLogHead {
        self.candidate
    }

    /// Returns the exact canonical signed candidate bytes for audit or gossip.
    #[must_use]
    pub fn exact_candidate_event_bytes(&self) -> &[u8] {
        &self.exact_candidate_event_bytes
    }
}

impl IdentityCommandPhase {
    const fn code(self) -> u64 {
        match self {
            Self::Pending => 1,
            Self::Committed => 2,
            Self::Reconciling => 3,
        }
    }
}

/// Immutable result of one committed identity append command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityAppendReceipt {
    head: IdentityLogHead,
    request_digest: Sha256Digest,
    phase: IdentityCommandPhase,
    committed_at: UtcMillis,
    exact_bytes: Vec<u8>,
}

impl IdentityAppendReceipt {
    pub(crate) fn new(
        head: IdentityLogHead,
        request_digest: Sha256Digest,
        phase: IdentityCommandPhase,
        committed_at: UtcMillis,
    ) -> Result<Self, IdentityPersistenceError> {
        let receipt = Self {
            head,
            request_digest,
            phase,
            committed_at,
            exact_bytes: Vec::new(),
        };
        let exact_bytes = encode_deterministic_cbor(&receipt)
            .map_err(|_| IdentityPersistenceError::InvalidCommand("identity receipt encoding"))?;
        Ok(Self {
            exact_bytes,
            ..receipt
        })
    }

    /// Returns the immutable committed log head.
    #[must_use]
    pub const fn head(&self) -> IdentityLogHead {
        self.head
    }

    /// Returns the internally computed canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the durable phase. `IM1b` only returns `Committed`.
    #[must_use]
    pub const fn phase(&self) -> IdentityCommandPhase {
        self.phase
    }

    /// Returns the trusted server commit time retained with the receipt.
    #[must_use]
    pub const fn committed_at(&self) -> UtcMillis {
        self.committed_at
    }

    /// Returns the exact immutable receipt bytes returned on idempotent replay.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub(crate) fn receipt_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(IDENTITY_APPEND_RECEIPT_HASH_DOMAIN, &self.exact_bytes)
    }

    pub(crate) fn verify_exact_bytes(
        &self,
        expected_bytes: &[u8],
        stored_digest: Sha256Digest,
    ) -> Result<(), IdentityPersistenceError> {
        if self.exact_bytes != expected_bytes || self.receipt_digest() != stored_digest {
            return Err(IdentityPersistenceError::ReceiptIntegrity);
        }
        Ok(())
    }
}

impl CanonicalEncode for IdentityAppendReceipt {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.head.identity_id().to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.head.wire().to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.head.sequence().to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.head.hash().to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.request_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Unsigned(self.phase.code()),
            ),
            (
                CanonicalValue::Unsigned(8),
                self.committed_at.to_canonical_value(),
            ),
        ])
    }
}

/// Returned disposition for a command after the enclosing transaction commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityAppendOutcome {
    /// This call performed the durable append once.
    Committed(IdentityAppendReceipt),
    /// The original committed result was returned after an exact retry.
    Replayed(IdentityAppendReceipt),
    /// A verified divergent candidate was retained as evidence and the identity
    /// moved into fail-closed reconciliation.
    Forked {
        /// The durable resolution receipt, replayable after a response loss.
        receipt: IdentityAppendReceipt,
        /// The exact candidate and observed canonical head to audit or gossip.
        evidence: IdentityForkEvidence,
    },
}

impl IdentityAppendOutcome {
    /// Returns the durable receipt regardless of whether this request executed or replayed.
    #[must_use]
    pub const fn receipt(&self) -> &IdentityAppendReceipt {
        match self {
            Self::Committed(receipt) | Self::Replayed(receipt) | Self::Forked { receipt, .. } => {
                receipt
            }
        }
    }

    /// Returns the durable fork proof when the command entered reconciliation.
    #[must_use]
    pub const fn evidence(&self) -> Option<&IdentityForkEvidence> {
        match self {
            Self::Forked { evidence, .. } => Some(evidence),
            Self::Committed(_) | Self::Replayed(_) => None,
        }
    }
}

/// Fully rehydrated durable identity state. The projection, not any WebSocket
/// or UI cache, is the local authorization fact for a later API boundary.
#[derive(Clone, Debug)]
pub struct IdentityLogSnapshot {
    head: IdentityLogHead,
    projection: IdentityLogV1,
    exact_events: Vec<Vec<u8>>,
}

impl IdentityLogSnapshot {
    pub(crate) fn new(
        head: IdentityLogHead,
        projection: IdentityLogV1,
        exact_events: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            head,
            projection,
            exact_events,
        }
    }

    /// Returns the exact durable head after full reducer rehydration.
    #[must_use]
    pub const fn head(&self) -> IdentityLogHead {
        self.head
    }

    /// Returns the verified current in-memory projection.
    #[must_use]
    pub const fn projection(&self) -> &IdentityLogV1 {
        &self.projection
    }

    /// Returns the retained canonical signed event bytes in sequence order.
    #[must_use]
    pub fn exact_events(&self) -> &[Vec<u8>] {
        &self.exact_events
    }
}

pub(crate) fn request_digest(
    command: &IdentityAppendCommand,
    identity_id: IdentityId,
) -> Result<Sha256Digest, IdentityPersistenceError> {
    let value = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(2),
            command
                .expected_head()
                .map_or(CanonicalValue::Null, |head| {
                    head.sequence().to_canonical_value()
                }),
        ),
        (
            CanonicalValue::Unsigned(3),
            command
                .expected_head()
                .map_or(CanonicalValue::Null, |head| {
                    head.hash().to_canonical_value()
                }),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(command.exact_event_bytes().to_vec()),
        ),
    ]);
    let bytes = encode_deterministic_cbor(&value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("identity request encoding"))?;
    Ok(Sha256Digest::hash_domain(
        IDENTITY_APPEND_REQUEST_HASH_DOMAIN,
        &bytes,
    ))
}
