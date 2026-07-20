use std::{collections::HashSet, fmt};

use dtx_domain::{DeviceId, EnvelopeId, IdentityId, MailboxId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, encode_deterministic_cbor,
};
use zeroize::Zeroize;

use crate::MailboxPersistenceError;

/// Domain-separated hash input for a raw mailbox write capability.
pub const MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN: &[u8] = b"dirextalk.mailbox-write-capability.v1\0";
/// Domain-separated digest for a register request's exact canonical bytes.
pub(crate) const MAILBOX_REGISTER_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-register-request.v1\0";
/// Domain-separated digest for an enqueue request's exact canonical bytes.
pub(crate) const MAILBOX_ENQUEUE_REQUEST_HASH_DOMAIN: &[u8] =
    b"dirextalk.mailbox-enqueue-request.v1\0";
/// Domain-separated digest for an acknowledgement's exact canonical bytes.
pub(crate) const MAILBOX_ACK_REQUEST_HASH_DOMAIN: &[u8] = b"dirextalk.mailbox-ack-request.v1\0";
/// Domain-separated digest for durable receipt bytes.
pub(crate) const MAILBOX_RECEIPT_HASH_DOMAIN: &[u8] = b"dirextalk.mailbox-receipt.v1\0";

/// Maximum opaque payload retained in one mailbox envelope.
pub const MAX_OPAQUE_CIPHERTEXT_BYTES: usize = 262_144;
/// Maximum unacknowledged/active envelopes per mailbox.
pub const MAX_ACTIVE_ENVELOPES: usize = 1_000;
/// Maximum unacknowledged/active opaque bytes per mailbox.
pub const MAX_ACTIVE_ENVELOPE_BYTES: usize = 67_108_864;
/// Maximum envelope lifetime from the server's transaction clock.
pub const MAX_ENVELOPE_TTL_MILLIS: i64 = 604_800_000;
/// Minimum exact mailbox-operation replay retention after durable expiry.
pub const MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS: i64 = 15 * 60 * 1_000;
/// Backward-compatible name for the enqueue portion of the replay horizon.
pub const MAILBOX_ENQUEUE_REPLAY_RETENTION_MILLIS: i64 = MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS;
/// Maximum entries in a pull page or acknowledgement command.
pub const MAX_PAGE_ENTRIES: usize = 100;

const MAX_REGISTER_COMMAND_BYTES: usize = 16_384;
const MAX_ENVELOPE_COMMAND_BYTES: usize = 262_400;
const MAX_ACK_COMMAND_BYTES: usize = 8_192;

/// A raw 256-bit mailbox write capability held only at the sender boundary.
///
/// Its value is redacted from `Debug`, zeroized on drop, and is converted to a
/// one-way domain-separated hash before any durable operation.  Do not place
/// it in a receipt, event, DTO, log, or error.
pub struct MailboxWriteCapability([u8; 32]);

impl fmt::Debug for MailboxWriteCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MailboxWriteCapability([REDACTED])")
    }
}

impl Drop for MailboxWriteCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl MailboxWriteCapability {
    /// Constructs a sender-held capability, rejecting an obviously invalid
    /// all-zero value before it reaches a relay operation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-command error for an all-zero value.
    pub fn new(value: [u8; 32]) -> Result<Self, MailboxPersistenceError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(MailboxPersistenceError::InvalidCommand(
                "mailbox write capability cannot be all zero",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the durable blinded capability hash.
    #[must_use]
    pub fn hash(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &self.0)
    }
}

/// A typed exact mailbox registration request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxRegistrationCommand {
    idempotency_key_hash: Sha256Digest,
    mailbox_id: MailboxId,
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    write_capability_hash: Sha256Digest,
    expires_at: UtcMillis,
    exact_bytes: Vec<u8>,
}

impl MailboxRegistrationCommand {
    /// Builds a registration command and proves its body is exact canonical
    /// V14 bytes before persistence can bind an idempotency key to it.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or noncanonical body.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        mailbox_id: MailboxId,
        owner_identity_id: IdentityId,
        owner_device_id: DeviceId,
        write_capability_hash: Sha256Digest,
        expires_at: UtcMillis,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, MailboxPersistenceError> {
        validate_exact_command_bytes(&exact_bytes, MAX_REGISTER_COMMAND_BYTES)?;
        let command = Self {
            idempotency_key_hash,
            mailbox_id,
            owner_identity_id,
            owner_device_id,
            write_capability_hash,
            expires_at,
            exact_bytes,
        };
        command.require_exact_bytes()?;
        Ok(command)
    }

    /// Returns the opaque mailbox identifier.
    #[must_use]
    pub const fn mailbox_id(&self) -> MailboxId {
        self.mailbox_id
    }

    /// Returns the authenticated owner identity requested by the body.
    #[must_use]
    pub const fn owner_identity_id(&self) -> IdentityId {
        self.owner_identity_id
    }

    /// Returns the authenticated owner device requested by the body.
    #[must_use]
    pub const fn owner_device_id(&self) -> DeviceId {
        self.owner_device_id
    }

    /// Returns only the blinded sender write capability.
    #[must_use]
    pub const fn write_capability_hash(&self) -> Sha256Digest {
        self.write_capability_hash
    }

    /// Returns the requested registration expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the stable HTTP idempotency digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    pub(crate) fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(MAILBOX_REGISTER_REQUEST_HASH_DOMAIN, &self.exact_bytes)
    }

    fn require_exact_bytes(&self) -> Result<(), MailboxPersistenceError> {
        let expected = encode_deterministic_cbor(&self.to_canonical_value())
            .map_err(|_| MailboxPersistenceError::InvalidCommand("mailbox register encoding"))?;
        if expected == self.exact_bytes {
            Ok(())
        } else {
            Err(MailboxPersistenceError::InvalidCommand(
                "mailbox register canonical bytes",
            ))
        }
    }
}

impl CanonicalEncode for MailboxRegistrationCommand {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.mailbox_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.owner_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.owner_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                self.write_capability_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }
}

/// A typed exact opaque envelope enqueue request.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxEnvelopeCommand {
    idempotency_key_hash: Sha256Digest,
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    opaque_ciphertext: Vec<u8>,
    expires_at: UtcMillis,
    exact_bytes: Vec<u8>,
}

impl fmt::Debug for MailboxEnvelopeCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxEnvelopeCommand")
            .field("idempotency_key_hash", &self.idempotency_key_hash)
            .field("mailbox_id", &self.mailbox_id)
            .field("envelope_id", &self.envelope_id)
            .field("opaque_ciphertext_len", &self.opaque_ciphertext.len())
            .field("expires_at", &self.expires_at)
            .field("exact_bytes_len", &self.exact_bytes.len())
            .finish()
    }
}

impl MailboxEnvelopeCommand {
    /// Builds one exact opaque envelope request.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, empty, or noncanonical
    /// envelope request bytes.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        mailbox_id: MailboxId,
        envelope_id: EnvelopeId,
        opaque_ciphertext: Vec<u8>,
        expires_at: UtcMillis,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, MailboxPersistenceError> {
        validate_exact_command_bytes(&exact_bytes, MAX_ENVELOPE_COMMAND_BYTES)?;
        if opaque_ciphertext.is_empty() || opaque_ciphertext.len() > MAX_OPAQUE_CIPHERTEXT_BYTES {
            return Err(MailboxPersistenceError::InvalidCommand(
                "mailbox opaque ciphertext byte length",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            mailbox_id,
            envelope_id,
            opaque_ciphertext,
            expires_at,
            exact_bytes,
        };
        command.require_exact_bytes()?;
        Ok(command)
    }

    /// Returns the destination mailbox.
    #[must_use]
    pub const fn mailbox_id(&self) -> MailboxId {
        self.mailbox_id
    }

    /// Returns the opaque envelope identifier.
    #[must_use]
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.envelope_id
    }

    /// Returns opaque ciphertext for immediate durable insertion only.
    #[must_use]
    pub fn opaque_ciphertext(&self) -> &[u8] {
        &self.opaque_ciphertext
    }

    /// Returns the requested envelope expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }

    /// Returns the stable HTTP idempotency digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    pub(crate) fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(MAILBOX_ENQUEUE_REQUEST_HASH_DOMAIN, &self.exact_bytes)
    }

    pub(crate) fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    fn require_exact_bytes(&self) -> Result<(), MailboxPersistenceError> {
        let expected = encode_deterministic_cbor(&self.to_canonical_value())
            .map_err(|_| MailboxPersistenceError::InvalidCommand("mailbox enqueue encoding"))?;
        if expected == self.exact_bytes {
            Ok(())
        } else {
            Err(MailboxPersistenceError::InvalidCommand(
                "mailbox enqueue canonical bytes",
            ))
        }
    }
}

impl CanonicalEncode for MailboxEnvelopeCommand {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.envelope_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(self.opaque_ciphertext.clone()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }
}

/// A bounded owner pull request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxPullRequest {
    after_sequence: SafeUint,
    limit: u16,
}

impl MailboxPullRequest {
    /// Validates a bounded cursor and page limit.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested limit is outside `1..=100`.
    pub fn new(after_sequence: SafeUint, limit: u16) -> Result<Self, MailboxPersistenceError> {
        if limit == 0 || usize::from(limit) > MAX_PAGE_ENTRIES {
            return Err(MailboxPersistenceError::InvalidCommand(
                "mailbox pull limit",
            ));
        }
        Ok(Self {
            after_sequence,
            limit,
        })
    }

    /// Returns the exclusive delivery cursor.
    #[must_use]
    pub const fn after_sequence(&self) -> SafeUint {
        self.after_sequence
    }

    /// Returns the bounded page size.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

/// A typed exact owner acknowledgement request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxAcknowledgementCommand {
    idempotency_key_hash: Sha256Digest,
    mailbox_id: MailboxId,
    envelope_ids: Vec<EnvelopeId>,
    exact_bytes: Vec<u8>,
}

impl MailboxAcknowledgementCommand {
    /// Builds a nonempty, deduplicated acknowledgement command.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is malformed, oversize, noncanonical, or
    /// contains no/duplicate/more-than-page envelope IDs.
    pub fn new(
        idempotency_key_hash: Sha256Digest,
        mailbox_id: MailboxId,
        envelope_ids: Vec<EnvelopeId>,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, MailboxPersistenceError> {
        validate_exact_command_bytes(&exact_bytes, MAX_ACK_COMMAND_BYTES)?;
        if envelope_ids.is_empty() || envelope_ids.len() > MAX_PAGE_ENTRIES {
            return Err(MailboxPersistenceError::InvalidCommand(
                "mailbox acknowledgement count",
            ));
        }
        if envelope_ids.iter().copied().collect::<HashSet<_>>().len() != envelope_ids.len() {
            return Err(MailboxPersistenceError::InvalidCommand(
                "mailbox acknowledgement duplicate envelope",
            ));
        }
        let command = Self {
            idempotency_key_hash,
            mailbox_id,
            envelope_ids,
            exact_bytes,
        };
        command.require_exact_bytes()?;
        Ok(command)
    }

    /// Returns the owner mailbox.
    #[must_use]
    pub const fn mailbox_id(&self) -> MailboxId {
        self.mailbox_id
    }

    /// Returns the bounded set of envelope identifiers to mark terminal.
    #[must_use]
    pub fn envelope_ids(&self) -> &[EnvelopeId] {
        &self.envelope_ids
    }

    /// Returns the stable HTTP idempotency digest.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    pub(crate) fn request_digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(MAILBOX_ACK_REQUEST_HASH_DOMAIN, &self.exact_bytes)
    }

    fn require_exact_bytes(&self) -> Result<(), MailboxPersistenceError> {
        let expected = encode_deterministic_cbor(&self.to_canonical_value()).map_err(|_| {
            MailboxPersistenceError::InvalidCommand("mailbox acknowledgement encoding")
        })?;
        if expected == self.exact_bytes {
            Ok(())
        } else {
            Err(MailboxPersistenceError::InvalidCommand(
                "mailbox acknowledgement canonical bytes",
            ))
        }
    }
}

impl CanonicalEncode for MailboxAcknowledgementCommand {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Array(
                    self.envelope_ids
                        .iter()
                        .map(|id| CanonicalValue::Text(id.to_string()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// Exact deterministic receipt bytes returned by a durable mailbox operation.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxOperationOutcome {
    receipt_bytes: Vec<u8>,
    replayed: bool,
}

impl fmt::Debug for MailboxOperationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxOperationOutcome")
            .field("receipt_bytes_len", &self.receipt_bytes.len())
            .field("replayed", &self.replayed)
            .finish()
    }
}

impl MailboxOperationOutcome {
    pub(crate) fn new(receipt_bytes: Vec<u8>, replayed: bool) -> Self {
        Self {
            receipt_bytes,
            replayed,
        }
    }

    /// Returns the immutable canonical receipt body.
    #[must_use]
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    /// Returns whether the exact bytes were recovered from durable replay
    /// state rather than newly committed in this call.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

pub(crate) fn receipt_hash(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::hash_domain(MAILBOX_RECEIPT_HASH_DOMAIN, bytes)
}

fn validate_exact_command_bytes(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<(), MailboxPersistenceError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        Err(MailboxPersistenceError::InvalidCommand(
            "mailbox exact command byte length",
        ))
    } else {
        Ok(())
    }
}
