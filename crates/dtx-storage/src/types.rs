use dtx_domain::{AuditId, OutboxId, RequestId, Revision, TenantId};
use dtx_wire::{
    ProtocolVersion, SafeUint, Sha256Digest, StableCode, UtcMillis, VerifiedCanonicalEvent,
};

/// Maximum bytes retained for an idempotent command result.
pub const MAX_COMMAND_RESULT_BYTES: usize = 1024 * 1024;
/// Maximum events allocated by one command transaction.
pub const MAX_EVENTS_PER_COMMAND: u16 = 64;

/// Immutable identity and digest fields used to admit an idempotent command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandDescriptor {
    pub(crate) tenant_id: TenantId,
    pub(crate) consumer: StableCode,
    pub(crate) idempotency_key_hash: Sha256Digest,
    pub(crate) request_hash: Sha256Digest,
    pub(crate) command_id: RequestId,
    pub(crate) created_at: UtcMillis,
}

impl CommandDescriptor {
    /// Creates a bounded command identity from authenticated and canonical inputs.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        consumer: StableCode,
        idempotency_key_hash: Sha256Digest,
        request_hash: Sha256Digest,
        command_id: RequestId,
        created_at: UtcMillis,
    ) -> Self {
        Self {
            tenant_id,
            consumer,
            idempotency_key_hash,
            request_hash,
            command_id,
            created_at,
        }
    }

    /// Returns the authenticated tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

/// Outbox metadata paired with one exact durable event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxWrite {
    pub(crate) outbox_id: OutboxId,
    pub(crate) destination: StableCode,
    pub(crate) available_at: UtcMillis,
}

impl OutboxWrite {
    /// Creates a pending outbox record.
    #[must_use]
    pub const fn new(
        outbox_id: OutboxId,
        destination: StableCode,
        available_at: UtcMillis,
    ) -> Self {
        Self {
            outbox_id,
            destination,
            available_at,
        }
    }
}

/// Bounded audit fact written with a command transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditWrite {
    pub(crate) audit_id: AuditId,
    pub(crate) action: StableCode,
    pub(crate) result_code: StableCode,
    pub(crate) occurred_at: UtcMillis,
}

impl AuditWrite {
    /// Creates an audit fact without arbitrary detail or secret-bearing payloads.
    #[must_use]
    pub const fn new(
        audit_id: AuditId,
        action: StableCode,
        result_code: StableCode,
        occurred_at: UtcMillis,
    ) -> Self {
        Self {
            audit_id,
            action,
            result_code,
            occurred_at,
        }
    }
}

/// Previously committed result returned for an identical idempotent command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCommandResult {
    command_id: RequestId,
    bytes: Vec<u8>,
    digest: Sha256Digest,
    completed_at: UtcMillis,
}

impl StoredCommandResult {
    pub(crate) const fn new(
        command_id: RequestId,
        bytes: Vec<u8>,
        digest: Sha256Digest,
        completed_at: UtcMillis,
    ) -> Self {
        Self {
            command_id,
            bytes,
            digest,
            completed_at,
        }
    }

    /// Returns the original command ID.
    #[must_use]
    pub const fn command_id(&self) -> RequestId {
        self.command_id
    }

    /// Returns the exact bounded result bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the domain-separated result digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the deterministic completion time.
    #[must_use]
    pub const fn completed_at(&self) -> UtcMillis {
        self.completed_at
    }
}

/// A contiguous positive tenant stream sequence allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamSequenceRange {
    start: SafeUint,
    end: SafeUint,
}

impl StreamSequenceRange {
    pub(crate) const fn new(start: SafeUint, end: SafeUint) -> Self {
        Self { start, end }
    }

    /// Returns the first allocated sequence.
    #[must_use]
    pub const fn start(self) -> SafeUint {
        self.start
    }

    /// Returns the final allocated sequence, inclusive.
    #[must_use]
    pub const fn end(self) -> SafeUint {
        self.end
    }
}

/// One exact event read from the tenant stream after metadata revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEvent {
    event: VerifiedCanonicalEvent,
}

impl StoredEvent {
    pub(crate) const fn new(event: VerifiedCanonicalEvent) -> Self {
        Self { event }
    }

    /// Returns the verified exact event.
    #[must_use]
    pub const fn event(&self) -> &VerifiedCanonicalEvent {
        &self.event
    }
}

/// Durable projection cursor and its deterministic projection hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionState {
    sequence: SafeUint,
    hash: Sha256Digest,
}

impl ProjectionState {
    /// Creates a cursor state, where sequence zero means no event was applied.
    #[must_use]
    pub const fn new(sequence: SafeUint, hash: Sha256Digest) -> Self {
        Self { sequence, hash }
    }

    /// Returns the last committed stream sequence.
    #[must_use]
    pub const fn sequence(&self) -> SafeUint {
        self.sequence
    }

    /// Returns the deterministic projection digest.
    #[must_use]
    pub const fn hash(&self) -> Sha256Digest {
        self.hash
    }
}

/// Reader settings used when replaying exact event bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventReadOptions {
    pub(crate) after: SafeUint,
    pub(crate) limit: u16,
    pub(crate) reader: ProtocolVersion,
}

impl EventReadOptions {
    /// Creates bounded event replay options.
    #[must_use]
    pub const fn new(after: SafeUint, limit: u16, reader: ProtocolVersion) -> Self {
        Self {
            after,
            limit,
            reader,
        }
    }
}

/// Verifies a concrete aggregate's locked revision before a state transition.
///
/// # Errors
///
/// Returns the actual revision when the caller's expected revision is stale.
pub const fn ensure_expected_revision(
    actual: Revision,
    expected: Revision,
) -> Result<(), Revision> {
    if actual.get() == expected.get() {
        Ok(())
    } else {
        Err(actual)
    }
}
