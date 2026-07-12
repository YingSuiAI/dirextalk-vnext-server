use std::{error::Error, fmt};

use dtx_domain::{Revision, RevisionError};
use dtx_wire::{CanonicalCborError, EventIntegrityError, KnownApiErrorCode};

/// `PostgreSQL` persistence boundary failure.
#[derive(Debug)]
pub enum StorageError {
    /// `SQLx` query, transaction, or pool operation failed.
    Database(sqlx::Error),
    /// A migration could not be applied or reverted safely.
    Migration(sqlx::migrate::MigrateError),
    /// Runtime credentials are privileged enough to bypass tenant isolation.
    UnsafeRuntimeRole,
    /// A pooled connection retained transaction-local tenant state.
    TenantContextLeak,
    /// The same idempotency key was reused with a different request body.
    IdempotencyConflict,
    /// A committed inbox row was not completed, violating the transaction contract.
    IncompleteCommand,
    /// A retained command result no longer matches its authenticated digest.
    CommandResultDigestMismatch,
    /// The concrete aggregate revision did not match the caller's expectation.
    RevisionConflict {
        /// Actual locked revision.
        current: Revision,
    },
    /// A revision or tenant stream sequence cannot advance safely.
    SequenceExhausted,
    /// Event bytes did not pass the wire verification boundary.
    EventIntegrity(EventIntegrityError),
    /// Stored event columns did not match their authenticated envelope.
    EventMetadataMismatch,
    /// An event belongs to another tenant.
    EventTenantMismatch,
    /// An event did not consume a sequence allocated by this command.
    EventSequenceNotAllocated,
    /// One command attempted an invalid or excessive allocation.
    InvalidEventCount,
    /// A required event/audit/result step was missing before completion.
    IncompleteTransaction,
    /// A command result exceeded its one MiB public boundary.
    ResultTooLarge,
    /// A replay page limit was zero or exceeded the v1 page bound.
    InvalidPageLimit,
    /// A projection reducer attempted to skip or repeat a tenant event sequence.
    ProjectionSequenceMismatch,
    /// Another reducer advanced the same projection cursor first.
    ProjectionCursorConflict,
    /// An unknown required event forbids advancing this projection cursor.
    ProjectionBlockedByUnknownEvent,
    /// The projection event is not the exact event retained in this tenant stream.
    ProjectionEventNotPersisted,
    /// A persisted primitive was malformed.
    InvalidPrimitive,
    /// Exact CBOR bytes could not be validated.
    CanonicalCbor(CanonicalCborError),
}

impl StorageError {
    /// Maps a storage conflict to its frozen public error code when applicable.
    #[must_use]
    pub const fn public_code(&self) -> Option<KnownApiErrorCode> {
        match self {
            Self::IdempotencyConflict => Some(KnownApiErrorCode::IdempotencyConflict),
            Self::RevisionConflict { .. } => Some(KnownApiErrorCode::RevisionConflict),
            _ => None,
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "database operation failed",
            Self::Migration(_) => "database migration failed",
            Self::UnsafeRuntimeRole => "runtime database role violates the tenant boundary",
            Self::TenantContextLeak => "pooled database connection retained tenant context",
            Self::IdempotencyConflict => "idempotency key was reused with a different request",
            Self::IncompleteCommand => "inbox command was not completed atomically",
            Self::CommandResultDigestMismatch => "stored command result digest does not match",
            Self::RevisionConflict { .. } => "aggregate revision conflict",
            Self::SequenceExhausted => "safe sequence range is exhausted",
            Self::EventIntegrity(_) => "event failed the verified persistence boundary",
            Self::EventMetadataMismatch => "stored event metadata does not match its envelope",
            Self::EventTenantMismatch => "event tenant does not match the transaction tenant",
            Self::EventSequenceNotAllocated => "event stream sequence was not allocated",
            Self::InvalidEventCount => "event allocation count is outside the command limit",
            Self::IncompleteTransaction => "command transaction is incomplete",
            Self::ResultTooLarge => "command result exceeds the one MiB limit",
            Self::InvalidPageLimit => "event page limit must be between 1 and 1000",
            Self::ProjectionSequenceMismatch => "projection event sequence is not contiguous",
            Self::ProjectionCursorConflict => "projection cursor was advanced concurrently",
            Self::ProjectionBlockedByUnknownEvent => {
                "unknown required event prevents projection cursor advancement"
            }
            Self::ProjectionEventNotPersisted => {
                "projection event is not retained in the tenant stream"
            }
            Self::InvalidPrimitive => "persisted primitive is invalid",
            Self::CanonicalCbor(_) => "stored bytes are not canonical CBOR",
        })
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Migration(error) => Some(error),
            Self::EventIntegrity(error) => Some(error),
            Self::CanonicalCbor(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for StorageError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl From<sqlx::migrate::MigrateError> for StorageError {
    fn from(value: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(value)
    }
}

impl From<EventIntegrityError> for StorageError {
    fn from(value: EventIntegrityError) -> Self {
        Self::EventIntegrity(value)
    }
}

impl From<CanonicalCborError> for StorageError {
    fn from(value: CanonicalCborError) -> Self {
        Self::CanonicalCbor(value)
    }
}

impl From<RevisionError> for StorageError {
    fn from(_: RevisionError) -> Self {
        Self::SequenceExhausted
    }
}
