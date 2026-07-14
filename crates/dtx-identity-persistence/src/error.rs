use std::{error::Error, fmt};

use dtx_identity_log::IdentityLogError;

use crate::IdentityLogHead;

/// Fail-closed errors at the durable self-certifying identity-log boundary.
#[derive(Debug)]
pub enum IdentityPersistenceError {
    /// `PostgreSQL` rejected or could not execute a storage operation.
    Database(sqlx::Error),
    /// The configured runtime principal is privileged enough to bypass ownership safeguards.
    UnsafeRuntimeRole,
    /// The configured principal is not a member of the identity writer group.
    RuntimeRoleUnauthorized,
    /// A pooled connection retained a tenant-scoped transaction setting.
    TenantContextLeak,
    /// The submitted command cannot be represented by the bounded durable contract.
    InvalidCommand(&'static str),
    /// The exact signed identity event failed canonical or reducer validation.
    IdentityLog(IdentityLogError),
    /// One idempotency key was reused for a different canonical request.
    IdempotencyConflict,
    /// A durable receipt was unexpectedly incomplete.
    IncompleteCommand,
    /// A stored receipt did not match its immutable exact bytes or digest.
    ReceiptIntegrity,
    /// The caller's expected head was stale, absent, or belongs to another log.
    HeadConflict {
        /// The current committed public head, if it can be read safely.
        current: Option<IdentityLogHead>,
    },
    /// A valid but different genesis attempted to reuse an existing identity ID.
    GenesisConflict,
    /// The durable head is tombstoned, forked, or otherwise not appendable.
    IdentityInactive,
    /// Stored rows did not rehydrate to one exact valid identity-log projection.
    CorruptData(&'static str),
}

impl fmt::Display for IdentityPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "identity persistence database operation failed",
            Self::UnsafeRuntimeRole => {
                "identity runtime database role violates the ownership boundary"
            }
            Self::RuntimeRoleUnauthorized => "identity runtime database role is not authorized",
            Self::TenantContextLeak => "identity transaction retained tenant context",
            Self::InvalidCommand(_) => "identity append command is invalid",
            Self::IdentityLog(_) => "identity log event was rejected",
            Self::IdempotencyConflict => {
                "identity idempotency key was reused with a different request"
            }
            Self::IncompleteCommand => "identity command receipt is incomplete",
            Self::ReceiptIntegrity => "identity command receipt integrity check failed",
            Self::HeadConflict { .. } => {
                "identity log head conflicts with the expected predecessor"
            }
            Self::GenesisConflict => "identity genesis conflicts with an existing identity log",
            Self::IdentityInactive => "identity log is not active",
            Self::CorruptData(_) => "identity persistence contained invalid durable data",
        })
    }
}

impl Error for IdentityPersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            Self::IdentityLog(source) => Some(source),
            Self::UnsafeRuntimeRole
            | Self::RuntimeRoleUnauthorized
            | Self::TenantContextLeak
            | Self::InvalidCommand(_)
            | Self::IdempotencyConflict
            | Self::IncompleteCommand
            | Self::ReceiptIntegrity
            | Self::HeadConflict { .. }
            | Self::GenesisConflict
            | Self::IdentityInactive
            | Self::CorruptData(_) => None,
        }
    }
}

impl From<sqlx::Error> for IdentityPersistenceError {
    fn from(source: sqlx::Error) -> Self {
        Self::Database(source)
    }
}

impl From<IdentityLogError> for IdentityPersistenceError {
    fn from(source: IdentityLogError) -> Self {
        Self::IdentityLog(source)
    }
}
