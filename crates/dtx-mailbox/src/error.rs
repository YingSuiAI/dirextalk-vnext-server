use std::{error::Error, fmt};

/// Fail-closed outcomes at the opaque mailbox persistence boundary.
#[derive(Debug)]
pub enum MailboxPersistenceError {
    /// `PostgreSQL` rejected or could not execute a mailbox operation.
    Database(sqlx::Error),
    /// The configured role lacks the narrow mailbox and identity-reader grants.
    RuntimeRoleUnauthorized,
    /// The configured role can escape the mailbox or identity-read boundary.
    RuntimeRoleOverprivileged,
    /// A pooled connection carried a tenant context into this global service.
    TenantContextLeak,
    /// A canonical command violates bounded mailbox invariants.
    InvalidCommand(&'static str),
    /// A device session was missing, expired, invalid, or revoked.
    DeviceAuthenticationRejected,
    /// The authenticated provider session is valid but not authorized for the
    /// exact Grant descriptor.
    ProviderAuthorizationRejected,
    /// Identity authorization could not be safely read in this transaction.
    IdentityAuthorizationUnavailable,
    /// No active provider with the required client-held E2EE material exists.
    KeyMaterialUnavailable,
    /// The mailbox does not exist, expired, or its write capability is invalid.
    MailboxUnavailable,
    /// An immutable mailbox or envelope identity conflicts with existing state.
    MailboxConflict,
    /// A first-admission Grant failed currentness or was invalidated.
    HistoryRecoveryInvalidated,
    /// A first-admission Grant or its challenge window has expired.
    HistoryRecoveryExpired,
    /// One idempotency key was reused for a different canonical request.
    IdempotencyConflict,
    /// Active opaque delivery quota would be exceeded.
    CapacityExceeded,
    /// A persisted receipt no longer matches its immutable digest.
    ReceiptIntegrity,
    /// A persisted mailbox row violates its expected typed invariant.
    CorruptData(&'static str),
}

impl fmt::Display for MailboxPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "mailbox persistence database operation failed",
            Self::RuntimeRoleUnauthorized => "mailbox runtime database role is not authorized",
            Self::RuntimeRoleOverprivileged => {
                "mailbox runtime database role exceeds the mailbox-only boundary"
            }
            Self::TenantContextLeak => "mailbox transaction retained tenant context",
            Self::InvalidCommand(_) => "mailbox command is invalid",
            Self::DeviceAuthenticationRejected => "device session authentication was rejected",
            Self::ProviderAuthorizationRejected => {
                "history grant provider authorization was rejected"
            }
            Self::IdentityAuthorizationUnavailable => "identity authorization is unavailable",
            Self::KeyMaterialUnavailable => "history recovery key material is unavailable",
            Self::MailboxUnavailable => "mailbox is unavailable",
            Self::MailboxConflict => "mailbox conflicts with immutable state",
            Self::HistoryRecoveryInvalidated => "history recovery grant was invalidated",
            Self::HistoryRecoveryExpired => "history recovery grant expired",
            Self::IdempotencyConflict => "mailbox idempotency key conflicts",
            Self::CapacityExceeded => "mailbox capacity is exceeded",
            Self::ReceiptIntegrity => "mailbox receipt integrity check failed",
            Self::CorruptData(_) => "mailbox persistence contained corrupt data",
        })
    }
}

impl Error for MailboxPersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            Self::RuntimeRoleUnauthorized
            | Self::RuntimeRoleOverprivileged
            | Self::TenantContextLeak
            | Self::InvalidCommand(_)
            | Self::DeviceAuthenticationRejected
            | Self::ProviderAuthorizationRejected
            | Self::IdentityAuthorizationUnavailable
            | Self::KeyMaterialUnavailable
            | Self::MailboxUnavailable
            | Self::MailboxConflict
            | Self::HistoryRecoveryInvalidated
            | Self::HistoryRecoveryExpired
            | Self::IdempotencyConflict
            | Self::CapacityExceeded
            | Self::ReceiptIntegrity
            | Self::CorruptData(_) => None,
        }
    }
}

impl From<sqlx::Error> for MailboxPersistenceError {
    fn from(source: sqlx::Error) -> Self {
        Self::Database(source)
    }
}
