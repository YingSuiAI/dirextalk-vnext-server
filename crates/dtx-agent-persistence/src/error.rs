use std::{error::Error, fmt};

/// Fail-closed error returned by Agent control persistence adapters.
#[derive(Debug)]
pub enum AgentPersistenceError {
    /// `PostgreSQL` rejected or could not execute the operation.
    Database(sqlx::Error),
    /// Stored data cannot represent a valid domain value.
    CorruptData(&'static str),
    /// An immutable identity was reused with different content.
    ImmutableConflict(&'static str),
    /// A current-state row did not match the caller's expected predecessor.
    RevisionConflict {
        /// Current stored safe-integer revision, or absent when not found.
        current: Option<u64>,
    },
    /// A Connector generation/spec/lease fence did not match durable state.
    FenceConflict,
    /// A currently fenced Connector cannot accept another Run.
    ClaimRejected(&'static str),
    /// Current tenant authorization no longer permits a new Run authority.
    AuthorizationRejected(&'static str),
    /// A durable command cursor was stale, ahead, or non-contiguous.
    CursorConflict {
        /// Server-committed acknowledgement cursor.
        acknowledged: u64,
        /// Last durable command sequence.
        last: u64,
    },
    /// Exact command bytes could not be decoded into their frozen typed projection.
    CommandDecodeRejected,
    /// A caller requested an intentionally bounded aggregate materialization beyond its limit.
    MaterializationLimitExceeded(&'static str),
    /// A complete row set failed domain rehydration validation.
    SnapshotRejected(&'static str),
}

impl fmt::Display for AgentPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "Agent persistence database operation failed",
            Self::CorruptData(_) => "Agent persistence contained corrupt domain data",
            Self::ImmutableConflict(_) => "Agent persistence immutable identity conflicted",
            Self::RevisionConflict { .. } => "Agent persistence revision conflicted",
            Self::FenceConflict => "Agent persistence fence conflicted",
            Self::ClaimRejected(_) => "Agent Run claim was rejected",
            Self::AuthorizationRejected(_) => "Agent Run authorization was rejected",
            Self::CursorConflict { .. } => "Agent persistence cursor conflicted",
            Self::CommandDecodeRejected => "Agent persistence command bytes were rejected",
            Self::MaterializationLimitExceeded(_) => {
                "Agent persistence materialization limit was exceeded"
            }
            Self::SnapshotRejected(_) => "Agent persistence snapshot was rejected",
        })
    }
}

impl Error for AgentPersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            Self::CorruptData(_)
            | Self::ImmutableConflict(_)
            | Self::RevisionConflict { .. }
            | Self::FenceConflict
            | Self::ClaimRejected(_)
            | Self::AuthorizationRejected(_)
            | Self::CursorConflict { .. }
            | Self::CommandDecodeRejected
            | Self::MaterializationLimitExceeded(_)
            | Self::SnapshotRejected(_) => None,
        }
    }
}

impl From<sqlx::Error> for AgentPersistenceError {
    fn from(source: sqlx::Error) -> Self {
        Self::Database(source)
    }
}
