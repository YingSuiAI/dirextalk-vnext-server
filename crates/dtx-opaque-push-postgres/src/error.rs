use std::{error::Error, fmt};

/// Stable category used by the future HTTP adapter; raw SQLSTATE/messages are
/// intentionally never exposed through this type's display implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCategory {
    Auth,
    Revoked,
    Conflict,
    Fence,
    Unavailable,
    Malformed,
}

pub enum PushPostgresError {
    Auth,
    Conflict,
    Fence,
    Unavailable,
    Malformed,
    Database(sqlx::Error),
    Domain(dtx_opaque_push::PushError),
    Identity(dtx_identity_persistence::IdentityPersistenceError),
}

impl fmt::Debug for PushPostgresError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(match self {
            Self::Auth => "Auth",
            Self::Conflict => "Conflict",
            Self::Fence => "Fence",
            Self::Unavailable | Self::Database(_) => "Unavailable",
            Self::Malformed | Self::Domain(_) => "Malformed",
            Self::Identity(_) => "Identity",
        })
        .finish()
    }
}

impl PushPostgresError {
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Auth => ErrorCategory::Auth,
            Self::Identity(error) => match error {
                dtx_identity_persistence::IdentityPersistenceError::Database(_) => {
                    ErrorCategory::Unavailable
                }
                dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected => {
                    ErrorCategory::Auth
                }
                dtx_identity_persistence::IdentityPersistenceError::DeviceSessionRevoked => {
                    ErrorCategory::Revoked
                }
                dtx_identity_persistence::IdentityPersistenceError::HeadConflict { .. }
                | dtx_identity_persistence::IdentityPersistenceError::IdentityInactive => {
                    ErrorCategory::Fence
                }
                _ => ErrorCategory::Malformed,
            },
            Self::Conflict => ErrorCategory::Conflict,
            Self::Fence => ErrorCategory::Fence,
            Self::Unavailable | Self::Database(_) => ErrorCategory::Unavailable,
            Self::Malformed => ErrorCategory::Malformed,
            Self::Domain(error) => match error {
                dtx_opaque_push::PushError::Encryption
                | dtx_opaque_push::PushError::Decryption
                | dtx_opaque_push::PushError::ProviderUnavailable
                | dtx_opaque_push::PushError::Persistence => ErrorCategory::Unavailable,
                dtx_opaque_push::PushError::LeaseLost | dtx_opaque_push::PushError::Expired => {
                    ErrorCategory::Fence
                }
                _ => ErrorCategory::Malformed,
            },
        }
    }
}

impl fmt::Display for PushPostgresError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Auth => "push authorization failed",
            Self::Conflict => "push mutation conflicts with durable state",
            Self::Fence => "push authorization fence changed",
            Self::Unavailable | Self::Database(_) => "push persistence unavailable",
            Self::Malformed => "push request or durable row is malformed",
            Self::Domain(_) => "push domain value rejected",
            Self::Identity(_) => "push identity authorization failed",
        })
    }
}
impl Error for PushPostgresError {}

impl From<sqlx::Error> for PushPostgresError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &error {
            match db.code().as_deref() {
                Some("42501") => return Self::Auth,
                Some("23505") => return Self::Conflict,
                Some("40001") => return Self::Fence,
                Some("22023" | "22P02" | "22003") => return Self::Malformed,
                _ => {}
            }
        }
        Self::Database(error)
    }
}

impl From<dtx_opaque_push::PushError> for PushPostgresError {
    fn from(error: dtx_opaque_push::PushError) -> Self {
        match error {
            dtx_opaque_push::PushError::Encryption
            | dtx_opaque_push::PushError::Decryption
            | dtx_opaque_push::PushError::ProviderUnavailable
            | dtx_opaque_push::PushError::Persistence => Self::Unavailable,
            dtx_opaque_push::PushError::LeaseLost | dtx_opaque_push::PushError::Expired => {
                Self::Fence
            }
            _ => Self::Malformed,
        }
    }
}

impl From<dtx_identity_persistence::IdentityPersistenceError> for PushPostgresError {
    fn from(error: dtx_identity_persistence::IdentityPersistenceError) -> Self {
        Self::Identity(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_categories_are_stable() {
        let database = PushPostgresError::Database(sqlx::Error::Protocol("secret-db".to_owned()));
        assert!(!format!("{database:?}").contains("secret-db"));
        let identity = PushPostgresError::Identity(
            dtx_identity_persistence::IdentityPersistenceError::InvalidCommand("secret-row"),
        );
        assert!(!format!("{identity:?}").contains("secret-row"));
        assert_eq!(
            PushPostgresError::from(dtx_opaque_push::PushError::Encryption).category(),
            ErrorCategory::Unavailable
        );
        assert_eq!(
            PushPostgresError::from(dtx_opaque_push::PushError::EnvelopeInvalid).category(),
            ErrorCategory::Malformed
        );
        assert_eq!(
            PushPostgresError::from(
                dtx_identity_persistence::IdentityPersistenceError::DeviceSessionRevoked
            )
            .category(),
            ErrorCategory::Revoked
        );
    }
}
