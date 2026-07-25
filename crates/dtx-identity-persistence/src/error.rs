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
    /// The configured principal has privileges outside the identity-writer boundary.
    RuntimeRoleOverprivileged,
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
    /// A device-session request was not authorized by an active certified device.
    DeviceAuthenticationRejected,
    /// A verified, fresh device session is bound to a device revoked by the
    /// authoritative active identity projection.
    DeviceSessionRevoked,
    /// A session attempted to revoke the same device that owns the session.
    CurrentSessionDeviceRevokeForbidden,
    /// A one-time device-session challenge was no longer within its validity window.
    DeviceSessionChallengeExpired,
    /// A one-time device-session challenge already issued a session.
    DeviceSessionChallengeConsumed,
    /// An active device requested fresh challenges faster than the durable limit.
    DeviceSessionChallengeRateLimited,
    /// A QR enrollment capability did not authenticate the requested challenge.
    DeviceEnrollmentCapabilityRejected,
    /// A QR enrollment challenge passed its deadline before approval.
    DeviceEnrollmentChallengeExpired,
    /// The candidate cancelled a QR enrollment challenge before approval.
    DeviceEnrollmentChallengeCancelled,
    /// A QR enrollment challenge already committed its exact device add.
    DeviceEnrollmentChallengeApproved,
    /// No active target device has an unconsumed unexpired opaque `KeyPackage`.
    KeyPackageUnavailable,
    /// A `KeyPackage` ID or opaque package digest conflicts with immutable state.
    KeyPackageConflict,
    /// Recovery bytes were not one exact deterministic canonical-CBOR value.
    RecoveryExactCborInvalid,
    /// A catalog generation, predecessor, or immutable body conflicts.
    RecoveryCatalogConflict,
    /// The signed catalog was outside its accepted validity window.
    RecoveryCatalogExpired,
    /// A preparation or provider response conflicts with immutable state.
    RecoveryPreparationConflict,
    /// The response capability did not authenticate candidate status access.
    RecoveryResponseCapabilityRejected,
    /// The bounded preparation or response has expired.
    RecoveryPreparationExpired,
    /// The linked enrollment was cancelled, closed, or otherwise revoked.
    RecoveryPreparationRevoked,
    /// The selected catalog generation, head, or observed identity head changed.
    RecoveryCatalogHeadChanged,
    /// The selected catalog authority changed or is no longer active.
    RecoveryAuthorityChanged,
    /// The linked candidate identity, device, or public keys changed.
    RecoveryCandidateKeyChanged,
    /// A catalog/preparation fence changed after preparation.
    RecoveryPreparationInvalidated,
    /// An authenticated provider session did not match the request provider.
    RecoveryProviderMismatch,
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
            Self::RuntimeRoleOverprivileged => {
                "identity runtime database role exceeds the identity-only boundary"
            }
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
            Self::DeviceAuthenticationRejected => "device session authentication was rejected",
            Self::DeviceSessionRevoked => "device session is revoked",
            Self::CurrentSessionDeviceRevokeForbidden => {
                "the current device session cannot revoke its own device"
            }
            Self::DeviceSessionChallengeExpired => "device session challenge expired",
            Self::DeviceSessionChallengeConsumed => "device session challenge was consumed",
            Self::DeviceSessionChallengeRateLimited => "device session challenge rate limited",
            Self::DeviceEnrollmentCapabilityRejected => "device enrollment capability was rejected",
            Self::DeviceEnrollmentChallengeExpired => "device enrollment challenge expired",
            Self::DeviceEnrollmentChallengeCancelled => "device enrollment challenge was cancelled",
            Self::DeviceEnrollmentChallengeApproved => "device enrollment challenge was approved",
            Self::KeyPackageUnavailable => "key package is unavailable",
            Self::KeyPackageConflict => "key package conflicts with immutable state",
            Self::RecoveryExactCborInvalid => "recovery catalog bytes are not exact canonical CBOR",
            Self::RecoveryCatalogConflict => "recovery catalog conflicts with immutable state",
            Self::RecoveryCatalogExpired => "recovery catalog expired",
            Self::RecoveryPreparationConflict => {
                "recovery catalog preparation conflicts with immutable state"
            }
            Self::RecoveryResponseCapabilityRejected => "recovery response capability was rejected",
            Self::RecoveryPreparationExpired => "recovery catalog preparation expired",
            Self::RecoveryPreparationRevoked => "recovery catalog preparation was revoked",
            Self::RecoveryCatalogHeadChanged => "recovery catalog head changed",
            Self::RecoveryAuthorityChanged => "recovery catalog authority changed",
            Self::RecoveryCandidateKeyChanged => "recovery candidate key changed",
            Self::RecoveryPreparationInvalidated => "recovery catalog preparation invalidated",
            Self::RecoveryProviderMismatch => "recovery catalog provider mismatch",
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
            | Self::RuntimeRoleOverprivileged
            | Self::TenantContextLeak
            | Self::InvalidCommand(_)
            | Self::IdempotencyConflict
            | Self::IncompleteCommand
            | Self::ReceiptIntegrity
            | Self::HeadConflict { .. }
            | Self::GenesisConflict
            | Self::IdentityInactive
            | Self::DeviceAuthenticationRejected
            | Self::DeviceSessionRevoked
            | Self::CurrentSessionDeviceRevokeForbidden
            | Self::DeviceSessionChallengeExpired
            | Self::DeviceSessionChallengeConsumed
            | Self::DeviceSessionChallengeRateLimited
            | Self::DeviceEnrollmentCapabilityRejected
            | Self::DeviceEnrollmentChallengeExpired
            | Self::DeviceEnrollmentChallengeCancelled
            | Self::DeviceEnrollmentChallengeApproved
            | Self::KeyPackageUnavailable
            | Self::KeyPackageConflict
            | Self::RecoveryExactCborInvalid
            | Self::RecoveryCatalogConflict
            | Self::RecoveryCatalogExpired
            | Self::RecoveryPreparationConflict
            | Self::RecoveryResponseCapabilityRejected
            | Self::RecoveryPreparationExpired
            | Self::RecoveryPreparationRevoked
            | Self::RecoveryCatalogHeadChanged
            | Self::RecoveryAuthorityChanged
            | Self::RecoveryCandidateKeyChanged
            | Self::RecoveryPreparationInvalidated
            | Self::RecoveryProviderMismatch
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_session_error_has_only_a_redacted_public_representation() {
        let error = IdentityPersistenceError::DeviceSessionRevoked;
        assert_eq!(format!("{error:?}"), "DeviceSessionRevoked");
        assert_eq!(error.to_string(), "device session is revoked");
    }
}
