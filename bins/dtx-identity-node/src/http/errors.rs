use super::{
    BootstrapFailure, DeviceEnrollmentFailure, DeviceRevokeFailure, DeviceSessionFailure,
    FederatedIdentityError, IdentityLogPageFailure, IdentityPersistenceError, InitialDeviceFailure,
    KeyPackageFailure, RecoveryCatalogFailure,
};

pub(crate) fn map_identity_log_page_persistence_error(
    error: &IdentityPersistenceError,
) -> IdentityLogPageFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) => IdentityLogPageFailure::InvalidRequest,
        IdentityPersistenceError::IdentityInactive => IdentityLogPageFailure::Inactive,
        _ => IdentityLogPageFailure::TemporarilyUnavailable,
    }
}

pub(crate) fn map_persistence_error(error: &IdentityPersistenceError) -> BootstrapFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            BootstrapFailure::InvalidBootstrap
        }
        IdentityPersistenceError::IdempotencyConflict => BootstrapFailure::IdempotencyConflict,
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::IdentityInactive => BootstrapFailure::IdentityConflict,
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => BootstrapFailure::TemporarilyUnavailable,
    }
}

pub(crate) fn map_initial_device_persistence_error(
    error: &IdentityPersistenceError,
) -> InitialDeviceFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            InitialDeviceFailure::InvalidInitialDevice
        }
        IdentityPersistenceError::IdempotencyConflict => InitialDeviceFailure::IdempotencyConflict,
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::IdentityInactive => InitialDeviceFailure::IdentityConflict,
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => InitialDeviceFailure::TemporarilyUnavailable,
    }
}

pub(crate) fn map_device_session_persistence_error(
    error: &IdentityPersistenceError,
) -> DeviceSessionFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            DeviceSessionFailure::InvalidRequest
        }
        IdentityPersistenceError::IdempotencyConflict => DeviceSessionFailure::IdempotencyConflict,
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => {
            DeviceSessionFailure::AuthenticationRejected
        }
        IdentityPersistenceError::DeviceSessionChallengeExpired => {
            DeviceSessionFailure::ChallengeExpired
        }
        IdentityPersistenceError::DeviceSessionChallengeConsumed => {
            DeviceSessionFailure::ChallengeConsumed
        }
        IdentityPersistenceError::DeviceSessionChallengeRateLimited => {
            DeviceSessionFailure::ChallengeRateLimited
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => DeviceSessionFailure::TemporarilyUnavailable,
    }
}

pub(crate) fn map_recovery_catalog_publish_error(
    error: &IdentityPersistenceError,
) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            RecoveryCatalogFailure::InvalidRequest
        }
        IdentityPersistenceError::RecoveryExactCborInvalid => {
            RecoveryCatalogFailure::ExactCborInvalid
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => {
            RecoveryCatalogFailure::AuthenticationRejected
        }
        IdentityPersistenceError::RecoveryCatalogExpired => RecoveryCatalogFailure::CatalogExpired,
        IdentityPersistenceError::RecoveryCatalogConflict => {
            RecoveryCatalogFailure::CatalogConflict
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict => RecoveryCatalogFailure::IdentityHeadChanged,
        IdentityPersistenceError::IdempotencyConflict => {
            RecoveryCatalogFailure::IdempotencyConflict
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
    }
}

pub(crate) fn map_recovery_catalog_prepare_error(
    error: &IdentityPersistenceError,
) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            RecoveryCatalogFailure::InvalidRequest
        }
        IdentityPersistenceError::RecoveryExactCborInvalid => {
            RecoveryCatalogFailure::ExactCborInvalid
        }
        IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected => {
            RecoveryCatalogFailure::CapabilityRejected
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked => {
            RecoveryCatalogFailure::AuthenticationRejected
        }
        IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired => {
            RecoveryCatalogFailure::PreparationExpired
        }
        IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved => {
            RecoveryCatalogFailure::PreparationRevoked
        }
        IdentityPersistenceError::RecoveryCatalogExpired => RecoveryCatalogFailure::CatalogExpired,
        IdentityPersistenceError::RecoveryPreparationInvalidated => {
            RecoveryCatalogFailure::PreparationInvalidated
        }
        IdentityPersistenceError::RecoveryCatalogConflict => {
            RecoveryCatalogFailure::CatalogConflict
        }
        IdentityPersistenceError::RecoveryPreparationConflict => {
            RecoveryCatalogFailure::PreparationConflict
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::IdentityInactive => RecoveryCatalogFailure::IdentityHeadChanged,
        IdentityPersistenceError::RecoveryCatalogHeadChanged => {
            RecoveryCatalogFailure::CatalogHeadChanged
        }
        IdentityPersistenceError::RecoveryAuthorityChanged => {
            RecoveryCatalogFailure::AuthorityChanged
        }
        IdentityPersistenceError::RecoveryCandidateKeyChanged => {
            RecoveryCatalogFailure::CandidateKeyChanged
        }
        IdentityPersistenceError::IdempotencyConflict => {
            RecoveryCatalogFailure::IdempotencyConflict
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
    }
}

pub(crate) fn map_recovery_catalog_status_error(
    error: &IdentityPersistenceError,
) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected => {
            RecoveryCatalogFailure::CapabilityRejected
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::InvalidCommand(_)
        | IdentityPersistenceError::IdentityLog(_)
        | IdentityPersistenceError::IdempotencyConflict
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::IdentityInactive
        | IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
    }
}

pub(crate) fn map_recovery_catalog_provider_error(
    error: &IdentityPersistenceError,
) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            RecoveryCatalogFailure::InvalidRequest
        }
        IdentityPersistenceError::RecoveryExactCborInvalid => {
            RecoveryCatalogFailure::ExactCborInvalid
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => {
            RecoveryCatalogFailure::AuthenticationRejected
        }
        IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired => {
            RecoveryCatalogFailure::PreparationExpired
        }
        IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled => {
            RecoveryCatalogFailure::PreparationRevoked
        }
        IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged => {
            RecoveryCatalogFailure::PreparationInvalidated
        }
        IdentityPersistenceError::RecoveryProviderMismatch => {
            RecoveryCatalogFailure::ProviderMismatch
        }
        IdentityPersistenceError::RecoveryCatalogConflict => {
            RecoveryCatalogFailure::CatalogConflict
        }
        IdentityPersistenceError::RecoveryPreparationConflict => {
            RecoveryCatalogFailure::PreparationConflict
        }
        IdentityPersistenceError::IdempotencyConflict => {
            RecoveryCatalogFailure::IdempotencyConflict
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
    }
}

pub(crate) fn map_device_enrollment_persistence_error(
    error: &IdentityPersistenceError,
) -> DeviceEnrollmentFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            DeviceEnrollmentFailure::InvalidRequest
        }
        IdentityPersistenceError::IdempotencyConflict => {
            DeviceEnrollmentFailure::IdempotencyConflict
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked => {
            DeviceEnrollmentFailure::AuthenticationRejected
        }
        IdentityPersistenceError::DeviceEnrollmentCapabilityRejected => {
            DeviceEnrollmentFailure::CapabilityRejected
        }
        IdentityPersistenceError::DeviceEnrollmentChallengeExpired => {
            DeviceEnrollmentFailure::ChallengeExpired
        }
        IdentityPersistenceError::DeviceEnrollmentChallengeCancelled => {
            DeviceEnrollmentFailure::ChallengeCancelled
        }
        IdentityPersistenceError::DeviceEnrollmentChallengeApproved => {
            DeviceEnrollmentFailure::ChallengeApproved
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::IdentityInactive => DeviceEnrollmentFailure::IdentityConflict,
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => {
            DeviceEnrollmentFailure::TemporarilyUnavailable
        }
    }
}

pub(crate) fn map_device_revoke_persistence_error(
    error: &IdentityPersistenceError,
) -> DeviceRevokeFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            DeviceRevokeFailure::InvalidRequest
        }
        IdentityPersistenceError::IdempotencyConflict => DeviceRevokeFailure::IdempotencyConflict,
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => DeviceRevokeFailure::AuthenticationRejected,
        IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden => {
            DeviceRevokeFailure::CurrentSessionForbidden
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict => DeviceRevokeFailure::IdentityConflict,
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => DeviceRevokeFailure::TemporarilyUnavailable,
    }
}

pub(crate) fn map_key_package_persistence_error(
    error: &IdentityPersistenceError,
) -> KeyPackageFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            KeyPackageFailure::InvalidRequest
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => KeyPackageFailure::AuthenticationRejected,
        IdentityPersistenceError::KeyPackageUnavailable => KeyPackageFailure::Unavailable,
        IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict => KeyPackageFailure::Conflict,
        IdentityPersistenceError::IdempotencyConflict => KeyPackageFailure::IdempotencyConflict,
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryProviderMismatch
        | IdentityPersistenceError::CorruptData(_) => KeyPackageFailure::TemporarilyUnavailable,
    }
}

pub(crate) fn map_federated_identity_error(error: FederatedIdentityError) -> KeyPackageFailure {
    match error {
        FederatedIdentityError::TemporarilyUnavailable => KeyPackageFailure::TemporarilyUnavailable,
        FederatedIdentityError::InvalidOrigin
        | FederatedIdentityError::InvalidTrustRoot
        | FederatedIdentityError::InvalidIdentityLog
        | FederatedIdentityError::InvalidRecoveryAuthorization
        | FederatedIdentityError::RecoveryAuthorizationUnavailable
        | FederatedIdentityError::DeviceUnavailable => KeyPackageFailure::AuthenticationRejected,
    }
}
