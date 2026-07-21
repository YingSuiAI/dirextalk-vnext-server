#![forbid(unsafe_code)]

//! Durable `PostgreSQL` storage for the self-certifying identity log.

mod device_enrollment;
mod device_session;
mod error;
mod key_package;
mod recovery_scope_catalog;
mod repository;
mod store;
mod types;

pub use device_enrollment::{
    CreateDeviceEnrollmentChallengeCommand, CreateHistoryRecoveryRequestCommand,
    DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_HASH_DOMAIN,
    DEVICE_ENROLLMENT_APPROVAL_REQUEST_HASH_DOMAIN, DEVICE_ENROLLMENT_APPROVAL_RETENTION_MILLIS,
    DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN, DEVICE_ENROLLMENT_CHALLENGE_TTL_MILLIS,
    DEVICE_ENROLLMENT_CREATE_REQUEST_HASH_DOMAIN, DEVICE_ENROLLMENT_EVENT_HASH_DOMAIN,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentChallenge,
    DeviceEnrollmentChallengeOutcome, DeviceEnrollmentChallengeState,
    DeviceEnrollmentChallengeStatus, DeviceEnrollmentRepository,
    HISTORY_RECOVERY_REQUEST_HASH_DOMAIN, HISTORY_RECOVERY_REQUEST_SIGNATURE_DOMAIN,
    history_recovery_request_signature_input, history_recovery_request_unsigned_canonical_bytes,
};
pub use device_session::{
    AuthenticatedDeviceSession, AuthenticatedDeviceSigningSession,
    DEVICE_SESSION_CHALLENGE_MIN_INTERVAL_MILLIS, DEVICE_SESSION_CHALLENGE_TTL_MILLIS,
    DEVICE_SESSION_PROOF_HASH_DOMAIN, DEVICE_SESSION_RECEIPT_HASH_DOMAIN,
    DEVICE_SESSION_REQUEST_HASH_DOMAIN, DEVICE_SESSION_SECRET_HASH_DOMAIN,
    DEVICE_SESSION_SIGNATURE_DOMAIN, DEVICE_SESSION_TTL_MILLIS, DeviceSessionChallenge,
    DeviceSessionCompletionCommand, DeviceSessionCredential, DeviceSessionOutcome,
    DeviceSessionReceipt, DeviceSessionRepository, device_session_proof_canonical_bytes,
    device_session_proof_input,
};
pub use error::IdentityPersistenceError;
pub use key_package::{
    FEDERATED_KEY_PACKAGE_CLAIM_BINDING_HASH_DOMAIN, FEDERATED_KEY_PACKAGE_CLAIM_BODY_HASH_DOMAIN,
    FEDERATED_KEY_PACKAGE_CLAIM_METHOD, FEDERATED_KEY_PACKAGE_CLAIM_PATH,
    FEDERATED_KEY_PACKAGE_CLAIM_PROOF_MAX_LIFETIME_MILLIS,
    FEDERATED_KEY_PACKAGE_CLAIM_SIGNATURE_DOMAIN, FederatedKeyPackageClaimProof,
    HistoryRecoveryKeyPackageScope, KEY_PACKAGE_BYTES_HASH_DOMAIN,
    KEY_PACKAGE_CLAIM_RECEIPT_HASH_DOMAIN, KEY_PACKAGE_CLAIM_REPLAY_RETENTION_MILLIS,
    KEY_PACKAGE_CLAIM_REQUEST_HASH_DOMAIN, KEY_PACKAGE_MAX_TTL_MILLIS,
    KEY_PACKAGE_PUBLISH_BINDING_HASH_DOMAIN, KEY_PACKAGE_PUBLISH_RECEIPT_HASH_DOMAIN,
    KEY_PACKAGE_PUBLISH_REQUEST_HASH_DOMAIN, KEY_PACKAGE_PUBLISH_SIGNATURE_DOMAIN,
    KeyPackageClaimCommand, KeyPackageClaimOutcome, KeyPackageClaimReceipt,
    KeyPackagePublishCommand, KeyPackagePublishOutcome, KeyPackagePublishReceipt,
    KeyPackageRepository, MAX_KEY_PACKAGE_BYTES, MAX_KEY_PACKAGE_PUBLISH_BYTES,
    VerifiedFederatedKeyPackageClaimant, federated_key_package_claim_body_digest,
    federated_key_package_claim_signature_input, key_package_publish_binding_canonical_bytes,
    key_package_publish_signature_input,
};
pub use recovery_scope_catalog::{
    CATALOG_CIPHERTEXT_HASH_DOMAIN, CATALOG_HEAD_DIGEST_DOMAIN, CATALOG_HEAD_SIGNATURE_DOMAIN,
    CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN, CatalogPreparationCommand,
    CatalogProviderResponseCommand, CatalogStatus, CatalogStatusInvalidation, CatalogUploadCommand,
    MAX_RECOVERY_SCOPE_CATALOG_CIPHERTEXT_BYTES, MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES,
    MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES, PREPARATION_DIGEST_DOMAIN,
    PREPARATION_SIGNATURE_DOMAIN, PROVIDER_CIPHERTEXT_HASH_DOMAIN, PROVIDER_RESPONSE_DIGEST_DOMAIN,
    PROVIDER_RESPONSE_SIGNATURE_DOMAIN, RECIPIENT_KEY_HASH_DOMAIN, RESPONSE_CAPABILITY_HASH_DOMAIN,
    RecoveryResponseCapability, RecoveryScopeCatalogOutcome, RecoveryScopeCatalogRepository,
    RecoveryScopeCatalogStatusOutcome,
};
pub use repository::{
    IdentityLogPageReadOutcome, IdentityLogRepository, lock_and_load_active_snapshot,
};
pub use store::{IdentityPgStore, IdentitySession};
pub use types::{
    DeviceRevokeCommand, IDENTITY_APPEND_RECEIPT_HASH_DOMAIN, IDENTITY_APPEND_REQUEST_HASH_DOMAIN,
    IdentityAppendCommand, IdentityAppendOutcome, IdentityAppendReceipt, IdentityCommandPhase,
    IdentityForkEvidence, IdentityLogHead, IdentityLogSnapshot,
};
