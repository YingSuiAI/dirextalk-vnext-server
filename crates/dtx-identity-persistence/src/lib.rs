#![forbid(unsafe_code)]

//! Durable `PostgreSQL` storage for the self-certifying identity log.

mod device_enrollment;
mod device_session;
mod error;
mod key_package;
mod repository;
mod store;
mod types;

pub use device_enrollment::{
    CreateDeviceEnrollmentChallengeCommand, DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_HASH_DOMAIN,
    DEVICE_ENROLLMENT_APPROVAL_REQUEST_HASH_DOMAIN, DEVICE_ENROLLMENT_APPROVAL_RETENTION_MILLIS,
    DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN, DEVICE_ENROLLMENT_CHALLENGE_TTL_MILLIS,
    DEVICE_ENROLLMENT_CREATE_REQUEST_HASH_DOMAIN, DEVICE_ENROLLMENT_EVENT_HASH_DOMAIN,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentChallenge,
    DeviceEnrollmentChallengeOutcome, DeviceEnrollmentChallengeState,
    DeviceEnrollmentChallengeStatus, DeviceEnrollmentRepository,
};
pub use device_session::{
    AuthenticatedDeviceSession, DEVICE_SESSION_CHALLENGE_MIN_INTERVAL_MILLIS,
    DEVICE_SESSION_CHALLENGE_TTL_MILLIS, DEVICE_SESSION_PROOF_HASH_DOMAIN,
    DEVICE_SESSION_RECEIPT_HASH_DOMAIN, DEVICE_SESSION_REQUEST_HASH_DOMAIN,
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DEVICE_SESSION_SIGNATURE_DOMAIN, DEVICE_SESSION_TTL_MILLIS,
    DeviceSessionChallenge, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionOutcome, DeviceSessionReceipt, DeviceSessionRepository,
    device_session_proof_canonical_bytes, device_session_proof_input,
};
pub use error::IdentityPersistenceError;
pub use key_package::{
    KEY_PACKAGE_BYTES_HASH_DOMAIN, KEY_PACKAGE_CLAIM_RECEIPT_HASH_DOMAIN,
    KEY_PACKAGE_CLAIM_REPLAY_RETENTION_MILLIS, KEY_PACKAGE_CLAIM_REQUEST_HASH_DOMAIN,
    KEY_PACKAGE_MAX_TTL_MILLIS, KEY_PACKAGE_PUBLISH_BINDING_HASH_DOMAIN,
    KEY_PACKAGE_PUBLISH_RECEIPT_HASH_DOMAIN, KEY_PACKAGE_PUBLISH_REQUEST_HASH_DOMAIN,
    KEY_PACKAGE_PUBLISH_SIGNATURE_DOMAIN, KeyPackageClaimCommand, KeyPackageClaimOutcome,
    KeyPackageClaimReceipt, KeyPackagePublishCommand, KeyPackagePublishOutcome,
    KeyPackagePublishReceipt, KeyPackageRepository, MAX_KEY_PACKAGE_BYTES,
    MAX_KEY_PACKAGE_PUBLISH_BYTES, key_package_publish_binding_canonical_bytes,
    key_package_publish_signature_input,
};
pub use repository::IdentityLogRepository;
pub use store::{IdentityPgStore, IdentitySession};
pub use types::{
    IDENTITY_APPEND_RECEIPT_HASH_DOMAIN, IDENTITY_APPEND_REQUEST_HASH_DOMAIN,
    IdentityAppendCommand, IdentityAppendOutcome, IdentityAppendReceipt, IdentityCommandPhase,
    IdentityForkEvidence, IdentityLogHead, IdentityLogSnapshot,
};
