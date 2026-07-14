#![forbid(unsafe_code)]

//! Durable `PostgreSQL` storage for the self-certifying identity log.

mod device_enrollment;
mod device_session;
mod error;
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
pub use repository::IdentityLogRepository;
pub use store::{IdentityPgStore, IdentitySession};
pub use types::{
    IDENTITY_APPEND_RECEIPT_HASH_DOMAIN, IDENTITY_APPEND_REQUEST_HASH_DOMAIN,
    IdentityAppendCommand, IdentityAppendOutcome, IdentityAppendReceipt, IdentityCommandPhase,
    IdentityForkEvidence, IdentityLogHead, IdentityLogSnapshot,
};
