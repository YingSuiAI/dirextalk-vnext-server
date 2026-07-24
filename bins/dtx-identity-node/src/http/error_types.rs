use super::{
    Base64UrlUnpadded, ClientBindingWorkflowError, Deserialize, DeviceEnrollmentChallenge,
    DeviceId, DeviceSessionAuthorizationError, DeviceSessionChallengeId, DeviceSessionId,
    Ed25519Signature, Encoding, IdentityId, RecoveryScopeCatalogOutcome,
    RecoveryScopeCatalogStatusOutcome, RequestId, Serialize, StatusCode,
};

impl std::fmt::Display for DeviceSessionAuthorizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid device session authorization")
    }
}

impl std::error::Error for DeviceSessionAuthorizationError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceSessionChallengeRequest {
    pub(crate) identity_id: IdentityId,
    pub(crate) device_id: DeviceId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceSessionCompletionRequest {
    pub(crate) identity_id: IdentityId,
    pub(crate) device_id: DeviceId,
    pub(crate) challenge_id: DeviceSessionChallengeId,
    pub(crate) session_id: DeviceSessionId,
    pub(crate) challenge_nonce: String,
    pub(crate) session_secret: String,
    pub(crate) proof: Ed25519Signature,
}

#[derive(Serialize)]
pub(crate) struct DeviceSessionChallengeResponse {
    pub(crate) challenge_id: DeviceSessionChallengeId,
    pub(crate) identity_id: IdentityId,
    pub(crate) device_id: DeviceId,
    pub(crate) challenge_nonce: String,
    pub(crate) audience: String,
    pub(crate) expires_at_ms: i64,
    pub(crate) session_expires_at_ms: i64,
}

impl From<dtx_identity_persistence::DeviceSessionChallenge> for DeviceSessionChallengeResponse {
    fn from(challenge: dtx_identity_persistence::DeviceSessionChallenge) -> Self {
        Self {
            challenge_id: challenge.challenge_id(),
            identity_id: challenge.identity_id(),
            device_id: challenge.device_id(),
            challenge_nonce: Base64UrlUnpadded::encode_string(challenge.nonce()),
            audience: challenge.audience().to_owned(),
            expires_at_ms: challenge.expires_at().get(),
            session_expires_at_ms: challenge.session_expires_at().get(),
        }
    }
}

pub(crate) struct BootstrapSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum IdentityLogPageFailure {
    InvalidRequest,
    NotFound,
    CursorAhead,
    Inactive,
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum MlsV5RecoveryAuthorizationFailure {
    InvalidRequest,
    Unavailable,
    TemporarilyUnavailable,
}

#[derive(Clone, Copy)]
pub(crate) enum BootstrapFailure {
    InvalidBootstrap,
    IdempotencyConflict,
    IdentityConflict,
    TemporarilyUnavailable,
}

pub(crate) struct InitialDeviceSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) enum InitialDeviceFailure {
    InvalidInitialDevice,
    IdempotencyConflict,
    IdentityConflict,
    TemporarilyUnavailable,
}

#[derive(Clone, Copy)]
pub(crate) enum ClientBindingFailure {
    Invalid,
    Conflict,
    Unauthorized,
    Expired,
    Revoked,
    Unavailable,
}

pub(crate) fn map_client_binding_error(error: &ClientBindingWorkflowError) -> ClientBindingFailure {
    match error {
        ClientBindingWorkflowError::Invalid | ClientBindingWorkflowError::Corrupt => {
            ClientBindingFailure::Invalid
        }
        ClientBindingWorkflowError::Unauthorized => ClientBindingFailure::Unauthorized,
        ClientBindingWorkflowError::Conflict => ClientBindingFailure::Conflict,
        ClientBindingWorkflowError::Expired => ClientBindingFailure::Expired,
        ClientBindingWorkflowError::Revoked => ClientBindingFailure::Revoked,
        ClientBindingWorkflowError::Persistence(_) => ClientBindingFailure::Unavailable,
    }
}

pub(crate) struct DeviceSessionSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) enum DeviceSessionFailure {
    InvalidRequest,
    AuthenticationRejected,
    ChallengeExpired,
    ChallengeConsumed,
    ChallengeRateLimited,
    IdempotencyConflict,
    TemporarilyUnavailable,
}

pub(crate) struct DeviceEnrollmentChallengeSuccess {
    pub(crate) status: StatusCode,
    pub(crate) challenge: DeviceEnrollmentChallenge,
}

pub(crate) struct DeviceEnrollmentApprovalSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
}

pub(crate) struct HistoryRecoveryRequestV4Success {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
}

pub(crate) struct DeviceRevokeSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
}

pub(crate) struct KeyPackagePublishSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
}

pub(crate) struct KeyPackageClaimSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_publish_bytes: Vec<u8>,
}

pub(crate) struct RecoveryCatalogHeadSuccess {
    pub(crate) status: StatusCode,
    pub(crate) outcome: RecoveryScopeCatalogOutcome,
}

pub(crate) struct RecoveryCatalogStatusSuccess {
    pub(crate) status: StatusCode,
    pub(crate) outcome: RecoveryScopeCatalogStatusOutcome,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RecoveryCatalogFailure {
    InvalidRequest,
    ExactCborInvalid,
    CapabilityRejected,
    AuthenticationRejected,
    PreparationExpired,
    PreparationRevoked,
    CatalogExpired,
    PreparationInvalidated,
    CatalogConflict,
    PreparationConflict,
    IdentityHeadChanged,
    CatalogHeadChanged,
    AuthorityChanged,
    CandidateKeyChanged,
    IdempotencyConflict,
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DeviceEnrollmentFailure {
    InvalidRequest,
    CapabilityRejected,
    AuthenticationRejected,
    ChallengeExpired,
    ChallengeCancelled,
    ChallengeApproved,
    IdentityConflict,
    IdempotencyConflict,
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DeviceRevokeFailure {
    InvalidRequest,
    AuthenticationRejected,
    CurrentSessionForbidden,
    IdentityConflict,
    IdempotencyConflict,
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum KeyPackageFailure {
    InvalidRequest,
    AuthenticationRejected,
    Unavailable,
    Conflict,
    IdempotencyConflict,
    TemporarilyUnavailable,
}

#[derive(Serialize)]
pub(crate) struct BootstrapErrorEnvelope {
    pub(crate) error: BootstrapErrorBody,
}

#[derive(Serialize)]
pub(crate) struct BootstrapErrorBody {
    pub(crate) code: BootstrapErrorCode,
    pub(crate) request_id: RequestId,
    pub(crate) retryable: bool,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum BootstrapErrorCode {
    #[serde(rename = "IDENTITY_BOOTSTRAP_INVALID")]
    InvalidBootstrap,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "IDENTITY_BOOTSTRAP_CONFLICT")]
    IdentityConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum IdentityLogPageErrorCode {
    #[serde(rename = "IDENTITY_LOG_PAGE_INVALID")]
    InvalidRequest,
    #[serde(rename = "IDENTITY_LOG_NOT_FOUND")]
    NotFound,
    #[serde(rename = "IDENTITY_LOG_CURSOR_AHEAD")]
    CursorAhead,
    #[serde(rename = "IDENTITY_LOG_INACTIVE")]
    Inactive,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum MlsV5RecoveryAuthorizationErrorCode {
    #[serde(rename = "MLS_V5_RECOVERY_AUTHORIZATION_REQUEST_INVALID")]
    InvalidRequest,
    #[serde(rename = "MLS_V5_RECOVERY_AUTHORIZATION_UNAVAILABLE")]
    Unavailable,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum InitialDeviceErrorCode {
    #[serde(rename = "INITIAL_DEVICE_ENROLL_INVALID")]
    InvalidInitialDevice,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "INITIAL_DEVICE_ENROLL_CONFLICT")]
    IdentityConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum DeviceSessionErrorCode {
    #[serde(rename = "DEVICE_SESSION_INVALID")]
    InvalidRequest,
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    AuthenticationRejected,
    #[serde(rename = "DEVICE_SESSION_CHALLENGE_EXPIRED")]
    ChallengeExpired,
    #[serde(rename = "DEVICE_SESSION_CHALLENGE_CONSUMED")]
    ChallengeConsumed,
    #[serde(rename = "DEVICE_SESSION_CHALLENGE_RATE_LIMITED")]
    ChallengeRateLimited,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum DeviceEnrollmentErrorCode {
    #[serde(rename = "DEVICE_ENROLLMENT_INVALID")]
    InvalidRequest,
    #[serde(rename = "DEVICE_ENROLLMENT_CAPABILITY_INVALID")]
    CapabilityRejected,
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    AuthenticationRejected,
    #[serde(rename = "DEVICE_ENROLLMENT_CHALLENGE_EXPIRED")]
    ChallengeExpired,
    #[serde(rename = "DEVICE_ENROLLMENT_CHALLENGE_CANCELLED")]
    ChallengeCancelled,
    #[serde(rename = "DEVICE_ENROLLMENT_CHALLENGE_ALREADY_APPROVED")]
    ChallengeApproved,
    #[serde(rename = "IDENTITY_APPEND_CONFLICT")]
    IdentityConflict,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum DeviceRevokeErrorCode {
    #[serde(rename = "DEVICE_REVOKE_INVALID")]
    InvalidRequest,
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    AuthenticationRejected,
    #[serde(rename = "DEVICE_REVOKE_CURRENT_SESSION_FORBIDDEN")]
    CurrentSessionForbidden,
    #[serde(rename = "IDENTITY_APPEND_CONFLICT")]
    IdentityConflict,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum KeyPackageErrorCode {
    #[serde(rename = "KEY_PACKAGE_INVALID")]
    InvalidRequest,
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    AuthenticationRejected,
    #[serde(rename = "KEY_PACKAGE_UNAVAILABLE")]
    Unavailable,
    #[serde(rename = "KEY_PACKAGE_CONFLICT")]
    Conflict,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum RecoveryCatalogErrorCode {
    #[serde(rename = "RECOVERY_CATALOG_INVALID")]
    InvalidRequest,
    #[serde(rename = "EXACT_CBOR_INVALID")]
    ExactCborInvalid,
    #[serde(rename = "RECOVERY_RESPONSE_CAPABILITY_REJECTED")]
    CapabilityRejected,
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    AuthenticationRejected,
    #[serde(rename = "RECOVERY_PREPARATION_EXPIRED")]
    PreparationExpired,
    #[serde(rename = "RECOVERY_PREPARATION_REVOKED")]
    PreparationRevoked,
    #[serde(rename = "RECOVERY_CATALOG_EXPIRED")]
    CatalogExpired,
    #[serde(rename = "RECOVERY_PREPARATION_INVALIDATED")]
    PreparationInvalidated,
    #[serde(rename = "RECOVERY_CATALOG_CONFLICT")]
    CatalogConflict,
    #[serde(rename = "RECOVERY_PREPARATION_CONFLICT")]
    PreparationConflict,
    #[serde(rename = "IDENTITY_HEAD_CHANGED")]
    IdentityHeadChanged,
    #[serde(rename = "CATALOG_HEAD_CHANGED")]
    CatalogHeadChanged,
    #[serde(rename = "AUTHORITY_CHANGED")]
    AuthorityChanged,
    #[serde(rename = "CANDIDATE_KEY_CHANGED")]
    CandidateKeyChanged,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

#[derive(Serialize)]
pub(crate) struct SafeErrorEnvelope<C> {
    pub(crate) error: SafeErrorBody<C>,
}

#[derive(Serialize)]
pub(crate) struct SafeErrorBody<C> {
    pub(crate) code: C,
    pub(crate) request_id: RequestId,
    pub(crate) retryable: bool,
}
