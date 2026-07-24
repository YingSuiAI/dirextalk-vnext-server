use super::{
    Base64UrlUnpadded, BootstrapErrorBody, BootstrapErrorCode, BootstrapErrorEnvelope,
    BootstrapFailure, BootstrapSuccess, CanonicalEncode, CanonicalValue, ClientBindingFailure,
    ContactRequestRecord, ContactStoreError, DEVICE_ENROLLMENT_STATUS_CONTENT_TYPE,
    DEVICE_SESSION_RECEIPT_CONTENT_TYPE, DeviceEnrollmentApprovalSuccess,
    DeviceEnrollmentChallenge, DeviceEnrollmentChallengeState, DeviceEnrollmentChallengeStatus,
    DeviceEnrollmentChallengeSuccess, DeviceEnrollmentErrorCode, DeviceEnrollmentFailure,
    DeviceRevokeErrorCode, DeviceRevokeFailure, DeviceRevokeSuccess,
    DeviceSessionChallengeResponse, DeviceSessionErrorCode, DeviceSessionFailure,
    DeviceSessionSuccess, Encoding, HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE, HeaderMap,
    HeaderValue, HistoryRecoveryRequestV4Success, IDENTITY_APPEND_RECEIPT_CONTENT_TYPE,
    IDENTITY_LOG_PAGE_CONTENT_TYPE, IdentityLogPageErrorCode, IdentityLogPageFailure,
    IdentityLogPageV1, InitialDeviceErrorCode, InitialDeviceFailure, InitialDeviceSuccess,
    IntoResponse, KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE, KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE,
    KeyPackageClaimSuccess, KeyPackageErrorCode, KeyPackageFailure, KeyPackagePublishSuccess,
    MlsV5RecoveryAuthorizationErrorCode, MlsV5RecoveryAuthorizationFailure,
    RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE, REQUEST_ID_HEADER, RecoveryCatalogErrorCode,
    RecoveryCatalogFailure, RecoveryCatalogHeadSuccess, RecoveryCatalogReceiptKind,
    RecoveryCatalogStatusSuccess, RequestId, Response, SafeErrorBody, SafeErrorEnvelope, Serialize,
    StatusCode, UtcMillis, encode_deterministic_cbor, header,
};

pub(crate) fn bootstrap_success_response(
    success: BootstrapSuccess,
    request_id: RequestId,
) -> Response {
    let mut response = (success.status, success.exact_receipt_bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(IDENTITY_APPEND_RECEIPT_CONTENT_TYPE),
    );
    with_common_headers(response, request_id)
}

pub(crate) fn identity_log_page_success_response(
    page: &IdentityLogPageV1,
    request_id: RequestId,
) -> Response {
    match page.to_deterministic_cbor() {
        Ok(exact_page_bytes) => exact_cbor_response(
            StatusCode::OK,
            exact_page_bytes,
            IDENTITY_LOG_PAGE_CONTENT_TYPE,
            request_id,
        ),
        Err(_) => identity_log_page_failure_response(
            IdentityLogPageFailure::TemporarilyUnavailable,
            request_id,
        ),
    }
}

pub(crate) fn identity_log_page_failure_response(
    failure: IdentityLogPageFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        IdentityLogPageFailure::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            IdentityLogPageErrorCode::InvalidRequest,
            false,
        ),
        IdentityLogPageFailure::NotFound => (
            StatusCode::NOT_FOUND,
            IdentityLogPageErrorCode::NotFound,
            false,
        ),
        IdentityLogPageFailure::CursorAhead => (
            StatusCode::CONFLICT,
            IdentityLogPageErrorCode::CursorAhead,
            false,
        ),
        IdentityLogPageFailure::Inactive => {
            (StatusCode::GONE, IdentityLogPageErrorCode::Inactive, false)
        }
        IdentityLogPageFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            IdentityLogPageErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn mls_v5_recovery_authorization_failure_response(
    failure: MlsV5RecoveryAuthorizationFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        MlsV5RecoveryAuthorizationFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            MlsV5RecoveryAuthorizationErrorCode::InvalidRequest,
            false,
        ),
        MlsV5RecoveryAuthorizationFailure::Unavailable => (
            StatusCode::NOT_FOUND,
            MlsV5RecoveryAuthorizationErrorCode::Unavailable,
            false,
        ),
        MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            MlsV5RecoveryAuthorizationErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn bootstrap_failure_response(
    failure: BootstrapFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        BootstrapFailure::InvalidBootstrap => (
            StatusCode::UNPROCESSABLE_ENTITY,
            BootstrapErrorCode::InvalidBootstrap,
            false,
        ),
        BootstrapFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            BootstrapErrorCode::IdempotencyConflict,
            false,
        ),
        BootstrapFailure::IdentityConflict => (
            StatusCode::CONFLICT,
            BootstrapErrorCode::IdentityConflict,
            false,
        ),
        BootstrapFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            BootstrapErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    let body = serde_json::to_vec(&BootstrapErrorEnvelope {
        error: BootstrapErrorBody {
            code,
            request_id,
            retryable,
        },
    })
    .expect("the fixed bootstrap error envelope always serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    with_common_headers(response, request_id)
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum ClientBindingErrorCode {
    #[serde(rename = "CLIENT_BINDING_INVALID")]
    Invalid,
    #[serde(rename = "CLIENT_BINDING_CONFLICT")]
    Conflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    Unavailable,
}

pub(crate) fn client_binding_failure_response(
    failure: ClientBindingFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        ClientBindingFailure::Invalid
        | ClientBindingFailure::Unauthorized
        | ClientBindingFailure::Expired
        | ClientBindingFailure::Revoked => (
            StatusCode::UNPROCESSABLE_ENTITY,
            ClientBindingErrorCode::Invalid,
            false,
        ),
        ClientBindingFailure::Conflict => (
            StatusCode::CONFLICT,
            ClientBindingErrorCode::Conflict,
            false,
        ),
        ClientBindingFailure::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ClientBindingErrorCode::Unavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn initial_device_success_response(
    success: InitialDeviceSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_receipt_bytes,
        IDENTITY_APPEND_RECEIPT_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn initial_device_failure_response(
    failure: InitialDeviceFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        InitialDeviceFailure::InvalidInitialDevice => (
            StatusCode::UNPROCESSABLE_ENTITY,
            InitialDeviceErrorCode::InvalidInitialDevice,
            false,
        ),
        InitialDeviceFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            InitialDeviceErrorCode::IdempotencyConflict,
            false,
        ),
        InitialDeviceFailure::IdentityConflict => (
            StatusCode::CONFLICT,
            InitialDeviceErrorCode::IdentityConflict,
            false,
        ),
        InitialDeviceFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            InitialDeviceErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn device_session_challenge_success_response(
    challenge: &DeviceSessionChallengeResponse,
    request_id: RequestId,
) -> Response {
    let body = serde_json::to_vec(&challenge)
        .expect("the fixed device session challenge response always serializes");
    let mut response = (StatusCode::CREATED, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    with_common_headers(response, request_id)
}

pub(crate) fn device_session_success_response(
    success: DeviceSessionSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_receipt_bytes,
        DEVICE_SESSION_RECEIPT_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn device_session_failure_response(
    failure: DeviceSessionFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        DeviceSessionFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            DeviceSessionErrorCode::InvalidRequest,
            false,
        ),
        DeviceSessionFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            DeviceSessionErrorCode::AuthenticationRejected,
            false,
        ),
        DeviceSessionFailure::ChallengeExpired => (
            StatusCode::CONFLICT,
            DeviceSessionErrorCode::ChallengeExpired,
            false,
        ),
        DeviceSessionFailure::ChallengeConsumed => (
            StatusCode::CONFLICT,
            DeviceSessionErrorCode::ChallengeConsumed,
            false,
        ),
        DeviceSessionFailure::ChallengeRateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            DeviceSessionErrorCode::ChallengeRateLimited,
            true,
        ),
        DeviceSessionFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            DeviceSessionErrorCode::IdempotencyConflict,
            false,
        ),
        DeviceSessionFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            DeviceSessionErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn device_enrollment_challenge_success_response(
    success: &DeviceEnrollmentChallengeSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        encode_device_enrollment_challenge(&success.challenge),
        DEVICE_ENROLLMENT_STATUS_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn device_enrollment_status_response(
    status: DeviceEnrollmentChallengeStatus,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        StatusCode::OK,
        encode_device_enrollment_status(status),
        DEVICE_ENROLLMENT_STATUS_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn device_enrollment_approval_success_response(
    success: DeviceEnrollmentApprovalSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_receipt_bytes,
        IDENTITY_APPEND_RECEIPT_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn history_recovery_request_v4_success_response(
    success: HistoryRecoveryRequestV4Success,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_receipt_bytes,
        HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn device_revoke_success_response(
    success: DeviceRevokeSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_receipt_bytes,
        IDENTITY_APPEND_RECEIPT_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn device_revoke_failure_response(
    failure: DeviceRevokeFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        DeviceRevokeFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            DeviceRevokeErrorCode::InvalidRequest,
            false,
        ),
        DeviceRevokeFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            DeviceRevokeErrorCode::AuthenticationRejected,
            false,
        ),
        DeviceRevokeFailure::CurrentSessionForbidden => (
            StatusCode::CONFLICT,
            DeviceRevokeErrorCode::CurrentSessionForbidden,
            false,
        ),
        DeviceRevokeFailure::IdentityConflict => (
            StatusCode::CONFLICT,
            DeviceRevokeErrorCode::IdentityConflict,
            false,
        ),
        DeviceRevokeFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            DeviceRevokeErrorCode::IdempotencyConflict,
            false,
        ),
        DeviceRevokeFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            DeviceRevokeErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn device_enrollment_failure_response(
    failure: DeviceEnrollmentFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        DeviceEnrollmentFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            DeviceEnrollmentErrorCode::InvalidRequest,
            false,
        ),
        DeviceEnrollmentFailure::CapabilityRejected => (
            StatusCode::UNAUTHORIZED,
            DeviceEnrollmentErrorCode::CapabilityRejected,
            false,
        ),
        DeviceEnrollmentFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            DeviceEnrollmentErrorCode::AuthenticationRejected,
            false,
        ),
        DeviceEnrollmentFailure::ChallengeExpired => (
            StatusCode::CONFLICT,
            DeviceEnrollmentErrorCode::ChallengeExpired,
            false,
        ),
        DeviceEnrollmentFailure::ChallengeCancelled => (
            StatusCode::CONFLICT,
            DeviceEnrollmentErrorCode::ChallengeCancelled,
            false,
        ),
        DeviceEnrollmentFailure::ChallengeApproved => (
            StatusCode::CONFLICT,
            DeviceEnrollmentErrorCode::ChallengeApproved,
            false,
        ),
        DeviceEnrollmentFailure::IdentityConflict => (
            StatusCode::CONFLICT,
            DeviceEnrollmentErrorCode::IdentityConflict,
            false,
        ),
        DeviceEnrollmentFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            DeviceEnrollmentErrorCode::IdempotencyConflict,
            false,
        ),
        DeviceEnrollmentFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            DeviceEnrollmentErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn key_package_publish_success_response(
    success: KeyPackagePublishSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_receipt_bytes,
        KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn key_package_claim_success_response(
    success: KeyPackageClaimSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_publish_bytes,
        KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn key_package_failure_response(
    failure: KeyPackageFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        KeyPackageFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            KeyPackageErrorCode::InvalidRequest,
            false,
        ),
        KeyPackageFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            KeyPackageErrorCode::AuthenticationRejected,
            false,
        ),
        // Intentionally unify missing identities/devices, revoked targets,
        // expired packages, and prior consumption to avoid directory probing.
        KeyPackageFailure::Unavailable => (
            StatusCode::NOT_FOUND,
            KeyPackageErrorCode::Unavailable,
            false,
        ),
        KeyPackageFailure::Conflict => (StatusCode::CONFLICT, KeyPackageErrorCode::Conflict, false),
        KeyPackageFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            KeyPackageErrorCode::IdempotencyConflict,
            false,
        ),
        KeyPackageFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            KeyPackageErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn recovery_catalog_head_response(
    success: RecoveryCatalogHeadSuccess,
    request_id: RequestId,
) -> Response {
    exact_cbor_response(
        success.status,
        success.outcome.exact_head_bytes,
        RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE,
        request_id,
    )
}

pub(crate) fn recovery_catalog_status_response(
    success: &RecoveryCatalogStatusSuccess,
    request_id: RequestId,
) -> Response {
    let response = if success.receipt != RecoveryCatalogReceiptKind::None {
        success.outcome.receipt_bytes.clone().ok_or(())
    } else {
        success.outcome.exact_bytes().map_err(|_| ())
    };
    match response {
        Ok(bytes) => exact_cbor_response(
            success.status,
            bytes,
            match success.receipt {
                RecoveryCatalogReceiptKind::Preparation => {
                    RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE
                }
                RecoveryCatalogReceiptKind::ProviderResponse => {
                    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE
                }
                RecoveryCatalogReceiptKind::None => RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE,
            },
            request_id,
        ),
        Err(_) => recovery_catalog_failure_response(
            RecoveryCatalogFailure::TemporarilyUnavailable,
            request_id,
        ),
    }
}

pub(crate) fn recovery_catalog_failure_response(
    failure: RecoveryCatalogFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
        RecoveryCatalogFailure::NotAcceptable => (
            StatusCode::NOT_ACCEPTABLE,
            RecoveryCatalogErrorCode::NotAcceptable,
            false,
        ),
        RecoveryCatalogFailure::UnsupportedMedia => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            RecoveryCatalogErrorCode::UnsupportedMedia,
            false,
        ),
        RecoveryCatalogFailure::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            RecoveryCatalogErrorCode::TooLarge,
            false,
        ),
        RecoveryCatalogFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            RecoveryCatalogErrorCode::InvalidRequest,
            false,
        ),
        RecoveryCatalogFailure::ExactCborInvalid => (
            StatusCode::UNPROCESSABLE_ENTITY,
            RecoveryCatalogErrorCode::ExactCborInvalid,
            false,
        ),
        RecoveryCatalogFailure::CapabilityRejected => (
            StatusCode::UNAUTHORIZED,
            RecoveryCatalogErrorCode::CapabilityRejected,
            false,
        ),
        RecoveryCatalogFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            RecoveryCatalogErrorCode::AuthenticationRejected,
            false,
        ),
        RecoveryCatalogFailure::PreparationExpired => (
            StatusCode::GONE,
            RecoveryCatalogErrorCode::PreparationExpired,
            false,
        ),
        RecoveryCatalogFailure::PreparationRevoked => (
            StatusCode::GONE,
            RecoveryCatalogErrorCode::PreparationRevoked,
            false,
        ),
        RecoveryCatalogFailure::CatalogExpired => (
            StatusCode::GONE,
            RecoveryCatalogErrorCode::CatalogExpired,
            false,
        ),
        RecoveryCatalogFailure::PreparationInvalidated => (
            StatusCode::PRECONDITION_FAILED,
            RecoveryCatalogErrorCode::PreparationInvalidated,
            false,
        ),
        RecoveryCatalogFailure::CatalogConflict => (
            StatusCode::CONFLICT,
            RecoveryCatalogErrorCode::CatalogConflict,
            false,
        ),
        RecoveryCatalogFailure::PreparationConflict => (
            StatusCode::CONFLICT,
            RecoveryCatalogErrorCode::PreparationConflict,
            false,
        ),
        RecoveryCatalogFailure::IdentityHeadChanged => (
            StatusCode::PRECONDITION_FAILED,
            RecoveryCatalogErrorCode::IdentityHeadChanged,
            false,
        ),
        RecoveryCatalogFailure::CatalogHeadChanged => (
            StatusCode::PRECONDITION_FAILED,
            RecoveryCatalogErrorCode::CatalogHeadChanged,
            false,
        ),
        RecoveryCatalogFailure::AuthorityChanged => (
            StatusCode::PRECONDITION_FAILED,
            RecoveryCatalogErrorCode::AuthorityChanged,
            false,
        ),
        RecoveryCatalogFailure::CandidateKeyChanged => (
            StatusCode::PRECONDITION_FAILED,
            RecoveryCatalogErrorCode::CandidateKeyChanged,
            false,
        ),
        RecoveryCatalogFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            RecoveryCatalogErrorCode::IdempotencyConflict,
            false,
        ),
        RecoveryCatalogFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            RecoveryCatalogErrorCode::TemporarilyUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

pub(crate) fn encode_device_enrollment_status(status: DeviceEnrollmentChallengeStatus) -> Vec<u8> {
    let state = match status.state() {
        DeviceEnrollmentChallengeState::Open => 1,
        DeviceEnrollmentChallengeState::Approved => 2,
        DeviceEnrollmentChallengeState::Cancelled => 3,
        DeviceEnrollmentChallengeState::Expired => 4,
    };
    encode_device_enrollment_status_fields(
        status.challenge_id().to_string(),
        status.identity_id().to_string(),
        status.target_device_id().to_string(),
        state,
        status.expires_at(),
    )
}

pub(crate) fn encode_device_enrollment_challenge(challenge: &DeviceEnrollmentChallenge) -> Vec<u8> {
    encode_device_enrollment_status_fields(
        challenge.challenge_id().to_string(),
        challenge.identity_id().to_string(),
        challenge.target_device_id().to_string(),
        1,
        challenge.expires_at(),
    )
}

pub(crate) fn encode_device_enrollment_status_fields(
    challenge_id: String,
    identity_id: String,
    target_device_id: String,
    state: u64,
    expires_at: UtcMillis,
) -> Vec<u8> {
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(challenge_id),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(identity_id),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(target_device_id),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(state)),
        (CanonicalValue::Unsigned(6), expires_at.to_canonical_value()),
    ]);
    encode_deterministic_cbor(&value)
        .expect("trusted device enrollment status always has a bounded canonical representation")
}

pub(crate) fn contact_secret(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<[u8; 32], ContactStoreError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(ContactStoreError::NotFound)?;
    if values.next().is_some() || value.as_bytes().len() != 43 {
        return Err(ContactStoreError::NotFound);
    }
    let mut output = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(value.as_bytes(), &mut output)
        .map_err(|_| ContactStoreError::NotFound)?;
    if decoded.len() != output.len()
        || Base64UrlUnpadded::encode_string(&output).as_bytes() != value.as_bytes()
    {
        return Err(ContactStoreError::NotFound);
    }
    Ok(output)
}

pub(crate) fn encode_pending(
    values: &[ContactRequestRecord],
) -> Result<Vec<u8>, ContactStoreError> {
    let entries = values
        .iter()
        .map(|value| {
            CanonicalValue::Map(vec![
                (
                    CanonicalValue::Unsigned(1),
                    CanonicalValue::Text(value.request_id.to_string()),
                ),
                (
                    CanonicalValue::Unsigned(2),
                    CanonicalValue::Text(value.invite_id.to_string()),
                ),
                (
                    CanonicalValue::Unsigned(3),
                    CanonicalValue::Bytes(value.sealed_request.clone()),
                ),
                (
                    CanonicalValue::Unsigned(4),
                    value.created_at.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(5),
                    value.expires_at.to_canonical_value(),
                ),
                (
                    CanonicalValue::Unsigned(6),
                    value.receipt_capability_hash.to_canonical_value(),
                ),
            ])
        })
        .collect();
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Array(entries)),
    ]))
    .map_err(|_| ContactStoreError::Invalid)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the owned error is consumed at the HTTP boundary"
)]
pub(crate) fn contact_failure(error: ContactStoreError, request_id: RequestId) -> Response {
    let status = match error {
        ContactStoreError::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
        ContactStoreError::Authentication => StatusCode::UNAUTHORIZED,
        ContactStoreError::NotFound => StatusCode::NOT_FOUND,
        ContactStoreError::RateLimited | ContactStoreError::Quota => StatusCode::TOO_MANY_REQUESTS,
        ContactStoreError::Conflict
        | ContactStoreError::Expired
        | ContactStoreError::Revoked
        | ContactStoreError::Exhausted => StatusCode::CONFLICT,
        ContactStoreError::Persistence(_)
        | ContactStoreError::Database(_)
        | ContactStoreError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    with_common_headers(status.into_response(), request_id)
}

pub(crate) fn exact_cbor_response(
    status: StatusCode,
    exact_bytes: Vec<u8>,
    content_type: &'static str,
    request_id: RequestId,
) -> Response {
    let mut response = (status, exact_bytes).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    with_common_headers(response, request_id)
}

pub(crate) fn safe_error_response<C>(
    status: StatusCode,
    code: C,
    retryable: bool,
    request_id: RequestId,
) -> Response
where
    C: Serialize,
{
    let body = serde_json::to_vec(&SafeErrorEnvelope {
        error: SafeErrorBody {
            code,
            request_id,
            retryable,
        },
    })
    .expect("the fixed identity error envelope always serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    with_common_headers(response, request_id)
}

pub(crate) fn with_common_headers(mut response: Response, request_id: RequestId) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let request_id = request_id.to_string();
    let request_id = HeaderValue::from_str(&request_id)
        .expect("a canonical UUIDv7 request ID is a valid HTTP header value");
    response.headers_mut().insert(REQUEST_ID_HEADER, request_id);
    response
}
