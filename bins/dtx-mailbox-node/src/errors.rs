pub(super) struct MailboxSuccess {
    pub(crate) status: StatusCode,
    pub(crate) exact_receipt_bytes: Vec<u8>,
    pub(crate) content_type: &'static str,
}

impl MailboxSuccess {
    pub(crate) fn write(outcome: &MailboxOperationOutcome, content_type: &'static str) -> Self {
        Self {
            status: if outcome.replayed() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            exact_receipt_bytes: outcome.receipt_bytes().to_vec(),
            content_type,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum MailboxFailure {
    InvalidRequest,
    AuthenticationRejected,
    Forbidden,
    Gone,
    Invalidated,
    Unavailable,
    Conflict,
    IdempotencyConflict,
    CapacityExceeded,
    TemporarilyUnavailable,
}

pub(super) fn map_persistence_error(error: &MailboxPersistenceError) -> MailboxFailure {
    match error {
        MailboxPersistenceError::InvalidCommand(_) => MailboxFailure::InvalidRequest,
        MailboxPersistenceError::DeviceAuthenticationRejected => {
            MailboxFailure::AuthenticationRejected
        }
        MailboxPersistenceError::ProviderAuthorizationRejected => MailboxFailure::Forbidden,
        MailboxPersistenceError::HistoryRecoveryExpired => MailboxFailure::Gone,
        MailboxPersistenceError::HistoryRecoveryInvalidated => MailboxFailure::Invalidated,
        MailboxPersistenceError::MailboxUnavailable
        | MailboxPersistenceError::KeyMaterialUnavailable => MailboxFailure::Unavailable,
        MailboxPersistenceError::MailboxConflict => MailboxFailure::Conflict,
        MailboxPersistenceError::IdempotencyConflict => MailboxFailure::IdempotencyConflict,
        MailboxPersistenceError::CapacityExceeded => MailboxFailure::CapacityExceeded,
        MailboxPersistenceError::Database(_)
        | MailboxPersistenceError::RuntimeRoleUnauthorized
        | MailboxPersistenceError::RuntimeRoleOverprivileged
        | MailboxPersistenceError::TenantContextLeak
        | MailboxPersistenceError::IdentityAuthorizationUnavailable
        | MailboxPersistenceError::ReceiptIntegrity
        | MailboxPersistenceError::CorruptData(_) => MailboxFailure::TemporarilyUnavailable,
    }
}

pub(super) fn mailbox_success_response(success: MailboxSuccess, request_id: RequestId) -> Response {
    let mut response = (success.status, success.exact_receipt_bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(success.content_type),
    );
    with_common_headers(response, request_id)
}

pub(super) fn mailbox_failure_response(failure: MailboxFailure, request_id: RequestId) -> Response {
    let (status, code, retryable) = match failure {
        MailboxFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            MailboxErrorCode::Invalid,
            false,
        ),
        MailboxFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            MailboxErrorCode::DeviceAuthenticationFailed,
            false,
        ),
        MailboxFailure::Forbidden => (
            StatusCode::FORBIDDEN,
            MailboxErrorCode::ProviderForbidden,
            false,
        ),
        MailboxFailure::Gone => (StatusCode::GONE, MailboxErrorCode::WorkflowExpired, false),
        MailboxFailure::Invalidated => (
            StatusCode::PRECONDITION_FAILED,
            MailboxErrorCode::RecoveryInvalidated,
            false,
        ),
        MailboxFailure::Unavailable => {
            (StatusCode::NOT_FOUND, MailboxErrorCode::Unavailable, false)
        }
        MailboxFailure::Conflict => (StatusCode::CONFLICT, MailboxErrorCode::Conflict, false),
        MailboxFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            MailboxErrorCode::IdempotencyConflict,
            false,
        ),
        MailboxFailure::CapacityExceeded => (
            StatusCode::TOO_MANY_REQUESTS,
            MailboxErrorCode::CapacityExceeded,
            true,
        ),
        MailboxFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            MailboxErrorCode::ServiceUnavailable,
            true,
        ),
    };
    safe_error_response(status, code, retryable, request_id)
}

#[derive(Clone, Copy, Serialize)]
enum MailboxErrorCode {
    #[serde(rename = "MAILBOX_INVALID")]
    Invalid,
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    DeviceAuthenticationFailed,
    #[serde(rename = "PROVIDER_NOT_AUTHORIZED")]
    ProviderForbidden,
    #[serde(rename = "WORKFLOW_EXPIRED")]
    WorkflowExpired,
    #[serde(rename = "RECOVERY_INVALIDATED")]
    RecoveryInvalidated,
    #[serde(rename = "MAILBOX_UNAVAILABLE")]
    Unavailable,
    #[serde(rename = "MAILBOX_CONFLICT")]
    Conflict,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "MAILBOX_CAPACITY_EXCEEDED")]
    CapacityExceeded,
    #[serde(rename = "MAILBOX_SERVICE_UNAVAILABLE")]
    ServiceUnavailable,
}

#[derive(Serialize)]
struct SafeErrorEnvelope {
    error: SafeErrorBody,
}

#[derive(Serialize)]
struct SafeErrorBody {
    code: MailboxErrorCode,
    request_id: RequestId,
    retryable: bool,
}

fn safe_error_response(
    status: StatusCode,
    code: MailboxErrorCode,
    retryable: bool,
    request_id: RequestId,
) -> Response {
    let body = serde_json::to_vec(&SafeErrorEnvelope {
        error: SafeErrorBody {
            code,
            request_id,
            retryable,
        },
    })
    .expect("the fixed mailbox error envelope always serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    with_common_headers(response, request_id)
}

pub(super) fn with_common_headers(mut response: Response, request_id: RequestId) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    let request_id = HeaderValue::from_str(&request_id.to_string())
        .expect("a canonical UUIDv7 request ID is a valid HTTP header value");
    response.headers_mut().insert(REQUEST_ID_HEADER, request_id);
    response
}
use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use dtx_domain::RequestId;
use dtx_mailbox::{MailboxOperationOutcome, MailboxPersistenceError};
use serde::Serialize;

use super::REQUEST_ID_HEADER;
