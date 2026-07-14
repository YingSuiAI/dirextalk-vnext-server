#![forbid(unsafe_code)]

//! First self-authenticated HTTP boundary for the vNext identity service.
//!
//! This crate intentionally exposes only bootstrap. Device sessions, QR
//! enrollment, and non-genesis appends need their own durable challenge and
//! credential contracts; accepting a generic bearer token here would weaken
//! the self-certifying identity boundary.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use dtx_domain::{Clock, RequestId, SystemClock};
use dtx_identity_log::{IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1, IdentityLogEventV1};
use dtx_identity_persistence::{
    IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository, IdentityPersistenceError,
    IdentityPgStore,
};
use dtx_wire::{Sha256Digest, UtcMillis};
use serde::Serialize;

/// Route for the self-authenticated identity genesis request.
pub const IDENTITY_BOOTSTRAP_PATH: &str = "/v1/identity/bootstrap";
/// Required media type for exact signed V1.1 identity-log events.
pub const IDENTITY_LOG_EVENT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-log.v1.1+cbor";
/// Response media type for immutable canonical append receipts.
pub const IDENTITY_APPEND_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-append-receipt.v1+cbor";
/// Largest accepted exact genesis event body.
pub const MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES: usize = 1_048_576;

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-bootstrap-http-idempotency-key.v1\0";

/// State for the bootstrap-only identity HTTP surface.
#[derive(Clone)]
pub struct IdentityBootstrapState {
    store: IdentityPgStore,
    repository: IdentityLogRepository,
    clock: Arc<dyn Clock>,
}

impl IdentityBootstrapState {
    /// Creates production state using the system UTC clock for durable commit time.
    #[must_use]
    pub fn new(store: IdentityPgStore) -> Self {
        Self::with_clock(store, Arc::new(SystemClock))
    }

    /// Creates state with an explicit clock for deterministic boundary tests.
    #[must_use]
    pub fn with_clock(store: IdentityPgStore, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            repository: IdentityLogRepository::new(),
            clock,
        }
    }
}

/// Builds the bootstrap router using production wall-clock time.
pub fn identity_bootstrap_router(store: IdentityPgStore) -> Router {
    identity_bootstrap_router_with_state(IdentityBootstrapState::new(store))
}

/// Builds the bootstrap router with explicit state.
///
/// This is public so an eventual TLS/session host can compose the exact route
/// without duplicating body, idempotency, or receipt handling.
pub fn identity_bootstrap_router_with_state(state: IdentityBootstrapState) -> Router {
    Router::new()
        .route(IDENTITY_BOOTSTRAP_PATH, post(bootstrap_identity))
        .with_state(state)
}

async fn bootstrap_identity(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.bootstrap(&parts.headers, body).await {
        Ok(success) => bootstrap_success_response(success, request_id),
        Err(failure) => bootstrap_failure_response(failure, request_id),
    }
}

impl IdentityBootstrapState {
    async fn bootstrap(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<BootstrapSuccess, BootstrapFailure> {
        if !has_exact_event_content_type(headers)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(BootstrapFailure::InvalidBootstrap);
        }
        let idempotency_key_hash = idempotency_key_hash(headers)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| BootstrapFailure::InvalidBootstrap)?;
        if exact_event_bytes.is_empty() {
            return Err(BootstrapFailure::InvalidBootstrap);
        }

        let event = IdentityLogEventV1::decode_and_verify(&exact_event_bytes)
            .map_err(|_| BootstrapFailure::InvalidBootstrap)?;
        if event.wire() != IDENTITY_LOG_WIRE_VERSION
            || event.sequence().get() != 1
            || event.previous_event_hash().is_some()
            || !matches!(event.payload(), IdentityLogEventPayloadV1::Genesis { .. })
        {
            return Err(BootstrapFailure::InvalidBootstrap);
        }

        let command =
            IdentityAppendCommand::new(idempotency_key_hash, None, exact_event_bytes.to_vec())
                .map_err(|_| BootstrapFailure::InvalidBootstrap)?;
        let committed_at = UtcMillis::new(
            self.clock
                .now_utc_millis()
                .map_err(|_| BootstrapFailure::TemporarilyUnavailable)?,
        )
        .map_err(|_| BootstrapFailure::TemporarilyUnavailable)?;

        match self
            .repository
            .append_bootstrap(&self.store, &command, committed_at)
            .await
        {
            Ok(IdentityAppendOutcome::Committed(receipt)) => Ok(BootstrapSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Replayed(receipt)) => Ok(BootstrapSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(BootstrapFailure::IdentityConflict),
            Err(error) => Err(map_persistence_error(&error)),
        }
    }
}

fn has_exact_event_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == IDENTITY_LOG_EVENT_CONTENT_TYPE.as_bytes())
        && values.next().is_none()
}

fn idempotency_key_hash(headers: &HeaderMap) -> Result<Sha256Digest, BootstrapFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(BootstrapFailure::InvalidBootstrap);
    };
    if values.next().is_some() {
        return Err(BootstrapFailure::InvalidBootstrap);
    }
    let bytes = value.as_bytes();
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&bytes.len())
        || !bytes.iter().copied().all(is_base64url_byte)
    {
        return Err(BootstrapFailure::InvalidBootstrap);
    }
    Ok(Sha256Digest::hash_domain(
        HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN,
        bytes,
    ))
}

const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || matches!(value, b'-' | b'_')
}

fn map_persistence_error(error: &IdentityPersistenceError) -> BootstrapFailure {
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
        | IdentityPersistenceError::CorruptData(_) => BootstrapFailure::TemporarilyUnavailable,
    }
}

struct BootstrapSuccess {
    status: StatusCode,
    exact_receipt_bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum BootstrapFailure {
    InvalidBootstrap,
    IdempotencyConflict,
    IdentityConflict,
    TemporarilyUnavailable,
}

#[derive(Serialize)]
struct BootstrapErrorEnvelope {
    error: BootstrapErrorBody,
}

#[derive(Serialize)]
struct BootstrapErrorBody {
    code: BootstrapErrorCode,
    request_id: RequestId,
    retryable: bool,
}

#[derive(Clone, Copy, Serialize)]
enum BootstrapErrorCode {
    #[serde(rename = "IDENTITY_BOOTSTRAP_INVALID")]
    InvalidBootstrap,
    #[serde(rename = "IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "IDENTITY_BOOTSTRAP_CONFLICT")]
    IdentityConflict,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    TemporarilyUnavailable,
}

fn bootstrap_success_response(success: BootstrapSuccess, request_id: RequestId) -> Response {
    let mut response = (success.status, success.exact_receipt_bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(IDENTITY_APPEND_RECEIPT_CONTENT_TYPE),
    );
    with_common_headers(response, request_id)
}

fn bootstrap_failure_response(failure: BootstrapFailure, request_id: RequestId) -> Response {
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

fn with_common_headers(mut response: Response, request_id: RequestId) -> Response {
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
