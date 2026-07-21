#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::put,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{DeviceSessionId, TenantId};
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_opaque_push_postgres::{
    AdapterError, PushRegistrationService, RegistrationAction, RegistrationRequest,
    RegistrationResult,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;

pub const PUSH_PATH: &str = "/v1/devices/push-registrations/fcm";
pub const DEVICE_SESSION_HEADER: &str = "DTX-Device-Session";
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";
pub const IF_MATCH_HEADER: &str = "If-Match";
pub const REGISTER_MEDIA_TYPE: &str = "application/vnd.dirextalk.opaque-push-register.v1+cbor";
pub const RECEIPT_MEDIA_TYPE: &str = "application/vnd.dirextalk.opaque-push-receipt.v1+cbor";
pub const MAX_REQUEST_BODY_BYTES: usize = 4_114;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const MAX_SAFE_UINT: u64 = 9_007_199_254_740_991;

const DEVICE_SESSION_NAME: HeaderName = HeaderName::from_static("dtx-device-session");
const IDEMPOTENCY_NAME: HeaderName = HeaderName::from_static("idempotency-key");
const IF_MATCH_NAME: HeaderName = HeaderName::from_static("if-match");
const CONTENT_ENCODING_NAME: HeaderName = HeaderName::from_static("content-encoding");

pub trait RegistrationBackend: Send + Sync + 'static {
    fn mutate<'a>(
        &'a self,
        request: RegistrationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<RegistrationResult, AdapterError>> + Send + 'a>>;
}

impl<S> RegistrationBackend for PushRegistrationService<S>
where
    S: dtx_opaque_push_postgres::TokenSealer + Send + Sync + 'static,
{
    fn mutate<'a>(
        &'a self,
        request: RegistrationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<RegistrationResult, AdapterError>> + Send + 'a>> {
        Box::pin(async move { self.register_typed(request).await })
    }
}

pub struct PushRouterState<B> {
    backend: Arc<B>,
    tenant_id: TenantId,
}

impl<B> Clone for PushRouterState<B> {
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            tenant_id: self.tenant_id,
        }
    }
}

impl<B> PushRouterState<B> {
    pub fn new(backend: Arc<B>, tenant_id: TenantId) -> Self {
        Self { backend, tenant_id }
    }
}

pub fn router<B: RegistrationBackend>(state: PushRouterState<B>) -> Router {
    Router::new()
        .route(PUSH_PATH, put(handle_put::<B>).delete(handle_delete::<B>))
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(
            MAX_REQUEST_BODY_BYTES + 1,
        ))
}

async fn handle_put<B: RegistrationBackend>(
    State(state): State<PushRouterState<B>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES + 1).await else {
        return error_response(PublicError::InvalidPushRegistration, Uuid::now_v7());
    };
    handle_mutation(state, parts.headers, body, true).await
}

async fn handle_delete<B: RegistrationBackend>(
    State(state): State<PushRouterState<B>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES + 1).await else {
        return error_response(PublicError::InvalidRequest, Uuid::now_v7());
    };
    handle_mutation(state, parts.headers, body, false).await
}

async fn handle_mutation<B: RegistrationBackend>(
    state: PushRouterState<B>,
    headers: HeaderMap,
    body: Bytes,
    is_put: bool,
) -> Response {
    let request_id = Uuid::now_v7();
    let parsed = parse_request(&headers, &body, is_put);
    let (credential, key, revision, canonical_body) = match parsed {
        Ok(value) => value,
        Err(error) => return error_response(error, request_id),
    };
    let method = if is_put { "PUT" } else { "DELETE" };
    let digest = request_digest(&canonical_body);
    let action = if is_put {
        RegistrationAction::Put(parse_push_token(&canonical_body).expect("validated token"))
    } else {
        RegistrationAction::Delete
    };
    let request = match RegistrationRequest::new_for_adapter(
        credential,
        method,
        PUSH_PATH,
        key,
        revision,
        digest,
        state.tenant_id,
        action,
    ) {
        Ok(request) => request,
        Err(error) => return error_response(map_adapter_error(&error), request_id),
    };
    match state.backend.mutate(request).await {
        Ok(result) => success_response(&result, request_id),
        Err(error) => error_response(map_adapter_error(&error), request_id),
    }
}

fn success_response(result: &RegistrationResult, request_id: Uuid) -> Response {
    let status = match result {
        RegistrationResult::Created { .. } => StatusCode::CREATED,
        RegistrationResult::Updated { .. }
        | RegistrationResult::Replay { .. }
        | RegistrationResult::Revoked { .. } => StatusCode::OK,
    };
    let body = result.receipt().to_vec();
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(RECEIPT_MEDIA_TYPE),
    );
    common_headers(&mut response, request_id);
    response
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicError {
    InvalidRequest,
    DeviceAuthenticationFailed,
    RevisionOrIdempotencyConflict,
    DeviceSessionRevoked,
    UnsupportedMediaType,
    InvalidPushRegistration,
    PushServiceUnavailable,
}

impl PublicError {
    const fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::DeviceAuthenticationFailed => StatusCode::UNAUTHORIZED,
            Self::RevisionOrIdempotencyConflict => StatusCode::CONFLICT,
            Self::DeviceSessionRevoked => StatusCode::GONE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::InvalidPushRegistration => StatusCode::UNPROCESSABLE_ENTITY,
            Self::PushServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::DeviceAuthenticationFailed => "DEVICE_AUTHENTICATION_FAILED",
            Self::RevisionOrIdempotencyConflict => "REVISION_OR_IDEMPOTENCY_CONFLICT",
            Self::DeviceSessionRevoked => "DEVICE_SESSION_REVOKED",
            Self::UnsupportedMediaType => "UNSUPPORTED_MEDIA_TYPE",
            Self::InvalidPushRegistration => "INVALID_PUSH_REGISTRATION",
            Self::PushServiceUnavailable => "PUSH_SERVICE_UNAVAILABLE",
        }
    }
}

impl fmt::Display for PublicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

fn error_response(error: PublicError, request_id: Uuid) -> Response {
    let body = serde_json::json!({"error": {"code": error.code(), "retryable": error == PublicError::PushServiceUnavailable}});
    let mut response = (
        error.status(),
        serde_json::to_vec(&body).expect("fixed error"),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    common_headers(&mut response, request_id);
    response
}

fn common_headers(response: &mut Response, request_id: Uuid) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("uuid header"),
    );
}

fn map_adapter_error(error: &AdapterError) -> PublicError {
    match error.category() {
        dtx_opaque_push_postgres::ErrorCategory::Auth => PublicError::DeviceAuthenticationFailed,
        dtx_opaque_push_postgres::ErrorCategory::Revoked => PublicError::DeviceSessionRevoked,
        dtx_opaque_push_postgres::ErrorCategory::Conflict => {
            PublicError::RevisionOrIdempotencyConflict
        }
        // Identity fences are retryable service failures, never public conflicts.
        dtx_opaque_push_postgres::ErrorCategory::Fence
        | dtx_opaque_push_postgres::ErrorCategory::Unavailable => {
            PublicError::PushServiceUnavailable
        }
        dtx_opaque_push_postgres::ErrorCategory::Malformed => PublicError::InvalidPushRegistration,
    }
}

fn parse_request(
    headers: &HeaderMap,
    body: &[u8],
    is_put: bool,
) -> Result<(DeviceSessionCredential, Vec<u8>, u64, Vec<u8>), PublicError> {
    if headers.contains_key(CONTENT_ENCODING_NAME) {
        return Err(PublicError::UnsupportedMediaType);
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(PublicError::InvalidRequest);
    }
    if headers.get_all(&DEVICE_SESSION_NAME).iter().count() > 1 {
        return Err(PublicError::InvalidRequest);
    }
    let session = exact_single_header(headers, &DEVICE_SESSION_NAME)
        .ok_or(PublicError::DeviceAuthenticationFailed)
        .and_then(parse_session)?;
    let key = exact_single_header(headers, &IDEMPOTENCY_NAME)
        .ok_or(PublicError::InvalidRequest)
        .and_then(parse_idempotency_key)?;
    let revision = exact_single_header(headers, &IF_MATCH_NAME)
        .ok_or(PublicError::InvalidRequest)
        .and_then(parse_revision)?;
    let content_type_values: Vec<&HeaderValue> =
        headers.get_all(header::CONTENT_TYPE).iter().collect();
    if content_type_values.len() > 1 {
        return Err(PublicError::UnsupportedMediaType);
    }
    if let Some(content_type) = content_type_values.first() {
        let content_type = content_type
            .to_str()
            .map_err(|_| PublicError::UnsupportedMediaType)?;
        if is_put && content_type != REGISTER_MEDIA_TYPE {
            return Err(PublicError::UnsupportedMediaType);
        }
        if !is_put {
            return Err(PublicError::UnsupportedMediaType);
        }
    } else if is_put {
        return Err(PublicError::UnsupportedMediaType);
    }
    if is_put {
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(PublicError::InvalidPushRegistration);
        }
        parse_push_token(body)?;
    } else if !body.is_empty() {
        return Err(PublicError::InvalidRequest);
    }
    Ok((session, key, revision, body.to_vec()))
}

fn exact_single_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn parse_session(value: &str) -> Result<DeviceSessionCredential, PublicError> {
    let value = value
        .strip_prefix("DTX-Device-Session ")
        .ok_or(PublicError::DeviceAuthenticationFailed)?;
    let (id, secret) = value
        .split_once('.')
        .ok_or(PublicError::DeviceAuthenticationFailed)?;
    if secret.contains('.') || secret.len() != 43 || !secret.bytes().all(is_base64url_byte) {
        return Err(PublicError::DeviceAuthenticationFailed);
    }
    let session_id = id
        .parse::<DeviceSessionId>()
        .map_err(|_| PublicError::DeviceAuthenticationFailed)?;
    if session_id.as_uuid().get_version_num() != 7 {
        return Err(PublicError::DeviceAuthenticationFailed);
    }
    let mut bytes = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(secret, &mut bytes)
        .map_err(|_| PublicError::DeviceAuthenticationFailed)?;
    if decoded.len() != 32 {
        return Err(PublicError::DeviceAuthenticationFailed);
    }
    DeviceSessionCredential::new(session_id, bytes)
        .map_err(|_| PublicError::DeviceAuthenticationFailed)
}

const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || value == b'-'
        || value == b'_'
}

fn parse_idempotency_key(value: &str) -> Result<Vec<u8>, PublicError> {
    if !(16..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&value.len())
        || !value.bytes().all(is_base64url_byte)
    {
        return Err(PublicError::InvalidRequest);
    }
    Ok(value.as_bytes().to_vec())
}

fn parse_revision(value: &str) -> Result<u64, PublicError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(PublicError::InvalidRequest);
    }
    let revision = value
        .parse::<u64>()
        .map_err(|_| PublicError::InvalidRequest)?;
    if revision > MAX_SAFE_UINT {
        return Err(PublicError::InvalidRequest);
    }
    Ok(revision)
}

fn parse_push_token(body: &[u8]) -> Result<dtx_opaque_push::SecretToken, PublicError> {
    if body.len() < 5 || body[0] != 0xa2 || body[1] != 0x01 || body[2] != 0x01 || body[3] != 0x02 {
        return Err(PublicError::InvalidPushRegistration);
    }
    let (length, data_start): (usize, usize) = match body[4] {
        value @ 0x41..=0x57 => (usize::from(value - 0x40), 5),
        0x58 => (
            usize::from(*body.get(5).ok_or(PublicError::InvalidPushRegistration)?),
            6,
        ),
        0x59 => {
            let high = usize::from(*body.get(5).ok_or(PublicError::InvalidPushRegistration)?);
            let low = usize::from(*body.get(6).ok_or(PublicError::InvalidPushRegistration)?);
            ((high << 8) | low, 7)
        }
        _ => return Err(PublicError::InvalidPushRegistration),
    };
    if !(1..=4096).contains(&length) || data_start.saturating_add(length) != body.len() {
        return Err(PublicError::InvalidPushRegistration);
    }
    if body[4] == 0x58 && length < 24 {
        return Err(PublicError::InvalidPushRegistration);
    }
    if body[4] == 0x59 && length < 256 {
        return Err(PublicError::InvalidPushRegistration);
    }
    dtx_opaque_push::SecretToken::new(body[data_start..].to_vec())
        .map_err(|_| PublicError::InvalidPushRegistration)
}

fn request_digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

pub struct Cancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

#[derive(Default)]
pub struct Readiness {
    pools: AtomicBool,
    broker: AtomicBool,
    router: AtomicBool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupStep {
    SecureLoads,
    PrivilegeDrop,
    Pools,
    Provider,
    Listeners,
}

pub const STARTUP_ORDER: &[StartupStep] = &[
    StartupStep::SecureLoads,
    StartupStep::PrivilegeDrop,
    StartupStep::Pools,
    StartupStep::Provider,
    StartupStep::Listeners,
];

#[derive(Default)]
pub struct StartupTrace {
    steps: Vec<StartupStep>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupOrderError;

impl StartupTrace {
    pub fn record(&mut self, step: StartupStep) -> Result<(), StartupOrderError> {
        if STARTUP_ORDER.get(self.steps.len()) != Some(&step) {
            return Err(StartupOrderError);
        }
        self.steps.push(step);
        Ok(())
    }
    pub fn steps(&self) -> &[StartupStep] {
        &self.steps
    }
}

impl Readiness {
    pub fn mark_pools_ready(&self) {
        self.pools.store(true, Ordering::Release);
    }
    pub fn mark_broker_ready(&self) {
        self.broker.store(true, Ordering::Release);
    }
    pub fn mark_router_ready(&self) {
        self.router.store(true, Ordering::Release);
    }
    pub fn is_ready(&self) -> bool {
        self.pools.load(Ordering::Acquire)
            && self.broker.load(Ordering::Acquire)
            && self.router.load(Ordering::Acquire)
    }
}

impl Cancellation {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub async fn run_broker_loop<S, K, P>(
    broker: dtx_opaque_push::Broker<S, K, P>,
    cancellation: Arc<Cancellation>,
    interval: Duration,
) where
    S: dtx_opaque_push::PushPersistence,
    K: dtx_security::KeyManagement,
    P: dtx_opaque_push::PushProvider,
{
    let interval = interval.max(Duration::from_millis(10));
    let mut ticker = tokio::time::interval(interval);
    while !cancellation.is_cancelled() {
        tokio::select! {
            _ = ticker.tick() => { let _ = broker.process_once(dtx_opaque_push::MAX_CLAIM_BATCH).await; }
            () = cancellation.notify.notified() => break,
        }
    }
}

pub async fn run_prune_loop(
    persistence: dtx_opaque_push_postgres::PostgresPushPersistence,
    cancellation: Arc<Cancellation>,
) {
    let mut ticker = tokio::time::interval(Duration::from_mins(1));
    while !cancellation.is_cancelled() {
        tokio::select! {
            _ = ticker.tick() => { let _ = persistence.prune(128).await; }
            () = cancellation.notify.notified() => break,
        }
    }
}

pub fn ready_listener(readiness: Arc<Readiness>) -> Router {
    Router::new()
        .route(
            "/local/live",
            axum::routing::get(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/local/ready",
            axum::routing::get(move |State(state): State<Arc<Readiness>>| async move {
                if state.is_ready() {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        )
        .with_state(readiness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, header},
    };
    use dtx_opaque_push::{RedactedReceipt, RegistrationState};
    use std::sync::Mutex;
    use tower::ServiceExt;

    struct FakeBackend {
        result: Mutex<Option<Result<RegistrationResult, AdapterError>>>,
    }

    impl RegistrationBackend for FakeBackend {
        fn mutate<'a>(
            &'a self,
            _request: RegistrationRequest,
        ) -> Pin<Box<dyn Future<Output = Result<RegistrationResult, AdapterError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.result
                    .lock()
                    .expect("test mutex")
                    .take()
                    .expect("one call")
            })
        }
    }

    fn receipt(state: RegistrationState) -> Vec<u8> {
        RedactedReceipt::new(1, state)
            .expect("test receipt")
            .canonical_cbor()
    }

    fn session_header() -> String {
        let id = DeviceSessionId::new();
        let encoded = Base64UrlUnpadded::encode_string(&[7_u8; 32]);
        format!("DTX-Device-Session {id}.{encoded}")
    }

    fn put_request() -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(PUSH_PATH)
            .header(DEVICE_SESSION_HEADER, session_header())
            .header(IDEMPOTENCY_HEADER, "abcdefghijklmnop")
            .header(IF_MATCH_HEADER, "0")
            .header(header::CONTENT_TYPE, REGISTER_MEDIA_TYPE)
            .body(Body::from(vec![0xa2, 1, 1, 2, 0x41, b'x']))
            .expect("test request")
    }

    #[tokio::test]
    async fn router_preserves_typed_statuses_receipt_bytes_and_common_headers() {
        for (result, status) in [
            (
                RegistrationResult::Created {
                    receipt: receipt(RegistrationState::Active),
                },
                StatusCode::CREATED,
            ),
            (
                RegistrationResult::Updated {
                    receipt: receipt(RegistrationState::Active),
                },
                StatusCode::OK,
            ),
            (
                RegistrationResult::Replay {
                    receipt: receipt(RegistrationState::Active),
                },
                StatusCode::OK,
            ),
            (
                RegistrationResult::Revoked {
                    receipt: receipt(RegistrationState::Revoked),
                },
                StatusCode::OK,
            ),
        ] {
            let expected = result.receipt().to_vec();
            let app = router(PushRouterState::new(
                Arc::new(FakeBackend {
                    result: Mutex::new(Some(Ok(result))),
                }),
                TenantId::new(),
            ));
            let response = app.oneshot(put_request()).await.expect("response");
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            assert_eq!(response.headers()[header::CONTENT_TYPE], RECEIPT_MEDIA_TYPE);
            let request_id = response.headers()["x-request-id"]
                .to_str()
                .expect("request id")
                .parse::<Uuid>()
                .expect("uuid");
            assert_eq!(request_id.get_version_num(), 7);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), MAX_REQUEST_BODY_BYTES)
                    .await
                    .expect("body"),
                expected
            );
        }
    }

    #[tokio::test]
    async fn router_exposes_all_stable_error_mappings_without_details() {
        let errors = [
            (
                AdapterError::Auth,
                StatusCode::UNAUTHORIZED,
                "DEVICE_AUTHENTICATION_FAILED",
            ),
            (
                AdapterError::Conflict,
                StatusCode::CONFLICT,
                "REVISION_OR_IDEMPOTENCY_CONFLICT",
            ),
            (
                AdapterError::Identity(
                    dtx_identity_persistence::IdentityPersistenceError::DeviceSessionRevoked,
                ),
                StatusCode::GONE,
                "DEVICE_SESSION_REVOKED",
            ),
            (
                AdapterError::Malformed,
                StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_PUSH_REGISTRATION",
            ),
            (
                AdapterError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "PUSH_SERVICE_UNAVAILABLE",
            ),
            (
                AdapterError::Fence,
                StatusCode::SERVICE_UNAVAILABLE,
                "PUSH_SERVICE_UNAVAILABLE",
            ),
        ];
        for (error, status, code) in errors {
            let app = router(PushRouterState::new(
                Arc::new(FakeBackend {
                    result: Mutex::new(Some(Err(error))),
                }),
                TenantId::new(),
            ));
            let response = app.oneshot(put_request()).await.expect("response");
            assert_eq!(response.status(), status);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .expect("body");
            assert!(std::str::from_utf8(&body).expect("json").contains(code));
            assert!(!std::str::from_utf8(&body).expect("json").contains("secret"));
        }
    }

    #[tokio::test]
    async fn parser_rejects_authorization_duplicates_media_encoding_and_noncanonical_cbor() {
        let app = router(PushRouterState::new(
            Arc::new(FakeBackend {
                result: Mutex::new(None),
            }),
            TenantId::new(),
        ));
        let mut request = put_request();
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer forbidden"),
        );
        assert_eq!(
            app.clone()
                .oneshot(request)
                .await
                .expect("response")
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut request = put_request();
        request.headers_mut().append(
            HeaderName::from_static("idempotency-key"),
            HeaderValue::from_static("abcdefghijklmnop"),
        );
        assert_eq!(
            app.clone()
                .oneshot(request)
                .await
                .expect("response")
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut request = put_request();
        request
            .headers_mut()
            .insert(CONTENT_ENCODING_NAME, HeaderValue::from_static("gzip"));
        assert_eq!(
            app.clone()
                .oneshot(request)
                .await
                .expect("response")
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let mut request = put_request();
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        assert_eq!(
            app.clone()
                .oneshot(request)
                .await
                .expect("response")
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let mut request = put_request();
        *request.body_mut() = Body::from(vec![0xa2, 1, 1, 2, 0x18, 1, b'x']);
        assert_eq!(
            app.oneshot(request).await.expect("response").status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn readiness_requires_all_components_and_cancellation_is_fail_closed() {
        let readiness = Readiness::default();
        assert!(!readiness.is_ready());
        readiness.mark_pools_ready();
        readiness.mark_broker_ready();
        assert!(!readiness.is_ready());
        readiness.mark_router_ready();
        assert!(readiness.is_ready());
        let cancellation = Cancellation::new();
        assert!(!cancellation.is_cancelled());
        cancellation.cancel();
        assert!(cancellation.is_cancelled());
        assert_eq!(STARTUP_ORDER[0], StartupStep::SecureLoads);
        assert_eq!(STARTUP_ORDER[1], StartupStep::PrivilegeDrop);
        assert_eq!(STARTUP_ORDER[2], StartupStep::Pools);
        assert_eq!(STARTUP_ORDER[3], StartupStep::Provider);
        assert_eq!(STARTUP_ORDER[4], StartupStep::Listeners);
        let mut trace = StartupTrace::default();
        trace.record(StartupStep::SecureLoads).expect("secure load");
        assert!(trace.record(StartupStep::Pools).is_err());
        assert_eq!(trace.steps(), &[StartupStep::SecureLoads]);
        trace.record(StartupStep::PrivilegeDrop).expect("drop");
        trace.record(StartupStep::Pools).expect("pools");
    }

    #[test]
    fn parser_enforces_canonical_revision_and_cbor() {
        assert_eq!(parse_revision("0"), Ok(0));
        assert!(parse_revision("01").is_err());
        assert!(parse_revision("+1").is_err());
        assert!(parse_push_token(&[0xa2, 1, 1, 2, 0x41, b'x']).is_ok());
        assert!(parse_push_token(&[0xa2, 1, 1, 2, 0x18, 1, b'x']).is_err());
        let body = [0xa2, 1, 1, 2, 0x41, b'x'];
        let expected: [u8; 32] = Sha256::digest(body).into();
        assert_eq!(request_digest(&body), expected);
    }

    #[test]
    fn error_mapping_keeps_identity_fence_retryable() {
        assert_eq!(
            map_adapter_error(&AdapterError::Fence),
            PublicError::PushServiceUnavailable
        );
    }
}
