#![forbid(unsafe_code)]

//! First self-authenticated HTTP boundary for the vNext identity service.
//!
//! This crate exposes only the self-authenticated genesis, the root-authorized
//! first device, and active-device short sessions. QR enrollment and other
//! non-genesis appends need their own durable challenge and credential
//! contracts; accepting a generic bearer token here would weaken the
//! self-certifying identity boundary.

use std::{str::FromStr, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, DeviceId, DeviceSessionChallengeId, DeviceSessionId, IdentityId, RequestId, SystemClock,
};
use dtx_identity_log::{IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1, IdentityLogEventV1};
use dtx_identity_persistence::{
    DeviceSessionCompletionCommand, DeviceSessionCredential, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository,
    IdentityPersistenceError, IdentityPgStore,
};
use dtx_wire::{Ed25519Signature, Sha256Digest, UtcMillis};
use getrandom::fill as fill_random;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroize;

/// Route for the self-authenticated identity genesis request.
pub const IDENTITY_BOOTSTRAP_PATH: &str = "/v1/identity/bootstrap";
/// Route for the root-authorized first device after genesis.
pub const INITIAL_DEVICE_ENROLL_PATH: &str = "/v1/devices/initial-enroll";
/// Route that starts an active-device signature challenge.
pub const DEVICE_SESSION_CHALLENGE_PATH: &str = "/v1/devices/sessions/challenges";
/// Route that exchanges a device signature for a short-lived session.
pub const DEVICE_SESSION_PATH: &str = "/v1/devices/sessions";
/// Required media type for exact signed V1.1 identity-log events.
pub const IDENTITY_LOG_EVENT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-log.v1.1+cbor";
/// Response media type for immutable canonical append receipts.
pub const IDENTITY_APPEND_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-append-receipt.v1+cbor";
/// Response media type for immutable canonical device-session receipts.
pub const DEVICE_SESSION_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-session-receipt.v1+cbor";
/// Exact authorization scheme for short-lived device sessions.
pub const DEVICE_SESSION_AUTHORIZATION_SCHEME: &str = "DTX-Device-Session";
/// Largest accepted exact genesis event body.
pub const MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES: usize = 1_048_576;
/// Largest accepted JSON device-session request body.
pub const MAX_DEVICE_SESSION_REQUEST_BYTES: usize = 16_384;

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-bootstrap-http-idempotency-key.v1\0";
const HTTP_INITIAL_DEVICE_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-initial-device-http-idempotency-key.v1\0";
const HTTP_DEVICE_SESSION_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-session-http-idempotency-key.v1\0";
const DEFAULT_DEVICE_SESSION_AUDIENCE: &str = "http://127.0.0.1";

/// State for bootstrap, first-device, and short device-session HTTP boundaries.
#[derive(Clone)]
pub struct IdentityBootstrapState {
    store: IdentityPgStore,
    repository: IdentityLogRepository,
    device_sessions: DeviceSessionRepository,
    clock: Arc<dyn Clock>,
    device_session_audience: Arc<str>,
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
        Self::with_clock_and_device_session_audience(store, clock, DEFAULT_DEVICE_SESSION_AUDIENCE)
    }

    /// Creates state with a fixed server-owned audience for device proofs.
    ///
    /// The current binary is loopback-only; a future public TLS host must set
    /// a unique canonical HTTPS audience rather than sharing this local value.
    #[must_use]
    pub fn with_clock_and_device_session_audience(
        store: IdentityPgStore,
        clock: Arc<dyn Clock>,
        audience: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            store,
            repository: IdentityLogRepository::new(),
            device_sessions: DeviceSessionRepository,
            clock,
            device_session_audience: audience.into(),
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
        .route(INITIAL_DEVICE_ENROLL_PATH, post(enroll_initial_device))
        .route(
            DEVICE_SESSION_CHALLENGE_PATH,
            post(create_device_session_challenge),
        )
        .route(DEVICE_SESSION_PATH, post(complete_device_session))
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

async fn enroll_initial_device(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.enroll_initial_device(&parts.headers, body).await {
        Ok(success) => initial_device_success_response(success, request_id),
        Err(failure) => initial_device_failure_response(failure, request_id),
    }
}

async fn create_device_session_challenge(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .create_device_session_challenge(&parts.headers, body)
        .await
    {
        Ok(challenge) => device_session_challenge_success_response(&challenge, request_id),
        Err(failure) => device_session_failure_response(failure, request_id),
    }
}

async fn complete_device_session(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.complete_device_session(&parts.headers, body).await {
        Ok(success) => device_session_success_response(success, request_id),
        Err(failure) => device_session_failure_response(failure, request_id),
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
        let idempotency_key_hash = idempotency_key_hash(headers, HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN)?;
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

    async fn enroll_initial_device(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<InitialDeviceSuccess, InitialDeviceFailure> {
        if !has_exact_event_content_type(headers) || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(InitialDeviceFailure::InvalidInitialDevice);
        }
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_INITIAL_DEVICE_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| InitialDeviceFailure::InvalidInitialDevice)?;
        let expected_genesis_hash = expected_genesis_hash(headers)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| InitialDeviceFailure::InvalidInitialDevice)?;
        if exact_event_bytes.is_empty() {
            return Err(InitialDeviceFailure::InvalidInitialDevice);
        }
        let committed_at = self
            .committed_at()
            .map_err(|()| InitialDeviceFailure::TemporarilyUnavailable)?;
        match self
            .repository
            .append_initial_device(
                &self.store,
                idempotency_key_hash,
                expected_genesis_hash,
                exact_event_bytes.to_vec(),
                committed_at,
            )
            .await
        {
            Ok(IdentityAppendOutcome::Committed(receipt)) => Ok(InitialDeviceSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Replayed(receipt)) => Ok(InitialDeviceSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(InitialDeviceFailure::IdentityConflict),
            Err(error) => Err(map_initial_device_persistence_error(&error)),
        }
    }

    async fn create_device_session_challenge(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceSessionChallengeResponse, DeviceSessionFailure> {
        if !has_exact_json_content_type(headers)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
        {
            return Err(DeviceSessionFailure::InvalidRequest);
        }
        let request: DeviceSessionChallengeRequest = parse_json_body(body).await?;
        let mut nonce = [0_u8; 32];
        fill_random(&mut nonce).map_err(|_| DeviceSessionFailure::TemporarilyUnavailable)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceSessionFailure::TemporarilyUnavailable)?;
        let challenge = self
            .device_sessions
            .issue_challenge(
                &self.store,
                request.identity_id,
                request.device_id,
                nonce,
                &self.device_session_audience,
                now,
            )
            .await
            .map_err(|error| map_device_session_persistence_error(&error))?;
        Ok(DeviceSessionChallengeResponse::from(challenge))
    }

    async fn complete_device_session(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceSessionSuccess, DeviceSessionFailure> {
        if !has_exact_json_content_type(headers)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
        {
            return Err(DeviceSessionFailure::InvalidRequest);
        }
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_DEVICE_SESSION_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
        let mut request: DeviceSessionCompletionRequest = parse_json_body(body).await?;
        let challenge_nonce = decode_base64url_32(&request.challenge_nonce)?;
        let session_secret = decode_base64url_32(&request.session_secret)?;
        request.challenge_nonce.zeroize();
        request.session_secret.zeroize();
        let command = DeviceSessionCompletionCommand::new(
            idempotency_key_hash,
            request.identity_id,
            request.device_id,
            request.challenge_id,
            request.session_id,
            challenge_nonce,
            session_secret,
            request.proof,
        )
        .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceSessionFailure::TemporarilyUnavailable)?;
        match self
            .device_sessions
            .complete(&self.store, &command, now)
            .await
            .map_err(|error| map_device_session_persistence_error(&error))?
        {
            DeviceSessionOutcome::Issued(receipt) => Ok(DeviceSessionSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            DeviceSessionOutcome::Replayed(receipt) => Ok(DeviceSessionSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
        }
    }

    fn committed_at(&self) -> Result<UtcMillis, ()> {
        UtcMillis::new(self.clock.now_utc_millis().map_err(|_| ())?).map_err(|_| ())
    }
}

fn has_exact_event_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == IDENTITY_LOG_EVENT_CONTENT_TYPE.as_bytes())
        && values.next().is_none()
}

fn idempotency_key_hash(
    headers: &HeaderMap,
    domain: &[u8],
) -> Result<Sha256Digest, BootstrapFailure> {
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
    Ok(Sha256Digest::hash_domain(domain, bytes))
}

fn expected_genesis_hash(headers: &HeaderMap) -> Result<Sha256Digest, InitialDeviceFailure> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(InitialDeviceFailure::InvalidInitialDevice);
    };
    if values.next().is_some() {
        return Err(InitialDeviceFailure::InvalidInitialDevice);
    }
    let value = value
        .to_str()
        .map_err(|_| InitialDeviceFailure::InvalidInitialDevice)?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(InitialDeviceFailure::InvalidInitialDevice)?;
    Sha256Digest::from_str(value).map_err(|_| InitialDeviceFailure::InvalidInitialDevice)
}

fn has_exact_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == b"application/json")
        && values.next().is_none()
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
        | IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::CorruptData(_) => BootstrapFailure::TemporarilyUnavailable,
    }
}

fn map_initial_device_persistence_error(error: &IdentityPersistenceError) -> InitialDeviceFailure {
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
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::CorruptData(_) => InitialDeviceFailure::TemporarilyUnavailable,
    }
}

fn map_device_session_persistence_error(error: &IdentityPersistenceError) -> DeviceSessionFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            DeviceSessionFailure::InvalidRequest
        }
        IdentityPersistenceError::IdempotencyConflict => DeviceSessionFailure::IdempotencyConflict,
        IdentityPersistenceError::DeviceAuthenticationRejected
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
        | IdentityPersistenceError::CorruptData(_) => DeviceSessionFailure::TemporarilyUnavailable,
    }
}

async fn parse_json_body<T>(body: Body) -> Result<T, DeviceSessionFailure>
where
    T: DeserializeOwned,
{
    let bytes = to_bytes(body, MAX_DEVICE_SESSION_REQUEST_BYTES)
        .await
        .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
    if bytes.is_empty() {
        return Err(DeviceSessionFailure::InvalidRequest);
    }
    serde_json::from_slice(&bytes).map_err(|_| DeviceSessionFailure::InvalidRequest)
}

fn decode_base64url_32(value: &str) -> Result<[u8; 32], DeviceSessionFailure> {
    if value.len() != 43 || !value.bytes().all(is_base64url_byte) {
        return Err(DeviceSessionFailure::InvalidRequest);
    }
    let mut buffer = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(value, &mut buffer)
        .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
    if decoded.len() != 32 {
        buffer.zeroize();
        return Err(DeviceSessionFailure::InvalidRequest);
    }
    let result = buffer;
    Ok(result)
}

/// Strictly parses an opaque short-lived device-session capability.
///
/// The returned credential owns a zeroizing secret buffer. Callers still must
/// invoke [`DeviceSessionRepository::authenticate`] within their own durable
/// authorization transaction; parsing a header alone never authorizes a
/// request.
///
/// # Errors
///
/// Rejects missing, duplicate, malformed, noncanonical, or all-zero values
/// without reflecting the credential in an error response.
pub fn parse_device_session_authorization(
    headers: &HeaderMap,
) -> Result<DeviceSessionCredential, DeviceSessionAuthorizationError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(DeviceSessionAuthorizationError);
    };
    if values.next().is_some() {
        return Err(DeviceSessionAuthorizationError);
    }
    let value = value
        .to_str()
        .map_err(|_| DeviceSessionAuthorizationError)?;
    let prefix = format!("{DEVICE_SESSION_AUTHORIZATION_SCHEME} ");
    let value = value
        .strip_prefix(&prefix)
        .ok_or(DeviceSessionAuthorizationError)?;
    let (session_id, secret) = value
        .split_once('.')
        .ok_or(DeviceSessionAuthorizationError)?;
    if secret.contains('.') {
        return Err(DeviceSessionAuthorizationError);
    }
    let session_id = session_id
        .parse::<DeviceSessionId>()
        .map_err(|_| DeviceSessionAuthorizationError)?;
    let secret = decode_base64url_32(secret).map_err(|_| DeviceSessionAuthorizationError)?;
    DeviceSessionCredential::new(session_id, secret).map_err(|_| DeviceSessionAuthorizationError)
}

/// Opaque parser failure for a short-lived session capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSessionAuthorizationError;

impl std::fmt::Display for DeviceSessionAuthorizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid device session authorization")
    }
}

impl std::error::Error for DeviceSessionAuthorizationError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionChallengeRequest {
    identity_id: IdentityId,
    device_id: DeviceId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSessionCompletionRequest {
    identity_id: IdentityId,
    device_id: DeviceId,
    challenge_id: DeviceSessionChallengeId,
    session_id: DeviceSessionId,
    challenge_nonce: String,
    session_secret: String,
    proof: Ed25519Signature,
}

#[derive(Serialize)]
struct DeviceSessionChallengeResponse {
    challenge_id: DeviceSessionChallengeId,
    identity_id: IdentityId,
    device_id: DeviceId,
    challenge_nonce: String,
    audience: String,
    expires_at_ms: i64,
    session_expires_at_ms: i64,
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

struct InitialDeviceSuccess {
    status: StatusCode,
    exact_receipt_bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum InitialDeviceFailure {
    InvalidInitialDevice,
    IdempotencyConflict,
    IdentityConflict,
    TemporarilyUnavailable,
}

struct DeviceSessionSuccess {
    status: StatusCode,
    exact_receipt_bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum DeviceSessionFailure {
    InvalidRequest,
    AuthenticationRejected,
    ChallengeExpired,
    ChallengeConsumed,
    ChallengeRateLimited,
    IdempotencyConflict,
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

#[derive(Clone, Copy, Serialize)]
enum InitialDeviceErrorCode {
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
enum DeviceSessionErrorCode {
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

#[derive(Serialize)]
struct SafeErrorEnvelope<C> {
    error: SafeErrorBody<C>,
}

#[derive(Serialize)]
struct SafeErrorBody<C> {
    code: C,
    request_id: RequestId,
    retryable: bool,
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

fn initial_device_success_response(
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

fn initial_device_failure_response(
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

fn device_session_challenge_success_response(
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

fn device_session_success_response(
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

fn device_session_failure_response(
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

fn exact_cbor_response(
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

fn safe_error_response<C>(
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
