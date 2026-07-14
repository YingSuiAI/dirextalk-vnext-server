#![forbid(unsafe_code)]

//! First self-authenticated HTTP boundary for the vNext identity service.
//!
//! This crate exposes the self-authenticated genesis, root-authorized first
//! device, active-device short sessions, and capability-gated QR enrollment
//! for one additional device. Other non-genesis appends still need their own
//! durable challenge and credential contracts; accepting a generic bearer
//! token here would weaken the self-certifying identity boundary.

use std::{str::FromStr, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{post, put},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionChallengeId, DeviceSessionId,
    IdentityId, KeyPackageId, RequestId, SystemClock,
};
use dtx_identity_log::{
    DeviceEncryptionPublicKey, IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1,
    IdentityLogEventV1,
};
use dtx_identity_persistence::{
    CreateDeviceEnrollmentChallengeCommand, DeviceEnrollmentApprovalCommand,
    DeviceEnrollmentCapability, DeviceEnrollmentChallenge, DeviceEnrollmentChallengeOutcome,
    DeviceEnrollmentChallengeState, DeviceEnrollmentChallengeStatus, DeviceEnrollmentRepository,
    DeviceSessionCompletionCommand, DeviceSessionCredential, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository,
    IdentityPersistenceError, IdentityPgStore, KeyPackageClaimCommand, KeyPackageClaimOutcome,
    KeyPackagePublishCommand, KeyPackagePublishOutcome, KeyPackageRepository,
    MAX_KEY_PACKAGE_PUBLISH_BYTES,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
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
/// Candidate-created five-minute QR enrollment challenge route.
pub const DEVICE_ENROLLMENT_CHALLENGE_PATH: &str = "/v1/devices/enroll/challenges";
/// Capability-gated QR enrollment status and cancellation route.
pub const DEVICE_ENROLLMENT_CHALLENGE_STATUS_PATH: &str =
    "/v1/devices/enroll/challenges/{challenge_id}";
/// Active-device approval route for a candidate QR enrollment challenge.
pub const DEVICE_ENROLLMENT_PATH: &str = "/v1/devices/enroll";
/// Route template that accepts one exact opaque `KeyPackage` publish envelope.
pub const KEY_PACKAGE_PUBLISH_PATH_TEMPLATE: &str = "/v1/key-packages/{package_id}";
/// Route that atomically consumes one opaque `KeyPackage` for a target device.
pub const KEY_PACKAGE_CLAIM_PATH: &str = "/v1/key-packages/claim";
/// Required media type for exact signed V1.1 identity-log events.
pub const IDENTITY_LOG_EVENT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-log.v1.1+cbor";
/// Response media type for immutable canonical append receipts.
pub const IDENTITY_APPEND_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-append-receipt.v1+cbor";
/// Response media type for immutable canonical device-session receipts.
pub const DEVICE_SESSION_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-session-receipt.v1+cbor";
/// Exact candidate challenge request media type.
pub const DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-enrollment-candidate.v1+cbor";
/// Capability-gated enrollment status response media type.
pub const DEVICE_ENROLLMENT_STATUS_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-enrollment-status.v1+cbor";
/// Exact active-device enrollment approval request media type.
pub const DEVICE_ENROLLMENT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-enrollment.v1+cbor";
/// Exact signed opaque `KeyPackage` publish request media type.
pub const KEY_PACKAGE_PUBLISH_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-publish.v1+cbor";
/// Immutable `KeyPackage` publish receipt media type.
pub const KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-publish-receipt.v1+cbor";
/// Exact `KeyPackage` target claim request media type.
pub const KEY_PACKAGE_CLAIM_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-claim.v1+cbor";
/// Exact original publish envelope returned by a one-time claim.
pub const KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-claim-receipt.v1+cbor";
/// Header that carries a candidate-owned status/cancellation capability.
pub const DEVICE_ENROLLMENT_CAPABILITY_HEADER: &str = "DTX-Enrollment-Capability";
/// Exact authorization scheme for short-lived device sessions.
pub const DEVICE_SESSION_AUTHORIZATION_SCHEME: &str = "DTX-Device-Session";
/// Largest accepted exact genesis event body.
pub const MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES: usize = 1_048_576;
/// Largest accepted JSON device-session request body.
pub const MAX_DEVICE_SESSION_REQUEST_BYTES: usize = 16_384;
/// Largest accepted exact candidate enrollment request body.
pub const MAX_DEVICE_ENROLLMENT_CANDIDATE_BYTES: usize = 16_384;
/// Largest accepted exact enrollment approval body.
pub const MAX_DEVICE_ENROLLMENT_COMPLETION_BYTES: usize = 1_048_576;
/// Largest accepted exact `KeyPackage` target claim body.
pub const MAX_KEY_PACKAGE_CLAIM_BYTES: usize = 16_384;

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
const HTTP_DEVICE_ENROLLMENT_CHALLENGE_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-http-challenge-idempotency-key.v1\0";
const HTTP_DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-http-approval-idempotency-key.v1\0";
const HTTP_KEY_PACKAGE_PUBLISH_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-http-publish-idempotency-key.v1\0";
const HTTP_KEY_PACKAGE_CLAIM_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-http-claim-idempotency-key.v1\0";
const DEFAULT_DEVICE_SESSION_AUDIENCE: &str = "http://127.0.0.1";

/// State for bootstrap, device-session, and QR device-enrollment HTTP boundaries.
#[derive(Clone)]
pub struct IdentityBootstrapState {
    store: IdentityPgStore,
    repository: IdentityLogRepository,
    device_sessions: DeviceSessionRepository,
    device_enrollments: DeviceEnrollmentRepository,
    key_packages: KeyPackageRepository,
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
            device_enrollments: DeviceEnrollmentRepository,
            key_packages: KeyPackageRepository::new(),
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
        .route(
            DEVICE_ENROLLMENT_CHALLENGE_PATH,
            post(create_device_enrollment_challenge),
        )
        .route(
            DEVICE_ENROLLMENT_CHALLENGE_STATUS_PATH,
            axum::routing::get(get_device_enrollment_challenge)
                .delete(cancel_device_enrollment_challenge),
        )
        .route(DEVICE_ENROLLMENT_PATH, post(approve_device_enrollment))
        .route(KEY_PACKAGE_PUBLISH_PATH_TEMPLATE, put(publish_key_package))
        .route(KEY_PACKAGE_CLAIM_PATH, post(claim_key_package))
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

async fn create_device_enrollment_challenge(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .create_device_enrollment_challenge(&parts.headers, body)
        .await
    {
        Ok(success) => device_enrollment_challenge_success_response(&success, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

async fn get_device_enrollment_challenge(
    State(state): State<IdentityBootstrapState>,
    Path(challenge_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .get_device_enrollment_challenge(&challenge_id, &parts.headers, body)
        .await
    {
        Ok(status) => device_enrollment_status_response(status, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

async fn cancel_device_enrollment_challenge(
    State(state): State<IdentityBootstrapState>,
    Path(challenge_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .cancel_device_enrollment_challenge(&challenge_id, &parts.headers, body)
        .await
    {
        Ok(status) => device_enrollment_status_response(status, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

async fn approve_device_enrollment(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.approve_device_enrollment(&parts.headers, body).await {
        Ok(success) => device_enrollment_approval_success_response(success, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

async fn publish_key_package(
    State(state): State<IdentityBootstrapState>,
    Path(package_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .publish_key_package(&package_id, &parts.headers, body)
        .await
    {
        Ok(success) => key_package_publish_success_response(success, request_id),
        Err(failure) => key_package_failure_response(failure, request_id),
    }
}

async fn claim_key_package(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.claim_key_package(&parts.headers, body).await {
        Ok(success) => key_package_claim_success_response(success, request_id),
        Err(failure) => key_package_failure_response(failure, request_id),
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

    async fn create_device_enrollment_challenge(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentChallengeSuccess, DeviceEnrollmentFailure> {
        if !has_exact_content_type(headers, DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        }
        let idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_DEVICE_ENROLLMENT_CHALLENGE_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_DEVICE_ENROLLMENT_CANDIDATE_BYTES)
            .await
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let candidate = parse_device_enrollment_candidate(&bytes)?;
        let command = CreateDeviceEnrollmentChallengeCommand::new(
            idempotency_key_hash,
            candidate.identity_id,
            candidate.target_device_id,
            candidate.target_device_signing_key,
            candidate.target_device_encryption_key,
            candidate.capability,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        match self
            .device_enrollments
            .create_challenge(&self.store, command, now)
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))?
        {
            DeviceEnrollmentChallengeOutcome::Created(challenge) => {
                Ok(DeviceEnrollmentChallengeSuccess {
                    status: StatusCode::CREATED,
                    challenge,
                })
            }
            DeviceEnrollmentChallengeOutcome::Replayed(challenge) => {
                Ok(DeviceEnrollmentChallengeSuccess {
                    status: StatusCode::OK,
                    challenge,
                })
            }
        }
    }

    async fn get_device_enrollment_challenge(
        &self,
        challenge_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentChallengeStatus, DeviceEnrollmentFailure> {
        let (challenge_id, capability) =
            parse_device_enrollment_status_request(challenge_id, headers, body).await?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        self.device_enrollments
            .status(&self.store, challenge_id, capability, now)
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))
    }

    async fn cancel_device_enrollment_challenge(
        &self,
        challenge_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentChallengeStatus, DeviceEnrollmentFailure> {
        let (challenge_id, capability) =
            parse_device_enrollment_status_request(challenge_id, headers, body).await?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        self.device_enrollments
            .cancel(&self.store, challenge_id, capability, now)
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))
    }

    async fn approve_device_enrollment(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentApprovalSuccess, DeviceEnrollmentFailure> {
        if !has_exact_content_type(headers, DEVICE_ENROLLMENT_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| DeviceEnrollmentFailure::AuthenticationRejected)?;
        let approval_idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let expected_head_hash =
            expected_genesis_hash(headers).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_DEVICE_ENROLLMENT_COMPLETION_BYTES)
            .await
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let completion = parse_device_enrollment_completion(&bytes)?;
        let command = DeviceEnrollmentApprovalCommand::new(
            approval_idempotency_key_hash,
            completion.challenge_id,
            completion.capability,
            expected_head_hash,
            completion.exact_device_add_bytes,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        match self
            .device_enrollments
            .approve(&self.store, command, credential, now)
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))?
        {
            IdentityAppendOutcome::Committed(receipt) => Ok(DeviceEnrollmentApprovalSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Replayed(receipt) => Ok(DeviceEnrollmentApprovalSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Forked { .. } => Err(DeviceEnrollmentFailure::IdentityConflict),
        }
    }

    async fn publish_key_package(
        &self,
        route_package_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<KeyPackagePublishSuccess, KeyPackageFailure> {
        if !has_exact_content_type(headers, KEY_PACKAGE_PUBLISH_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
        let idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_KEY_PACKAGE_PUBLISH_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let route_package_id = route_package_id
            .parse::<KeyPackageId>()
            .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_KEY_PACKAGE_PUBLISH_BYTES)
            .await
            .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let publish = parse_key_package_publish(&bytes)?;
        if publish.package_id != route_package_id {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let command = KeyPackagePublishCommand::new(
            idempotency_key_hash,
            publish.identity_id,
            publish.device_id,
            publish.package_id,
            publish.published_head_sequence,
            publish.published_head_hash,
            publish.expires_at,
            publish.opaque_key_package,
            publish.detached_signature,
            bytes.to_vec(),
        )
        .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| KeyPackageFailure::TemporarilyUnavailable)?;
        match self
            .key_packages
            .publish(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_key_package_persistence_error(&error))?
        {
            KeyPackagePublishOutcome::Published(receipt) => Ok(KeyPackagePublishSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            KeyPackagePublishOutcome::Replayed(receipt) => Ok(KeyPackagePublishSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
        }
    }

    async fn claim_key_package(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<KeyPackageClaimSuccess, KeyPackageFailure> {
        if !has_exact_content_type(headers, KEY_PACKAGE_CLAIM_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_KEY_PACKAGE_CLAIM_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_KEY_PACKAGE_CLAIM_BYTES)
            .await
            .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let claim = parse_key_package_claim(&bytes)?;
        let command = KeyPackageClaimCommand::new(
            idempotency_key_hash,
            claim.target_identity_id,
            claim.target_device_id,
            bytes.to_vec(),
        )
        .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| KeyPackageFailure::TemporarilyUnavailable)?;
        match self
            .key_packages
            .claim(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_key_package_persistence_error(&error))?
        {
            KeyPackageClaimOutcome::Claimed(receipt) => Ok(KeyPackageClaimSuccess {
                status: StatusCode::CREATED,
                exact_publish_bytes: receipt.exact_publish_bytes().to_vec(),
            }),
            KeyPackageClaimOutcome::Replayed(receipt) => Ok(KeyPackageClaimSuccess {
                status: StatusCode::OK,
                exact_publish_bytes: receipt.exact_publish_bytes().to_vec(),
            }),
        }
    }

    fn committed_at(&self) -> Result<UtcMillis, ()> {
        UtcMillis::new(self.clock.now_utc_millis().map_err(|_| ())?).map_err(|_| ())
    }
}

fn has_exact_event_content_type(headers: &HeaderMap) -> bool {
    has_exact_content_type(headers, IDENTITY_LOG_EVENT_CONTENT_TYPE)
}

fn has_exact_content_type(headers: &HeaderMap, expected: &'static str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
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
    has_exact_content_type(headers, "application/json")
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
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
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
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
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
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::CorruptData(_) => DeviceSessionFailure::TemporarilyUnavailable,
    }
}

fn map_device_enrollment_persistence_error(
    error: &IdentityPersistenceError,
) -> DeviceEnrollmentFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            DeviceEnrollmentFailure::InvalidRequest
        }
        IdentityPersistenceError::IdempotencyConflict => {
            DeviceEnrollmentFailure::IdempotencyConflict
        }
        IdentityPersistenceError::DeviceAuthenticationRejected => {
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
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::CorruptData(_) => {
            DeviceEnrollmentFailure::TemporarilyUnavailable
        }
    }
}

fn map_key_package_persistence_error(error: &IdentityPersistenceError) -> KeyPackageFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            KeyPackageFailure::InvalidRequest
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
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
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::CorruptData(_) => KeyPackageFailure::TemporarilyUnavailable,
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

struct DeviceEnrollmentCandidateRequest {
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    target_device_encryption_key: DeviceEncryptionPublicKey,
    capability: DeviceEnrollmentCapability,
}

struct DeviceEnrollmentCompletionRequest {
    challenge_id: DeviceEnrollmentChallengeId,
    capability: DeviceEnrollmentCapability,
    exact_device_add_bytes: Vec<u8>,
}

fn parse_device_enrollment_candidate(
    bytes: &[u8],
) -> Result<DeviceEnrollmentCandidateRequest, DeviceEnrollmentFailure> {
    if bytes.is_empty() {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 6)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let identity_id = parse_cbor_identity_id(cbor_field(fields, 2)?)?;
    let target_device_id = parse_cbor_device_id(cbor_field(fields, 3)?)?;
    let target_device_signing_key =
        SigningPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(fields, 4)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let target_device_encryption_key =
        DeviceEncryptionPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(fields, 5)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let capability =
        DeviceEnrollmentCapability::new(parse_cbor_bytes::<32>(cbor_field(fields, 6)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    Ok(DeviceEnrollmentCandidateRequest {
        identity_id,
        target_device_id,
        target_device_signing_key,
        target_device_encryption_key,
        capability,
    })
}

fn parse_device_enrollment_completion(
    bytes: &[u8],
) -> Result<DeviceEnrollmentCompletionRequest, DeviceEnrollmentFailure> {
    if bytes.is_empty() {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 4)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let challenge_id = parse_cbor_challenge_id(cbor_field(fields, 2)?)?;
    let capability =
        DeviceEnrollmentCapability::new(parse_cbor_bytes::<32>(cbor_field(fields, 3)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let exact_device_add_bytes = match cbor_field(fields, 4)? {
        CanonicalValue::Bytes(value) if !value.is_empty() => value.clone(),
        _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
    };
    Ok(DeviceEnrollmentCompletionRequest {
        challenge_id,
        capability,
        exact_device_add_bytes,
    })
}

struct KeyPackagePublishRequest {
    identity_id: IdentityId,
    device_id: DeviceId,
    package_id: KeyPackageId,
    published_head_sequence: SafeUint,
    published_head_hash: Sha256Digest,
    expires_at: UtcMillis,
    opaque_key_package: Vec<u8>,
    detached_signature: Ed25519Signature,
}

struct KeyPackageClaimRequest {
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
}

fn parse_key_package_publish(bytes: &[u8]) -> Result<KeyPackagePublishRequest, KeyPackageFailure> {
    if bytes.is_empty() {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| KeyPackageFailure::InvalidRequest)?;
    let fields = key_package_cbor_fields(&value, 9)?;
    key_package_require_version(key_package_cbor_field(fields, 1)?)?;
    let identity_id = key_package_parse_identity_id(key_package_cbor_field(fields, 2)?)?;
    let device_id = key_package_parse_device_id(key_package_cbor_field(fields, 3)?)?;
    let package_id = key_package_parse_package_id(key_package_cbor_field(fields, 4)?)?;
    let published_head_sequence = key_package_parse_safe_uint(key_package_cbor_field(fields, 5)?)?;
    let published_head_hash = Sha256Digest::from_bytes(key_package_parse_bytes::<32>(
        key_package_cbor_field(fields, 6)?,
    )?);
    let expires_at = key_package_parse_utc_millis(key_package_cbor_field(fields, 7)?)?;
    let opaque_key_package = match key_package_cbor_field(fields, 8)? {
        CanonicalValue::Bytes(value) if !value.is_empty() => value.clone(),
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    let detached_signature = Ed25519Signature::from_bytes(key_package_parse_bytes::<64>(
        key_package_cbor_field(fields, 9)?,
    )?);
    Ok(KeyPackagePublishRequest {
        identity_id,
        device_id,
        package_id,
        published_head_sequence,
        published_head_hash,
        expires_at,
        opaque_key_package,
        detached_signature,
    })
}

fn parse_key_package_claim(bytes: &[u8]) -> Result<KeyPackageClaimRequest, KeyPackageFailure> {
    if bytes.is_empty() {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| KeyPackageFailure::InvalidRequest)?;
    let fields = key_package_cbor_fields(&value, 3)?;
    key_package_require_version(key_package_cbor_field(fields, 1)?)?;
    Ok(KeyPackageClaimRequest {
        target_identity_id: key_package_parse_identity_id(key_package_cbor_field(fields, 2)?)?,
        target_device_id: key_package_parse_device_id(key_package_cbor_field(fields, 3)?)?,
    })
}

fn key_package_cbor_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], KeyPackageFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(KeyPackageFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

fn key_package_cbor_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, KeyPackageFailure> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(KeyPackageFailure::InvalidRequest)?,
        )
        .map(|(_, value)| value)
        .ok_or(KeyPackageFailure::InvalidRequest)
}

fn key_package_require_version(value: &CanonicalValue) -> Result<(), KeyPackageFailure> {
    if value == &CanonicalValue::Unsigned(1) {
        Ok(())
    } else {
        Err(KeyPackageFailure::InvalidRequest)
    }
}

fn key_package_parse_identity_id(value: &CanonicalValue) -> Result<IdentityId, KeyPackageFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value.parse().map_err(|_| KeyPackageFailure::InvalidRequest)
}

fn key_package_parse_device_id(value: &CanonicalValue) -> Result<DeviceId, KeyPackageFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value.parse().map_err(|_| KeyPackageFailure::InvalidRequest)
}

fn key_package_parse_package_id(value: &CanonicalValue) -> Result<KeyPackageId, KeyPackageFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value.parse().map_err(|_| KeyPackageFailure::InvalidRequest)
}

fn key_package_parse_safe_uint(value: &CanonicalValue) -> Result<SafeUint, KeyPackageFailure> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    SafeUint::new(*value).map_err(|_| KeyPackageFailure::InvalidRequest)
}

fn key_package_parse_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, KeyPackageFailure> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| KeyPackageFailure::InvalidRequest)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    UtcMillis::new(value).map_err(|_| KeyPackageFailure::InvalidRequest)
}

fn key_package_parse_bytes<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], KeyPackageFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(KeyPackageFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| KeyPackageFailure::InvalidRequest)
}

async fn parse_device_enrollment_status_request(
    challenge_id: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<(DeviceEnrollmentChallengeId, DeviceEnrollmentCapability), DeviceEnrollmentFailure> {
    if headers.contains_key(header::CONTENT_TYPE)
        || headers.contains_key(header::CONTENT_ENCODING)
        || headers.contains_key(header::IF_MATCH)
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
    {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    }
    let body = to_bytes(body, 1)
        .await
        .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    if !body.is_empty() {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    }
    let challenge_id = challenge_id
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    let capability = parse_device_enrollment_capability(headers)?;
    Ok((challenge_id, capability))
}

fn parse_device_enrollment_capability(
    headers: &HeaderMap,
) -> Result<DeviceEnrollmentCapability, DeviceEnrollmentFailure> {
    let mut values = headers.get_all(DEVICE_ENROLLMENT_CAPABILITY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    };
    if values.next().is_some() {
        return Err(DeviceEnrollmentFailure::CapabilityRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    let bytes =
        decode_base64url_32(value).map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
    DeviceEnrollmentCapability::new(bytes).map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)
}

fn exact_cbor_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], DeviceEnrollmentFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(DeviceEnrollmentFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

fn cbor_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, DeviceEnrollmentFailure> {
    fields
        .get(
            key.checked_sub(1)
                .ok_or(DeviceEnrollmentFailure::InvalidRequest)?,
        )
        .map(|(_, value)| value)
        .ok_or(DeviceEnrollmentFailure::InvalidRequest)
}

fn require_cbor_version(value: &CanonicalValue) -> Result<(), DeviceEnrollmentFailure> {
    if value == &CanonicalValue::Unsigned(1) {
        Ok(())
    } else {
        Err(DeviceEnrollmentFailure::InvalidRequest)
    }
}

fn parse_cbor_identity_id(value: &CanonicalValue) -> Result<IdentityId, DeviceEnrollmentFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
}

fn parse_cbor_device_id(value: &CanonicalValue) -> Result<DeviceId, DeviceEnrollmentFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
}

fn parse_cbor_challenge_id(
    value: &CanonicalValue,
) -> Result<DeviceEnrollmentChallengeId, DeviceEnrollmentFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .parse()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
}

fn parse_cbor_bytes<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], DeviceEnrollmentFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)
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

struct DeviceEnrollmentChallengeSuccess {
    status: StatusCode,
    challenge: DeviceEnrollmentChallenge,
}

struct DeviceEnrollmentApprovalSuccess {
    status: StatusCode,
    exact_receipt_bytes: Vec<u8>,
}

struct KeyPackagePublishSuccess {
    status: StatusCode,
    exact_receipt_bytes: Vec<u8>,
}

struct KeyPackageClaimSuccess {
    status: StatusCode,
    exact_publish_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum DeviceEnrollmentFailure {
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
enum KeyPackageFailure {
    InvalidRequest,
    AuthenticationRejected,
    Unavailable,
    Conflict,
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

#[derive(Clone, Copy, Serialize)]
enum DeviceEnrollmentErrorCode {
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
enum KeyPackageErrorCode {
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

fn device_enrollment_challenge_success_response(
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

fn device_enrollment_status_response(
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

fn device_enrollment_approval_success_response(
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

fn device_enrollment_failure_response(
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

fn key_package_publish_success_response(
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

fn key_package_claim_success_response(
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

fn key_package_failure_response(failure: KeyPackageFailure, request_id: RequestId) -> Response {
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

fn encode_device_enrollment_status(status: DeviceEnrollmentChallengeStatus) -> Vec<u8> {
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

fn encode_device_enrollment_challenge(challenge: &DeviceEnrollmentChallenge) -> Vec<u8> {
    encode_device_enrollment_status_fields(
        challenge.challenge_id().to_string(),
        challenge.identity_id().to_string(),
        challenge.target_device_id().to_string(),
        1,
        challenge.expires_at(),
    )
}

fn encode_device_enrollment_status_fields(
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

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;

    #[test]
    fn enrollment_cbor_boundary_is_exact_and_status_does_not_echo_capability() {
        let signing_key = SigningKey::from_bytes(&[4; 32]);
        let signing_public_key = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes())
            .expect("test signing key is a valid Ed25519 key");
        let identity_id = IdentityId::derive(signing_public_key.as_domain_key());
        let device_id: DeviceId = "0190f2a5-7b1c-7abc-8def-0123456789ab"
            .parse()
            .expect("fixed test UUIDv7 is valid");
        let capability = [9; 32];
        let candidate = CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Bytes(signing_public_key.as_bytes().to_vec()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Bytes(vec![7; 32]),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Bytes(capability.to_vec()),
            ),
        ]);
        let candidate_bytes =
            encode_deterministic_cbor(&candidate).expect("fixed candidate encodes canonically");
        let parsed = parse_device_enrollment_candidate(&candidate_bytes)
            .expect("exact frozen candidate shape is accepted");
        assert_eq!(parsed.identity_id, identity_id);
        assert_eq!(parsed.target_device_id, device_id);
        assert_eq!(parsed.capability.as_bytes(), &capability);

        let challenge_id: DeviceEnrollmentChallengeId = "0190f2a5-7b1e-7abc-8def-0123456789ab"
            .parse()
            .expect("fixed test UUIDv7 is valid");
        let status = encode_device_enrollment_status_fields(
            challenge_id.to_string(),
            identity_id.to_string(),
            device_id.to_string(),
            1,
            UtcMillis::new(902_000).expect("fixed expiry is valid"),
        );
        let decoded = decode_deterministic_cbor(&status).expect("generated status is canonical");
        let fields = exact_cbor_fields(&decoded, 6).expect("generated status has frozen fields");
        assert_eq!(
            cbor_field(fields, 5).expect("generated state field exists"),
            &CanonicalValue::Unsigned(1)
        );
        assert_eq!(
            cbor_field(fields, 6).expect("generated expiry field exists"),
            &CanonicalValue::Unsigned(902_000)
        );
        assert!(
            !status
                .windows(capability.len())
                .any(|window| window == capability.as_slice())
        );
    }
}
