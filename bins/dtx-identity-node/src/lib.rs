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
    routing::{delete, get, post, put},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_contact::{
    ContactInviteV1, ContactRepository, ContactRequestRecord, ContactRequestV1, ContactReviewV1,
    ContactStoreError,
};
use dtx_domain::{
    Clock, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionChallengeId, DeviceSessionId,
    IdentityId, InviteCapabilityId, KeyPackageId, RequestId, SystemClock,
};
use dtx_federated_identity::{
    FederatedIdentityError, FederatedIdentityVerifier, HISTORY_RECOVERY_AUTHORITY_ID_DOMAIN,
    MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE, MlsV5RecoveryAuthorityKind,
    MlsV5RecoveryAuthorizationProjection, MlsV5RecoveryAuthorizationQuery,
};
use dtx_identity_log::{
    DeviceEncryptionPublicKey, DeviceStatusV1, IDENTITY_LOG_WIRE_VERSION,
    IdentityLogEventPayloadV1, IdentityLogEventV1, IdentityLogPageV1, IdentityLogV1,
    MAX_IDENTITY_LOG_PAGE_EVENTS,
};
use dtx_identity_persistence::{
    CatalogPreparationCommand, CatalogProviderResponseCommand, CatalogStatus, CatalogUploadCommand,
    ClientBindingAuthorization, ClientBindingRepository, ClientBindingWorkflowError,
    CreateDeviceEnrollmentChallengeCommand, CreateHistoryRecoveryRequestCommand,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentChallenge,
    DeviceEnrollmentChallengeOutcome, DeviceEnrollmentChallengeState,
    DeviceEnrollmentChallengeStatus, DeviceEnrollmentRepository, DeviceRevokeCommand,
    DeviceSessionCompletionCommand, DeviceSessionCredential, DeviceSessionOutcome,
    DeviceSessionRepository, FEDERATED_KEY_PACKAGE_CLAIM_PATH, FederatedKeyPackageClaimProof,
    HistoryRecoveryKeyPackageScope, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogPageReadOutcome, IdentityLogRepository, IdentityPersistenceError, IdentityPgStore,
    KeyPackageClaimCommand, KeyPackageClaimOutcome, KeyPackagePublishCommand,
    KeyPackagePublishOutcome, KeyPackageRepository, MAX_KEY_PACKAGE_PUBLISH_BYTES,
    MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES, MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES,
    RecoveryResponseCapability, RecoveryScopeCatalogOutcome, RecoveryScopeCatalogRepository,
    RecoveryScopeCatalogStatusOutcome, lock_and_load_active_snapshot,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use getrandom::fill as fill_random;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::Row;
use zeroize::Zeroize;

/// Route for the self-authenticated identity genesis request.
pub const IDENTITY_BOOTSTRAP_PATH: &str = "/v1/identity/bootstrap";
/// Route for the root-authorized first device after genesis.
pub const INITIAL_DEVICE_ENROLL_PATH: &str = "/v1/devices/initial-enroll";
pub const DEPLOYMENT_BOOTSTRAP_PATH: &str = "/v1/identity/deployment-bootstrap";
pub const DEPLOYMENT_INITIAL_DEVICE_PATH: &str = "/v1/identity/deployment-bootstrap/initial-device";
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
/// Remote-device proof route for a claim against another identity origin.
pub const KEY_PACKAGE_FEDERATED_CLAIM_PATH: &str = FEDERATED_KEY_PACKAGE_CLAIM_PATH;
/// Public read-only route template for exact signed identity-log pages.
pub const IDENTITY_LOG_PAGE_PATH_TEMPLATE: &str = "/v1/identities/{identity_id}/log";
/// Public identity-origin route for one fresh redacted MLS V5 recovery authorization.
pub const MLS_V5_RECOVERY_AUTHORIZATION_PATH_TEMPLATE: &str =
    "/v1/identities/{identity_id}/history-recovery-requests/{request_id}/mls-v5-authorization";
/// Active-device route for one exact root-signed revocation of another device.
pub const DEVICE_REVOKE_PATH_TEMPLATE: &str =
    "/v1/identities/{identity_id}/devices/{device_id}/revoke";
/// Active-device publication route for one immutable encrypted catalog generation.
pub const RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE: &str = "/v1/recovery-scope-catalogs/{generation}";
/// Candidate route that freezes the current catalog before ordinary enrollment.
pub const RECOVERY_SCOPE_CATALOG_PREPARATIONS_PATH: &str =
    "/v2/devices/enroll/catalog-preparations";
/// Candidate capability route for one redacted preparation status.
pub const RECOVERY_SCOPE_CATALOG_PREPARATION_PATH_TEMPLATE: &str =
    "/v2/devices/enroll/catalog-preparations/{request_id}";
/// Active-provider route for the preparation's one immutable response.
pub const RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE: &str =
    "/v2/devices/enroll/catalog-preparations/{request_id}/provider-response";
pub const CONTACT_INVITES_PATH: &str = "/v1/contact-invites";
pub const CONTACT_INVITE_PATH: &str = "/v1/contact-invites/{invite_id}";
pub const CONTACT_REQUESTS_PATH: &str = "/v1/contact-requests";
pub const CONTACT_REVIEW_PATH: &str = "/v1/contact-requests/{request_id}/review";
pub const CONTACT_RECEIPT_PATH: &str = "/v1/contact-requests/{request_id}/receipt";
/// Required media type for exact signed V1.1 identity-log events.
pub const IDENTITY_LOG_EVENT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-log.v1.1+cbor";
/// Exact deterministic-CBOR media type for a verified identity-log page.
pub const IDENTITY_LOG_PAGE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-log-page.v1+cbor";
/// Response media type for immutable canonical append receipts.
pub const IDENTITY_APPEND_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.identity-append-receipt.v1+cbor";
/// Response media type for immutable canonical device-session receipts.
pub const DEVICE_SESSION_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-session-receipt.v1+cbor";
/// Exact candidate challenge request media type.
pub const DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-enrollment-candidate.v1+cbor";
pub const HISTORY_RECOVERY_REQUEST_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.history-recovery-request.v1+cbor";
/// Capability-gated enrollment status response media type.
pub const DEVICE_ENROLLMENT_STATUS_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-enrollment-status.v1+cbor";
/// Exact active-device enrollment approval request media type.
pub const DEVICE_ENROLLMENT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.device-enrollment.v1+cbor";
/// Exact signed opaque `KeyPackage` publish request media type.
pub const KEY_PACKAGE_PUBLISH_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-publish.v1+cbor";
pub const KEY_PACKAGE_PUBLISH_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-publish.v2+cbor";
/// Immutable `KeyPackage` publish receipt media type.
pub const KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-publish-receipt.v1+cbor";
/// Exact `KeyPackage` target claim request media type.
pub const KEY_PACKAGE_CLAIM_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-claim.v1+cbor";
pub const KEY_PACKAGE_CLAIM_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-claim.v2+cbor";
/// V1 target body authenticated by a requester-origin V2 device proof.
pub const KEY_PACKAGE_FEDERATED_CLAIM_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-claim.v2+cbor";
/// Exact original publish envelope returned by a one-time claim.
pub const KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.key-package-claim-receipt.v1+cbor";
/// Exact encrypted catalog upload media type.
pub const RECOVERY_SCOPE_CATALOG_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.recovery-scope-catalog.v1+cbor";
/// Exact signed catalog-head response media type.
pub const RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-head.v1+cbor";
/// Exact candidate preparation media type.
pub const RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-preparation.v1+cbor";
/// Exact active-provider response media type.
pub const RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-provider-response.v1+cbor";
/// Exact redacted preparation status media type.
pub const RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-status.v1+cbor";
pub const CONTACT_INVITE_CONTENT_TYPE: &str = "application/vnd.dirextalk.contact-invite.v1+cbor";
pub const CONTACT_INVITE_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.contact-invite-receipt.v1+cbor";
pub const CONTACT_REQUEST_CONTENT_TYPE: &str = "application/vnd.dirextalk.contact-request.v1+cbor";
pub const CONTACT_REVIEW_CONTENT_TYPE: &str = "application/vnd.dirextalk.contact-review.v1+cbor";
pub const CONTACT_RECEIPT_CONTENT_TYPE: &str = "application/vnd.dirextalk.contact-receipt.v1+cbor";
pub const CONTACT_PENDING_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.contact-pending-page.v1+cbor";
pub const CONTACT_INVITE_SECRET_HEADER: &str = "DTX-Contact-Invite-Secret";
pub const CONTACT_RECEIPT_SECRET_HEADER: &str = "DTX-Contact-Receipt-Secret";
/// Header that carries a candidate-owned status/cancellation capability.
pub const DEVICE_ENROLLMENT_CAPABILITY_HEADER: &str = "DTX-Enrollment-Capability";
/// Candidate-held capability for reading the independent recovery response.
pub const RECOVERY_RESPONSE_CAPABILITY_HEADER: &str = "DTX-Recovery-Response-Capability";
/// Canonical remote identity origin covered by the V2 claim proof.
pub const IDENTITY_ORIGIN_HEADER: &str = "DTX-Identity-Origin";
/// Base64url canonical-CBOR V2 remote device proof.
pub const KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER: &str = "DTX-KeyPackage-Claim-Proof";
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
const MAX_KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER_BYTES: usize = 4_096;

const DEFAULT_IDENTITY_LOG_PAGE_LIMIT: usize = 32;

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-bootstrap-http-idempotency-key.v1\0";
const HTTP_INITIAL_DEVICE_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.identity-initial-device-http-idempotency-key.v1\0";
const CLIENT_BINDING_HEADER: &str = "X-Dirextalk-Client-Binding";
const CLIENT_BINDING_AUTHORIZATION_SCHEME: &str = "DTX-Client-Binding";
const HTTP_DEVICE_SESSION_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-session-http-idempotency-key.v1\0";
const HTTP_DEVICE_ENROLLMENT_CHALLENGE_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-http-challenge-idempotency-key.v1\0";
const HTTP_DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-enrollment-http-approval-idempotency-key.v1\0";
const HTTP_DEVICE_REVOKE_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.device-revoke-http-idempotency-key.v1\0";
const HTTP_KEY_PACKAGE_PUBLISH_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-http-publish-idempotency-key.v1\0";
const HTTP_KEY_PACKAGE_CLAIM_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.key-package-http-claim-idempotency-key.v1\0";
const HTTP_RECOVERY_CATALOG_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-http-publish-idempotency-key.v1\0";
const HTTP_RECOVERY_PREPARATION_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-http-preparation-idempotency-key.v1\0";
const HTTP_RECOVERY_PROVIDER_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-http-provider-idempotency-key.v1\0";
const DEFAULT_DEVICE_SESSION_AUDIENCE: &str = "http://127.0.0.1";

/// State for bootstrap, device-session, and QR device-enrollment HTTP boundaries.
#[derive(Clone)]
pub struct IdentityBootstrapState {
    store: IdentityPgStore,
    repository: IdentityLogRepository,
    device_sessions: DeviceSessionRepository,
    device_enrollments: DeviceEnrollmentRepository,
    key_packages: KeyPackageRepository,
    recovery_catalogs: RecoveryScopeCatalogRepository,
    contacts: ContactRepository,
    client_bindings: ClientBindingRepository,
    federated_identity: FederatedIdentityVerifier,
    public_origin: Arc<str>,
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
    ///
    /// # Panics
    ///
    /// Panics only if the process cannot construct its fixed HTTPS-only
    /// identity-log HTTP client.
    #[must_use]
    pub fn with_clock_and_device_session_audience(
        store: IdentityPgStore,
        clock: Arc<dyn Clock>,
        audience: impl Into<Arc<str>>,
    ) -> Self {
        let device_session_audience = audience.into();
        let federated_identity = FederatedIdentityVerifier::new(std::iter::empty())
            .expect("the fixed HTTPS-only federated identity client is valid");
        Self {
            store,
            repository: IdentityLogRepository::new(),
            device_sessions: DeviceSessionRepository,
            device_enrollments: DeviceEnrollmentRepository,
            key_packages: KeyPackageRepository::new(),
            recovery_catalogs: RecoveryScopeCatalogRepository,
            contacts: ContactRepository,
            client_bindings: ClientBindingRepository,
            federated_identity,
            public_origin: device_session_audience.clone(),
            clock,
            device_session_audience,
        }
    }

    /// Installs the canonical public origin, development-only HTTP allowlist,
    /// and optional additional CA root used for remote identity-log proofs.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical origin, unsafe HTTP origin, or an
    /// invalid additional trust root.
    pub fn with_federated_identity_configuration(
        mut self,
        public_origin: impl AsRef<str>,
        allowed_http_origins: impl IntoIterator<Item = String>,
        additional_trust_root_pem: Option<&[u8]>,
    ) -> Result<Self, IdentityNodeConfigurationError> {
        let (federated_identity, public_origin) =
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                public_origin.as_ref(),
                allowed_http_origins,
                additional_trust_root_pem,
            )
            .map_err(IdentityNodeConfigurationError)?;
        self.federated_identity = federated_identity;
        self.public_origin = Arc::from(public_origin);
        Ok(self)
    }
}

/// Invalid federated identity configuration for the identity node.
#[derive(Clone, Copy, Debug)]
pub struct IdentityNodeConfigurationError(FederatedIdentityError);

impl std::fmt::Display for IdentityNodeConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for IdentityNodeConfigurationError {}

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
        .route(
            DEPLOYMENT_BOOTSTRAP_PATH,
            post(deployment_bootstrap_identity),
        )
        .route(
            DEPLOYMENT_INITIAL_DEVICE_PATH,
            post(deployment_initial_device),
        )
        .route(IDENTITY_LOG_PAGE_PATH_TEMPLATE, get(get_identity_log_page))
        .route(
            MLS_V5_RECOVERY_AUTHORIZATION_PATH_TEMPLATE,
            get(get_mls_v5_recovery_authorization),
        )
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
        .route(DEVICE_REVOKE_PATH_TEMPLATE, post(revoke_device))
        .route(
            RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE,
            put(publish_recovery_scope_catalog),
        )
        .route(
            RECOVERY_SCOPE_CATALOG_PREPARATIONS_PATH,
            post(prepare_recovery_scope_catalog),
        )
        .route(
            RECOVERY_SCOPE_CATALOG_PREPARATION_PATH_TEMPLATE,
            get(get_recovery_scope_catalog_preparation),
        )
        .route(
            RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE,
            put(put_recovery_scope_catalog_provider_response),
        )
        .route(KEY_PACKAGE_PUBLISH_PATH_TEMPLATE, put(publish_key_package))
        .route(KEY_PACKAGE_CLAIM_PATH, post(claim_key_package))
        .route(
            KEY_PACKAGE_FEDERATED_CLAIM_PATH,
            post(claim_key_package_federated),
        )
        .route(CONTACT_INVITES_PATH, post(create_contact_invite))
        .route(CONTACT_INVITE_PATH, delete(revoke_contact_invite))
        .route(
            CONTACT_REQUESTS_PATH,
            get(pending_contact_requests).post(submit_contact_request),
        )
        .route(CONTACT_REVIEW_PATH, post(review_contact_request))
        .route(CONTACT_RECEIPT_PATH, get(get_contact_receipt))
        .with_state(state)
}

#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
async fn create_contact_invite(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    if !has_exact_content_type(&parts.headers, CONTACT_INVITE_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
    {
        return contact_failure(ContactStoreError::Invalid, request_id);
    }
    let credential = match parse_device_session_authorization(&parts.headers) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Authentication, request_id),
    };
    let idempotency =
        match idempotency_key_hash(&parts.headers, b"dirextalk.contact-invite-http.v1\0") {
            Ok(v) => v,
            Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
        };
    let secret = match contact_secret(&parts.headers, CONTACT_INVITE_SECRET_HEADER) {
        Ok(v) => v,
        Err(e) => return contact_failure(e, request_id),
    };
    let bytes = match to_bytes(body, 65_536).await {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let invite = match ContactInviteV1::decode(&bytes) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, request_id),
    };
    match state
        .contacts
        .create_invite(
            &state.store,
            &credential,
            *idempotency.as_bytes(),
            &invite,
            &bytes,
            secret,
            now,
        )
        .await
    {
        Ok(receipt) => exact_cbor_response(
            StatusCode::CREATED,
            receipt,
            CONTACT_INVITE_RECEIPT_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
async fn revoke_contact_invite(
    State(state): State<IdentityBootstrapState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = RequestId::new();
    let Ok(invite_id) = id.parse::<InviteCapabilityId>() else {
        return contact_failure(ContactStoreError::Invalid, request_id);
    };
    let credential = match parse_device_session_authorization(&headers) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Authentication, request_id),
    };
    let idempotency = match idempotency_key_hash(&headers, b"dirextalk.contact-revoke-http.v1\0") {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, request_id),
    };
    match state
        .contacts
        .revoke_invite(
            &state.store,
            &credential,
            *idempotency.as_bytes(),
            invite_id,
            now,
        )
        .await
    {
        Ok(receipt) => exact_cbor_response(
            StatusCode::OK,
            receipt,
            CONTACT_INVITE_RECEIPT_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
async fn submit_contact_request(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    if !has_exact_content_type(&parts.headers, CONTACT_REQUEST_CONTENT_TYPE)
        || parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
    {
        return contact_failure(ContactStoreError::Invalid, request_id);
    }
    let secret = match contact_secret(&parts.headers, CONTACT_INVITE_SECRET_HEADER) {
        Ok(v) => v,
        Err(e) => return contact_failure(e, request_id),
    };
    let bytes = match to_bytes(body, 150_000).await {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let command = match ContactRequestV1::decode(&bytes) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, request_id),
    };
    match state
        .contacts
        .submit_request(&state.store, &command, &bytes, secret, now)
        .await
    {
        Ok(receipt) => exact_cbor_response(
            StatusCode::CREATED,
            receipt.exact_bytes,
            CONTACT_RECEIPT_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
async fn pending_contact_requests(
    State(state): State<IdentityBootstrapState>,
    headers: HeaderMap,
) -> Response {
    let request_id = RequestId::new();
    let credential = match parse_device_session_authorization(&headers) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Authentication, request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, request_id),
    };
    match state
        .contacts
        .pending(&state.store, &credential, now)
        .await
        .and_then(|v| encode_pending(&v))
    {
        Ok(bytes) => exact_cbor_response(
            StatusCode::OK,
            bytes,
            CONTACT_PENDING_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
async fn review_contact_request(
    State(state): State<IdentityBootstrapState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let http_request_id = RequestId::new();
    let Ok(route_id) = id.parse::<RequestId>() else {
        return contact_failure(ContactStoreError::Invalid, http_request_id);
    };
    let (parts, body) = request.into_parts();
    if !has_exact_content_type(&parts.headers, CONTACT_REVIEW_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
    {
        return contact_failure(ContactStoreError::Invalid, http_request_id);
    }
    let credential = match parse_device_session_authorization(&parts.headers) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Authentication, http_request_id),
    };
    let idem = match idempotency_key_hash(&parts.headers, b"dirextalk.contact-review-http.v1\0") {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, http_request_id),
    };
    let bytes = match to_bytes(body, 300_000).await {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, http_request_id),
    };
    let review = match ContactReviewV1::decode(&bytes) {
        Ok(v) if v.request_id() == route_id => v,
        _ => return contact_failure(ContactStoreError::Invalid, http_request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, http_request_id),
    };
    match state
        .contacts
        .review(
            &state.store,
            &credential,
            *idem.as_bytes(),
            &review,
            &bytes,
            now,
        )
        .await
    {
        Ok(v) => exact_cbor_response(
            StatusCode::OK,
            v.exact_bytes,
            CONTACT_RECEIPT_CONTENT_TYPE,
            http_request_id,
        ),
        Err(e) => contact_failure(e, http_request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
async fn get_contact_receipt(
    State(state): State<IdentityBootstrapState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let http_request_id = RequestId::new();
    let Ok(id) = id.parse::<RequestId>() else {
        return contact_failure(ContactStoreError::Invalid, http_request_id);
    };
    let secret = match contact_secret(&headers, CONTACT_RECEIPT_SECRET_HEADER) {
        Ok(v) => v,
        Err(e) => return contact_failure(e, http_request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, http_request_id),
    };
    match state.contacts.receipt(&state.store, id, secret, now).await {
        Ok(v) => exact_cbor_response(
            StatusCode::OK,
            v.exact_bytes,
            CONTACT_RECEIPT_CONTENT_TYPE,
            http_request_id,
        ),
        Err(e) => contact_failure(e, http_request_id),
    }
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

async fn deployment_bootstrap_identity(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.deployment_bootstrap(&parts.headers, body).await {
        Ok(success) => bootstrap_success_response(success, request_id),
        Err(failure) => client_binding_failure_response(failure, request_id),
    }
}

async fn deployment_initial_device(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.deployment_initial_device(&parts.headers, body).await {
        Ok(success) => initial_device_success_response(success, request_id),
        Err(failure) => client_binding_failure_response(failure, request_id),
    }
}

async fn get_identity_log_page(
    State(state): State<IdentityBootstrapState>,
    Path(route_identity_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .get_identity_log_page(&route_identity_id, parts.uri.query(), &parts.headers, body)
        .await
    {
        Ok(page) => identity_log_page_success_response(&page, request_id),
        Err(failure) => identity_log_page_failure_response(failure, request_id),
    }
}

async fn get_mls_v5_recovery_authorization(
    State(state): State<IdentityBootstrapState>,
    Path((route_identity_id, route_request_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .mls_v5_recovery_authorization(
            &route_identity_id,
            &route_request_id,
            parts.uri.query(),
            &parts.headers,
            body,
        )
        .await
    {
        Ok(projection) => match projection.exact_bytes() {
            Ok(bytes) => exact_cbor_response(
                StatusCode::OK,
                bytes,
                MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE,
                request_id,
            ),
            Err(_) => mls_v5_recovery_authorization_failure_response(
                MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable,
                request_id,
            ),
        },
        Err(failure) => mls_v5_recovery_authorization_failure_response(failure, request_id),
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

async fn revoke_device(
    State(state): State<IdentityBootstrapState>,
    Path((identity_id, device_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .revoke_device(&identity_id, &device_id, &parts.headers, body)
        .await
    {
        Ok(success) => device_revoke_success_response(success, request_id),
        Err(failure) => device_revoke_failure_response(failure, request_id),
    }
}

async fn publish_recovery_scope_catalog(
    State(state): State<IdentityBootstrapState>,
    Path(generation): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .publish_recovery_scope_catalog(&generation, &parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_head_response(success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
    }
}

async fn prepare_recovery_scope_catalog(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .prepare_recovery_scope_catalog(&parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_status_response(&success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
    }
}

async fn get_recovery_scope_catalog_preparation(
    State(state): State<IdentityBootstrapState>,
    Path(route_request_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .get_recovery_scope_catalog_preparation(&route_request_id, &parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_status_response(&success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
    }
}

async fn put_recovery_scope_catalog_provider_response(
    State(state): State<IdentityBootstrapState>,
    Path(route_request_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .put_recovery_scope_catalog_provider_response(&route_request_id, &parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_status_response(&success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
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

async fn claim_key_package_federated(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .claim_key_package_federated(&parts.uri, &parts.headers, body)
        .await
    {
        Ok(success) => key_package_claim_success_response(success, request_id),
        Err(failure) => key_package_failure_response(failure, request_id),
    }
}

impl IdentityBootstrapState {
    async fn mls_v5_recovery_authorization(
        &self,
        route_identity_id: &str,
        route_request_id: &str,
        raw_query: Option<&str>,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MlsV5RecoveryAuthorizationProjection, MlsV5RecoveryAuthorizationFailure> {
        if !has_exact_header(
            headers,
            header::ACCEPT,
            MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE,
        ) || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(header::CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
            || headers.contains_key(IDENTITY_ORIGIN_HEADER)
        {
            return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
        }
        let body = to_bytes(body, 1)
            .await
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
        if !body.is_empty() {
            return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
        }
        let query = parse_mls_v5_recovery_authorization_query(
            route_identity_id,
            route_request_id,
            raw_query,
        )?;
        let now = self
            .committed_at()
            .map_err(|()| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
        let mut session = self
            .store
            .begin()
            .await
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
        let result =
            load_mls_v5_recovery_authorization_projection(session.connection(), query, now).await;
        session
            .rollback()
            .await
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
        result
    }

    async fn get_identity_log_page(
        &self,
        route_identity_id: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<IdentityLogPageV1, IdentityLogPageFailure> {
        if headers.contains_key(header::CONTENT_ENCODING) {
            return Err(IdentityLogPageFailure::InvalidRequest);
        }
        let body = to_bytes(body, 1)
            .await
            .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
        if !body.is_empty() {
            return Err(IdentityLogPageFailure::InvalidRequest);
        }
        let (identity_id, after_sequence, limit) =
            parse_identity_log_page_request(route_identity_id, query)?;
        match self
            .repository
            .read_page(&self.store, identity_id, after_sequence, limit)
            .await
        {
            Ok(IdentityLogPageReadOutcome::Page(page)) => Ok(page),
            Ok(IdentityLogPageReadOutcome::NotFound) => Err(IdentityLogPageFailure::NotFound),
            Ok(IdentityLogPageReadOutcome::Inactive) => Err(IdentityLogPageFailure::Inactive),
            Ok(IdentityLogPageReadOutcome::CursorAhead) => Err(IdentityLogPageFailure::CursorAhead),
            Err(error) => Err(map_identity_log_page_persistence_error(&error)),
        }
    }

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

    async fn deployment_bootstrap(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<BootstrapSuccess, ClientBindingFailure> {
        if !has_exact_event_content_type(headers)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(ClientBindingFailure::Invalid);
        }
        let binding_id = client_binding_id(headers)?;
        let authorization = client_binding_authorization(headers)?;
        let idem = idempotency_key_hash_binding(headers, HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| ClientBindingFailure::Invalid)?;
        if exact_event_bytes.is_empty() {
            return Err(ClientBindingFailure::Invalid);
        }
        let now = self
            .committed_at()
            .map_err(|_| ClientBindingFailure::Unavailable)?;
        match self
            .client_bindings
            .deployment_bootstrap(
                &self.store,
                binding_id,
                authorization.digest(),
                idem,
                exact_event_bytes.to_vec(),
                now,
            )
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
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(ClientBindingFailure::Conflict),
            Err(error) => Err(map_client_binding_error(error)),
        }
    }

    async fn deployment_initial_device(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<InitialDeviceSuccess, ClientBindingFailure> {
        if !has_exact_event_content_type(headers) || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(ClientBindingFailure::Invalid);
        }
        let binding_id = client_binding_id(headers)?;
        let authorization = client_binding_authorization(headers)?;
        let idem =
            idempotency_key_hash_binding(headers, HTTP_INITIAL_DEVICE_IDEMPOTENCY_KEY_HASH_DOMAIN)?;
        let expected = expected_genesis_hash(headers).map_err(|_| ClientBindingFailure::Invalid)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| ClientBindingFailure::Invalid)?;
        if exact_event_bytes.is_empty() {
            return Err(ClientBindingFailure::Invalid);
        }
        let now = self
            .committed_at()
            .map_err(|_| ClientBindingFailure::Unavailable)?;
        match self
            .client_bindings
            .initial_device(
                &self.store,
                binding_id,
                authorization.digest(),
                idem,
                expected,
                exact_event_bytes.to_vec(),
                now,
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
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(ClientBindingFailure::Conflict),
            Err(error) => Err(map_client_binding_error(error)),
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
        let history_recovery =
            has_exact_content_type(headers, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE);
        if (!history_recovery
            && !has_exact_content_type(headers, DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE))
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
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        let outcome = if history_recovery {
            let request = parse_history_recovery_request(&bytes)?;
            let command = CreateHistoryRecoveryRequestCommand::new(
                idempotency_key_hash,
                request.request_id,
                request.identity_id,
                request.target_device_id,
                request.target_device_signing_key,
                request.recipient_encryption_key,
                IdentityLogHead::observed(
                    request.identity_id,
                    request.observed_head_sequence,
                    request.observed_head_hash,
                )
                .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
                request.issued_at,
                request.expires_at,
                request.capability,
                request.candidate_signature,
                request.exact_signed_request,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
            self.device_enrollments
                .create_history_recovery_request(&self.store, command, now)
                .await
        } else {
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
            self.device_enrollments
                .create_challenge(&self.store, command, now)
                .await
        }
        .map_err(|error| map_device_enrollment_persistence_error(&error))?;
        match outcome {
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

    async fn revoke_device(
        &self,
        route_identity_id: &str,
        route_device_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceRevokeSuccess, DeviceRevokeFailure> {
        if !has_exact_event_content_type(headers)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(DeviceRevokeFailure::InvalidRequest);
        }
        let identity_id = IdentityId::from_str(route_identity_id)
            .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let target_device_id =
            DeviceId::from_str(route_device_id).map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| DeviceRevokeFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_DEVICE_REVOKE_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let expected_head_hash = expected_device_revoke_head_hash(headers)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| DeviceRevokeFailure::InvalidRequest)?
            .to_vec();
        let command = DeviceRevokeCommand::new(
            idempotency_key_hash,
            identity_id,
            target_device_id,
            expected_head_hash,
            exact_event_bytes,
        )
        .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceRevokeFailure::TemporarilyUnavailable)?;
        match self
            .repository
            .revoke_device(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_device_revoke_persistence_error(&error))?
        {
            IdentityAppendOutcome::Committed(receipt) => Ok(DeviceRevokeSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Replayed(receipt) => Ok(DeviceRevokeSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Forked { .. } => Err(DeviceRevokeFailure::IdentityConflict),
        }
    }

    async fn publish_recovery_scope_catalog(
        &self,
        route_generation: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogHeadSuccess, RecoveryCatalogFailure> {
        if !has_exact_content_type(headers, RECOVERY_SCOPE_CATALOG_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
            || headers.contains_key(RECOVERY_RESPONSE_CAPABILITY_HEADER)
        {
            return Err(RecoveryCatalogFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| RecoveryCatalogFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_RECOVERY_CATALOG_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let generation = parse_positive_safe_uint_path(route_generation)?;
        let bytes = to_bytes(body, MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES)
            .await
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let command = CatalogUploadCommand::parse(idempotency_key_hash, generation, &bytes)
            .map_err(|error| map_recovery_catalog_publish_error(&error))?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let outcome = self
            .recovery_catalogs
            .publish(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_recovery_catalog_publish_error(&error))?;
        Ok(RecoveryCatalogHeadSuccess {
            status: if outcome.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            outcome,
        })
    }

    async fn prepare_recovery_scope_catalog(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogStatusSuccess, RecoveryCatalogFailure> {
        if !has_exact_content_type(headers, RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::AUTHORIZATION)
        {
            return Err(RecoveryCatalogFailure::InvalidRequest);
        }
        let idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_RECOVERY_PREPARATION_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let enrollment_capability = parse_recovery_enrollment_capability(headers)?;
        let response_capability = parse_recovery_response_capability(headers)?;
        let bytes = to_bytes(body, MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES)
            .await
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let command = CatalogPreparationCommand::parse(
            idempotency_key_hash,
            bytes.to_vec(),
            enrollment_capability,
            &response_capability,
        )
        .map_err(|error| map_recovery_catalog_prepare_error(&error))?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let (created, outcome) = self
            .recovery_catalogs
            .prepare(&self.store, &command, now)
            .await
            .map_err(|error| map_recovery_catalog_prepare_error(&error))?;
        Ok(RecoveryCatalogStatusSuccess {
            status: if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            outcome,
        })
    }

    async fn get_recovery_scope_catalog_preparation(
        &self,
        route_request_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogStatusSuccess, RecoveryCatalogFailure> {
        if headers.contains_key(header::CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(RecoveryCatalogFailure::CapabilityRejected);
        }
        let body = to_bytes(body, 1)
            .await
            .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
        if !body.is_empty() {
            return Err(RecoveryCatalogFailure::CapabilityRejected);
        }
        let request_id = route_request_id
            .parse::<DeviceEnrollmentChallengeId>()
            .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
        let response_capability = parse_recovery_response_capability(headers)?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let outcome = self
            .recovery_catalogs
            .status(&self.store, request_id, &response_capability, now)
            .await
            .map_err(|error| map_recovery_catalog_status_error(&error))?;
        let status = match outcome.status {
            CatalogStatus::Pending | CatalogStatus::ResponseAvailable => StatusCode::OK,
            CatalogStatus::Expired => StatusCode::GONE,
            CatalogStatus::Invalidated(_) => StatusCode::PRECONDITION_FAILED,
        };
        Ok(RecoveryCatalogStatusSuccess { status, outcome })
    }

    async fn put_recovery_scope_catalog_provider_response(
        &self,
        route_request_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogStatusSuccess, RecoveryCatalogFailure> {
        if !has_exact_content_type(
            headers,
            RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        ) || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
            || headers.contains_key(RECOVERY_RESPONSE_CAPABILITY_HEADER)
        {
            return Err(RecoveryCatalogFailure::InvalidRequest);
        }
        let request_id = route_request_id
            .parse::<DeviceEnrollmentChallengeId>()
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| RecoveryCatalogFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_RECOVERY_PROVIDER_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES)
            .await
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let command =
            CatalogProviderResponseCommand::parse(idempotency_key_hash, request_id, bytes.to_vec())
                .map_err(|error| map_recovery_catalog_provider_error(&error))?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let outcome = self
            .recovery_catalogs
            .put_provider_response(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_recovery_catalog_provider_error(&error))?;
        Ok(RecoveryCatalogStatusSuccess {
            status: StatusCode::OK,
            outcome,
        })
    }

    async fn publish_key_package(
        &self,
        route_package_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<KeyPackagePublishSuccess, KeyPackageFailure> {
        let recovery_v2 = has_exact_content_type(headers, KEY_PACKAGE_PUBLISH_V2_CONTENT_TYPE);
        if (!recovery_v2 && !has_exact_content_type(headers, KEY_PACKAGE_PUBLISH_CONTENT_TYPE))
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
        if recovery_v2 != publish.history_recovery_scope.is_some() {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let command = if let Some(scope) = publish.history_recovery_scope {
            KeyPackagePublishCommand::new_history_recovery_v2(
                idempotency_key_hash,
                publish.identity_id,
                publish.device_id,
                publish.package_id,
                publish.published_head_sequence,
                publish.published_head_hash,
                publish.expires_at,
                publish.opaque_key_package,
                scope,
                publish.detached_signature,
                bytes.to_vec(),
            )
        } else {
            KeyPackagePublishCommand::new(
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
        }
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
        let recovery_v2 = has_exact_content_type(headers, KEY_PACKAGE_CLAIM_V2_CONTENT_TYPE);
        if (!recovery_v2 && !has_exact_content_type(headers, KEY_PACKAGE_CLAIM_CONTENT_TYPE))
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
        if recovery_v2 != claim.history_recovery_scope.is_some() {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let command = if let Some(scope) = claim.history_recovery_scope {
            KeyPackageClaimCommand::new_history_recovery_v2(
                idempotency_key_hash,
                claim.target_identity_id,
                claim.target_device_id,
                scope,
                bytes.to_vec(),
            )
        } else {
            KeyPackageClaimCommand::new(
                idempotency_key_hash,
                claim.target_identity_id,
                claim.target_device_id,
                bytes.to_vec(),
            )
        }
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

    async fn claim_key_package_federated(
        &self,
        uri: &axum::http::Uri,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<KeyPackageClaimSuccess, KeyPackageFailure> {
        if uri.path() != KEY_PACKAGE_FEDERATED_CLAIM_PATH
            || uri.query().is_some()
            || !has_exact_content_type(headers, KEY_PACKAGE_FEDERATED_CLAIM_CONTENT_TYPE)
            || !has_exact_header(
                headers,
                header::ACCEPT,
                KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE,
            )
            || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let identity_origin = single_graphic_header(headers, IDENTITY_ORIGIN_HEADER, 8, 512)
            .map_err(|()| KeyPackageFailure::AuthenticationRejected)?;
        if identity_origin == self.public_origin.as_ref() {
            return Err(KeyPackageFailure::AuthenticationRejected);
        }
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
        let proof = parse_federated_key_package_claim_proof(headers)?;
        if proof.requester_identity_origin() != identity_origin {
            return Err(KeyPackageFailure::AuthenticationRejected);
        }
        let now = self
            .committed_at()
            .map_err(|()| KeyPackageFailure::TemporarilyUnavailable)?;
        let signing_key = self
            .federated_identity
            .active_device_signing_key(
                identity_origin,
                proof.requester_identity_id(),
                proof.requester_device_id(),
            )
            .await
            .map_err(map_federated_identity_error)?;
        let claimant = proof
            .verify(&command, now, signing_key)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
        match self
            .key_packages
            .claim_federated(&self.store, &command, &claimant, now)
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

fn has_exact_header(headers: &HeaderMap, name: header::HeaderName, expected: &'static str) -> bool {
    let mut values = headers.get_all(name).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

fn single_graphic_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    minimum_bytes: usize,
    maximum_bytes: usize,
) -> Result<&'a str, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if !(minimum_bytes..=maximum_bytes).contains(&value.len())
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(());
    }
    Ok(value)
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

fn idempotency_key_hash_binding(
    headers: &HeaderMap,
    domain: &[u8],
) -> Result<Sha256Digest, ClientBindingFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(ClientBindingFailure::Invalid);
    };
    if values.next().is_some() {
        return Err(ClientBindingFailure::Invalid);
    }
    let bytes = value.as_bytes();
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&bytes.len())
        || !bytes.iter().copied().all(is_base64url_byte)
    {
        return Err(ClientBindingFailure::Invalid);
    }
    Ok(Sha256Digest::hash_domain(domain, bytes))
}

fn client_binding_id(headers: &HeaderMap) -> Result<uuid::Uuid, ClientBindingFailure> {
    let value = single_graphic_header(headers, CLIENT_BINDING_HEADER, 36, 36)
        .map_err(|_| ClientBindingFailure::Invalid)?;
    let id = uuid::Uuid::parse_str(value).map_err(|_| ClientBindingFailure::Invalid)?;
    if id.to_string() != value || id.get_version_num() != 7 {
        return Err(ClientBindingFailure::Invalid);
    }
    Ok(id)
}

fn client_binding_authorization(
    headers: &HeaderMap,
) -> Result<ClientBindingAuthorization, ClientBindingFailure> {
    let value = single_graphic_header(headers, header::AUTHORIZATION.as_str(), 61, 80)
        .map_err(|_| ClientBindingFailure::Invalid)?;
    let raw = value
        .strip_prefix(CLIENT_BINDING_AUTHORIZATION_SCHEME)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(ClientBindingFailure::Invalid)?;
    ClientBindingAuthorization::parse(raw).map_err(|_| ClientBindingFailure::Invalid)
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

fn expected_device_revoke_head_hash(
    headers: &HeaderMap,
) -> Result<Sha256Digest, DeviceRevokeFailure> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(DeviceRevokeFailure::InvalidRequest);
    };
    if values.next().is_some() {
        return Err(DeviceRevokeFailure::InvalidRequest);
    }
    let value = value
        .to_str()
        .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(DeviceRevokeFailure::InvalidRequest)?;
    Sha256Digest::from_str(value).map_err(|_| DeviceRevokeFailure::InvalidRequest)
}

fn has_exact_json_content_type(headers: &HeaderMap) -> bool {
    has_exact_content_type(headers, "application/json")
}

fn parse_identity_log_page_request(
    route_identity_id: &str,
    query: Option<&str>,
) -> Result<(IdentityId, u64, usize), IdentityLogPageFailure> {
    let identity_id = IdentityId::from_str(route_identity_id)
        .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
    let mut after_sequence = None;
    let mut limit = None;
    if let Some(query) = query {
        if query.is_empty() {
            return Err(IdentityLogPageFailure::InvalidRequest);
        }
        for segment in query.split('&') {
            let Some((name, value)) = segment.split_once('=') else {
                return Err(IdentityLogPageFailure::InvalidRequest);
            };
            match name {
                "after" if after_sequence.is_none() => {
                    after_sequence = Some(parse_canonical_safe_uint(value)?);
                }
                "limit" if limit.is_none() => {
                    let value = parse_canonical_safe_uint(value)?;
                    let value = usize::try_from(value)
                        .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
                    if value == 0 || value > MAX_IDENTITY_LOG_PAGE_EVENTS {
                        return Err(IdentityLogPageFailure::InvalidRequest);
                    }
                    limit = Some(value);
                }
                _ => return Err(IdentityLogPageFailure::InvalidRequest),
            }
        }
    }
    Ok((
        identity_id,
        after_sequence.unwrap_or(0),
        limit.unwrap_or(DEFAULT_IDENTITY_LOG_PAGE_LIMIT),
    ))
}

fn parse_mls_v5_recovery_authorization_query(
    route_identity_id: &str,
    route_request_id: &str,
    raw_query: Option<&str>,
) -> Result<MlsV5RecoveryAuthorizationQuery, MlsV5RecoveryAuthorizationFailure> {
    let identity_id = route_identity_id
        .parse::<IdentityId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let request_id = route_request_id
        .parse::<DeviceEnrollmentChallengeId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let raw_query = raw_query.ok_or(MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let mut fields = raw_query.split('&');
    let candidate_device_id = mls_v5_query_value(fields.next(), "candidate_device_id=")?
        .parse::<DeviceId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let controller_device_id = mls_v5_query_value(fields.next(), "controller_device_id=")?
        .parse::<DeviceId>()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let identity_head_digest =
        Sha256Digest::from_str(mls_v5_query_value(fields.next(), "identity_head_digest=")?)
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let key_package_digest =
        Sha256Digest::from_str(mls_v5_query_value(fields.next(), "key_package_digest=")?)
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let recovery_request_digest = Sha256Digest::from_str(mls_v5_query_value(
        fields.next(),
        "recovery_request_digest=",
    )?)
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    let recovery_scope_digest =
        Sha256Digest::from_str(mls_v5_query_value(fields.next(), "recovery_scope_digest=")?)
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
    if fields.next().is_some() {
        return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
    }
    let query = MlsV5RecoveryAuthorizationQuery::new(
        identity_id,
        request_id,
        candidate_device_id,
        controller_device_id,
        identity_head_digest,
        key_package_digest,
        recovery_request_digest,
        recovery_scope_digest,
    );
    if query.canonical_query() != raw_query {
        return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
    }
    Ok(query)
}

fn mls_v5_query_value<'a>(
    field: Option<&'a str>,
    name: &str,
) -> Result<&'a str, MlsV5RecoveryAuthorizationFailure> {
    field
        .and_then(|field| field.strip_prefix(name))
        .filter(|value| !value.is_empty())
        .ok_or(MlsV5RecoveryAuthorizationFailure::InvalidRequest)
}

async fn load_mls_v5_recovery_authorization_projection(
    connection: &mut sqlx::PgConnection,
    query: MlsV5RecoveryAuthorizationQuery,
    now: UtcMillis,
) -> Result<MlsV5RecoveryAuthorizationProjection, MlsV5RecoveryAuthorizationFailure> {
    let snapshot = lock_and_load_active_snapshot(connection, query.identity_id())
        .await
        .map_err(|error| map_mls_v5_recovery_authorization_persistence_error(&error))?;
    if snapshot.head().hash() != query.identity_head_digest()
        || snapshot
            .projection()
            .device_status(query.candidate_device_id())
            != Some(DeviceStatusV1::Active)
        || snapshot
            .projection()
            .device_status(query.controller_device_id())
            != Some(DeviceStatusV1::Active)
    {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    let row = sqlx::query(
        "SELECT provider_device_id,authority_kind,authority_id,
                history_grant_digest,attachment_digest,claim_receipt_digest,
                authorization_expires_at_ms
           FROM identity.mls_v5_recovery_authorization_projection(
               $1,$2,$3,$4,$5,$6,$7,$8,$9
           )",
    )
    .bind(query.identity_id().to_string())
    .bind(*query.request_id().as_uuid())
    .bind(*query.candidate_device_id().as_uuid())
    .bind(*query.controller_device_id().as_uuid())
    .bind(query.identity_head_digest().as_bytes().as_slice())
    .bind(query.key_package_digest().as_bytes().as_slice())
    .bind(query.recovery_request_digest().as_bytes().as_slice())
    .bind(query.recovery_scope_digest().as_bytes().as_slice())
    .bind(now.get())
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?
    .ok_or(MlsV5RecoveryAuthorizationFailure::Unavailable)?;
    let provider_device_id: DeviceId = row
        .try_get::<uuid::Uuid, _>("provider_device_id")
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?
        .try_into()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    if snapshot.projection().device_status(provider_device_id) != Some(DeviceStatusV1::Active) {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    let authority_kind: String = row
        .try_get("authority_kind")
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    let authority_id: String = row
        .try_get("authority_id")
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    let authority_kind = verify_mls_v5_recovery_authority(
        snapshot.projection(),
        provider_device_id,
        &authority_kind,
        &authority_id,
    )?;
    let expires_at = UtcMillis::new(
        row.try_get("authorization_expires_at_ms")
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?,
    )
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    if expires_at <= now {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    MlsV5RecoveryAuthorizationProjection::new(
        query,
        provider_device_id,
        authority_kind,
        authority_id,
        database_digest(&row, "history_grant_digest")?,
        database_digest(&row, "attachment_digest")?,
        database_digest(&row, "claim_receipt_digest")?,
        expires_at,
    )
    .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)
}

fn verify_mls_v5_recovery_authority(
    projection: &IdentityLogV1,
    provider_device_id: DeviceId,
    authority_kind: &str,
    authority_id: &str,
) -> Result<MlsV5RecoveryAuthorityKind, MlsV5RecoveryAuthorizationFailure> {
    match authority_kind {
        "active_device" => {
            let authority = authority_id
                .parse::<DeviceId>()
                .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
            if authority == provider_device_id
                || projection.device_status(authority) != Some(DeviceStatusV1::Active)
            {
                return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
            }
            Ok(MlsV5RecoveryAuthorityKind::ActiveDevice)
        }
        "root" => {
            verify_mls_v5_recovery_key_authority(
                authority_id,
                projection.current_root_key().as_bytes(),
            )?;
            Ok(MlsV5RecoveryAuthorityKind::Root)
        }
        "recovery" => {
            verify_mls_v5_recovery_key_authority(
                authority_id,
                projection.current_recovery_key().as_bytes(),
            )?;
            Ok(MlsV5RecoveryAuthorityKind::Recovery)
        }
        _ => Err(MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable),
    }
}

fn verify_mls_v5_recovery_key_authority(
    authority_id: &str,
    current_key: &[u8],
) -> Result<(), MlsV5RecoveryAuthorizationFailure> {
    if authority_id
        != Sha256Digest::hash_domain(HISTORY_RECOVERY_AUTHORITY_ID_DOMAIN, current_key).to_string()
    {
        return Err(MlsV5RecoveryAuthorizationFailure::Unavailable);
    }
    Ok(())
}

fn database_digest(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
) -> Result<Sha256Digest, MlsV5RecoveryAuthorizationFailure> {
    let bytes: Vec<u8> = row
        .try_get(column)
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn map_mls_v5_recovery_authorization_persistence_error(
    error: &IdentityPersistenceError,
) -> MlsV5RecoveryAuthorizationFailure {
    match error {
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::IdentityInactive
        | IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked => {
            MlsV5RecoveryAuthorizationFailure::Unavailable
        }
        _ => MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable,
    }
}

fn parse_canonical_safe_uint(value: &str) -> Result<u64, IdentityLogPageFailure> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(IdentityLogPageFailure::InvalidRequest);
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
    SafeUint::new(value).map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
    Ok(value)
}

fn parse_positive_safe_uint_path(value: &str) -> Result<SafeUint, RecoveryCatalogFailure> {
    let value =
        parse_canonical_safe_uint(value).map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
    if value == 0 {
        return Err(RecoveryCatalogFailure::InvalidRequest);
    }
    SafeUint::new(value).map_err(|_| RecoveryCatalogFailure::InvalidRequest)
}

fn parse_recovery_enrollment_capability(
    headers: &HeaderMap,
) -> Result<DeviceEnrollmentCapability, RecoveryCatalogFailure> {
    DeviceEnrollmentCapability::new(parse_recovery_capability_header(
        headers,
        DEVICE_ENROLLMENT_CAPABILITY_HEADER,
    )?)
    .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)
}

fn parse_recovery_response_capability(
    headers: &HeaderMap,
) -> Result<RecoveryResponseCapability, RecoveryCatalogFailure> {
    RecoveryResponseCapability::new(parse_recovery_capability_header(
        headers,
        RECOVERY_RESPONSE_CAPABILITY_HEADER,
    )?)
    .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)
}

fn parse_recovery_capability_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<[u8; 32], RecoveryCatalogFailure> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or(RecoveryCatalogFailure::CapabilityRejected)?;
    if values.next().is_some() {
        return Err(RecoveryCatalogFailure::CapabilityRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
    let bytes =
        decode_base64url_32(value).map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
    if Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(RecoveryCatalogFailure::CapabilityRejected);
    }
    Ok(bytes)
}

const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || matches!(value, b'-' | b'_')
}

fn map_identity_log_page_persistence_error(
    error: &IdentityPersistenceError,
) -> IdentityLogPageFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) => IdentityLogPageFailure::InvalidRequest,
        IdentityPersistenceError::IdentityInactive => IdentityLogPageFailure::Inactive,
        _ => IdentityLogPageFailure::TemporarilyUnavailable,
    }
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
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
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
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
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
        | IdentityPersistenceError::DeviceSessionRevoked
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
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::CorruptData(_) => DeviceSessionFailure::TemporarilyUnavailable,
    }
}

fn map_recovery_catalog_publish_error(error: &IdentityPersistenceError) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            RecoveryCatalogFailure::InvalidRequest
        }
        IdentityPersistenceError::RecoveryExactCborInvalid => {
            RecoveryCatalogFailure::ExactCborInvalid
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => {
            RecoveryCatalogFailure::AuthenticationRejected
        }
        IdentityPersistenceError::RecoveryCatalogExpired => RecoveryCatalogFailure::CatalogExpired,
        IdentityPersistenceError::RecoveryCatalogConflict => {
            RecoveryCatalogFailure::CatalogConflict
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict => RecoveryCatalogFailure::IdentityHeadChanged,
        IdentityPersistenceError::IdempotencyConflict => {
            RecoveryCatalogFailure::IdempotencyConflict
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
    }
}

fn map_recovery_catalog_prepare_error(error: &IdentityPersistenceError) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            RecoveryCatalogFailure::InvalidRequest
        }
        IdentityPersistenceError::RecoveryExactCborInvalid => {
            RecoveryCatalogFailure::ExactCborInvalid
        }
        IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected => {
            RecoveryCatalogFailure::CapabilityRejected
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked => {
            RecoveryCatalogFailure::AuthenticationRejected
        }
        IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired => {
            RecoveryCatalogFailure::PreparationExpired
        }
        IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved => {
            RecoveryCatalogFailure::PreparationRevoked
        }
        IdentityPersistenceError::RecoveryCatalogExpired => RecoveryCatalogFailure::CatalogExpired,
        IdentityPersistenceError::RecoveryPreparationInvalidated => {
            RecoveryCatalogFailure::PreparationInvalidated
        }
        IdentityPersistenceError::RecoveryCatalogConflict => {
            RecoveryCatalogFailure::CatalogConflict
        }
        IdentityPersistenceError::RecoveryPreparationConflict => {
            RecoveryCatalogFailure::PreparationConflict
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::IdentityInactive => RecoveryCatalogFailure::IdentityHeadChanged,
        IdentityPersistenceError::RecoveryCatalogHeadChanged => {
            RecoveryCatalogFailure::CatalogHeadChanged
        }
        IdentityPersistenceError::RecoveryAuthorityChanged => {
            RecoveryCatalogFailure::AuthorityChanged
        }
        IdentityPersistenceError::RecoveryCandidateKeyChanged => {
            RecoveryCatalogFailure::CandidateKeyChanged
        }
        IdentityPersistenceError::IdempotencyConflict => {
            RecoveryCatalogFailure::IdempotencyConflict
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
    }
}

fn map_recovery_catalog_status_error(error: &IdentityPersistenceError) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected => {
            RecoveryCatalogFailure::CapabilityRejected
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::InvalidCommand(_)
        | IdentityPersistenceError::IdentityLog(_)
        | IdentityPersistenceError::IdempotencyConflict
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::IdentityInactive
        | IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
    }
}

fn map_recovery_catalog_provider_error(error: &IdentityPersistenceError) -> RecoveryCatalogFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            RecoveryCatalogFailure::InvalidRequest
        }
        IdentityPersistenceError::RecoveryExactCborInvalid => {
            RecoveryCatalogFailure::ExactCborInvalid
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => {
            RecoveryCatalogFailure::AuthenticationRejected
        }
        IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired => {
            RecoveryCatalogFailure::PreparationExpired
        }
        IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled => {
            RecoveryCatalogFailure::PreparationRevoked
        }
        IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged => {
            RecoveryCatalogFailure::PreparationInvalidated
        }
        IdentityPersistenceError::RecoveryCatalogConflict => {
            RecoveryCatalogFailure::CatalogConflict
        }
        IdentityPersistenceError::RecoveryPreparationConflict => {
            RecoveryCatalogFailure::PreparationConflict
        }
        IdentityPersistenceError::IdempotencyConflict => {
            RecoveryCatalogFailure::IdempotencyConflict
        }
        IdentityPersistenceError::Database(_)
        | IdentityPersistenceError::UnsafeRuntimeRole
        | IdentityPersistenceError::RuntimeRoleUnauthorized
        | IdentityPersistenceError::RuntimeRoleOverprivileged
        | IdentityPersistenceError::TenantContextLeak
        | IdentityPersistenceError::IncompleteCommand
        | IdentityPersistenceError::ReceiptIntegrity
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::CorruptData(_) => {
            RecoveryCatalogFailure::TemporarilyUnavailable
        }
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
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked => {
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
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::CorruptData(_) => {
            DeviceEnrollmentFailure::TemporarilyUnavailable
        }
    }
}

fn map_device_revoke_persistence_error(error: &IdentityPersistenceError) -> DeviceRevokeFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            DeviceRevokeFailure::InvalidRequest
        }
        IdentityPersistenceError::IdempotencyConflict => DeviceRevokeFailure::IdempotencyConflict,
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
        | IdentityPersistenceError::IdentityInactive => DeviceRevokeFailure::AuthenticationRejected,
        IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden => {
            DeviceRevokeFailure::CurrentSessionForbidden
        }
        IdentityPersistenceError::HeadConflict { .. }
        | IdentityPersistenceError::GenesisConflict => DeviceRevokeFailure::IdentityConflict,
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
        | IdentityPersistenceError::KeyPackageUnavailable
        | IdentityPersistenceError::KeyPackageConflict
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::CorruptData(_) => DeviceRevokeFailure::TemporarilyUnavailable,
    }
}

fn map_key_package_persistence_error(error: &IdentityPersistenceError) -> KeyPackageFailure {
    match error {
        IdentityPersistenceError::InvalidCommand(_) | IdentityPersistenceError::IdentityLog(_) => {
            KeyPackageFailure::InvalidRequest
        }
        IdentityPersistenceError::DeviceAuthenticationRejected
        | IdentityPersistenceError::DeviceSessionRevoked
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
        | IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden
        | IdentityPersistenceError::DeviceSessionChallengeExpired
        | IdentityPersistenceError::DeviceSessionChallengeConsumed
        | IdentityPersistenceError::DeviceSessionChallengeRateLimited
        | IdentityPersistenceError::DeviceEnrollmentCapabilityRejected
        | IdentityPersistenceError::DeviceEnrollmentChallengeExpired
        | IdentityPersistenceError::DeviceEnrollmentChallengeCancelled
        | IdentityPersistenceError::DeviceEnrollmentChallengeApproved
        | IdentityPersistenceError::RecoveryExactCborInvalid
        | IdentityPersistenceError::RecoveryCatalogConflict
        | IdentityPersistenceError::RecoveryCatalogExpired
        | IdentityPersistenceError::RecoveryPreparationConflict
        | IdentityPersistenceError::RecoveryResponseCapabilityRejected
        | IdentityPersistenceError::RecoveryPreparationExpired
        | IdentityPersistenceError::RecoveryPreparationRevoked
        | IdentityPersistenceError::RecoveryCatalogHeadChanged
        | IdentityPersistenceError::RecoveryAuthorityChanged
        | IdentityPersistenceError::RecoveryCandidateKeyChanged
        | IdentityPersistenceError::RecoveryPreparationInvalidated
        | IdentityPersistenceError::CorruptData(_) => KeyPackageFailure::TemporarilyUnavailable,
    }
}

fn map_federated_identity_error(error: FederatedIdentityError) -> KeyPackageFailure {
    match error {
        FederatedIdentityError::TemporarilyUnavailable => KeyPackageFailure::TemporarilyUnavailable,
        FederatedIdentityError::InvalidOrigin
        | FederatedIdentityError::InvalidTrustRoot
        | FederatedIdentityError::InvalidIdentityLog
        | FederatedIdentityError::InvalidRecoveryAuthorization
        | FederatedIdentityError::RecoveryAuthorizationUnavailable
        | FederatedIdentityError::DeviceUnavailable => KeyPackageFailure::AuthenticationRejected,
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

struct HistoryRecoveryCandidateRequest {
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    target_device_id: DeviceId,
    target_device_signing_key: SigningPublicKey,
    recipient_encryption_key: DeviceEncryptionPublicKey,
    observed_head_sequence: SafeUint,
    observed_head_hash: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    candidate_signature: Ed25519Signature,
    capability: DeviceEnrollmentCapability,
    exact_signed_request: Vec<u8>,
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

fn parse_history_recovery_request(
    bytes: &[u8],
) -> Result<HistoryRecoveryCandidateRequest, DeviceEnrollmentFailure> {
    let value =
        decode_deterministic_cbor(bytes).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 13)?;
    if cbor_field(fields, 1)? != &CanonicalValue::Unsigned(2) {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    if cbor_field(fields, 9)? != &CanonicalValue::Unsigned(1) {
        return Err(DeviceEnrollmentFailure::InvalidRequest);
    }
    let exact_signed_request = encode_deterministic_cbor(&CanonicalValue::Map(
        fields.iter().take(12).cloned().collect(),
    ))
    .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
    Ok(HistoryRecoveryCandidateRequest {
        request_id: parse_cbor_challenge_id(cbor_field(fields, 2)?)?,
        identity_id: parse_cbor_identity_id(cbor_field(fields, 3)?)?,
        target_device_id: parse_cbor_device_id(cbor_field(fields, 4)?)?,
        target_device_signing_key: SigningPublicKey::try_from(parse_cbor_bytes::<32>(cbor_field(
            fields, 5,
        )?)?)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
        recipient_encryption_key: DeviceEncryptionPublicKey::try_from(parse_cbor_bytes::<32>(
            cbor_field(fields, 6)?,
        )?)
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
        observed_head_sequence: match cbor_field(fields, 7)? {
            CanonicalValue::Unsigned(value) => {
                SafeUint::new(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
            }
            _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
        },
        observed_head_hash: Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 8)?)?),
        issued_at: match cbor_field(fields, 10)? {
            CanonicalValue::Negative(value) => {
                UtcMillis::new(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
            }
            CanonicalValue::Unsigned(value) => UtcMillis::new(
                i64::try_from(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
        },
        expires_at: match cbor_field(fields, 11)? {
            CanonicalValue::Negative(value) => {
                UtcMillis::new(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?
            }
            CanonicalValue::Unsigned(value) => UtcMillis::new(
                i64::try_from(*value).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
            _ => return Err(DeviceEnrollmentFailure::InvalidRequest),
        },
        candidate_signature: Ed25519Signature::from_bytes(parse_cbor_bytes(cbor_field(
            fields, 12,
        )?)?),
        capability: DeviceEnrollmentCapability::new(parse_cbor_bytes(cbor_field(fields, 13)?)?)
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
        exact_signed_request,
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
    history_recovery_scope: Option<HistoryRecoveryKeyPackageScope>,
}

struct KeyPackageClaimRequest {
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    history_recovery_scope: Option<HistoryRecoveryKeyPackageScope>,
}

fn parse_key_package_publish(bytes: &[u8]) -> Result<KeyPackagePublishRequest, KeyPackageFailure> {
    if bytes.is_empty() {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| KeyPackageFailure::InvalidRequest)?;
    let field_count = match &value {
        CanonicalValue::Map(fields) => fields.len(),
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    if !matches!(field_count, 9 | 12) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let fields = key_package_cbor_fields(&value, field_count)?;
    let version = if field_count == 12 { 2 } else { 1 };
    if key_package_cbor_field(fields, 1)? != &CanonicalValue::Unsigned(version) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
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
    let history_recovery_scope = if version == 2 {
        if key_package_cbor_field(fields, 12)? != &CanonicalValue::Unsigned(1) {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        Some(
            HistoryRecoveryKeyPackageScope::new(
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 10,
                )?)?),
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 11,
                )?)?),
            )
            .map_err(|_| KeyPackageFailure::InvalidRequest)?,
        )
    } else {
        None
    };
    Ok(KeyPackagePublishRequest {
        identity_id,
        device_id,
        package_id,
        published_head_sequence,
        published_head_hash,
        expires_at,
        opaque_key_package,
        detached_signature,
        history_recovery_scope,
    })
}

fn parse_key_package_claim(bytes: &[u8]) -> Result<KeyPackageClaimRequest, KeyPackageFailure> {
    if bytes.is_empty() {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| KeyPackageFailure::InvalidRequest)?;
    let field_count = match &value {
        CanonicalValue::Map(fields) => fields.len(),
        _ => return Err(KeyPackageFailure::InvalidRequest),
    };
    if !matches!(field_count, 3 | 6) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let fields = key_package_cbor_fields(&value, field_count)?;
    let version = if field_count == 6 { 2 } else { 1 };
    if key_package_cbor_field(fields, 1)? != &CanonicalValue::Unsigned(version) {
        return Err(KeyPackageFailure::InvalidRequest);
    }
    let history_recovery_scope = if version == 2 {
        if key_package_cbor_field(fields, 6)? != &CanonicalValue::Unsigned(1) {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        Some(
            HistoryRecoveryKeyPackageScope::new(
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 4,
                )?)?),
                Sha256Digest::from_bytes(key_package_parse_bytes(key_package_cbor_field(
                    fields, 5,
                )?)?),
            )
            .map_err(|_| KeyPackageFailure::InvalidRequest)?,
        )
    } else {
        None
    };
    Ok(KeyPackageClaimRequest {
        target_identity_id: key_package_parse_identity_id(key_package_cbor_field(fields, 2)?)?,
        target_device_id: key_package_parse_device_id(key_package_cbor_field(fields, 3)?)?,
        history_recovery_scope,
    })
}

fn parse_federated_key_package_claim_proof(
    headers: &HeaderMap,
) -> Result<FederatedKeyPackageClaimProof, KeyPackageFailure> {
    let proof = single_graphic_header(
        headers,
        KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER,
        1,
        MAX_KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER_BYTES,
    )
    .map_err(|()| KeyPackageFailure::AuthenticationRejected)?;
    if !proof.bytes().all(is_base64url_byte) {
        return Err(KeyPackageFailure::AuthenticationRejected);
    }
    let mut decoded = vec![0_u8; MAX_KEY_PACKAGE_FEDERATED_CLAIM_PROOF_HEADER_BYTES * 3 / 4];
    let exact = Base64UrlUnpadded::decode(proof, &mut decoded)
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
    if Base64UrlUnpadded::encode_string(exact) != proof {
        decoded.zeroize();
        return Err(KeyPackageFailure::AuthenticationRejected);
    }
    let value =
        decode_deterministic_cbor(exact).map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
    decoded.zeroize();
    let fields = key_package_cbor_fields(&value, 14)
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
    if key_package_cbor_field(fields, 1).map_err(|_| KeyPackageFailure::AuthenticationRejected)?
        != &CanonicalValue::Unsigned(2)
    {
        return Err(KeyPackageFailure::AuthenticationRejected);
    }
    let text = |key| -> Result<String, KeyPackageFailure> {
        match key_package_cbor_field(fields, key)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?
        {
            CanonicalValue::Text(value) => Ok(value.clone()),
            _ => Err(KeyPackageFailure::AuthenticationRejected),
        }
    };
    FederatedKeyPackageClaimProof::new(
        text(2)?,
        key_package_parse_identity_id(
            key_package_cbor_field(fields, 3)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_device_id(
            key_package_cbor_field(fields, 4)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_identity_id(
            key_package_cbor_field(fields, 5)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_device_id(
            key_package_cbor_field(fields, 6)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        text(7)?,
        text(8)?,
        Sha256Digest::from_bytes(
            key_package_parse_bytes::<32>(
                key_package_cbor_field(fields, 9)
                    .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
            )
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        ),
        key_package_parse_utc_millis(
            key_package_cbor_field(fields, 10)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_utc_millis(
            key_package_cbor_field(fields, 11)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        key_package_parse_bytes::<32>(
            key_package_cbor_field(fields, 12)
                .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        )
        .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        Sha256Digest::from_bytes(
            key_package_parse_bytes::<32>(
                key_package_cbor_field(fields, 13)
                    .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
            )
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        ),
        Ed25519Signature::from_bytes(
            key_package_parse_bytes::<64>(
                key_package_cbor_field(fields, 14)
                    .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
            )
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?,
        ),
    )
    .map_err(|_| KeyPackageFailure::AuthenticationRejected)
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

#[derive(Clone, Copy, Debug)]
enum IdentityLogPageFailure {
    InvalidRequest,
    NotFound,
    CursorAhead,
    Inactive,
    TemporarilyUnavailable,
}

#[derive(Clone, Copy, Debug)]
enum MlsV5RecoveryAuthorizationFailure {
    InvalidRequest,
    Unavailable,
    TemporarilyUnavailable,
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

#[derive(Clone, Copy)]
enum ClientBindingFailure {
    Invalid,
    Conflict,
    Unauthorized,
    Expired,
    Revoked,
    Unavailable,
}

fn map_client_binding_error(error: ClientBindingWorkflowError) -> ClientBindingFailure {
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

struct DeviceRevokeSuccess {
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

struct RecoveryCatalogHeadSuccess {
    status: StatusCode,
    outcome: RecoveryScopeCatalogOutcome,
}

struct RecoveryCatalogStatusSuccess {
    status: StatusCode,
    outcome: RecoveryScopeCatalogStatusOutcome,
}

#[derive(Clone, Copy, Debug)]
enum RecoveryCatalogFailure {
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
enum DeviceRevokeFailure {
    InvalidRequest,
    AuthenticationRejected,
    CurrentSessionForbidden,
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
enum IdentityLogPageErrorCode {
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
enum MlsV5RecoveryAuthorizationErrorCode {
    #[serde(rename = "MLS_V5_RECOVERY_AUTHORIZATION_REQUEST_INVALID")]
    InvalidRequest,
    #[serde(rename = "MLS_V5_RECOVERY_AUTHORIZATION_UNAVAILABLE")]
    Unavailable,
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
enum DeviceRevokeErrorCode {
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

#[derive(Clone, Copy, Serialize)]
enum RecoveryCatalogErrorCode {
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

fn identity_log_page_success_response(page: &IdentityLogPageV1, request_id: RequestId) -> Response {
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

fn identity_log_page_failure_response(
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

fn mls_v5_recovery_authorization_failure_response(
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

#[derive(Clone, Copy, Serialize)]
enum ClientBindingErrorCode {
    #[serde(rename = "CLIENT_BINDING_INVALID")]
    Invalid,
    #[serde(rename = "CLIENT_BINDING_CONFLICT")]
    Conflict,
    #[serde(rename = "CLIENT_BINDING_INVALID")]
    Unauthorized,
    #[serde(rename = "CLIENT_BINDING_INVALID")]
    Expired,
    #[serde(rename = "CLIENT_BINDING_INVALID")]
    Revoked,
    #[serde(rename = "IDENTITY_SERVICE_UNAVAILABLE")]
    Unavailable,
}

fn client_binding_failure_response(
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

fn device_revoke_success_response(success: DeviceRevokeSuccess, request_id: RequestId) -> Response {
    exact_cbor_response(
        success.status,
        success.exact_receipt_bytes,
        IDENTITY_APPEND_RECEIPT_CONTENT_TYPE,
        request_id,
    )
}

fn device_revoke_failure_response(failure: DeviceRevokeFailure, request_id: RequestId) -> Response {
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

fn recovery_catalog_head_response(
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

fn recovery_catalog_status_response(
    success: &RecoveryCatalogStatusSuccess,
    request_id: RequestId,
) -> Response {
    match success.outcome.exact_bytes() {
        Ok(bytes) => exact_cbor_response(
            success.status,
            bytes,
            RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE,
            request_id,
        ),
        Err(_) => recovery_catalog_failure_response(
            RecoveryCatalogFailure::TemporarilyUnavailable,
            request_id,
        ),
    }
}

fn recovery_catalog_failure_response(
    failure: RecoveryCatalogFailure,
    request_id: RequestId,
) -> Response {
    let (status, code, retryable) = match failure {
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

fn contact_secret(headers: &HeaderMap, name: &'static str) -> Result<[u8; 32], ContactStoreError> {
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

fn encode_pending(values: &[ContactRequestRecord]) -> Result<Vec<u8>, ContactStoreError> {
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
fn contact_failure(error: ContactStoreError, request_id: RequestId) -> Response {
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

    #[test]
    fn client_binding_headers_reject_duplicates_and_non_exact_media_inputs() {
        let mut headers = HeaderMap::new();
        headers.append(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("0123456789abcdef"),
        );
        headers.append(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("0123456789abcdef"),
        );
        assert!(idempotency_key_hash_binding(&headers, HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN).is_err());

        let mut binding = HeaderMap::new();
        binding.insert(
            CLIENT_BINDING_HEADER,
            HeaderValue::from_static("0190f2a5-7b1c-7abc-8def-0123456789ab"),
        );
        binding.append(
            header::AUTHORIZATION,
            HeaderValue::from_static(
                "DTX-Client-Binding AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        );
        binding.append(
            header::AUTHORIZATION,
            HeaderValue::from_static(
                "DTX-Client-Binding AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        );
        assert!(client_binding_authorization(&binding).is_err());

        let mut malformed = HeaderMap::new();
        malformed.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(
                "application/vnd.dirextalk.identity-log.v1.1+cbor; charset=utf-8",
            ),
        );
        assert!(!has_exact_event_content_type(&malformed));
        malformed.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(IDENTITY_LOG_EVENT_CONTENT_TYPE),
        );
        malformed.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(malformed.contains_key(header::CONTENT_ENCODING));
    }
}
