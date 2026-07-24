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
    CreateHistoryRecoveryRequestV4Command, DeviceEnrollmentApprovalCommand,
    DeviceEnrollmentCapability, DeviceEnrollmentChallenge, DeviceEnrollmentChallengeOutcome,
    DeviceEnrollmentChallengeState, DeviceEnrollmentChallengeStatus, DeviceEnrollmentRepository,
    DeviceRevokeCommand, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionOutcome, DeviceSessionRepository, FEDERATED_KEY_PACKAGE_CLAIM_PATH,
    FederatedKeyPackageClaimProof, HistoryRecoveryKeyPackageScope, IdentityAppendCommand,
    IdentityAppendOutcome, IdentityLogHead, IdentityLogPageReadOutcome, IdentityLogRepository,
    IdentityPersistenceError, IdentityPgStore, KeyPackageClaimCommand, KeyPackageClaimOutcome,
    KeyPackagePublishCommand, KeyPackagePublishOutcome, KeyPackageRepository,
    MAX_KEY_PACKAGE_PUBLISH_BYTES, MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES,
    MAX_RECOVERY_SCOPE_CATALOG_SIGNED_METADATA_BYTES, RecoveryResponseCapability,
    RecoveryScopeCatalogOutcome, RecoveryScopeCatalogRepository, RecoveryScopeCatalogStatusOutcome,
    lock_and_load_active_snapshot,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use getrandom::fill as fill_random;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::Row;
use zeroize::{Zeroize, Zeroizing};

#[path = "http/auth.rs"]
mod auth;
#[path = "http/contacts.rs"]
mod contacts;
#[path = "http/enrollment_codec.rs"]
mod enrollment_codec;
#[path = "http/error_types.rs"]
mod error_types;
#[path = "http/errors.rs"]
mod errors;
#[path = "http/identity.rs"]
mod identity;
#[path = "http/identity_codec.rs"]
mod identity_codec;
#[path = "http/key_package_codec.rs"]
mod key_package_codec;
#[path = "http/key_packages.rs"]
mod key_packages;
#[path = "http/recovery.rs"]
mod recovery;
#[path = "http/responses.rs"]
mod responses;
#[path = "http/sessions_enrollment.rs"]
mod sessions_enrollment;

pub(crate) use auth::{
    client_binding_id, expected_device_revoke_head_hash, expected_genesis_hash,
    has_exact_content_type, has_exact_event_content_type, has_exact_header,
    has_exact_json_content_type, idempotency_key_hash, idempotency_key_hash_binding,
    single_graphic_header, take_client_binding_authorization_digest,
};
pub(crate) use contacts::{
    create_contact_invite, get_contact_receipt, pending_contact_requests, review_contact_request,
    revoke_contact_invite, submit_contact_request,
};
pub use enrollment_codec::parse_device_session_authorization;
pub(crate) use enrollment_codec::{
    DeviceSessionAuthorizationError, decode_base64url_32, parse_device_enrollment_candidate,
    parse_device_enrollment_completion, parse_device_enrollment_status_request,
    parse_history_recovery_request, parse_history_recovery_request_v4, parse_json_body,
};
pub(crate) use error_types::map_client_binding_error;
pub(crate) use error_types::{
    BootstrapErrorBody, BootstrapErrorCode, BootstrapErrorEnvelope, BootstrapFailure,
    BootstrapSuccess, ClientBindingFailure, DeviceEnrollmentApprovalSuccess,
    DeviceEnrollmentChallengeSuccess, DeviceEnrollmentErrorCode, DeviceEnrollmentFailure,
    DeviceRevokeErrorCode, DeviceRevokeFailure, DeviceRevokeSuccess, DeviceSessionChallengeRequest,
    DeviceSessionChallengeResponse, DeviceSessionCompletionRequest, DeviceSessionErrorCode,
    DeviceSessionFailure, DeviceSessionSuccess, HistoryRecoveryRequestV4Success,
    IdentityLogPageErrorCode, IdentityLogPageFailure, InitialDeviceErrorCode, InitialDeviceFailure,
    InitialDeviceSuccess, KeyPackageClaimSuccess, KeyPackageErrorCode, KeyPackageFailure,
    KeyPackagePublishSuccess, MlsV5RecoveryAuthorizationErrorCode,
    MlsV5RecoveryAuthorizationFailure, RecoveryCatalogErrorCode, RecoveryCatalogFailure,
    RecoveryCatalogHeadSuccess, RecoveryCatalogStatusSuccess, SafeErrorBody, SafeErrorEnvelope,
};
pub(crate) use errors::{
    map_device_enrollment_persistence_error, map_device_revoke_persistence_error,
    map_device_session_persistence_error, map_federated_identity_error,
    map_identity_log_page_persistence_error, map_initial_device_persistence_error,
    map_key_package_persistence_error, map_persistence_error, map_recovery_catalog_prepare_error,
    map_recovery_catalog_provider_error, map_recovery_catalog_publish_error,
    map_recovery_catalog_status_error,
};
pub(crate) use identity::{
    bootstrap_identity, deployment_bootstrap_identity, deployment_initial_device,
    enroll_initial_device, get_identity_log_page, get_mls_v5_recovery_authorization,
};
pub(crate) use identity_codec::{
    is_base64url_byte, load_mls_v5_recovery_authorization_projection,
    parse_identity_log_page_request, parse_mls_v5_recovery_authorization_query,
    parse_positive_safe_uint_path, parse_recovery_capability_header,
    parse_recovery_enrollment_capability, parse_recovery_response_capability,
};
pub(crate) use key_package_codec::{
    parse_federated_key_package_claim_proof, parse_key_package_claim, parse_key_package_publish,
};
pub(crate) use key_packages::{
    claim_key_package, claim_key_package_federated, publish_key_package,
};
pub(crate) use recovery::{
    get_recovery_scope_catalog_preparation, prepare_recovery_scope_catalog,
    publish_recovery_scope_catalog, put_recovery_scope_catalog_provider_response,
};
pub(crate) use responses::{
    bootstrap_failure_response, bootstrap_success_response, client_binding_failure_response,
    contact_failure, contact_secret, device_enrollment_approval_success_response,
    device_enrollment_challenge_success_response, device_enrollment_failure_response,
    device_enrollment_status_response, device_revoke_failure_response,
    device_revoke_success_response, device_session_challenge_success_response,
    device_session_failure_response, device_session_success_response, encode_pending,
    exact_cbor_response, history_recovery_request_v4_success_response,
    identity_log_page_failure_response, identity_log_page_success_response,
    initial_device_failure_response, initial_device_success_response,
    key_package_claim_success_response, key_package_failure_response,
    key_package_publish_success_response, mls_v5_recovery_authorization_failure_response,
    recovery_catalog_failure_response, recovery_catalog_head_response,
    recovery_catalog_status_response,
};
pub(crate) use sessions_enrollment::{
    approve_device_enrollment, cancel_device_enrollment_challenge, complete_device_session,
    create_device_enrollment_challenge, create_device_session_challenge,
    create_history_recovery_request_v4, get_device_enrollment_challenge, revoke_device,
};

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
    "/v3/devices/enroll/catalog-preparations";
/// Candidate capability route for one redacted preparation status.
pub const RECOVERY_SCOPE_CATALOG_PREPARATION_PATH_TEMPLATE: &str =
    "/v3/devices/enroll/catalog-preparations/{request_id}";
/// Active-provider route for the preparation's one immutable response.
pub const RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE: &str =
    "/v3/devices/enroll/catalog-preparations/{request_id}/provider-response";
/// Candidate-signed catalog-exhaustive History Recovery Request V4 route.
pub const HISTORY_RECOVERY_REQUEST_V4_PATH: &str = "/v4/devices/history-recovery-requests";
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
pub const HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.history-recovery-request.v4+cbor";
pub const HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.history-recovery-request-receipt.v4+cbor";
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
    "application/vnd.dirextalk.recovery-scope-catalog-preparation.v2+cbor";
/// Exact active-provider response media type.
pub const RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor";
/// Exact redacted preparation status media type.
pub const RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-status.v2+cbor";
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
pub(crate) const HTTP_HISTORY_RECOVERY_REQUEST_V4_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.request-idempotency.v4\0";
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
        .route(
            HISTORY_RECOVERY_REQUEST_V4_PATH,
            post(create_history_recovery_request_v4),
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

#[cfg(test)]
mod tests {
    use super::enrollment_codec::{
        cbor_field, exact_cbor_fields, parse_device_enrollment_candidate,
    };
    use super::responses::{
        client_binding_failure_response, encode_device_enrollment_status_fields,
    };
    use super::{
        CLIENT_BINDING_HEADER, CanonicalValue, ClientBindingAuthorization, ClientBindingFailure,
        DeviceEnrollmentChallengeId, DeviceId, HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN, HeaderMap,
        HeaderValue, IDEMPOTENCY_KEY_HEADER, IDENTITY_LOG_EVENT_CONTENT_TYPE, IdentityId,
        RequestId, SigningPublicKey, StatusCode, UtcMillis, decode_deterministic_cbor,
        encode_deterministic_cbor, has_exact_event_content_type, idempotency_key_hash_binding,
        take_client_binding_authorization_digest,
    };
    use axum::http::header;

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
        assert!(take_client_binding_authorization_digest(&mut binding).is_err());
        assert!(!binding.contains_key(header::AUTHORIZATION));

        let mut exact_authorization = HeaderMap::new();
        exact_authorization.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static(
                "DTX-Client-Binding AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        );
        let expected =
            ClientBindingAuthorization::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .expect("fixed authorization decodes")
                .digest();
        let Ok(actual) = take_client_binding_authorization_digest(&mut exact_authorization) else {
            panic!("fixed authorization is accepted");
        };
        assert_eq!(actual, expected);
        assert!(!exact_authorization.contains_key(header::AUTHORIZATION));

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

    #[tokio::test]
    async fn client_binding_error_response_is_redacted_and_exact() {
        for (failure, status, code, retryable) in [
            (
                ClientBindingFailure::Invalid,
                StatusCode::UNPROCESSABLE_ENTITY,
                "CLIENT_BINDING_INVALID",
                false,
            ),
            (
                ClientBindingFailure::Conflict,
                StatusCode::CONFLICT,
                "CLIENT_BINDING_CONFLICT",
                false,
            ),
            (
                ClientBindingFailure::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "IDENTITY_SERVICE_UNAVAILABLE",
                true,
            ),
        ] {
            let request_id = RequestId::new();
            let response = client_binding_failure_response(failure, request_id);
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE),
                Some(&HeaderValue::from_static("application/json"))
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL),
                Some(&HeaderValue::from_static("no-store"))
            );
            assert_eq!(
                response.headers().get(header::X_CONTENT_TYPE_OPTIONS),
                Some(&HeaderValue::from_static("nosniff"))
            );
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .expect("fixed error body is bounded");
            let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON envelope");
            assert_eq!(value["error"]["code"], code);
            assert_eq!(value["error"]["request_id"], request_id.to_string());
            assert_eq!(value["error"]["retryable"], retryable);
            assert!(value["error"].get("authorization").is_none());
            assert!(value["error"].get("body").is_none());
        }
    }
}
