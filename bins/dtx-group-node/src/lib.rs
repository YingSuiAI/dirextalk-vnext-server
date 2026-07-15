#![forbid(unsafe_code)]

//! Tenant-affine HTTP boundary for durable group policy and membership intents.
//!
//! This node deliberately stops at a durable `pending_commit` receipt. It does
//! not invent an MLS result: a later Sequencer adapter is the only component
//! allowed to turn that intent into a committed membership fact.

mod federated_identity;
mod sequencer_key;

use std::{fmt::Write as _, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    ChannelId, Clock, ConversationId, DeviceId, DeviceSessionId, IdentityId, InviteCapabilityId,
    JoinRequestId, RequestId, Revision, SystemClock, TenantId,
};
use dtx_group_persistence::{
    GroupControlCommand, GroupControlDisposition, GroupControlExecution, GroupControlOperation,
    GroupControlReceipt, GroupControlRejection, GroupControlRepository, GroupMembershipRepository,
    GroupPersistenceError, GroupPgStore, MLS_IDEMPOTENCY_KEY_HASH_DOMAIN,
    MembershipCommandExecution, MlsCommitAuthorization, MlsCommitCommand, MlsCommitExecution,
    MlsCommitReceipt, MlsCommitSequencerRepository, MlsDeviceJoinConfirmation,
    PendingJoinRequestCursor, PendingJoinRequestPage, VerifiedDeviceActor,
    mls_opaque_commit_digest,
};
use dtx_group_policy::{GroupScope, MAX_ADMINS};
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_membership_command::{
    ApproveJoinCommand, CandidateMembership, JoinRequestCommand, MembershipAdmission,
    MembershipCommandContext, MembershipCommandId, MembershipCommandPhase, MembershipFence,
    MembershipReceipt, MembershipRejection,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, SigningPublicKey, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;

use crate::federated_identity::{FederatedIdentityError, FederatedIdentityVerifier};

pub use crate::sequencer_key::load_mls_sequencer_signing_key;

/// Invalid local-development federation configuration.
#[derive(Clone, Copy, Debug)]
pub struct GroupNodeConfigurationError(FederatedIdentityError);

impl std::fmt::Display for GroupNodeConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for GroupNodeConfigurationError {}

/// Group creation path template.
pub const GROUP_SCOPE_PATH_TEMPLATE: &str = "/v1/groups/{scope_kind}/{scope_id}";
/// Administrator grant path template.
pub const GROUP_ADMIN_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/admins/{administrator_identity_id}";
/// Administrator revocation path template.
pub const GROUP_ADMIN_REVOKE_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/admins/{administrator_identity_id}/revoke";
/// Invitation issue path template.
pub const GROUP_INVITE_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/invites/{invite_id}";
/// Invitation revocation path template.
pub const GROUP_INVITE_REVOKE_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/invites/{invite_id}/revoke";
/// Candidate join-request path template.
pub const GROUP_JOIN_REQUEST_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/join-requests/{join_request_id}";
/// Owner/Admin pending join-request collection path template.
pub const GROUP_JOIN_REQUEST_COLLECTION_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/join-requests";
/// Owner/Admin approval path template.
pub const GROUP_JOIN_APPROVAL_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/join-requests/{join_request_id}/approvals";
/// Durable membership-receipt path template.
pub const GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/membership-receipts/{membership_command_id}";
/// V2 MLS commit submit/query path. V1 is intentionally not routed.
pub const MLS_COMMIT_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/mls-commits/{submission_id}";
/// V2 exact-device confirmation path.
pub const MLS_CONFIRMATION_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/mls-commits/{submission_id}/confirmations/{device_id}";
/// Origin-bound public verification key descriptor.
pub const MLS_SEQUENCER_DESCRIPTOR_PATH: &str = "/v1/mls-sequencer";
/// Public V29 Group Service descriptor path.
pub const GROUP_SERVICE_DESCRIPTOR_PATH: &str = "/v1/group-service";

/// Exact create request media type.
pub const GROUP_CREATE_CONTENT_TYPE: &str = "application/vnd.dirextalk.group-create.v1+cbor";
/// Exact grant-admin request media type.
pub const GROUP_GRANT_ADMIN_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-grant-admin.v1+cbor";
/// Exact revoke-admin request media type.
pub const GROUP_REVOKE_ADMIN_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-revoke-admin.v1+cbor";
/// Exact invitation issue request media type.
pub const GROUP_ISSUE_INVITE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-issue-invite.v1+cbor";
/// Exact invitation revocation request media type.
pub const GROUP_REVOKE_INVITE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-revoke-invite.v1+cbor";
/// Exact candidate join request media type.
pub const GROUP_JOIN_REQUEST_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-join-request.v1+cbor";
/// Exact owner/admin approval request media type.
pub const GROUP_APPROVE_JOIN_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-approve-join.v1+cbor";
/// Exact local policy receipt media type.
pub const GROUP_ACTION_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-action-receipt.v1+cbor";
/// Exact membership receipt media type.
pub const MEMBERSHIP_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.membership-receipt.v1+cbor";
/// Exact V29 Owner/Admin pending-request page media type.
pub const GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-join-request-page.v1+cbor";
/// Exact V29 public Group Service descriptor media type.
pub const GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-service.v1+cbor";
/// Exact V2 MLS commit request media type.
pub const MLS_COMMIT_CONTENT_TYPE: &str = "application/vnd.dirextalk.mls-commit.v2+cbor";
/// Exact V2 signed receipt media type.
pub const MLS_COMMIT_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-commit-receipt.v2+cbor";
/// Exact V2 candidate confirmation media type.
pub const MLS_CONFIRMATION_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-device-join-confirmation.v2+cbor";
/// Exact authorization scheme for active device sessions.
pub const DEVICE_SESSION_AUTHORIZATION_SCHEME: &str = "DTX-Device-Session";
/// Canonical HTTPS origin serving the actor's self-authenticated identity log.
pub const IDENTITY_ORIGIN_HEADER: &str = "dtx-identity-origin";
/// Base64url canonical-CBOR proof authorizing a federated receipt lookup.
pub const RECEIPT_QUERY_PROOF_HEADER: &str = "dtx-receipt-query-proof";
/// Base64url canonical-CBOR proof authorizing a pending-request query.
pub const GROUP_QUERY_PROOF_HEADER: &str = "dtx-group-query-proof";

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_CONTROL_BODY_BYTES: usize = 16_384;
const MAX_MEMBERSHIP_BODY_BYTES: usize = 32_768;
const MAX_MLS_COMMIT_BODY_BYTES: usize = 1_100_000;
const MAX_GET_BODY_BYTES: usize = 1_024;
const MAX_ACTION_PROOF_LIFETIME_MS: i64 = 300_000;
const MAX_GROUP_QUERY_PROOF_BYTES: usize = 2_048;
const MAX_GROUP_JOIN_REQUEST_PAGE_SIZE: usize = 64;
const GROUP_SERVICE_CACHE_CONTROL: &str = "public, max-age=60, stale-while-revalidate=300";

const IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"dirextalk.membership-idempotency-key.v1\0";
const BUSINESS_FIELDS_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-business-fields.v1\0";
const ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v1\0";
const ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v1\0";
const FEDERATED_ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v2\0";
const FEDERATED_ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v2\0";
const RECEIPT_QUERY_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-receipt-query-binding.v2\0";
const RECEIPT_QUERY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-receipt-query-signature.v2\0";
const GROUP_QUERY_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.group-query-binding.v1\0";
const GROUP_QUERY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.group-query-signature.v1\0";
const CONTROL_COMMAND_HASH_DOMAIN: &[u8] = b"dirextalk.group-control-command.v1\0";

/// Shared state for a node that serves one trusted configured tenant.
#[derive(Clone)]
pub struct GroupNodeState {
    store: GroupPgStore,
    tenant_id: TenantId,
    control_repository: GroupControlRepository,
    membership_repository: GroupMembershipRepository,
    mls_repository: MlsCommitSequencerRepository,
    mls_signing_key: Option<Arc<SigningKey>>,
    public_origin: Option<Arc<str>>,
    federated_identity: FederatedIdentityVerifier,
    clock: Arc<dyn Clock>,
}

impl GroupNodeState {
    /// Creates production state using the system UTC clock.
    #[must_use]
    pub fn new(store: GroupPgStore, tenant_id: TenantId) -> Self {
        Self::with_clock(store, tenant_id, Arc::new(SystemClock))
    }

    /// Creates state with a deterministic clock for boundary tests.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed HTTPS-only Rustls client cannot be constructed.
    #[must_use]
    pub fn with_clock(store: GroupPgStore, tenant_id: TenantId, clock: Arc<dyn Clock>) -> Self {
        let federated_identity = FederatedIdentityVerifier::new(std::iter::empty())
            .expect("the fixed HTTPS-only federated identity client is valid");
        Self {
            store,
            tenant_id,
            control_repository: GroupControlRepository,
            membership_repository: GroupMembershipRepository,
            mls_repository: MlsCommitSequencerRepository,
            mls_signing_key: None,
            public_origin: None,
            federated_identity,
            clock,
        }
    }

    /// Installs the stable, externally provisioned sequencer signing key.
    #[must_use]
    pub fn with_mls_sequencer_signing_key(mut self, signing_key: SigningKey) -> Self {
        self.mls_signing_key = Some(Arc::new(signing_key));
        self
    }

    /// Atomically installs the trusted public origin and development-only HTTP
    /// identity-origin allowlist used by federation and local persistence.
    /// HTTPS is accepted by default; an HTTP public origin must exactly match
    /// one canonical entry in `allowed_http_origins`.
    ///
    /// # Errors
    ///
    /// Returns [`GroupNodeConfigurationError`] when an origin is not canonical,
    /// an allowlist entry is not HTTP, or an HTTP public origin is not explicitly
    /// allowlisted.
    pub fn with_public_origin_and_allowed_http_identity_origins(
        mut self,
        public_origin: impl AsRef<str>,
        allowed_http_origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, GroupNodeConfigurationError> {
        let (federated_identity, public_origin) =
            FederatedIdentityVerifier::new_with_public_origin(
                public_origin.as_ref(),
                allowed_http_origins,
            )
            .map_err(GroupNodeConfigurationError)?;
        self.public_origin = Some(Arc::from(public_origin));
        self.federated_identity = federated_identity;
        Ok(self)
    }

    fn now(&self) -> Result<UtcMillis, GroupFailure> {
        self.clock
            .now_utc_millis()
            .map_err(|_| GroupFailure::TemporarilyUnavailable)
            .and_then(|value| {
                UtcMillis::new(value).map_err(|_| GroupFailure::TemporarilyUnavailable)
            })
    }

    async fn federated_actor(
        &self,
        headers: &HeaderMap,
        proof: &ActionProof,
    ) -> Result<Option<VerifiedDeviceActor>, GroupFailure> {
        let Some(origin) = single_optional_header(headers, IDENTITY_ORIGIN_HEADER)? else {
            if proof.identity_origin.is_some() {
                return Err(GroupFailure::ActionProofInvalid);
            }
            return Ok(None);
        };
        if headers.contains_key(header::AUTHORIZATION)
            || proof.identity_origin.as_deref() != Some(origin)
        {
            return Err(GroupFailure::ActionProofInvalid);
        }
        let signing_key = self
            .federated_identity
            .active_device_signing_key(origin, proof.actor_identity_id, proof.actor_device_id)
            .await
            .map_err(map_federated_identity_error)?;
        Ok(Some(VerifiedDeviceActor::new(
            proof.actor_identity_id,
            proof.actor_device_id,
            signing_key,
        )))
    }

    async fn federated_receipt_actor(
        &self,
        headers: &HeaderMap,
        proof: &ReceiptQueryProof,
        expected_path: &str,
        expected_scope: GroupScope,
        expected_command_id: MembershipCommandId,
        now: UtcMillis,
    ) -> Result<Option<VerifiedDeviceActor>, GroupFailure> {
        let Some(origin) = single_optional_header(headers, IDENTITY_ORIGIN_HEADER)? else {
            if headers.contains_key(RECEIPT_QUERY_PROOF_HEADER) {
                return Err(GroupFailure::ActionProofInvalid);
            }
            return Ok(None);
        };
        if headers.contains_key(header::AUTHORIZATION) || proof.identity_origin != origin {
            return Err(GroupFailure::ActionProofInvalid);
        }
        let signing_key = self
            .federated_identity
            .active_device_signing_key(origin, proof.actor_identity_id, proof.actor_device_id)
            .await
            .map_err(map_federated_identity_error)?;
        proof.verify(
            expected_path,
            expected_scope,
            expected_command_id,
            now,
            signing_key,
        )?;
        Ok(Some(VerifiedDeviceActor::new(
            proof.actor_identity_id,
            proof.actor_device_id,
            signing_key,
        )))
    }

    #[allow(clippy::too_many_arguments)] // The explicit proof-bound values are the security contract; a one-use parameter bag would obscure them at each route.
    async fn execute_control(
        &self,
        headers: &HeaderMap,
        action: GroupAction,
        scope: GroupScope,
        expected_path: String,
        signable: CanonicalValue,
        proof: ActionProof,
        operation: GroupControlOperation,
        now: UtcMillis,
    ) -> Result<GroupControlExecution, GroupFailure> {
        let idempotency_key_hash = idempotency_key_hash(headers)?;
        let business_digest = canonical_hash(BUSINESS_FIELDS_HASH_DOMAIN, &signable)?;
        let binding_digest = proof.binding_digest()?;
        let request_digest = control_command_digest(
            action,
            scope,
            &expected_path,
            proof.actor_identity_id,
            proof.actor_device_id,
            business_digest,
        )?;
        let command = GroupControlCommand::new(
            RequestId::new(),
            idempotency_key_hash,
            proof.actor_identity_id,
            proof.actor_device_id,
            operation,
            request_digest,
            binding_digest,
        );
        let federated_actor = self.federated_actor(headers, &proof).await?;
        let execution = if let Some(actor) = federated_actor {
            self.control_repository
                .execute_verified_with_proof_outcome(
                    &self.store,
                    self.tenant_id,
                    actor,
                    command,
                    now.get(),
                    move |signing_key| {
                        proof.verify(
                            action,
                            &expected_path,
                            scope,
                            idempotency_key_hash,
                            business_digest,
                            now,
                            signing_key,
                        )
                    },
                )
                .await
        } else {
            let credential = parse_device_session_authorization(headers)?;
            self.control_repository
                .execute_authenticated_with_proof_outcome(
                    &self.store,
                    self.tenant_id,
                    &credential,
                    command,
                    now.get(),
                    move |signing_key| {
                        proof.verify(
                            action,
                            &expected_path,
                            scope,
                            idempotency_key_hash,
                            business_digest,
                            now,
                            signing_key,
                        )
                    },
                )
                .await
        }
        .map_err(|error| map_persistence_error(&error))?;
        Ok(execution)
    }

    async fn request_join(
        &self,
        headers: &HeaderMap,
        scope: GroupScope,
        expected_path: String,
        parsed: JoinRequestBody,
        now: UtcMillis,
    ) -> Result<MembershipCommandExecution, GroupFailure> {
        let idempotency_key_hash = idempotency_key_hash(headers)?;
        let signable = join_request_signable(&parsed);
        let business_digest = canonical_hash(BUSINESS_FIELDS_HASH_DOMAIN, &signable)?;
        let proof = parsed.proof;
        let context = MembershipCommandContext::new(
            MembershipCommandId::new(parsed.command_id),
            idempotency_key_hash,
            scope,
            proof.actor_identity_id,
            proof.actor_device_id,
            parsed.join_request_id,
            proof.actor_identity_id,
            proof.actor_device_id,
            parsed.invite_id,
            MembershipFence::new(parsed.expected_revision, parsed.sequencer_head),
        );
        let federated_actor = self.federated_actor(headers, &proof).await?;
        let candidate_identity_origin = if federated_actor.is_some() {
            proof
                .identity_origin
                .clone()
                .ok_or(GroupFailure::ActionProofInvalid)?
        } else {
            self.public_origin
                .as_deref()
                .map(str::to_owned)
                .ok_or(GroupFailure::TemporarilyUnavailable)?
        };
        let result = if let Some(actor) = federated_actor {
            self.membership_repository
                .request_join_verified_with_proof_outcome(
                    &self.store,
                    self.tenant_id,
                    actor,
                    JoinRequestCommand::new(context),
                    CandidateMembership::NotMember,
                    &candidate_identity_origin,
                    now.get(),
                    move |signing_key| {
                        proof.verify(
                            GroupAction::RequestJoin,
                            &expected_path,
                            scope,
                            idempotency_key_hash,
                            business_digest,
                            now,
                            signing_key,
                        )
                    },
                )
                .await
        } else {
            let credential = parse_device_session_authorization(headers)?;
            self.membership_repository
                .request_join_authenticated_with_proof_outcome(
                    &self.store,
                    self.tenant_id,
                    &credential,
                    JoinRequestCommand::new(context),
                    CandidateMembership::NotMember,
                    &candidate_identity_origin,
                    now.get(),
                    move |signing_key| {
                        proof.verify(
                            GroupAction::RequestJoin,
                            &expected_path,
                            scope,
                            idempotency_key_hash,
                            business_digest,
                            now,
                            signing_key,
                        )
                    },
                )
                .await
        };
        result.map_err(|error| map_persistence_error(&error))
    }

    async fn approve_join(
        &self,
        headers: &HeaderMap,
        scope: GroupScope,
        expected_path: String,
        parsed: ApproveJoinBody,
        now: UtcMillis,
    ) -> Result<MembershipCommandExecution, GroupFailure> {
        let idempotency_key_hash = idempotency_key_hash(headers)?;
        let signable = approve_join_signable(&parsed);
        let business_digest = canonical_hash(BUSINESS_FIELDS_HASH_DOMAIN, &signable)?;
        let proof = parsed.proof;
        let authorization_digest = proof.binding_digest()?;
        let context = MembershipCommandContext::new(
            MembershipCommandId::new(parsed.command_id),
            idempotency_key_hash,
            scope,
            proof.actor_identity_id,
            proof.actor_device_id,
            parsed.join_request_id,
            parsed.candidate_identity_id,
            parsed.candidate_device_id,
            parsed.invite_id,
            MembershipFence::new(parsed.expected_revision, parsed.sequencer_head),
        );
        let federated_actor = self.federated_actor(headers, &proof).await?;
        let result = if let Some(actor) = federated_actor {
            self.membership_repository
                .approve_join_verified_with_proof_outcome(
                    &self.store,
                    self.tenant_id,
                    actor,
                    ApproveJoinCommand::new(context, authorization_digest),
                    CandidateMembership::NotMember,
                    now.get(),
                    move |signing_key| {
                        proof.verify(
                            GroupAction::ApproveJoin,
                            &expected_path,
                            scope,
                            idempotency_key_hash,
                            business_digest,
                            now,
                            signing_key,
                        )
                    },
                )
                .await
        } else {
            let credential = parse_device_session_authorization(headers)?;
            self.membership_repository
                .approve_join_authenticated_with_proof_outcome(
                    &self.store,
                    self.tenant_id,
                    &credential,
                    ApproveJoinCommand::new(context, authorization_digest),
                    CandidateMembership::NotMember,
                    now.get(),
                    move |signing_key| {
                        proof.verify(
                            GroupAction::ApproveJoin,
                            &expected_path,
                            scope,
                            idempotency_key_hash,
                            business_digest,
                            now,
                            signing_key,
                        )
                    },
                )
                .await
        };
        result.map_err(|error| map_persistence_error(&error))
    }
}

/// Builds the production router for one tenant-affine Group Node.
pub fn group_router(store: GroupPgStore, tenant_id: TenantId) -> Router {
    group_router_with_state(GroupNodeState::new(store, tenant_id))
}

/// Builds the Group Node router with explicit state for deterministic tests.
pub fn group_router_with_state(state: GroupNodeState) -> Router {
    Router::new()
        .route(GROUP_SCOPE_PATH_TEMPLATE, put(create_group))
        .route(GROUP_ADMIN_PATH_TEMPLATE, put(grant_admin))
        .route(GROUP_ADMIN_REVOKE_PATH_TEMPLATE, post(revoke_admin))
        .route(GROUP_INVITE_PATH_TEMPLATE, put(issue_invite))
        .route(GROUP_INVITE_REVOKE_PATH_TEMPLATE, post(revoke_invite))
        .route(GROUP_JOIN_REQUEST_PATH_TEMPLATE, put(request_join))
        .route(
            GROUP_JOIN_REQUEST_COLLECTION_PATH_TEMPLATE,
            get(list_join_requests),
        )
        .route(GROUP_JOIN_APPROVAL_PATH_TEMPLATE, post(approve_join))
        .route(
            GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE,
            get(get_membership_receipt),
        )
        .route(
            MLS_COMMIT_PATH_TEMPLATE,
            post(submit_mls_commit).get(get_mls_commit_receipt),
        )
        .route(
            MLS_CONFIRMATION_PATH_TEMPLATE,
            post(confirm_mls_device_join),
        )
        .route(
            MLS_SEQUENCER_DESCRIPTOR_PATH,
            get(get_mls_sequencer_descriptor),
        )
        .route(
            GROUP_SERVICE_DESCRIPTOR_PATH,
            get(get_group_service_descriptor),
        )
        .with_state(state)
}

async fn get_mls_sequencer_descriptor(
    State(state): State<GroupNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        require_exact_route(&parts.uri, MLS_SEQUENCER_DESCRIPTOR_PATH)?;
        require_empty_get(&parts.headers, body).await?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(signing_key.verifying_key().to_bytes().to_vec()),
            ),
        ]))
        .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        Ok(cbor_response(
            StatusCode::OK,
            body,
            "application/vnd.dirextalk.mls-sequencer-descriptor.v2+cbor",
        ))
    }
    .await;
    finish(result, request_id)
}

async fn get_group_service_descriptor(
    State(state): State<GroupNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        require_exact_route(&parts.uri, GROUP_SERVICE_DESCRIPTOR_PATH)?;
        require_empty_get(&parts.headers, body).await?;
        let public_origin = state
            .public_origin
            .as_deref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let descriptor = encode_deterministic_cbor(&numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(public_origin.to_owned()),
            CanonicalValue::Array(vec![CanonicalValue::Text(
                "membership-discovery-v1".to_owned(),
            )]),
            CanonicalValue::Unsigned(MAX_ADMINS as u64),
            CanonicalValue::Unsigned(MAX_GROUP_JOIN_REQUEST_PAGE_SIZE as u64),
            CanonicalValue::Bytes(signing_key.verifying_key().to_bytes().to_vec()),
        ]))
        .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        let etag = representation_etag(&descriptor);
        let not_modified = if_none_match(&parts.headers, &etag)?;
        let mut response = if not_modified {
            StatusCode::NOT_MODIFIED.into_response()
        } else {
            cbor_response(
                StatusCode::OK,
                descriptor,
                GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE,
            )
        };
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&etag).expect("generated Group Service ETag is valid"),
        );
        Ok(response)
    }
    .await;
    finish_public_descriptor(result, request_id)
}

async fn create_group(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let expected_path = canonical_scope_path(scope);
        require_exact_route(&parts.uri, &expected_path)?;
        let proof = parse_create_body(
            &parts.headers,
            body,
            GROUP_CREATE_CONTENT_TYPE,
            MAX_CONTROL_BODY_BYTES,
        )
        .await?;
        let now = state.now()?;
        let operation = GroupControlOperation::CreateGroup {
            scope,
            owner_identity_id: proof.actor_identity_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::CreateGroup,
                scope,
                expected_path,
                create_group_signable(),
                proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::CreateGroup, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn grant_admin(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, administrator_identity_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let administrator_identity_id = parse_identity_id(&administrator_identity_id)?;
        let expected_path = format!(
            "{}/admins/{administrator_identity_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed =
            parse_role_change_body(&parts.headers, body, GROUP_GRANT_ADMIN_CONTENT_TYPE).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::GrantAdmin {
            scope,
            expected_revision: parsed.expected_revision,
            administrator_identity_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::GrantAdmin,
                scope,
                expected_path,
                role_change_signable(parsed.expected_revision),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::GrantAdmin, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn revoke_admin(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, administrator_identity_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let administrator_identity_id = parse_identity_id(&administrator_identity_id)?;
        let expected_path = format!(
            "{}/admins/{administrator_identity_id}/revoke",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed =
            parse_role_change_body(&parts.headers, body, GROUP_REVOKE_ADMIN_CONTENT_TYPE).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::RevokeAdmin {
            scope,
            expected_revision: parsed.expected_revision,
            administrator_identity_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::RevokeAdmin,
                scope,
                expected_path,
                role_change_signable(parsed.expected_revision),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::RevokeAdmin, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn issue_invite(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, invite_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let invite_id = parse_invite_id(&invite_id)?;
        let expected_path = format!("{}/invites/{invite_id}", canonical_scope_path(scope));
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed = parse_issue_invite_body(&parts.headers, body).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::IssueInvite {
            scope,
            expected_revision: parsed.expected_revision,
            invite_id,
            target_identity_id: parsed.target_identity_id,
            max_uses: parsed.max_uses,
            expires_at_ms: parsed.expires_at.get(),
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::IssueInvite,
                scope,
                expected_path,
                issue_invite_signable(&parsed),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::IssueInvite, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn revoke_invite(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, invite_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let invite_id = parse_invite_id(&invite_id)?;
        let expected_path = format!("{}/invites/{invite_id}/revoke", canonical_scope_path(scope));
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed =
            parse_role_change_body(&parts.headers, body, GROUP_REVOKE_INVITE_CONTENT_TYPE).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::RevokeInvite {
            scope,
            expected_revision: parsed.expected_revision,
            invite_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::RevokeInvite,
                scope,
                expected_path,
                role_change_signable(parsed.expected_revision),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::RevokeInvite, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn request_join(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, join_request_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let join_request_id = parse_join_request_id(&join_request_id)?;
        let expected_path = format!(
            "{}/join-requests/{join_request_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed = parse_join_request_body(&parts.headers, body, join_request_id).await?;
        let now = state.now()?;
        let execution = state
            .request_join(&parts.headers, scope, expected_path, parsed, now)
            .await?;
        membership_response(execution)
    }
    .await;
    finish(result, request_id)
}

async fn list_join_requests(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let collection_path = format!("{}/join-requests", canonical_scope_path(scope));
        let query = parse_join_request_query(&parts.uri, &collection_path)?;
        require_empty_get(&parts.headers, body).await?;
        let proof = parse_group_query_proof_header(&parts.headers)?;
        let now = state.now()?;
        let page = if let Some(identity_origin) =
            single_optional_header(&parts.headers, IDENTITY_ORIGIN_HEADER)?
        {
            if parts.headers.contains_key(header::AUTHORIZATION)
                || proof.identity_origin != identity_origin
            {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let signing_key = state
                .federated_identity
                .active_device_signing_key(
                    identity_origin,
                    proof.actor_identity_id,
                    proof.actor_device_id,
                )
                .await
                .map_err(map_federated_identity_error)?;
            let actor = VerifiedDeviceActor::new(
                proof.actor_identity_id,
                proof.actor_device_id,
                signing_key,
            );
            state
                .membership_repository
                .list_pending_join_requests_verified_with_proof(
                    &state.store,
                    state.tenant_id,
                    actor,
                    scope,
                    query.after,
                    query.limit,
                    move |signing_key| {
                        proof.verify(&query.canonical_target, scope, now, signing_key)
                    },
                )
                .await
        } else {
            let public_origin = state
                .public_origin
                .as_deref()
                .ok_or(GroupFailure::TemporarilyUnavailable)?;
            if proof.identity_origin != public_origin {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            state
                .membership_repository
                .list_pending_join_requests_authenticated_with_proof(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    proof.actor_identity_id,
                    proof.actor_device_id,
                    scope,
                    query.after,
                    query.limit,
                    now.get(),
                    move |signing_key| {
                        proof.verify(&query.canonical_target, scope, now, signing_key)
                    },
                )
                .await
        }
        .map_err(|error| map_persistence_error(&error))?;
        Ok(cbor_response(
            StatusCode::OK,
            encode_pending_join_request_page(scope, &page)?,
            GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE,
        ))
    }
    .await;
    finish(result, request_id)
}

async fn approve_join(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, join_request_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let join_request_id = parse_join_request_id(&join_request_id)?;
        let expected_path = format!(
            "{}/join-requests/{join_request_id}/approvals",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed = parse_approve_join_body(&parts.headers, body, join_request_id).await?;
        let now = state.now()?;
        let execution = state
            .approve_join(&parts.headers, scope, expected_path, parsed, now)
            .await?;
        membership_response(execution)
    }
    .await;
    finish(result, request_id)
}

async fn get_membership_receipt(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, membership_command_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let command_id = MembershipCommandId::new(parse_request_id(&membership_command_id)?);
        let expected_path = format!(
            "{}/membership-receipts/{membership_command_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        require_empty_get(&parts.headers, body).await?;
        let now = state.now()?;
        let query_proof = parse_receipt_query_proof_header(&parts.headers)?;
        let receipt = if let Some(query_proof) = query_proof {
            let actor = state
                .federated_receipt_actor(
                    &parts.headers,
                    &query_proof,
                    &expected_path,
                    scope,
                    command_id,
                    now,
                )
                .await?
                .ok_or(GroupFailure::ActionProofInvalid)?;
            state
                .membership_repository
                .load_receipt_verified(&state.store, state.tenant_id, actor, scope, command_id)
                .await
        } else {
            if parts.headers.contains_key(IDENTITY_ORIGIN_HEADER) {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            state
                .membership_repository
                .load_receipt_authenticated(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    scope,
                    command_id,
                    now.get(),
                )
                .await
        }
        .map_err(|error| map_persistence_error(&error))?;
        Ok(cbor_response(
            StatusCode::OK,
            encode_membership_receipt(receipt)?,
            MEMBERSHIP_RECEIPT_CONTENT_TYPE,
        ))
    }
    .await;
    finish(result, request_id)
}

async fn submit_mls_commit(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, submission_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let submission_id = parse_request_id(&submission_id)?;
        let expected_path = format!(
            "{}/mls-commits/{submission_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let idempotency_key_hash = mls_idempotency_key_hash(&parts.headers)?;
        let parsed = parse_mls_commit_body(
            &parts.headers,
            body,
            scope,
            submission_id,
            idempotency_key_hash,
        )
        .await?;
        let credential = parse_device_session_authorization(&parts.headers)?;
        let now = state.now()?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let signing_public_key = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes())
            .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        let signer = Arc::clone(signing_key);
        let execution = state
            .mls_repository
            .submit_authenticated(
                &state.store,
                state.tenant_id,
                &credential,
                &parsed.command,
                parsed.candidate_signature,
                parsed.controller_signature,
                now.get(),
                signing_public_key,
                move |input| Ok(Ed25519Signature::from_bytes(signer.sign(input).to_bytes())),
            )
            .await
            .map_err(|error| map_persistence_error(&error))?;
        mls_commit_response(&execution)
    }
    .await;
    finish(result, request_id)
}

async fn get_mls_commit_receipt(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, submission_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let submission_id = parse_request_id(&submission_id)?;
        let expected_path = format!(
            "{}/mls-commits/{submission_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        require_empty_get(&parts.headers, body).await?;
        let credential = parse_device_session_authorization(&parts.headers)?;
        let now = state.now()?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let signing_public_key = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes())
            .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        let receipt = state
            .mls_repository
            .receipt_authenticated(
                &state.store,
                state.tenant_id,
                &credential,
                scope,
                submission_id,
                now.get(),
                signing_public_key,
            )
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(cbor_response(
            StatusCode::OK,
            encode_mls_commit_receipt(&receipt)?,
            MLS_COMMIT_RECEIPT_CONTENT_TYPE,
        ))
    }
    .await;
    finish(result, request_id)
}

async fn confirm_mls_device_join(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, submission_id, device_id)): Path<(String, String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let submission_id = parse_request_id(&submission_id)?;
        let device_id = parse_device_id(&device_id)?;
        let expected_path = format!(
            "{}/mls-commits/{submission_id}/confirmations/{device_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let confirmation =
            parse_mls_confirmation_body(&parts.headers, body, submission_id, device_id).await?;
        let credential = parse_device_session_authorization(&parts.headers)?;
        let now = state.now()?;
        state
            .mls_repository
            .confirm_authenticated(
                &state.store,
                state.tenant_id,
                &credential,
                confirmation,
                now.get(),
            )
            .await
            .map_err(|error| map_persistence_error(&error))?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }
    .await;
    finish(result, request_id)
}

fn mls_commit_response(execution: &MlsCommitExecution) -> Result<Response, GroupFailure> {
    Ok(cbor_response(
        if execution.replayed() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        encode_mls_commit_receipt(execution.receipt())?,
        MLS_COMMIT_RECEIPT_CONTENT_TYPE,
    ))
}

fn encode_mls_commit_receipt(receipt: &MlsCommitReceipt) -> Result<Vec<u8>, GroupFailure> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            decode_deterministic_cbor(receipt.canonical_cbor())
                .map_err(|_| GroupFailure::TemporarilyUnavailable)?,
        ),
        (
            CanonicalValue::Unsigned(2),
            receipt.receipt_digest().to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(receipt.signing_public_key().as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(receipt.signature().as_bytes().to_vec()),
        ),
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn control_response(
    action: GroupAction,
    scope: GroupScope,
    execution: GroupControlExecution,
) -> Result<Response, GroupFailure> {
    let receipt = execution.receipt();
    match receipt.disposition() {
        GroupControlDisposition::Rejected(rejection) => Err(map_control_rejection(rejection)),
        GroupControlDisposition::Applied { .. }
        | GroupControlDisposition::AlreadyApplied { .. } => {
            let status = if execution.replayed() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            Ok(cbor_response(
                status,
                encode_control_receipt(action, scope, receipt)?,
                GROUP_ACTION_RECEIPT_CONTENT_TYPE,
            ))
        }
    }
}

fn membership_response(execution: MembershipCommandExecution) -> Result<Response, GroupFailure> {
    let status = if execution.replayed() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok(cbor_response(
        status,
        encode_membership_receipt(execution.receipt())?,
        MEMBERSHIP_RECEIPT_CONTENT_TYPE,
    ))
}

fn finish(result: Result<Response, GroupFailure>, request_id: RequestId) -> Response {
    match result {
        Ok(response) => with_common_headers(response, request_id),
        Err(failure) => group_failure_response(failure, request_id),
    }
}

fn finish_public_descriptor(
    result: Result<Response, GroupFailure>,
    request_id: RequestId,
) -> Response {
    let mut response = finish(result, request_id);
    if matches!(response.status(), StatusCode::OK | StatusCode::NOT_MODIFIED) {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(GROUP_SERVICE_CACHE_CONTROL),
        );
    }
    response
}

fn representation_etag(body: &[u8]) -> String {
    let digest = Sha256Digest::hash_domain(b"dirextalk.group-service-etag.v1\0", body);
    let mut value = String::with_capacity(66);
    value.push('"');
    for byte in digest.as_bytes() {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value.push('"');
    value
}

fn if_none_match(headers: &HeaderMap, expected: &str) -> Result<bool, GroupFailure> {
    let mut values = headers.get_all(header::IF_NONE_MATCH).iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    let value = value.to_str().map_err(|_| GroupFailure::InvalidRequest)?;
    if value.len() != 66
        || !value.starts_with('"')
        || !value.ends_with('"')
        || !value.as_bytes()[1..65]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(value == expected)
}

fn parse_scope(scope_kind: &str, scope_id: &str) -> Result<GroupScope, GroupFailure> {
    match scope_kind {
        "private-conversation" => scope_id
            .parse::<ConversationId>()
            .map(GroupScope::PrivateConversation)
            .map_err(|_| GroupFailure::InvalidRequest),
        "controlled-public-channel" => scope_id
            .parse::<ChannelId>()
            .map(GroupScope::ControlledPublicChannel)
            .map_err(|_| GroupFailure::InvalidRequest),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

fn canonical_scope_path(scope: GroupScope) -> String {
    match scope {
        GroupScope::PrivateConversation(conversation_id) => {
            format!("/v1/groups/private-conversation/{conversation_id}")
        }
        GroupScope::ControlledPublicChannel(channel_id) => {
            format!("/v1/groups/controlled-public-channel/{channel_id}")
        }
    }
}

fn require_exact_route(uri: &Uri, expected_path: &str) -> Result<(), GroupFailure> {
    if uri.path() == expected_path && uri.query().is_none() {
        Ok(())
    } else {
        Err(GroupFailure::InvalidRequest)
    }
}

struct MlsCommitBody {
    command: MlsCommitCommand,
    candidate_signature: Ed25519Signature,
    controller_signature: Option<Ed25519Signature>,
}

async fn parse_mls_commit_body(
    headers: &HeaderMap,
    body: Body,
    expected_scope: GroupScope,
    expected_submission_id: RequestId,
    idempotency_key_hash: Sha256Digest,
) -> Result<MlsCommitBody, GroupFailure> {
    let value = decode_body(
        headers,
        body,
        MLS_COMMIT_CONTENT_TYPE,
        MAX_MLS_COMMIT_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, 15)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(2) {
        return Err(GroupFailure::InvalidRequest);
    }
    let submission_id = parse_request_id_value(field(fields, 2)?)?;
    let scope = parse_scope_value(field(fields, 3)?)?;
    if submission_id != expected_submission_id || scope != expected_scope {
        return Err(GroupFailure::InvalidRequest);
    }
    let actor_identity_id = parse_identity_id_value(field(fields, 4)?)?;
    let actor_device_id = parse_device_id_value(field(fields, 5)?)?;
    let candidate_identity_id = parse_identity_id_value(field(fields, 6)?)?;
    let candidate_device_id = parse_device_id_value(field(fields, 7)?)?;
    let candidate_key_package_digest = parse_digest(field(fields, 8)?)?;
    let (candidate_proof_digest, candidate_signature) = parse_mls_device_proof(field(fields, 9)?)?;
    let expected_epoch = parse_safe_uint(field(fields, 10)?)?;
    let expected_head = parse_digest(field(fields, 11)?)?;
    let commit_bytes = match field(fields, 12)? {
        CanonicalValue::Bytes(bytes) if (1..=1_048_576).contains(&bytes.len()) => bytes.clone(),
        _ => return Err(GroupFailure::InvalidRequest),
    };
    let commit_digest = parse_digest(field(fields, 13)?)?;
    if commit_digest != mls_opaque_commit_digest(&commit_bytes) {
        return Err(GroupFailure::InvalidRequest);
    }
    let welcome_digest = parse_digest(field(fields, 14)?)?;
    let authorization_len = match field(fields, 15)? {
        CanonicalValue::Map(values) => values.len(),
        _ => return Err(GroupFailure::InvalidRequest),
    };
    let authorization_fields = exact_fields(field(fields, 15)?, authorization_len)?;
    let (authorization, controller_signature) = match field(authorization_fields, 1)? {
        CanonicalValue::Unsigned(1) if authorization_fields.len() == 1 => {
            (MlsCommitAuthorization::OwnerBootstrap, None)
        }
        CanonicalValue::Unsigned(2) if authorization_fields.len() == 3 => (
            MlsCommitAuthorization::ApprovedIdentityJoin {
                membership_command_id: MembershipCommandId::new(parse_request_id_value(field(
                    authorization_fields,
                    2,
                )?)?),
                authorization_digest: parse_digest(field(authorization_fields, 3)?)?,
            },
            None,
        ),
        CanonicalValue::Unsigned(3) if authorization_fields.len() == 4 => {
            let controller_device_id = parse_device_id_value(field(authorization_fields, 2)?)?;
            let controller_consent_digest = parse_digest(field(authorization_fields, 3)?)?;
            let (proof_digest, signature) =
                parse_mls_device_proof(field(authorization_fields, 4)?)?;
            if proof_digest != controller_consent_digest {
                return Err(GroupFailure::InvalidRequest);
            }
            (
                MlsCommitAuthorization::ExistingMemberDeviceAdd {
                    controller_device_id,
                    controller_consent_digest,
                },
                Some(signature),
            )
        }
        _ => return Err(GroupFailure::InvalidRequest),
    };
    let command = MlsCommitCommand::new(
        submission_id,
        scope,
        actor_identity_id,
        actor_device_id,
        candidate_identity_id,
        candidate_device_id,
        candidate_key_package_digest,
        candidate_proof_digest,
        idempotency_key_hash,
        expected_epoch,
        expected_head,
        commit_bytes,
        commit_digest,
        welcome_digest,
        authorization,
    )
    .map_err(|_| GroupFailure::InvalidRequest)?;
    Ok(MlsCommitBody {
        command,
        candidate_signature,
        controller_signature,
    })
}

fn parse_mls_device_proof(
    value: &CanonicalValue,
) -> Result<(Sha256Digest, Ed25519Signature), GroupFailure> {
    let fields = exact_fields(value, 3)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(2) {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok((
        parse_digest(field(fields, 2)?)?,
        Ed25519Signature::from_bytes(parse_exact_bytes(field(fields, 3)?)?),
    ))
}

async fn parse_mls_confirmation_body(
    headers: &HeaderMap,
    body: Body,
    expected_submission_id: RequestId,
    expected_device_id: DeviceId,
) -> Result<MlsDeviceJoinConfirmation, GroupFailure> {
    let value = decode_body(
        headers,
        body,
        MLS_CONFIRMATION_CONTENT_TYPE,
        MAX_MEMBERSHIP_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, 7)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(1) {
        return Err(GroupFailure::InvalidRequest);
    }
    let confirmation = MlsDeviceJoinConfirmation {
        submission_id: parse_request_id_value(field(fields, 2)?)?,
        identity_id: parse_identity_id_value(field(fields, 3)?)?,
        device_id: parse_device_id_value(field(fields, 4)?)?,
        receipt_digest: parse_digest(field(fields, 5)?)?,
        head_digest: parse_digest(field(fields, 6)?)?,
        signature: Ed25519Signature::from_bytes(parse_exact_bytes(field(fields, 7)?)?),
    };
    if confirmation.submission_id != expected_submission_id
        || confirmation.device_id != expected_device_id
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(confirmation)
}

async fn parse_create_body(
    headers: &HeaderMap,
    body: Body,
    content_type: &'static str,
    limit: usize,
) -> Result<ActionProof, GroupFailure> {
    let value = decode_body(headers, body, content_type, limit).await?;
    let fields = exact_fields(&value, 2)?;
    require_version(field(fields, 1)?)?;
    parse_action_proof(field(fields, 2)?)
}

struct RoleChangeBody {
    expected_revision: Revision,
    proof: ActionProof,
}

async fn parse_role_change_body(
    headers: &HeaderMap,
    body: Body,
    content_type: &'static str,
) -> Result<RoleChangeBody, GroupFailure> {
    let value = decode_body(headers, body, content_type, MAX_CONTROL_BODY_BYTES).await?;
    let fields = exact_fields(&value, 3)?;
    require_version(field(fields, 1)?)?;
    Ok(RoleChangeBody {
        expected_revision: parse_revision(field(fields, 2)?)?,
        proof: parse_action_proof(field(fields, 3)?)?,
    })
}

#[derive(Clone)]
struct IssueInviteBody {
    expected_revision: Revision,
    target_identity_id: Option<IdentityId>,
    max_uses: u32,
    expires_at: UtcMillis,
    proof: ActionProof,
}

async fn parse_issue_invite_body(
    headers: &HeaderMap,
    body: Body,
) -> Result<IssueInviteBody, GroupFailure> {
    let value = decode_body(
        headers,
        body,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        MAX_CONTROL_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, 6)?;
    require_version(field(fields, 1)?)?;
    let max_uses = parse_safe_uint(field(fields, 4)?)?;
    Ok(IssueInviteBody {
        expected_revision: parse_revision(field(fields, 2)?)?,
        target_identity_id: parse_optional_identity_id(field(fields, 3)?)?,
        max_uses: u32::try_from(max_uses).map_err(|_| GroupFailure::InvalidRequest)?,
        expires_at: parse_utc_millis(field(fields, 5)?)?,
        proof: parse_action_proof(field(fields, 6)?)?,
    })
}

#[derive(Clone)]
struct JoinRequestBody {
    command_id: RequestId,
    join_request_id: JoinRequestId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    proof: ActionProof,
}

async fn parse_join_request_body(
    headers: &HeaderMap,
    body: Body,
    join_request_id: JoinRequestId,
) -> Result<JoinRequestBody, GroupFailure> {
    let value = decode_body(
        headers,
        body,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        MAX_MEMBERSHIP_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, 6)?;
    require_version(field(fields, 1)?)?;
    Ok(JoinRequestBody {
        command_id: parse_request_id_value(field(fields, 2)?)?,
        join_request_id,
        invite_id: parse_invite_id_value(field(fields, 3)?)?,
        expected_revision: parse_revision(field(fields, 4)?)?,
        sequencer_head: parse_digest(field(fields, 5)?)?,
        proof: parse_action_proof(field(fields, 6)?)?,
    })
}

#[derive(Clone)]
struct ApproveJoinBody {
    command_id: RequestId,
    join_request_id: JoinRequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    invite_id: InviteCapabilityId,
    expected_revision: Revision,
    sequencer_head: Sha256Digest,
    proof: ActionProof,
}

async fn parse_approve_join_body(
    headers: &HeaderMap,
    body: Body,
    join_request_id: JoinRequestId,
) -> Result<ApproveJoinBody, GroupFailure> {
    let value = decode_body(
        headers,
        body,
        GROUP_APPROVE_JOIN_CONTENT_TYPE,
        MAX_MEMBERSHIP_BODY_BYTES,
    )
    .await?;
    let fields = exact_fields(&value, 8)?;
    require_version(field(fields, 1)?)?;
    Ok(ApproveJoinBody {
        command_id: parse_request_id_value(field(fields, 2)?)?,
        join_request_id,
        candidate_identity_id: parse_identity_id_value(field(fields, 3)?)?,
        candidate_device_id: parse_device_id_value(field(fields, 4)?)?,
        invite_id: parse_invite_id_value(field(fields, 5)?)?,
        expected_revision: parse_revision(field(fields, 6)?)?,
        sequencer_head: parse_digest(field(fields, 7)?)?,
        proof: parse_action_proof(field(fields, 8)?)?,
    })
}

async fn decode_body(
    headers: &HeaderMap,
    body: Body,
    content_type: &'static str,
    limit: usize,
) -> Result<CanonicalValue, GroupFailure> {
    if !has_exact_content_type(headers, content_type)
        || headers.contains_key(header::CONTENT_ENCODING)
    {
        return Err(GroupFailure::InvalidRequest);
    }
    let bytes = to_bytes(body, limit)
        .await
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if bytes.is_empty() {
        return Err(GroupFailure::InvalidRequest);
    }
    decode_deterministic_cbor(&bytes).map_err(|_| GroupFailure::InvalidRequest)
}

async fn require_empty_get(headers: &HeaderMap, body: Body) -> Result<(), GroupFailure> {
    if headers.contains_key(header::CONTENT_ENCODING)
        || headers.contains_key(header::CONTENT_TYPE)
        || !to_bytes(body, MAX_GET_BODY_BYTES)
            .await
            .map_err(|_| GroupFailure::InvalidRequest)?
            .is_empty()
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(())
}

fn create_group_signable() -> CanonicalValue {
    numbered_map(vec![CanonicalValue::Unsigned(1)])
}

fn role_change_signable(expected_revision: Revision) -> CanonicalValue {
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(expected_revision.get()),
    ])
}

fn issue_invite_signable(body: &IssueInviteBody) -> CanonicalValue {
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(body.expected_revision.get()),
        body.target_identity_id
            .map_or(CanonicalValue::Null, |identity_id| {
                CanonicalValue::Text(identity_id.to_string())
            }),
        CanonicalValue::Unsigned(u64::from(body.max_uses)),
        utc_value(body.expires_at),
    ])
}

fn join_request_signable(body: &JoinRequestBody) -> CanonicalValue {
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(body.command_id.to_string()),
        CanonicalValue::Text(body.invite_id.to_string()),
        CanonicalValue::Unsigned(body.expected_revision.get()),
        CanonicalValue::Bytes(body.sequencer_head.as_bytes().to_vec()),
    ])
}

fn approve_join_signable(body: &ApproveJoinBody) -> CanonicalValue {
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(body.command_id.to_string()),
        CanonicalValue::Text(body.candidate_identity_id.to_string()),
        CanonicalValue::Text(body.candidate_device_id.to_string()),
        CanonicalValue::Text(body.invite_id.to_string()),
        CanonicalValue::Unsigned(body.expected_revision.get()),
        CanonicalValue::Bytes(body.sequencer_head.as_bytes().to_vec()),
    ])
}

struct JoinRequestQuery {
    after: Option<PendingJoinRequestCursor>,
    limit: usize,
    canonical_target: String,
}

fn parse_join_request_query(
    uri: &Uri,
    expected_path: &str,
) -> Result<JoinRequestQuery, GroupFailure> {
    if uri.path() != expected_path {
        return Err(GroupFailure::InvalidRequest);
    }
    let query = uri.query().ok_or(GroupFailure::InvalidRequest)?;
    let mut parameters = query.split('&');
    let after_parameter = parameters.next().ok_or(GroupFailure::InvalidRequest)?;
    let limit_parameter = parameters.next().ok_or(GroupFailure::InvalidRequest)?;
    if parameters.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    let after_text = after_parameter
        .strip_prefix("after=")
        .ok_or(GroupFailure::InvalidRequest)?;
    let limit_text = limit_parameter
        .strip_prefix("limit=")
        .ok_or(GroupFailure::InvalidRequest)?;
    if limit_text.is_empty()
        || (limit_text.len() > 1 && limit_text.starts_with('0'))
        || !limit_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(GroupFailure::InvalidRequest);
    }
    let limit = limit_text
        .parse::<usize>()
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if !(1..=MAX_GROUP_JOIN_REQUEST_PAGE_SIZE).contains(&limit) {
        return Err(GroupFailure::InvalidRequest);
    }
    let after = if after_text.is_empty() {
        None
    } else {
        Some(parse_pending_join_cursor(after_text)?)
    };
    let canonical_query = format!("after={after_text}&limit={limit}");
    if query != canonical_query {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(JoinRequestQuery {
        after,
        limit,
        canonical_target: format!("{expected_path}?{canonical_query}"),
    })
}

fn parse_pending_join_cursor(value: &str) -> Result<PendingJoinRequestCursor, GroupFailure> {
    if value.len() > 256 || !value.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; value.len()];
    let exact =
        Base64UrlUnpadded::decode(value, &mut decoded).map_err(|_| GroupFailure::InvalidRequest)?;
    if Base64UrlUnpadded::encode_string(exact) != value {
        return Err(GroupFailure::InvalidRequest);
    }
    let decoded = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&decoded, 2)?;
    Ok(PendingJoinRequestCursor::new(
        parse_utc_millis(field(fields, 1)?)?,
        parse_join_request_id(&parse_text(field(fields, 2)?, 36, 36)?)?,
    ))
}

fn encode_pending_join_cursor(cursor: PendingJoinRequestCursor) -> Result<String, GroupFailure> {
    let bytes = encode_deterministic_cbor(&numbered_map(vec![
        utc_value(cursor.requested_at()),
        CanonicalValue::Text(cursor.join_request_id().to_string()),
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

#[derive(Clone)]
struct GroupQueryProof {
    canonical_target: String,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: String,
    signature: [u8; 64],
}

impl GroupQueryProof {
    fn binding_value(&self) -> CanonicalValue {
        numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(self.canonical_target.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.actor_identity_id.to_string()),
            CanonicalValue::Text(self.actor_device_id.to_string()),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
            CanonicalValue::Text(self.identity_origin.clone()),
        ])
    }

    fn verify(
        &self,
        expected_target: &str,
        expected_scope: GroupScope,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
        if self.canonical_target != expected_target
            || self.scope != expected_scope
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupPersistenceError::ActionProofRejected);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        let digest = Sha256Digest::hash_domain(GROUP_QUERY_BINDING_HASH_DOMAIN, &binding);
        let mut signature_input =
            Vec::with_capacity(GROUP_QUERY_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
        signature_input.extend_from_slice(GROUP_QUERY_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupPersistenceError::ActionProofRejected)
    }
}

fn parse_group_query_proof_header(headers: &HeaderMap) -> Result<GroupQueryProof, GroupFailure> {
    let encoded = single_optional_header(headers, GROUP_QUERY_PROOF_HEADER)?
        .ok_or(GroupFailure::ActionProofInvalid)?;
    if encoded.len() > MAX_GROUP_QUERY_PROOF_BYTES || !encoded.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; encoded.len()];
    let exact = Base64UrlUnpadded::decode(encoded, &mut decoded)
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if Base64UrlUnpadded::encode_string(exact) != encoded {
        return Err(GroupFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&value, 3)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(1) {
        return Err(GroupFailure::InvalidRequest);
    }
    let binding = exact_fields(field(fields, 2)?, 9)?;
    if field(binding, 1)? != &CanonicalValue::Unsigned(1)
        || field(binding, 2)? != &CanonicalValue::Unsigned(1)
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(GroupQueryProof {
        canonical_target: parse_text(field(binding, 3)?, 1, 768)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        actor_identity_id: parse_identity_id_value(field(binding, 5)?)?,
        actor_device_id: parse_device_id_value(field(binding, 6)?)?,
        issued_at: parse_utc_millis(field(binding, 7)?)?,
        expires_at: parse_utc_millis(field(binding, 8)?)?,
        identity_origin: parse_text(field(binding, 9)?, 10, 512)?,
        signature: parse_exact_bytes(field(fields, 3)?)?,
    })
}

#[derive(Clone)]
struct ActionProof {
    action: GroupAction,
    path: String,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    idempotency_key_hash: Sha256Digest,
    business_fields_digest: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: Option<String>,
    signature: [u8; 64],
}

impl ActionProof {
    fn binding_value(&self) -> CanonicalValue {
        let mut fields = vec![
            CanonicalValue::Unsigned(if self.identity_origin.is_some() { 2 } else { 1 }),
            CanonicalValue::Unsigned(self.action.code()),
            CanonicalValue::Text(self.path.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.actor_identity_id.to_string()),
            CanonicalValue::Text(self.actor_device_id.to_string()),
            CanonicalValue::Bytes(self.idempotency_key_hash.as_bytes().to_vec()),
            CanonicalValue::Bytes(self.business_fields_digest.as_bytes().to_vec()),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
        ];
        if let Some(origin) = &self.identity_origin {
            fields.push(CanonicalValue::Text(origin.clone()));
        }
        numbered_map(fields)
    }

    fn binding_digest(&self) -> Result<Sha256Digest, GroupFailure> {
        canonical_hash(self.binding_hash_domain(), &self.binding_value())
    }

    const fn binding_hash_domain(&self) -> &'static [u8] {
        if self.identity_origin.is_some() {
            FEDERATED_ACTION_BINDING_HASH_DOMAIN
        } else {
            ACTION_BINDING_HASH_DOMAIN
        }
    }

    const fn signature_domain(&self) -> &'static [u8] {
        if self.identity_origin.is_some() {
            FEDERATED_ACTION_SIGNATURE_DOMAIN
        } else {
            ACTION_SIGNATURE_DOMAIN
        }
    }

    #[allow(clippy::too_many_arguments)] // All independently bound proof coordinates are intentionally visible at the verification call site.
    fn verify(
        &self,
        expected_action: GroupAction,
        expected_path: &str,
        expected_scope: GroupScope,
        expected_idempotency_key_hash: Sha256Digest,
        expected_business_fields_digest: Sha256Digest,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
        if self.action != expected_action
            || self.path != expected_path
            || self.scope != expected_scope
            || self.idempotency_key_hash != expected_idempotency_key_hash
            || self.business_fields_digest != expected_business_fields_digest
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupPersistenceError::ActionProofRejected);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        let binding_digest = Sha256Digest::hash_domain(self.binding_hash_domain(), &binding);
        let mut signature_input =
            Vec::with_capacity(self.signature_domain().len() + binding_digest.as_bytes().len());
        signature_input.extend_from_slice(self.signature_domain());
        signature_input.extend_from_slice(binding_digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupPersistenceError::ActionProofRejected)
    }
}

struct ReceiptQueryProof {
    path: String,
    scope: GroupScope,
    command_id: MembershipCommandId,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: String,
    signature: [u8; 64],
}

impl ReceiptQueryProof {
    fn binding_value(&self) -> CanonicalValue {
        numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(self.path.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.command_id.request_id().to_string()),
            CanonicalValue::Text(self.actor_identity_id.to_string()),
            CanonicalValue::Text(self.actor_device_id.to_string()),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
            CanonicalValue::Text(self.identity_origin.clone()),
        ])
    }

    fn verify(
        &self,
        expected_path: &str,
        expected_scope: GroupScope,
        expected_command_id: MembershipCommandId,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupFailure> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupFailure::ActionProofInvalid)?;
        if self.path != expected_path
            || self.scope != expected_scope
            || self.command_id != expected_command_id
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupFailure::ActionProofInvalid);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupFailure::ActionProofInvalid)?;
        let digest = Sha256Digest::hash_domain(RECEIPT_QUERY_BINDING_HASH_DOMAIN, &binding);
        let mut signature_input =
            Vec::with_capacity(RECEIPT_QUERY_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
        signature_input.extend_from_slice(RECEIPT_QUERY_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupFailure::ActionProofInvalid)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupFailure::ActionProofInvalid)
    }
}

fn parse_receipt_query_proof_header(
    headers: &HeaderMap,
) -> Result<Option<ReceiptQueryProof>, GroupFailure> {
    let Some(encoded) = single_optional_header(headers, RECEIPT_QUERY_PROOF_HEADER)? else {
        return Ok(None);
    };
    if encoded.len() > 1_024 || !encoded.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; encoded.len()];
    let exact = Base64UrlUnpadded::decode(encoded, &mut decoded)
        .map_err(|_| GroupFailure::InvalidRequest)?;
    let value = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&value, 3)?;
    if parse_proof_version(field(fields, 1)?)? != 2 {
        return Err(GroupFailure::InvalidRequest);
    }
    let binding = exact_fields(field(fields, 2)?, 10)?;
    if parse_proof_version(field(binding, 1)?)? != 2
        || field(binding, 2)? != &CanonicalValue::Unsigned(8)
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(Some(ReceiptQueryProof {
        path: parse_text(field(binding, 3)?, 1, 512)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        command_id: MembershipCommandId::new(parse_request_id(&parse_text(
            field(binding, 5)?,
            36,
            36,
        )?)?),
        actor_identity_id: parse_identity_id_value(field(binding, 6)?)?,
        actor_device_id: parse_device_id_value(field(binding, 7)?)?,
        issued_at: parse_utc_millis(field(binding, 8)?)?,
        expires_at: parse_utc_millis(field(binding, 9)?)?,
        identity_origin: parse_text(field(binding, 10)?, 10, 512)?,
        signature: parse_exact_bytes(field(fields, 3)?)?,
    }))
}

fn parse_action_proof(value: &CanonicalValue) -> Result<ActionProof, GroupFailure> {
    let fields = exact_fields(value, 3)?;
    let proof_version = parse_proof_version(field(fields, 1)?)?;
    let binding = exact_fields(field(fields, 2)?, if proof_version == 2 { 11 } else { 10 })?;
    if parse_proof_version(field(binding, 1)?)? != proof_version {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(ActionProof {
        action: GroupAction::parse(field(binding, 2)?)?,
        path: parse_text(field(binding, 3)?, 1, 512)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        actor_identity_id: parse_identity_id_value(field(binding, 5)?)?,
        actor_device_id: parse_device_id_value(field(binding, 6)?)?,
        idempotency_key_hash: parse_digest(field(binding, 7)?)?,
        business_fields_digest: parse_digest(field(binding, 8)?)?,
        issued_at: parse_utc_millis(field(binding, 9)?)?,
        expires_at: parse_utc_millis(field(binding, 10)?)?,
        identity_origin: if proof_version == 2 {
            Some(parse_text(field(binding, 11)?, 10, 512)?)
        } else {
            None
        },
        signature: parse_exact_bytes(field(fields, 3)?)?,
    })
}

fn parse_proof_version(value: &CanonicalValue) -> Result<u64, GroupFailure> {
    match value {
        CanonicalValue::Unsigned(version @ (1 | 2)) => Ok(*version),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupAction {
    CreateGroup,
    GrantAdmin,
    RevokeAdmin,
    IssueInvite,
    RevokeInvite,
    RequestJoin,
    ApproveJoin,
}

impl GroupAction {
    const fn code(self) -> u64 {
        match self {
            Self::CreateGroup => 1,
            Self::GrantAdmin => 2,
            Self::RevokeAdmin => 3,
            Self::IssueInvite => 4,
            Self::RevokeInvite => 5,
            Self::RequestJoin => 6,
            Self::ApproveJoin => 7,
        }
    }

    fn parse(value: &CanonicalValue) -> Result<Self, GroupFailure> {
        match value {
            CanonicalValue::Unsigned(1) => Ok(Self::CreateGroup),
            CanonicalValue::Unsigned(2) => Ok(Self::GrantAdmin),
            CanonicalValue::Unsigned(3) => Ok(Self::RevokeAdmin),
            CanonicalValue::Unsigned(4) => Ok(Self::IssueInvite),
            CanonicalValue::Unsigned(5) => Ok(Self::RevokeInvite),
            CanonicalValue::Unsigned(6) => Ok(Self::RequestJoin),
            CanonicalValue::Unsigned(7) => Ok(Self::ApproveJoin),
            _ => Err(GroupFailure::InvalidRequest),
        }
    }
}

fn exact_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], GroupFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(GroupFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, GroupFailure> {
    fields
        .get(key.checked_sub(1).ok_or(GroupFailure::InvalidRequest)?)
        .map(|(_, value)| value)
        .ok_or(GroupFailure::InvalidRequest)
}

fn require_version(value: &CanonicalValue) -> Result<(), GroupFailure> {
    if value == &CanonicalValue::Unsigned(1) {
        Ok(())
    } else {
        Err(GroupFailure::InvalidRequest)
    }
}

fn parse_scope_value(value: &CanonicalValue) -> Result<GroupScope, GroupFailure> {
    let fields = exact_fields(value, 2)?;
    match field(fields, 1)? {
        CanonicalValue::Unsigned(1) => parse_text(field(fields, 2)?, 36, 36)?
            .parse::<ConversationId>()
            .map(GroupScope::PrivateConversation)
            .map_err(|_| GroupFailure::InvalidRequest),
        CanonicalValue::Unsigned(2) => parse_text(field(fields, 2)?, 57, 57)?
            .parse::<ChannelId>()
            .map(GroupScope::ControlledPublicChannel)
            .map_err(|_| GroupFailure::InvalidRequest),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

fn parse_text(value: &CanonicalValue, min: usize, max: usize) -> Result<String, GroupFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    if !(min..=max).contains(&value.len()) {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(value.clone())
}

fn parse_identity_id(value: &str) -> Result<IdentityId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_identity_id_value(value: &CanonicalValue) -> Result<IdentityId, GroupFailure> {
    parse_identity_id(&parse_text(value, 57, 57)?)
}

fn parse_optional_identity_id(value: &CanonicalValue) -> Result<Option<IdentityId>, GroupFailure> {
    match value {
        CanonicalValue::Null => Ok(None),
        _ => parse_identity_id_value(value).map(Some),
    }
}

fn parse_device_id_value(value: &CanonicalValue) -> Result<DeviceId, GroupFailure> {
    parse_device_id(&parse_text(value, 36, 36)?)
}

fn parse_device_id(value: &str) -> Result<DeviceId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_request_id(value: &str) -> Result<RequestId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_request_id_value(value: &CanonicalValue) -> Result<RequestId, GroupFailure> {
    parse_request_id(&parse_text(value, 36, 36)?)
}

fn parse_join_request_id(value: &str) -> Result<JoinRequestId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_invite_id(value: &str) -> Result<InviteCapabilityId, GroupFailure> {
    value.parse().map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_invite_id_value(value: &CanonicalValue) -> Result<InviteCapabilityId, GroupFailure> {
    parse_invite_id(&parse_text(value, 36, 36)?)
}

fn parse_safe_uint(value: &CanonicalValue) -> Result<u64, GroupFailure> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    if *value > (1_u64 << 53) - 1 {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(*value)
}

fn parse_revision(value: &CanonicalValue) -> Result<Revision, GroupFailure> {
    Revision::new(parse_safe_uint(value)?).map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_digest(value: &CanonicalValue) -> Result<Sha256Digest, GroupFailure> {
    Ok(Sha256Digest::from_bytes(parse_exact_bytes(value)?))
}

fn parse_exact_bytes<const N: usize>(value: &CanonicalValue) -> Result<[u8; N], GroupFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(GroupFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| GroupFailure::InvalidRequest)
}

fn parse_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, GroupFailure> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| GroupFailure::InvalidRequest)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(GroupFailure::InvalidRequest),
    };
    UtcMillis::new(value).map_err(|_| GroupFailure::InvalidRequest)
}

fn numbered_map(values: Vec<CanonicalValue>) -> CanonicalValue {
    CanonicalValue::Map(
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (CanonicalValue::Unsigned((index + 1) as u64), value))
            .collect(),
    )
}

fn scope_value(scope: GroupScope) -> CanonicalValue {
    match scope {
        GroupScope::PrivateConversation(conversation_id) => numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(conversation_id.to_string()),
        ]),
        GroupScope::ControlledPublicChannel(channel_id) => numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(channel_id.to_string()),
        ]),
    }
}

fn utc_value(value: UtcMillis) -> CanonicalValue {
    if value.get() >= 0 {
        CanonicalValue::Unsigned(
            u64::try_from(value.get()).expect("non-negative UTC milliseconds fit u64"),
        )
    } else {
        CanonicalValue::Negative(value.get())
    }
}

fn canonical_hash(domain: &[u8], value: &CanonicalValue) -> Result<Sha256Digest, GroupFailure> {
    let bytes = encode_deterministic_cbor(value).map_err(|_| GroupFailure::InvalidRequest)?;
    Ok(Sha256Digest::hash_domain(domain, &bytes))
}

fn control_command_digest(
    action: GroupAction,
    scope: GroupScope,
    path: &str,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    business_fields_digest: Sha256Digest,
) -> Result<Sha256Digest, GroupFailure> {
    canonical_hash(
        CONTROL_COMMAND_HASH_DOMAIN,
        &numbered_map(vec![
            CanonicalValue::Unsigned(action.code()),
            CanonicalValue::Text(path.to_owned()),
            scope_value(scope),
            CanonicalValue::Text(actor_identity_id.to_string()),
            CanonicalValue::Text(actor_device_id.to_string()),
            CanonicalValue::Bytes(business_fields_digest.as_bytes().to_vec()),
        ]),
    )
}

fn encode_control_receipt(
    action: GroupAction,
    scope: GroupScope,
    receipt: GroupControlReceipt,
) -> Result<Vec<u8>, GroupFailure> {
    let policy_revision = match receipt.disposition() {
        GroupControlDisposition::Applied { policy_revision }
        | GroupControlDisposition::AlreadyApplied { policy_revision } => policy_revision,
        GroupControlDisposition::Rejected(_) => return Err(GroupFailure::ActionConflict),
    };
    encode_deterministic_cbor(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(action.code()),
        scope_value(scope),
        CanonicalValue::Bytes(receipt.binding_digest().as_bytes().to_vec()),
        CanonicalValue::Unsigned(policy_revision.get()),
        CanonicalValue::Unsigned(u64::from(receipt.administrator_count())),
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn encode_pending_join_request_page(
    scope: GroupScope,
    page: &PendingJoinRequestPage,
) -> Result<Vec<u8>, GroupFailure> {
    let (epoch, head) = page.mls_head().map_or(
        (CanonicalValue::Null, CanonicalValue::Null),
        |(epoch, head)| {
            (
                CanonicalValue::Unsigned(epoch),
                CanonicalValue::Bytes(head.as_bytes().to_vec()),
            )
        },
    );
    let items = page
        .items()
        .iter()
        .map(|item| {
            numbered_map(vec![
                CanonicalValue::Text(item.join_request_id().to_string()),
                CanonicalValue::Text(item.candidate_identity_id().to_string()),
                CanonicalValue::Text(item.candidate_device_id().to_string()),
                CanonicalValue::Text(item.candidate_identity_origin().to_owned()),
                CanonicalValue::Text(item.invite_id().to_string()),
                utc_value(item.requested_at()),
                CanonicalValue::Text(item.request_command_id().request_id().to_string()),
                CanonicalValue::Bytes(item.request_digest().as_bytes().to_vec()),
            ])
        })
        .collect();
    let next_after = page
        .next_cursor()
        .map_or(Ok(CanonicalValue::Null), |cursor| {
            encode_pending_join_cursor(cursor).map(CanonicalValue::Text)
        })?;
    encode_deterministic_cbor(&numbered_map(vec![
        CanonicalValue::Unsigned(1),
        scope_value(scope),
        CanonicalValue::Unsigned(page.policy_revision().get()),
        epoch,
        head,
        CanonicalValue::Array(items),
        next_after,
    ]))
    .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn encode_membership_receipt(receipt: MembershipReceipt) -> Result<Vec<u8>, GroupFailure> {
    let mut fields = vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Text(receipt.command_id().request_id().to_string()),
        CanonicalValue::Bytes(receipt.request_digest().as_bytes().to_vec()),
    ];
    match receipt.phase() {
        MembershipCommandPhase::PendingApproval => {
            fields.push(CanonicalValue::Unsigned(1));
        }
        MembershipCommandPhase::PendingCommit => {
            fields.push(CanonicalValue::Unsigned(2));
        }
        MembershipCommandPhase::Reconciling => {
            fields.push(CanonicalValue::Unsigned(3));
        }
        MembershipCommandPhase::Committed(admission) => {
            fields.push(CanonicalValue::Unsigned(4));
            fields.push(CanonicalValue::Unsigned(match admission {
                MembershipAdmission::Applied(_) => 1,
                MembershipAdmission::AlreadyMember(_) => 2,
            }));
            fields.push(commit_reference_value(admission));
        }
        MembershipCommandPhase::Rejected(rejection) => {
            fields.push(CanonicalValue::Unsigned(5));
            fields.push(CanonicalValue::Unsigned(match rejection {
                MembershipRejection::PolicyDenied => 1,
                MembershipRejection::StaleFence => 2,
                MembershipRejection::AdmissionDenied => 3,
            }));
        }
    }
    encode_deterministic_cbor(&numbered_map(fields))
        .map_err(|_| GroupFailure::TemporarilyUnavailable)
}

fn commit_reference_value(admission: MembershipAdmission) -> CanonicalValue {
    let reference = admission.commit_reference();
    numbered_map(vec![
        CanonicalValue::Unsigned(1),
        scope_value(reference.scope()),
        CanonicalValue::Text(reference.command_id().request_id().to_string()),
        CanonicalValue::Bytes(reference.request_digest().as_bytes().to_vec()),
        CanonicalValue::Bytes(reference.committed_digest().as_bytes().to_vec()),
    ])
}

fn has_exact_content_type(headers: &HeaderMap, expected: &'static str) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    matches!(values.next(), Some(value) if value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

fn single_optional_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, GroupFailure> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    value
        .to_str()
        .ok()
        .filter(|value| !value.is_empty())
        .map(Some)
        .ok_or(GroupFailure::InvalidRequest)
}

fn idempotency_key_hash(headers: &HeaderMap) -> Result<Sha256Digest, GroupFailure> {
    idempotency_key_hash_with_domain(headers, IDEMPOTENCY_HASH_DOMAIN)
}

fn mls_idempotency_key_hash(headers: &HeaderMap) -> Result<Sha256Digest, GroupFailure> {
    idempotency_key_hash_with_domain(headers, MLS_IDEMPOTENCY_KEY_HASH_DOMAIN)
}

fn idempotency_key_hash_with_domain(
    headers: &HeaderMap,
    domain: &[u8],
) -> Result<Sha256Digest, GroupFailure> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(GroupFailure::InvalidRequest);
    };
    if values.next().is_some() {
        return Err(GroupFailure::InvalidRequest);
    }
    let bytes = value.as_bytes();
    if !(MIN_IDEMPOTENCY_KEY_BYTES..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&bytes.len())
        || !bytes.iter().copied().all(is_base64url_byte)
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(Sha256Digest::hash_domain(domain, bytes))
}

fn parse_device_session_authorization(
    headers: &HeaderMap,
) -> Result<DeviceSessionCredential, GroupFailure> {
    let value = exact_authorization_value(headers, DEVICE_SESSION_AUTHORIZATION_SCHEME)?;
    let (session_id, secret) = value
        .split_once('.')
        .ok_or(GroupFailure::AuthenticationRejected)?;
    if secret.contains('.') {
        return Err(GroupFailure::AuthenticationRejected);
    }
    let session_id = session_id
        .parse::<DeviceSessionId>()
        .map_err(|_| GroupFailure::AuthenticationRejected)?;
    let secret = decode_base64url_32(secret).map_err(|()| GroupFailure::AuthenticationRejected)?;
    DeviceSessionCredential::new(session_id, secret)
        .map_err(|_| GroupFailure::AuthenticationRejected)
}

fn exact_authorization_value<'a>(
    headers: &'a HeaderMap,
    scheme: &'static str,
) -> Result<&'a str, GroupFailure> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(GroupFailure::AuthenticationRejected);
    };
    if values.next().is_some() {
        return Err(GroupFailure::AuthenticationRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| GroupFailure::AuthenticationRejected)?;
    value
        .strip_prefix(&format!("{scheme} "))
        .filter(|value| !value.is_empty())
        .ok_or(GroupFailure::AuthenticationRejected)
}

fn decode_base64url_32(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 43 || !value.bytes().all(is_base64url_byte) {
        return Err(());
    }
    let mut buffer = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(value, &mut buffer).map_err(|_| ())?;
    if decoded.len() != 32 {
        return Err(());
    }
    Ok(buffer)
}

const fn is_base64url_byte(value: u8) -> bool {
    value.is_ascii_uppercase()
        || value.is_ascii_lowercase()
        || value.is_ascii_digit()
        || value == b'_'
        || value == b'-'
}

fn cbor_response(status: StatusCode, body: Vec<u8>, content_type: &'static str) -> Response {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[derive(Clone, Copy, Debug)]
enum GroupFailure {
    InvalidRequest,
    ActionProofInvalid,
    AuthenticationRejected,
    AccessDenied,
    Unavailable,
    ActionConflict,
    IdempotencyConflict,
    TemporarilyUnavailable,
}

fn map_federated_identity_error(error: FederatedIdentityError) -> GroupFailure {
    match error {
        FederatedIdentityError::TemporarilyUnavailable => GroupFailure::TemporarilyUnavailable,
        FederatedIdentityError::InvalidOrigin
        | FederatedIdentityError::InvalidIdentityLog
        | FederatedIdentityError::DeviceUnavailable => GroupFailure::AuthenticationRejected,
    }
}

fn map_control_rejection(rejection: GroupControlRejection) -> GroupFailure {
    match rejection {
        GroupControlRejection::PolicyDenied => GroupFailure::AccessDenied,
        GroupControlRejection::RevisionConflict
        | GroupControlRejection::AdminLimitReached
        | GroupControlRejection::GroupExists => GroupFailure::ActionConflict,
        GroupControlRejection::InvalidOperation => GroupFailure::InvalidRequest,
    }
}

fn map_persistence_error(error: &GroupPersistenceError) -> GroupFailure {
    use dtx_membership_command::MembershipCommandError;

    match error {
        GroupPersistenceError::DeviceAuthenticationRejected => GroupFailure::AuthenticationRejected,
        GroupPersistenceError::MembershipReceiptAccessDenied
        | GroupPersistenceError::MembershipDiscoveryAccessDenied => GroupFailure::AccessDenied,
        GroupPersistenceError::GroupNotFound
        | GroupPersistenceError::MembershipCommand(
            MembershipCommandError::CommandNotFound | MembershipCommandError::JoinRequestNotFound,
        ) => GroupFailure::Unavailable,
        GroupPersistenceError::ActionProofRejected
        | GroupPersistenceError::MlsAuthorizationRejected => GroupFailure::ActionProofInvalid,
        GroupPersistenceError::ControlCommandConflict
        | GroupPersistenceError::MlsCommitConflict => GroupFailure::IdempotencyConflict,
        GroupPersistenceError::MembershipCommand(MembershipCommandError::IdempotencyConflict) => {
            GroupFailure::IdempotencyConflict
        }
        GroupPersistenceError::MembershipCommand(
            MembershipCommandError::ActorCandidateMismatch
            | MembershipCommandError::JoinRequestMismatch,
        ) => GroupFailure::InvalidRequest,
        GroupPersistenceError::MembershipCommand(_)
        | GroupPersistenceError::GroupBootstrapConflict
        | GroupPersistenceError::StaleMlsHead
        | GroupPersistenceError::MlsDeviceConfirmationRejected => GroupFailure::ActionConflict,
        GroupPersistenceError::GroupPolicy(_)
        | GroupPersistenceError::Database(_)
        | GroupPersistenceError::UnsafeRuntimeRole
        | GroupPersistenceError::RuntimeRoleUnauthorized
        | GroupPersistenceError::RuntimeRoleOverprivileged
        | GroupPersistenceError::TenantContextLeak
        | GroupPersistenceError::GroupSnapshot(_)
        | GroupPersistenceError::CorruptData(_)
        | GroupPersistenceError::CandidateIdentityOriginUnavailable
        | GroupPersistenceError::LeaseLost
        | GroupPersistenceError::ScopeMismatch => GroupFailure::TemporarilyUnavailable,
    }
}

fn group_failure_response(failure: GroupFailure, request_id: RequestId) -> Response {
    let (status, code, retryable) = match failure {
        GroupFailure::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            GroupErrorCode::RequestInvalid,
            false,
        ),
        GroupFailure::ActionProofInvalid => (
            StatusCode::UNPROCESSABLE_ENTITY,
            GroupErrorCode::ActionProofInvalid,
            false,
        ),
        GroupFailure::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            GroupErrorCode::DeviceAuthenticationFailed,
            false,
        ),
        GroupFailure::AccessDenied => (StatusCode::FORBIDDEN, GroupErrorCode::AccessDenied, false),
        GroupFailure::Unavailable => (
            StatusCode::NOT_FOUND,
            GroupErrorCode::ResourceUnavailable,
            false,
        ),
        GroupFailure::ActionConflict => {
            (StatusCode::CONFLICT, GroupErrorCode::ActionConflict, false)
        }
        GroupFailure::IdempotencyConflict => (
            StatusCode::CONFLICT,
            GroupErrorCode::IdempotencyConflict,
            false,
        ),
        GroupFailure::TemporarilyUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            GroupErrorCode::ServiceUnavailable,
            true,
        ),
    };
    let body = serde_json::to_vec(&SafeErrorEnvelope {
        error: SafeErrorBody {
            code,
            request_id,
            retryable,
        },
    })
    .expect("the fixed Group Node error envelope always serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    with_common_headers(response, request_id)
}

#[derive(Clone, Copy, Serialize)]
enum GroupErrorCode {
    #[serde(rename = "DEVICE_AUTHENTICATION_FAILED")]
    DeviceAuthenticationFailed,
    #[serde(rename = "GROUP_ACCESS_DENIED")]
    AccessDenied,
    #[serde(rename = "GROUP_RESOURCE_UNAVAILABLE")]
    ResourceUnavailable,
    #[serde(rename = "GROUP_ACTION_CONFLICT")]
    ActionConflict,
    #[serde(rename = "GROUP_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    #[serde(rename = "GROUP_ACTION_PROOF_INVALID")]
    ActionProofInvalid,
    #[serde(rename = "GROUP_REQUEST_INVALID")]
    RequestInvalid,
    #[serde(rename = "GROUP_SERVICE_UNAVAILABLE")]
    ServiceUnavailable,
}

#[derive(Serialize)]
struct SafeErrorEnvelope {
    error: SafeErrorBody,
}

#[derive(Serialize)]
struct SafeErrorBody {
    code: GroupErrorCode,
    request_id: RequestId,
    retryable: bool,
}

fn with_common_headers(mut response: Response, request_id: RequestId) -> Response {
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
