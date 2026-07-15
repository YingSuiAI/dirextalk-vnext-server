#![forbid(unsafe_code)]

//! Tenant-affine HTTP boundary for durable group policy and membership intents.
//!
//! This node deliberately stops at a durable `pending_commit` receipt. It does
//! not invent an MLS result: a later Sequencer adapter is the only component
//! allowed to turn that intent into a committed membership fact.

mod federated_identity;

use std::sync::Arc;

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
    GroupPersistenceError, GroupPgStore, MembershipCommandExecution, VerifiedDeviceActor,
};
use dtx_group_policy::GroupScope;
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_membership_command::{
    ApproveJoinCommand, CandidateMembership, JoinRequestCommand, MembershipAdmission,
    MembershipCommandContext, MembershipCommandId, MembershipCommandPhase, MembershipFence,
    MembershipReceipt, MembershipRejection,
};
use dtx_wire::{
    CanonicalValue, Sha256Digest, SigningPublicKey, UtcMillis, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

use crate::federated_identity::{FederatedIdentityError, FederatedIdentityVerifier};

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
/// Owner/Admin approval path template.
pub const GROUP_JOIN_APPROVAL_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/join-requests/{join_request_id}/approvals";
/// Durable membership-receipt path template.
pub const GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE: &str =
    "/v1/groups/{scope_kind}/{scope_id}/membership-receipts/{membership_command_id}";

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
/// Exact authorization scheme for active device sessions.
pub const DEVICE_SESSION_AUTHORIZATION_SCHEME: &str = "DTX-Device-Session";
/// Canonical HTTPS origin serving the actor's self-authenticated identity log.
pub const IDENTITY_ORIGIN_HEADER: &str = "dtx-identity-origin";
/// Base64url canonical-CBOR proof authorizing a federated receipt lookup.
pub const RECEIPT_QUERY_PROOF_HEADER: &str = "dtx-receipt-query-proof";

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAX_CONTROL_BODY_BYTES: usize = 16_384;
const MAX_MEMBERSHIP_BODY_BYTES: usize = 32_768;
const MAX_GET_BODY_BYTES: usize = 1_024;
const MAX_ACTION_PROOF_LIFETIME_MS: i64 = 300_000;

const IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"dirextalk.membership-idempotency-key.v1\0";
const BUSINESS_FIELDS_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-business-fields.v1\0";
const ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v1\0";
const ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v1\0";
const FEDERATED_ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v2\0";
const FEDERATED_ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v2\0";
const RECEIPT_QUERY_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-receipt-query-binding.v2\0";
const RECEIPT_QUERY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-receipt-query-signature.v2\0";
const CONTROL_COMMAND_HASH_DOMAIN: &[u8] = b"dirextalk.group-control-command.v1\0";

/// Shared state for a node that serves one trusted configured tenant.
#[derive(Clone)]
pub struct GroupNodeState {
    store: GroupPgStore,
    tenant_id: TenantId,
    control_repository: GroupControlRepository,
    membership_repository: GroupMembershipRepository,
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
            federated_identity,
            clock,
        }
    }

    /// Allows exact HTTP identity origins only for an explicitly configured
    /// trusted local-development topology. Production origins remain HTTPS.
    ///
    /// # Errors
    ///
    /// Returns [`GroupNodeConfigurationError`] when an origin is not an exact
    /// canonical HTTP origin or the bounded verifier client cannot be built.
    pub fn with_allowed_http_identity_origins(
        mut self,
        origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, GroupNodeConfigurationError> {
        self.federated_identity =
            FederatedIdentityVerifier::new(origins).map_err(GroupNodeConfigurationError)?;
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
        let result = if let Some(actor) = federated_actor {
            self.membership_repository
                .request_join_verified_with_proof_outcome(
                    &self.store,
                    self.tenant_id,
                    actor,
                    JoinRequestCommand::new(context),
                    CandidateMembership::NotMember,
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
        .route(GROUP_JOIN_APPROVAL_PATH_TEMPLATE, post(approve_join))
        .route(
            GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE,
            get(get_membership_receipt),
        )
        .with_state(state)
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
    parse_text(value, 36, 36)?
        .parse()
        .map_err(|_| GroupFailure::InvalidRequest)
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
    Ok(Sha256Digest::hash_domain(IDEMPOTENCY_HASH_DOMAIN, bytes))
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
        GroupPersistenceError::MembershipReceiptAccessDenied => GroupFailure::AccessDenied,
        GroupPersistenceError::GroupNotFound
        | GroupPersistenceError::MembershipCommand(
            MembershipCommandError::CommandNotFound | MembershipCommandError::JoinRequestNotFound,
        ) => GroupFailure::Unavailable,
        GroupPersistenceError::ActionProofRejected => GroupFailure::ActionProofInvalid,
        GroupPersistenceError::ControlCommandConflict => GroupFailure::IdempotencyConflict,
        GroupPersistenceError::MembershipCommand(MembershipCommandError::IdempotencyConflict) => {
            GroupFailure::IdempotencyConflict
        }
        GroupPersistenceError::MembershipCommand(
            MembershipCommandError::ActorCandidateMismatch
            | MembershipCommandError::JoinRequestMismatch,
        ) => GroupFailure::InvalidRequest,
        GroupPersistenceError::MembershipCommand(_)
        | GroupPersistenceError::GroupBootstrapConflict => GroupFailure::ActionConflict,
        GroupPersistenceError::GroupPolicy(_)
        | GroupPersistenceError::Database(_)
        | GroupPersistenceError::UnsafeRuntimeRole
        | GroupPersistenceError::RuntimeRoleUnauthorized
        | GroupPersistenceError::RuntimeRoleOverprivileged
        | GroupPersistenceError::TenantContextLeak
        | GroupPersistenceError::GroupSnapshot(_)
        | GroupPersistenceError::CorruptData(_)
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
