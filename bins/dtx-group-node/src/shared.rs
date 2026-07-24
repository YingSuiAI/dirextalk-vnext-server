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
    ChannelId, Clock, ConversationId, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId,
    IdentityId, InviteCapabilityId, JoinRequestId, RequestId, Revision, SystemClock, TenantId,
};
use dtx_federated_identity::{
    FederatedIdentityError, FederatedIdentityVerifier, MlsV5RecoveryAuthorizationQuery,
};
use dtx_group_persistence::{
    GroupControlCommand, GroupControlDisposition, GroupControlExecution, GroupControlOperation,
    GroupControlReceipt, GroupControlRejection, GroupControlRepository, GroupMembershipRepository,
    GroupPersistenceError, GroupPgStore, MLS_IDEMPOTENCY_KEY_HASH_DOMAIN,
    MembershipCommandExecution, MlsCommitAuthorization, MlsCommitCommand, MlsCommitExecution,
    MlsCommitFeedPage, MlsCommitReceipt, MlsCommitSequencerRepository, MlsDeviceJoinConfirmation,
    PendingJoinRequestCursor, PendingJoinRequestPage, VerifiedDeviceActor,
    mls_opaque_commit_digest, mls_v5_controller_consent_digest,
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

pub use crate::sequencer_key::load_mls_sequencer_signing_key;

/// Invalid federation configuration.
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
/// V30 active-member commit catch-up collection path.
pub const MLS_COMMIT_FEED_PATH_TEMPLATE: &str = "/v1/groups/{scope_kind}/{scope_id}/mls-commits";
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
/// V30 candidate join request media type with exact `KeyPackage` binding.
pub const GROUP_JOIN_REQUEST_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-join-request.v2+cbor";
/// Exact owner/admin approval request media type.
pub const GROUP_APPROVE_JOIN_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-approve-join.v1+cbor";
/// V30 Owner/Admin approval media type with exact `KeyPackage` binding.
pub const GROUP_APPROVE_JOIN_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-approve-join.v2+cbor";
/// Exact local policy receipt media type.
pub const GROUP_ACTION_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-action-receipt.v1+cbor";
/// Exact membership receipt media type.
pub const MEMBERSHIP_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.membership-receipt.v1+cbor";
/// V30 membership receipt media type.
pub const MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.membership-receipt.v2+cbor";
/// Exact V29 Owner/Admin pending-request page media type.
pub const GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-join-request-page.v1+cbor";
/// V30 pending page carrying each candidate `KeyPackage` digest.
pub const GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-join-request-page.v2+cbor";
/// Exact V29 public Group Service descriptor media type.
pub const GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.group-service.v1+cbor";
/// Exact V2 MLS commit request media type.
pub const MLS_COMMIT_CONTENT_TYPE: &str = "application/vnd.dirextalk.mls-commit.v2+cbor";
/// V30 approved-identity commit request media type.
pub const MLS_COMMIT_V3_CONTENT_TYPE: &str = "application/vnd.dirextalk.mls-commit.v3+cbor";
/// V32 Owner-authored single-member removal commit request media type.
pub const MLS_COMMIT_V4_CONTENT_TYPE: &str = "application/vnd.dirextalk.mls-commit.v4+cbor";
/// V40 existing-member device recovery/removal request media type.
pub const MLS_COMMIT_V5_CONTENT_TYPE: &str = "application/vnd.dirextalk.mls-commit.v5+cbor";
/// Exact V2 signed receipt media type.
pub const MLS_COMMIT_RECEIPT_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-commit-receipt.v2+cbor";
/// V30 receipt media type binding candidate package, join, and approval digests.
pub const MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-commit-receipt.v3+cbor";
/// V32 receipt binding the removed leaf and product-policy revision fence.
pub const MLS_COMMIT_RECEIPT_V4_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-commit-receipt.v4+cbor";
pub const MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-commit-receipt.v5+cbor";
/// Exact V30 active-member commit catch-up page media type.
pub const MLS_COMMIT_FEED_CONTENT_TYPE: &str = "application/vnd.dirextalk.mls-commit-feed.v1+cbor";
/// V32 catch-up feed carrying consecutive V3 admissions and V4 removals.
pub const MLS_COMMIT_FEED_V2_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-commit-feed.v2+cbor";
/// V40 catch-up feed carrying consecutive V3, V4, and V5 commits.
pub const MLS_COMMIT_FEED_V3_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-commit-feed.v3+cbor";
/// Exact V2 candidate confirmation media type.
pub const MLS_CONFIRMATION_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-device-join-confirmation.v2+cbor";
/// V30 stable confirmation body media type.
pub const MLS_CONFIRMATION_V3_CONTENT_TYPE: &str =
    "application/vnd.dirextalk.mls-device-join-confirmation.v3+cbor";
/// Exact authorization scheme for active device sessions.
pub const DEVICE_SESSION_AUTHORIZATION_SCHEME: &str = "DTX-Device-Session";
/// Canonical HTTPS origin serving the actor's self-authenticated identity log.
pub const IDENTITY_ORIGIN_HEADER: &str = "dtx-identity-origin";
/// Base64url canonical-CBOR proof authorizing a federated receipt lookup.
pub const RECEIPT_QUERY_PROOF_HEADER: &str = "dtx-receipt-query-proof";
/// Base64url canonical-CBOR proof authorizing a pending-request query.
pub const GROUP_QUERY_PROOF_HEADER: &str = "dtx-group-query-proof";
/// Fresh route/body-bound proof for a federated V30 MLS confirmation.
pub const MLS_CONFIRMATION_PROOF_HEADER: &str = "dtx-mls-confirmation-proof";
/// Fresh route/request-bound proof for federated V30 commit submit/query.
pub const MLS_COMMIT_PROOF_HEADER: &str = "dtx-mls-commit-proof";

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
const MAX_MLS_COMMIT_FEED_PAGE_SIZE: usize = 64;
const MAX_SAFE_EPOCH: u64 = 9_007_199_254_740_991;
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
const MLS_CONFIRMATION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.mls-confirmation-binding.v3\0";
const MLS_CONFIRMATION_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-confirmation-proof-signature.v3\0";
const MLS_CONFIRMATION_BODY_HASH_DOMAIN: &[u8] = b"dirextalk.mls-confirmation-body.v3\0";
const MLS_COMMIT_FEDERATED_BINDING_HASH_DOMAIN: &[u8] =
    b"dirextalk.mls-commit-federated-binding.v3\0";
const MLS_COMMIT_FEDERATED_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-commit-federated-proof-signature.v3\0";
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
        self,
        public_origin: impl AsRef<str>,
        allowed_http_origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, GroupNodeConfigurationError> {
        self.with_federated_identity_configuration(public_origin, allowed_http_origins, None)
    }

    /// Atomically installs the federation origin policy and an optional additional
    /// PEM-encoded CA root for federated identity HTTPS fetches.
    ///
    /// The optional root must contain exactly one X.509 CA certificate. It is merged
    /// with the normal platform trust store, so certificate-chain and hostname
    /// validation remain enabled. Passing `None` preserves the production default.
    ///
    /// # Errors
    ///
    /// Returns [`GroupNodeConfigurationError`] for the origin-policy failures
    /// documented by [`Self::with_public_origin_and_allowed_http_identity_origins`]
    /// or when `additional_trust_root_pem` is not exactly one valid CA certificate.
    pub fn with_federated_identity_configuration(
        mut self,
        public_origin: impl AsRef<str>,
        allowed_http_origins: impl IntoIterator<Item = String>,
        additional_trust_root_pem: Option<&[u8]>,
    ) -> Result<Self, GroupNodeConfigurationError> {
        let (federated_identity, public_origin) =
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                public_origin.as_ref(),
                allowed_http_origins,
                additional_trust_root_pem,
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
        let context = membership_context(
            parsed.protocol_version,
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
            parsed.candidate_key_package_digest,
        )?;
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
        let context = membership_context(
            parsed.protocol_version,
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
            parsed.candidate_key_package_digest,
        )?;
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
