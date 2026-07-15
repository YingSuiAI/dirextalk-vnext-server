use std::str::FromStr;

use dtx_domain::{
    ChannelId, ConversationId, DeviceId, IdentityId, InviteCapabilityId, JoinRequestId, RequestId,
    Revision, TenantId,
};
use dtx_group_policy::{
    GroupApprovedJoinPersistence, GroupAuthorityPersistence, GroupInvitePersistence,
    GroupPendingJoinPersistence, GroupPolicy, GroupPolicyError, GroupPolicyPersistenceImage,
    GroupPolicySnapshot, GroupReservedJoinPersistence, GroupScope,
};
use dtx_identity_persistence::{
    AuthenticatedDeviceSession, AuthenticatedDeviceSigningSession, DeviceSessionCredential,
    DeviceSessionRepository, IdentityPersistenceError,
};
use dtx_membership_command::{
    ApproveJoinCommand, CandidateMembership, JoinRequestCommand, MembershipAdmission,
    MembershipCommandBook, MembershipCommandBookSnapshot, MembershipCommandContext,
    MembershipCommandId, MembershipCommandKind, MembershipCommandPersistence,
    MembershipCommandPhase, MembershipCommitReference, MembershipFence,
    MembershipIdempotencyPersistence, MembershipReceipt, MembershipRejection,
    MembershipWorkflowPersistence, MembershipWorkflowPersistencePhase, SequencerAction,
    SequencerResolution,
};
use dtx_wire::{Sha256Digest, SigningPublicKey, UtcMillis};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{GroupPersistenceError, GroupPgStore, PreparedSequencerAction, SequencerActionLease};

const PRIVATE_CONVERSATION_SCOPE: &str = "private_conversation";
const CONTROLLED_PUBLIC_CHANNEL_SCOPE: &str = "controlled_public_channel";
const REQUEST_JOIN_KIND: &str = "request_join";
const APPROVE_JOIN_KIND: &str = "approve_join";
const PENDING_APPROVAL_STATE: &str = "pending_approval";
const PENDING_COMMIT_STATE: &str = "pending_commit";
const RECONCILING_STATE: &str = "reconciling";
const COMMITTED_STATE: &str = "committed";
const REJECTED_STATE: &str = "rejected";
const PENDING_JOIN_STATE: &str = "pending";
const RESERVED_JOIN_STATE: &str = "reserved";
const APPROVED_JOIN_STATE: &str = "approved";
const OWNER_AUTHORITY: &str = "owner";
const ADMIN_AUTHORITY: &str = "admin";
const APPLIED_ADMISSION: &str = "applied";
const ALREADY_MEMBER_ADMISSION: &str = "already_member";
const POLICY_DENIED_REJECTION: &str = "policy_denied";
const STALE_FENCE_REJECTION: &str = "stale_fence";
const ADMISSION_DENIED_REJECTION: &str = "admission_denied";
const SUBMIT_ACTION: &str = "submit";
const QUERY_ACTION: &str = "query";

/// Durable repository for one normalized group-policy and membership-command saga.
#[derive(Clone, Copy, Debug, Default)]
pub struct GroupMembershipRepository;

/// Stable database cursor for Owner/Admin pending-request pagination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingJoinRequestCursor {
    requested_at: UtcMillis,
    join_request_id: JoinRequestId,
}

impl PendingJoinRequestCursor {
    /// Creates a validated stable cursor.
    #[must_use]
    pub const fn new(requested_at: UtcMillis, join_request_id: JoinRequestId) -> Self {
        Self {
            requested_at,
            join_request_id,
        }
    }

    /// Returns the persisted request timestamp.
    #[must_use]
    pub const fn requested_at(self) -> UtcMillis {
        self.requested_at
    }

    /// Returns the tie-breaking request ID.
    #[must_use]
    pub const fn join_request_id(self) -> JoinRequestId {
        self.join_request_id
    }
}

/// One pending request visible only to the current Owner or an active Admin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingJoinRequest {
    join_request_id: JoinRequestId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    candidate_identity_origin: String,
    invite_id: InviteCapabilityId,
    requested_at: UtcMillis,
    request_command_id: MembershipCommandId,
    request_digest: Sha256Digest,
}

impl PendingJoinRequest {
    /// Returns the stable request identifier.
    #[must_use]
    pub const fn join_request_id(&self) -> JoinRequestId {
        self.join_request_id
    }

    /// Returns the self-certifying candidate identity.
    #[must_use]
    pub const fn candidate_identity_id(&self) -> IdentityId {
        self.candidate_identity_id
    }

    /// Returns the exact candidate device proposed for MLS admission.
    #[must_use]
    pub const fn candidate_device_id(&self) -> DeviceId {
        self.candidate_device_id
    }

    /// Returns the verified canonical origin serving the candidate identity log.
    #[must_use]
    pub fn candidate_identity_origin(&self) -> &str {
        &self.candidate_identity_origin
    }

    /// Returns the invitation consumed by this workflow.
    #[must_use]
    pub const fn invite_id(&self) -> InviteCapabilityId {
        self.invite_id
    }

    /// Returns the durable request timestamp.
    #[must_use]
    pub const fn requested_at(&self) -> UtcMillis {
        self.requested_at
    }

    /// Returns the candidate-authored membership command identifier.
    #[must_use]
    pub const fn request_command_id(&self) -> MembershipCommandId {
        self.request_command_id
    }

    /// Returns the durable canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
}

/// Authorization-checked, stable page of pending membership requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingJoinRequestPage {
    policy_revision: Revision,
    mls_head: Option<(u64, Sha256Digest)>,
    items: Vec<PendingJoinRequest>,
    next_cursor: Option<PendingJoinRequestCursor>,
}

impl PendingJoinRequestPage {
    /// Returns the current group-policy revision observed by this page.
    #[must_use]
    pub const fn policy_revision(&self) -> Revision {
        self.policy_revision
    }

    /// Returns the current MLS epoch and head when the Sequencer is bootstrapped.
    #[must_use]
    pub const fn mls_head(&self) -> Option<(u64, Sha256Digest)> {
        self.mls_head
    }

    /// Returns the stable ordered pending items.
    #[must_use]
    pub fn items(&self) -> &[PendingJoinRequest] {
        &self.items
    }

    /// Returns the cursor for the next page when more rows exist.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<PendingJoinRequestCursor> {
        self.next_cursor
    }
}

/// Result of a membership command invocation at the public boundary.
///
/// The receipt is the durable fact; the replay marker only tells an HTTP
/// caller whether this invocation created that fact or recovered it exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipCommandExecution {
    receipt: MembershipReceipt,
    replayed: bool,
}

/// A device authorization that a Group Node verified outside the local
/// identity-session database, for example from a self-authenticated remote
/// identity log. The repository still binds these coordinates to the command
/// and verifies the domain-specific action proof before reading a receipt or
/// mutating group state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDeviceActor {
    identity_id: IdentityId,
    device_id: DeviceId,
    signing_key: SigningPublicKey,
}

impl VerifiedDeviceActor {
    /// Creates one already-verified active device actor.
    #[must_use]
    pub const fn new(
        identity_id: IdentityId,
        device_id: DeviceId,
        signing_key: SigningPublicKey,
    ) -> Self {
        Self {
            identity_id,
            device_id,
            signing_key,
        }
    }

    /// Returns the self-certifying actor identity.
    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    /// Returns the active actor device.
    #[must_use]
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Returns the current device signing key resolved by the caller.
    #[must_use]
    pub const fn signing_key(self) -> SigningPublicKey {
        self.signing_key
    }
}

impl MembershipCommandExecution {
    /// Returns the durable membership receipt.
    #[must_use]
    pub const fn receipt(self) -> MembershipReceipt {
        self.receipt
    }

    /// Reports whether this invocation exactly replayed existing durable state.
    #[must_use]
    pub const fn replayed(self) -> bool {
        self.replayed
    }
}

#[allow(clippy::missing_errors_doc, clippy::too_many_arguments)] // The shared error type documents the fail-closed boundary; proof-verified public commands retain explicit security inputs rather than a one-use parameter bag.
impl GroupMembershipRepository {
    /// Creates an initial durable group aggregate exactly once.
    ///
    /// Repeating the same bootstrap is a no-op; a different policy image for an
    /// existing scope is rejected rather than overwritten.
    pub async fn bootstrap(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        policy: &GroupPolicy,
        now_ms: i64,
    ) -> Result<(), GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            let key = ScopeKey::from_scope(tenant_id, policy.scope());
            if let Some(existing) = load_policy(&mut *session.connection(), key, true).await? {
                if existing == *policy {
                    return Ok(());
                }
                return Err(GroupPersistenceError::GroupBootstrapConflict);
            }
            persist_policy(&mut *session.connection(), tenant_id, policy, now_ms, true).await?;
            Ok(())
        }
        .await;
        settle(session, result).await
    }

    /// Loads a validated current policy projection for one exact scope.
    pub async fn load_policy(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        scope: GroupScope,
    ) -> Result<GroupPolicy, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            load_policy(
                &mut *session.connection(),
                ScopeKey::from_scope(tenant_id, scope),
                false,
            )
            .await?
            .ok_or(GroupPersistenceError::GroupNotFound)
        }
        .await;
        settle(session, result).await
    }

    /// Records or exactly replays one candidate-authored join request.
    ///
    /// Durable command/idempotency lookup happens before invitation validation,
    /// so a response loss can never be reclassified as an expired invitation.
    pub async fn request_join(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        command: JoinRequestCommand,
        candidate_membership: CandidateMembership,
        candidate_identity_origin: &str,
        now_ms: i64,
    ) -> Result<MembershipReceipt, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = request_join_in_transaction(
            session.connection(),
            tenant_id,
            command,
            candidate_membership,
            candidate_identity_origin,
            now_ms,
        )
        .await;
        settle(session, result)
            .await
            .map(MembershipCommandExecution::receipt)
    }

    /// Records a locally authenticated join and atomically binds the trusted
    /// public identity origin when this invocation creates the workflow.
    pub async fn request_join_authenticated_with_proof_outcome<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: JoinRequestCommand,
        candidate_membership: CandidateMembership,
        candidate_identity_origin: &str,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<MembershipCommandExecution, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let result = async {
            ensure_authenticated_actor(authenticated.session(), command.context())?;
            verify_proof(authenticated.signing_key())?;
            request_join_in_transaction(
                session.connection(),
                tenant_id,
                command,
                candidate_membership,
                candidate_identity_origin,
                now_ms,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Records a federated join and atomically binds the already verified
    /// identity-log origin when this invocation creates the workflow.
    pub async fn request_join_verified_with_proof_outcome<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        command: JoinRequestCommand,
        candidate_membership: CandidateMembership,
        candidate_identity_origin: &str,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<MembershipCommandExecution, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            ensure_verified_actor(actor, command.context())?;
            verify_proof(actor.signing_key())?;
            request_join_in_transaction(
                session.connection(),
                tenant_id,
                command,
                candidate_membership,
                candidate_identity_origin,
                now_ms,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Records or exactly replays an Owner/Admin approval and its durable submit outbox.
    ///
    /// The policy reservation and `PendingCommit` command state commit together
    /// before any caller can ask for a Sequencer action.
    pub async fn approve_join(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        command: ApproveJoinCommand,
        candidate_membership: CandidateMembership,
        now_ms: i64,
    ) -> Result<MembershipReceipt, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = approve_join_in_transaction(
            session.connection(),
            tenant_id,
            command,
            candidate_membership,
            now_ms,
        )
        .await;
        settle(session, result)
            .await
            .map(MembershipCommandExecution::receipt)
    }

    /// Records or exactly replays an Owner/Admin approval after same-transaction
    /// device-session validation.
    pub async fn approve_join_authenticated(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: ApproveJoinCommand,
        candidate_membership: CandidateMembership,
        now_ms: i64,
    ) -> Result<MembershipReceipt, GroupPersistenceError> {
        let (mut session, authenticated) =
            begin_authenticated(store, tenant_id, credential, now_ms).await?;
        let result = async {
            ensure_authenticated_actor(authenticated, command.context())?;
            approve_join_in_transaction(
                session.connection(),
                tenant_id,
                command,
                candidate_membership,
                now_ms,
            )
            .await
        }
        .await;
        settle(session, result)
            .await
            .map(MembershipCommandExecution::receipt)
    }

    /// Records an approval after same-transaction device-session and action
    /// proof verification.
    pub async fn approve_join_authenticated_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: ApproveJoinCommand,
        candidate_membership: CandidateMembership,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<MembershipReceipt, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        self.approve_join_authenticated_with_proof_outcome(
            store,
            tenant_id,
            credential,
            command,
            candidate_membership,
            now_ms,
            verify_proof,
        )
        .await
        .map(MembershipCommandExecution::receipt)
    }

    /// Records or exactly replays a proof-verified approval and reports
    /// whether this invocation created the durable receipt.
    pub async fn approve_join_authenticated_with_proof_outcome<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: ApproveJoinCommand,
        candidate_membership: CandidateMembership,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<MembershipCommandExecution, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let result = async {
            ensure_authenticated_actor(authenticated.session(), command.context())?;
            verify_proof(authenticated.signing_key())?;
            approve_join_in_transaction(
                session.connection(),
                tenant_id,
                command,
                candidate_membership,
                now_ms,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Records or replays a remote Owner/Admin approval after verification of
    /// the actor's current self-authenticated identity-log projection.
    pub async fn approve_join_verified_with_proof_outcome<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        command: ApproveJoinCommand,
        candidate_membership: CandidateMembership,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<MembershipCommandExecution, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            ensure_verified_actor(actor, command.context())?;
            verify_proof(actor.signing_key())?;
            approve_join_in_transaction(
                session.connection(),
                tenant_id,
                command,
                candidate_membership,
                now_ms,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Loads one membership receipt after revalidating the reading device in
    /// the same tenant transaction.
    ///
    /// The originating actor, the candidate carried by the workflow, and the
    /// current Owner/Admin role may read it. Other authenticated identities
    /// receive an access-denied result without receiving receipt facts.
    pub async fn load_receipt_authenticated(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        scope: GroupScope,
        command_id: MembershipCommandId,
        now_ms: i64,
    ) -> Result<MembershipReceipt, GroupPersistenceError> {
        let (mut session, authenticated) =
            begin_authenticated(store, tenant_id, credential, now_ms).await?;
        let result = load_receipt_for_identity_in_transaction(
            session.connection(),
            tenant_id,
            authenticated.identity_id(),
            scope,
            command_id,
        )
        .await;
        settle(session, result).await
    }

    /// Loads a receipt for an actor whose current device key and signed query
    /// proof were verified by the Group Node from a remote identity log.
    pub async fn load_receipt_verified(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        scope: GroupScope,
        command_id: MembershipCommandId,
    ) -> Result<MembershipReceipt, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = load_receipt_for_identity_in_transaction(
            session.connection(),
            tenant_id,
            actor.identity_id(),
            scope,
            command_id,
        )
        .await;
        settle(session, result).await
    }

    /// Lists pending requests for a locally authenticated current Owner/Admin
    /// after verifying the route/query-bound device signature in the same
    /// transaction used for authorization and paging.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_pending_join_requests_authenticated_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        scope: GroupScope,
        after: Option<PendingJoinRequestCursor>,
        limit: usize,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<PendingJoinRequestPage, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let result = async {
            if authenticated.session().identity_id() != actor_identity_id
                || authenticated.session().device_id() != actor_device_id
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            verify_proof(authenticated.signing_key())?;
            list_pending_join_requests_in_transaction(
                session.connection(),
                tenant_id,
                actor_identity_id,
                scope,
                after,
                limit,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Lists pending requests for a federated current Owner/Admin whose active
    /// device and route/query-bound signature were verified by the Group Node.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_pending_join_requests_verified_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        scope: GroupScope,
        after: Option<PendingJoinRequestCursor>,
        limit: usize,
        verify_proof: F,
    ) -> Result<PendingJoinRequestPage, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            verify_proof(actor.signing_key())?;
            list_pending_join_requests_in_transaction(
                session.connection(),
                tenant_id,
                actor.identity_id(),
                scope,
                after,
                limit,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Leases the next durable Sequencer action after its intent has committed.
    ///
    /// Claiming a `Submit` first persists the command as `Reconciling` and
    /// changes the durable outbox to `Query`. A crash or lost response therefore
    /// permits only lookup recovery, never a blind second submit.
    #[allow(clippy::too_many_lines)] // The one transaction deliberately keeps the lease, revocation recheck, receipt, policy, and outbox transition together.
    pub async fn prepare_next_action(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        now_ms: i64,
        lease_for_ms: i64,
    ) -> Result<Option<PreparedSequencerAction>, GroupPersistenceError> {
        if lease_for_ms <= 0 {
            return Err(GroupPersistenceError::CorruptData(
                "non-positive outbox lease",
            ));
        }
        let lease_expires_at_ms = now_ms
            .checked_add(lease_for_ms)
            .ok_or(GroupPersistenceError::CorruptData("outbox lease overflow"))?;
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            let Some(outbox) =
                lock_next_outbox(&mut *session.connection(), tenant_id, now_ms).await?
            else {
                return Ok(None);
            };
            let key = ScopeKey::from_storage(tenant_id, &outbox.scope_kind, &outbox.scope_id)?;
            let mut aggregate = load_aggregate(&mut *session.connection(), key, true)
                .await?
                .ok_or(GroupPersistenceError::CorruptData("outbox group missing"))?;
            let command_id = membership_command_id(outbox.command_id)?;
            let action = aggregate.book.next_sequencer_action(command_id)?.ok_or(
                GroupPersistenceError::CorruptData("active outbox has terminal command"),
            )?;
            let expected = action_code(&action);
            if expected != outbox.action {
                return Err(GroupPersistenceError::CorruptData("outbox action drift"));
            }
            if matches!(action, SequencerAction::Submit(_)) {
                match aggregate
                    .policy
                    .validate_reserved_join_authority(outbox.request_id)
                {
                    Ok(()) => {}
                    Err(GroupPolicyError::InviteIssuerNoLongerAuthorized) => {
                        let receipt = aggregate
                            .book
                            .reject_locally(command_id, MembershipRejection::PolicyDenied)?;
                        aggregate.policy.release_join_reservation(
                            aggregate.policy.revision(),
                            outbox.request_id,
                        )?;
                        persist_policy(
                            &mut *session.connection(),
                            tenant_id,
                            &aggregate.policy,
                            now_ms,
                            false,
                        )
                        .await?;
                        persist_book(
                            &mut *session.connection(),
                            &aggregate.book,
                            tenant_id,
                            key.scope,
                            now_ms,
                        )
                        .await?;
                        complete_unleased_outbox(
                            &mut *session.connection(),
                            key,
                            command_id,
                            now_ms,
                        )
                        .await?;
                        debug_assert!(matches!(
                            receipt.phase(),
                            MembershipCommandPhase::Rejected(_)
                        ));
                        return Ok(None);
                    }
                    Err(error) => return Err(GroupPersistenceError::GroupPolicy(error)),
                }
            }
            let lease = SequencerActionLease {
                token: Uuid::now_v7(),
            };
            if matches!(action, SequencerAction::Submit(_)) {
                aggregate
                    .book
                    .observe_sequencer_resolution(command_id, SequencerResolution::Unknown)?;
                persist_book(
                    &mut *session.connection(),
                    &aggregate.book,
                    tenant_id,
                    key.scope,
                    now_ms,
                )
                .await?;
                update_outbox_claim(
                    &mut *session.connection(),
                    key,
                    command_id,
                    QUERY_ACTION,
                    SUBMIT_ACTION,
                    lease,
                    lease_expires_at_ms,
                    now_ms,
                )
                .await?;
            } else {
                update_outbox_claim(
                    &mut *session.connection(),
                    key,
                    command_id,
                    QUERY_ACTION,
                    QUERY_ACTION,
                    lease,
                    lease_expires_at_ms,
                    now_ms,
                )
                .await?;
            }
            Ok(Some(PreparedSequencerAction {
                lease,
                command_id,
                action,
            }))
        }
        .await;
        settle(session, result).await
    }

    /// Atomically records one remote result and either finalizes or releases a reservation.
    ///
    /// `Unknown` retains `Reconciling` plus a query outbox. A linearizable
    /// `Absent` is the only result that re-arms the same command for submit.
    pub async fn resolve_action(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        lease: SequencerActionLease,
        resolution: SequencerResolution,
        now_ms: i64,
    ) -> Result<MembershipReceipt, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            let outbox = lock_leased_outbox(&mut *session.connection(), tenant_id, lease).await?;
            if outbox.lease_expires_at_ms <= now_ms {
                return Err(GroupPersistenceError::LeaseLost);
            }
            let key = ScopeKey::from_storage(tenant_id, &outbox.scope_kind, &outbox.scope_id)?;
            let mut aggregate = load_aggregate(&mut *session.connection(), key, true)
                .await?
                .ok_or(GroupPersistenceError::CorruptData("outbox group missing"))?;
            let command_id = membership_command_id(outbox.command_id)?;
            if matches!(resolution, SequencerResolution::Absent)
                && outbox.leased_action.as_deref() != Some(QUERY_ACTION)
            {
                return Err(GroupPersistenceError::CorruptData(
                    "Sequencer absence did not come from a query",
                ));
            }
            let receipt = aggregate
                .book
                .observe_sequencer_resolution(command_id, resolution)?;
            match resolution {
                SequencerResolution::Committed(_) => {
                    aggregate.policy.finalize_reserved_join(
                        aggregate.policy.revision(),
                        outbox.request_id,
                        now_ms,
                    )?;
                    persist_policy(
                        &mut *session.connection(),
                        tenant_id,
                        &aggregate.policy,
                        now_ms,
                        false,
                    )
                    .await?;
                    complete_outbox(&mut *session.connection(), key, command_id, lease, now_ms)
                        .await?;
                }
                SequencerResolution::Rejected(_) => {
                    aggregate
                        .policy
                        .release_join_reservation(aggregate.policy.revision(), outbox.request_id)?;
                    persist_policy(
                        &mut *session.connection(),
                        tenant_id,
                        &aggregate.policy,
                        now_ms,
                        false,
                    )
                    .await?;
                    complete_outbox(&mut *session.connection(), key, command_id, lease, now_ms)
                        .await?;
                }
                SequencerResolution::Unknown => {
                    release_outbox_for_recovery(
                        &mut *session.connection(),
                        key,
                        command_id,
                        lease,
                        QUERY_ACTION,
                        now_ms,
                    )
                    .await?;
                }
                SequencerResolution::Absent => {
                    release_outbox_for_recovery(
                        &mut *session.connection(),
                        key,
                        command_id,
                        lease,
                        SUBMIT_ACTION,
                        now_ms,
                    )
                    .await?;
                }
            }
            persist_book(
                &mut *session.connection(),
                &aggregate.book,
                tenant_id,
                key.scope,
                now_ms,
            )
            .await?;
            Ok(receipt)
        }
        .await;
        settle(session, result).await
    }
}

/// Finalizes the exact GM1 approval represented by an accepted MLS commit.
///
/// This is crate-visible only so the MLS sequencer can call it on the same
/// `PostgreSQL` transaction that persists the commit receipt and new group head.
/// It is deliberately not a second public membership fact source.
pub(crate) async fn resolve_mls_commit_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    command_id: MembershipCommandId,
    committed_digest: Sha256Digest,
    now_ms: i64,
) -> Result<MembershipReceipt, GroupPersistenceError> {
    let key = ScopeKey::from_scope(tenant_id, scope);
    let mut aggregate = load_aggregate(connection, key, true)
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound)?;
    if let Ok(receipt) = aggregate.book.receipt(command_id)
        && let MembershipCommandPhase::Committed(admission) = receipt.phase()
    {
        let reference = admission.commit_reference();
        if reference.scope() == scope
            && reference.command_id() == command_id
            && reference.committed_digest() == committed_digest
        {
            return Ok(receipt);
        }
        return Err(GroupPersistenceError::MlsCommitConflict);
    }
    let action = aggregate
        .book
        .next_sequencer_action(command_id)?
        .ok_or(GroupPersistenceError::MlsAuthorizationRejected)?;
    let (action_scope, action_command_id, request_digest, join_request_id) = match action {
        SequencerAction::Submit(submit) => {
            let (action_command_id, request_digest) = submit.idempotency();
            (
                submit.scope(),
                action_command_id,
                request_digest,
                submit.join_request_id(),
            )
        }
        SequencerAction::Query(_) => return Err(GroupPersistenceError::MlsAuthorizationRejected),
    };
    if action_scope != scope || action_command_id != command_id {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    }
    let reference =
        MembershipCommitReference::new(scope, command_id, request_digest, committed_digest);
    let receipt = aggregate
        .book
        .observe_sequencer_resolution(command_id, SequencerResolution::Committed(reference))?;
    aggregate.policy.finalize_reserved_join(
        aggregate.policy.revision(),
        join_request_id,
        now_ms,
    )?;
    persist_policy(connection, tenant_id, &aggregate.policy, now_ms, false).await?;
    persist_book(connection, &aggregate.book, tenant_id, scope, now_ms).await?;
    complete_unleased_outbox(connection, key, command_id, now_ms).await?;
    Ok(receipt)
}

#[allow(clippy::too_many_lines)] // Authorization, projection-head capture, integrity checks, and stable paging intentionally share one transaction boundary.
async fn list_pending_join_requests_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    actor_identity_id: IdentityId,
    scope: GroupScope,
    after: Option<PendingJoinRequestCursor>,
    limit: usize,
) -> Result<PendingJoinRequestPage, GroupPersistenceError> {
    if !(1..=64).contains(&limit) {
        return Err(GroupPersistenceError::CorruptData(
            "membership discovery page limit",
        ));
    }
    let key = ScopeKey::from_scope(tenant_id, scope);
    // Hold the small policy head while reading so membership/MLS mutations
    // cannot interleave a different revision or head with this page. The read
    // model intentionally avoids hydrating every member, invite, and workflow.
    let policy_revision =
        load_membership_discovery_revision(connection, key, actor_identity_id).await?;

    let missing_origin: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
               FROM groups.join_records AS join_record
               JOIN groups.membership_workflows AS workflow
                 ON workflow.tenant_id=join_record.tenant_id
                AND workflow.scope_kind=join_record.scope_kind
                AND workflow.scope_id=join_record.scope_id
                AND workflow.request_id=join_record.request_id
              WHERE join_record.tenant_id=$1
                AND join_record.scope_kind=$2
                AND join_record.scope_id=$3
                AND join_record.state='pending'
                AND workflow.state='pending_approval'
                AND workflow.candidate_identity_origin IS NULL
         )",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .fetch_one(&mut *connection)
    .await?;
    if missing_origin {
        return Err(GroupPersistenceError::CandidateIdentityOriginUnavailable);
    }

    let mls_head_row = sqlx::query(
        "SELECT epoch, head_digest
           FROM groups.mls_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .fetch_optional(&mut *connection)
    .await?;
    let mls_head = mls_head_row
        .map(|row| {
            let epoch = u64::try_from(row.try_get::<i64, _>("epoch")?)
                .map_err(|_| GroupPersistenceError::CorruptData("MLS epoch"))?;
            let head = digest(row.try_get("head_digest")?, "MLS head")?;
            Ok::<(u64, Sha256Digest), GroupPersistenceError>((epoch, head))
        })
        .transpose()?;

    let after_requested_at = after.map(|cursor| cursor.requested_at().get());
    let after_request_id = after.map(|cursor| uuid_from(cursor.join_request_id()));
    let fetch_limit = i64::try_from(limit + 1)
        .map_err(|_| GroupPersistenceError::CorruptData("membership discovery page limit"))?;
    let rows = sqlx::query(
        "SELECT join_record.request_id,
                join_record.candidate_identity_id AS join_candidate_identity_id,
                join_record.invite_id AS join_invite_id,
                join_record.requested_at_ms,
                workflow.candidate_identity_id,
                workflow.candidate_device_id,
                workflow.candidate_identity_origin,
                workflow.invite_id,
                command.command_id AS request_command_id,
                command.request_digest
           FROM groups.join_records AS join_record
           JOIN groups.membership_workflows AS workflow
             ON workflow.tenant_id=join_record.tenant_id
            AND workflow.scope_kind=join_record.scope_kind
            AND workflow.scope_id=join_record.scope_id
            AND workflow.request_id=join_record.request_id
           LEFT JOIN groups.membership_commands AS command
             ON command.tenant_id=workflow.tenant_id
            AND command.scope_kind=workflow.scope_kind
            AND command.scope_id=workflow.scope_id
            AND command.workflow_id=workflow.request_id
            AND command.kind='request_join'
          WHERE join_record.tenant_id=$1
            AND join_record.scope_kind=$2
            AND join_record.scope_id=$3
            AND join_record.state='pending'
            AND workflow.state='pending_approval'
            AND ($4::bigint IS NULL OR
                 (join_record.requested_at_ms, join_record.request_id) > ($4, $5::uuid))
          ORDER BY join_record.requested_at_ms, join_record.request_id
          LIMIT $6",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(after_requested_at)
    .bind(after_request_id)
    .bind(fetch_limit)
    .fetch_all(&mut *connection)
    .await?;

    let mut items = rows
        .iter()
        .map(pending_join_request_from_row)
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;
    let has_more = items.len() > limit;
    if has_more {
        items.pop();
    }
    let next_cursor = has_more.then(|| {
        let last = items
            .last()
            .expect("a positive page limit with an extra row retains one item");
        PendingJoinRequestCursor::new(last.requested_at(), last.join_request_id())
    });
    Ok(PendingJoinRequestPage {
        policy_revision,
        mls_head,
        items,
        next_cursor,
    })
}

async fn load_membership_discovery_revision(
    connection: &mut PgConnection,
    key: ScopeKey,
    actor_identity_id: IdentityId,
) -> Result<Revision, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT policy_head.policy_revision,
                (policy_head.owner_identity_id=$4 OR EXISTS (
                    SELECT 1
                      FROM groups.admin_terms AS administrator
                     WHERE administrator.tenant_id=policy_head.tenant_id
                       AND administrator.scope_kind=policy_head.scope_kind
                       AND administrator.scope_id=policy_head.scope_id
                       AND administrator.identity_id=$4
                       AND administrator.active
                )) AS authorized
           FROM groups.policy_heads AS policy_head
          WHERE policy_head.tenant_id=$1
            AND policy_head.scope_kind=$2
            AND policy_head.scope_id=$3
          FOR SHARE OF policy_head",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(actor_identity_id.to_string())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::GroupNotFound)?;
    if !row.try_get::<bool, _>("authorized")? {
        return Err(GroupPersistenceError::MembershipDiscoveryAccessDenied);
    }
    revision(row.try_get("policy_revision")?)
}

fn pending_join_request_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<PendingJoinRequest, GroupPersistenceError> {
    let join_request_id = join_request_id(row.try_get("request_id")?)?;
    let join_candidate_identity_id = identity_id(row.try_get("join_candidate_identity_id")?)?;
    let candidate_identity_id = identity_id(row.try_get("candidate_identity_id")?)?;
    let join_invite_id = invite_capability_id(row.try_get("join_invite_id")?)?;
    let invite_id = invite_capability_id(row.try_get("invite_id")?)?;
    if join_candidate_identity_id != candidate_identity_id || join_invite_id != invite_id {
        return Err(GroupPersistenceError::CorruptData(
            "pending membership discovery linkage",
        ));
    }
    let candidate_identity_origin = row
        .try_get::<Option<String>, _>("candidate_identity_origin")?
        .ok_or(GroupPersistenceError::CandidateIdentityOriginUnavailable)?;
    ensure_candidate_identity_origin(&candidate_identity_origin)?;
    let request_command_id = row
        .try_get::<Option<Uuid>, _>("request_command_id")?
        .ok_or(GroupPersistenceError::CorruptData(
            "pending request command",
        ))?;
    let request_digest = row
        .try_get::<Option<Vec<u8>>, _>("request_digest")?
        .ok_or(GroupPersistenceError::CorruptData("pending request digest"))?;
    Ok(PendingJoinRequest {
        join_request_id,
        candidate_identity_id,
        candidate_device_id: device_id(row.try_get("candidate_device_id")?)?,
        candidate_identity_origin,
        invite_id,
        requested_at: UtcMillis::new(row.try_get("requested_at_ms")?)
            .map_err(|_| GroupPersistenceError::CorruptData("pending request time"))?,
        request_command_id: membership_command_id(request_command_id)?,
        request_digest: digest(request_digest, "pending request digest")?,
    })
}

async fn load_receipt_for_identity_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    caller_identity_id: IdentityId,
    scope: GroupScope,
    command_id: MembershipCommandId,
) -> Result<MembershipReceipt, GroupPersistenceError> {
    let key = ScopeKey::from_scope(tenant_id, scope);
    let Some(aggregate) = load_aggregate(connection, key, false).await? else {
        return Err(GroupPersistenceError::GroupNotFound);
    };
    let access = sqlx::query(
        "SELECT command.actor_identity_id,
                workflow.candidate_identity_id
           FROM groups.membership_commands AS command
           LEFT JOIN groups.membership_workflows AS workflow
             ON workflow.tenant_id=command.tenant_id
            AND workflow.scope_kind=command.scope_kind
            AND workflow.scope_id=command.scope_id
            AND workflow.request_id=command.workflow_id
          WHERE command.tenant_id=$1 AND command.command_id=$2
            AND command.scope_kind=$3 AND command.scope_id=$4",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command_id.request_id()))
    .bind(key.kind)
    .bind(key.id())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::GroupNotFound)?;
    let caller = caller_identity_id.to_string();
    let is_actor = access.try_get::<String, _>("actor_identity_id")? == caller;
    let is_candidate = access
        .try_get::<Option<String>, _>("candidate_identity_id")?
        .as_deref()
        == Some(caller.as_str());
    if !is_actor && !is_candidate && !aggregate.policy.can_approve_join(caller_identity_id) {
        return Err(GroupPersistenceError::MembershipReceiptAccessDenied);
    }
    aggregate.book.receipt(command_id).map_err(Into::into)
}

/// Begins a tenant-bound group transaction and revalidates a device session on
/// that exact connection. The group runtime receives only the narrow identity
/// reads needed by [`DeviceSessionRepository::authenticate_in_transaction`].
pub(crate) async fn begin_authenticated<'store>(
    store: &'store GroupPgStore,
    tenant_id: TenantId,
    credential: &DeviceSessionCredential,
    now_ms: i64,
) -> Result<(crate::GroupSession<'store>, AuthenticatedDeviceSession), GroupPersistenceError> {
    let (session, authenticated) =
        begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
    Ok((session, authenticated.session()))
}

/// Same as [`begin_authenticated`], but retains the active device public key
/// so the caller can verify a domain-specific action signature before the
/// transaction reads a replay receipt or mutates group state.
pub(crate) async fn begin_authenticated_with_signing_key<'store>(
    store: &'store GroupPgStore,
    tenant_id: TenantId,
    credential: &DeviceSessionCredential,
    now_ms: i64,
) -> Result<
    (
        crate::GroupSession<'store>,
        AuthenticatedDeviceSigningSession,
    ),
    GroupPersistenceError,
> {
    let now = UtcMillis::new(now_ms)
        .map_err(|_| GroupPersistenceError::CorruptData("group authentication time"))?;
    let mut session = store.begin(tenant_id).await?;
    let authenticated = match DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        session.connection(),
        credential,
        now,
    )
    .await
    {
        Ok(authenticated) => authenticated,
        Err(error) => {
            let _ = session.rollback().await;
            return Err(map_identity_authentication_error(error));
        }
    };
    Ok((session, authenticated))
}

fn map_identity_authentication_error(error: IdentityPersistenceError) -> GroupPersistenceError {
    match error {
        IdentityPersistenceError::Database(error) => GroupPersistenceError::Database(error),
        _ => GroupPersistenceError::DeviceAuthenticationRejected,
    }
}

fn ensure_authenticated_actor(
    authenticated: AuthenticatedDeviceSession,
    context: MembershipCommandContext,
) -> Result<(), GroupPersistenceError> {
    if authenticated.identity_id() == context.actor_identity_id()
        && authenticated.device_id() == context.actor_device_id()
    {
        Ok(())
    } else {
        Err(GroupPersistenceError::DeviceAuthenticationRejected)
    }
}

fn ensure_verified_actor(
    actor: VerifiedDeviceActor,
    context: MembershipCommandContext,
) -> Result<(), GroupPersistenceError> {
    if actor.identity_id() == context.actor_identity_id()
        && actor.device_id() == context.actor_device_id()
    {
        Ok(())
    } else {
        Err(GroupPersistenceError::DeviceAuthenticationRejected)
    }
}

fn ensure_candidate_identity_origin(origin: &str) -> Result<(), GroupPersistenceError> {
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or(GroupPersistenceError::CorruptData(
            "candidate identity origin",
        ))?;
    if !(10..=512).contains(&origin.len())
        || authority.is_empty()
        || !origin.is_ascii()
        || !origin.bytes().all(|byte| byte.is_ascii_graphic())
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(GroupPersistenceError::CorruptData(
            "candidate identity origin",
        ));
    }
    Ok(())
}

async fn persist_new_candidate_identity_origin(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    context: MembershipCommandContext,
    execution: MembershipCommandExecution,
    candidate_identity_origin: &str,
) -> Result<(), GroupPersistenceError> {
    if execution.replayed()
        || !matches!(
            execution.receipt().phase(),
            MembershipCommandPhase::PendingApproval
        )
    {
        return Ok(());
    }
    let key = ScopeKey::from_scope(tenant_id, context.scope());
    let updated = sqlx::query(
        "UPDATE groups.membership_workflows
            SET candidate_identity_origin=$5
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND request_id=$4
            AND candidate_identity_origin IS NULL",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(context.join_request_id()))
    .bind(candidate_identity_origin)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(GroupPersistenceError::CorruptData(
            "candidate identity origin persistence",
        ));
    }
    Ok(())
}

#[allow(clippy::large_types_passed_by_value)] // The command is consumed by the reducer; a database round trip dominates this small typed copy.
async fn request_join_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: JoinRequestCommand,
    candidate_membership: CandidateMembership,
    candidate_identity_origin: &str,
    now_ms: i64,
) -> Result<MembershipCommandExecution, GroupPersistenceError> {
    ensure_candidate_identity_origin(candidate_identity_origin)?;
    let context = command.context();
    let key = ScopeKey::from_scope(tenant_id, context.scope());
    let mut aggregate = load_aggregate(connection, key, true)
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound)?;
    let had_exact_command = aggregate.book.receipt(context.command_id()).is_ok();
    let receipt = aggregate
        .book
        .record_join_request(command, candidate_membership)?;
    if had_exact_command || receipt.command_id() != context.command_id() {
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: true,
        });
    }
    if matches!(receipt.phase(), MembershipCommandPhase::Committed(_)) {
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    if let Err(policy_error) = aggregate.policy.request_join(
        context.fence().policy_revision(),
        context.actor_identity_id(),
        context.candidate_identity_id(),
        context.join_request_id(),
        context.invite_id(),
        now_ms,
    ) {
        let rejection = local_policy_rejection(policy_error)
            .ok_or(GroupPersistenceError::GroupPolicy(policy_error))?;
        let receipt = aggregate
            .book
            .reject_locally(context.command_id(), rejection)?;
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    persist_policy(connection, tenant_id, &aggregate.policy, now_ms, false).await?;
    persist_book(
        connection,
        &aggregate.book,
        tenant_id,
        context.scope(),
        now_ms,
    )
    .await?;
    let execution = MembershipCommandExecution {
        receipt,
        replayed: false,
    };
    persist_new_candidate_identity_origin(
        connection,
        tenant_id,
        context,
        execution,
        candidate_identity_origin,
    )
    .await?;
    Ok(execution)
}

#[allow(clippy::large_types_passed_by_value)] // The command is consumed by the reducer; a database round trip dominates this small typed copy.
async fn approve_join_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: ApproveJoinCommand,
    candidate_membership: CandidateMembership,
    now_ms: i64,
) -> Result<MembershipCommandExecution, GroupPersistenceError> {
    let context = command.context();
    let key = ScopeKey::from_scope(tenant_id, context.scope());
    let mut aggregate = load_aggregate(connection, key, true)
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound)?;
    let had_exact_command = aggregate.book.receipt(context.command_id()).is_ok();
    let receipt = aggregate.book.approve_join(command, candidate_membership)?;
    if had_exact_command || receipt.command_id() != context.command_id() {
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: true,
        });
    }
    if matches!(receipt.phase(), MembershipCommandPhase::Committed(_)) {
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    if let Err(policy_error) = aggregate.policy.reserve_join(
        context.fence().policy_revision(),
        context.actor_identity_id(),
        context.join_request_id(),
        now_ms,
    ) {
        let rejection = local_policy_rejection(policy_error)
            .ok_or(GroupPersistenceError::GroupPolicy(policy_error))?;
        let receipt = aggregate
            .book
            .reject_locally(context.command_id(), rejection)?;
        persist_book(
            connection,
            &aggregate.book,
            tenant_id,
            context.scope(),
            now_ms,
        )
        .await?;
        return Ok(MembershipCommandExecution {
            receipt,
            replayed: false,
        });
    }
    let action = aggregate
        .book
        .next_sequencer_action(context.command_id())?
        .ok_or(GroupPersistenceError::CorruptData(
            "approval missing submit action",
        ))?;
    if !matches!(action, SequencerAction::Submit(_)) {
        return Err(GroupPersistenceError::CorruptData(
            "approval action is not submit",
        ));
    }
    persist_policy(connection, tenant_id, &aggregate.policy, now_ms, false).await?;
    persist_book(
        connection,
        &aggregate.book,
        tenant_id,
        context.scope(),
        now_ms,
    )
    .await?;
    insert_outbox(
        connection,
        tenant_id,
        context.scope(),
        context.command_id(),
        context.join_request_id(),
        SUBMIT_ACTION,
        now_ms,
    )
    .await?;
    Ok(MembershipCommandExecution {
        receipt,
        replayed: false,
    })
}

struct LoadedAggregate {
    policy: GroupPolicy,
    book: MembershipCommandBook,
}

#[derive(Clone, Copy)]
pub(crate) struct ScopeKey {
    tenant_id: TenantId,
    scope: GroupScope,
    kind: &'static str,
}

impl ScopeKey {
    pub(crate) fn from_scope(tenant_id: TenantId, scope: GroupScope) -> Self {
        let (kind, _) = scope_columns(scope);
        Self {
            tenant_id,
            scope,
            kind,
        }
    }

    pub(crate) fn from_storage(
        tenant_id: TenantId,
        kind: &str,
        scope_id: &str,
    ) -> Result<Self, GroupPersistenceError> {
        let scope = scope_from_storage(kind, scope_id)?;
        Ok(Self::from_scope(tenant_id, scope))
    }

    pub(crate) fn tenant_id(self) -> Uuid {
        Uuid::from(self.tenant_id)
    }

    pub(crate) fn id(self) -> String {
        scope_columns(self.scope).1
    }
}

fn scope_columns(scope: GroupScope) -> (&'static str, String) {
    match scope {
        GroupScope::PrivateConversation(id) => (PRIVATE_CONVERSATION_SCOPE, id.to_string()),
        GroupScope::ControlledPublicChannel(id) => {
            (CONTROLLED_PUBLIC_CHANNEL_SCOPE, id.to_string())
        }
    }
}

struct OutboxRow {
    scope_kind: String,
    scope_id: String,
    command_id: Uuid,
    request_id: JoinRequestId,
    action: String,
    leased_action: Option<String>,
    lease_expires_at_ms: i64,
}

pub(crate) async fn settle<T>(
    session: crate::GroupSession<'_>,
    result: Result<T, GroupPersistenceError>,
) -> Result<T, GroupPersistenceError> {
    match result {
        Ok(value) => {
            session.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

async fn load_aggregate(
    connection: &mut PgConnection,
    key: ScopeKey,
    lock: bool,
) -> Result<Option<LoadedAggregate>, GroupPersistenceError> {
    let Some(policy) = load_policy(connection, key, lock).await? else {
        return Ok(None);
    };
    let book = load_book(connection, key).await?;
    Ok(Some(LoadedAggregate { policy, book }))
}

#[allow(clippy::too_many_lines)] // One projection validates every normalized policy row together.
pub(crate) async fn load_policy(
    connection: &mut PgConnection,
    key: ScopeKey,
    lock: bool,
) -> Result<Option<GroupPolicy>, GroupPersistenceError> {
    let scope_id = key.id();
    let statement = if lock {
        "SELECT owner_identity_id, policy_revision
           FROM groups.policy_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          FOR UPDATE"
    } else {
        "SELECT owner_identity_id, policy_revision
           FROM groups.policy_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3"
    };
    let Some(head) = sqlx::query(statement)
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(None);
    };
    let owner_id = identity_id(head.try_get("owner_identity_id")?)?;
    let policy_revision = revision(head.try_get("policy_revision")?)?;

    let admin_rows = sqlx::query(
        "SELECT identity_id, authorization_generation, active
           FROM groups.admin_terms
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY identity_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let mut administrators = Vec::new();
    let mut administrator_authorization_generations = Vec::with_capacity(admin_rows.len());
    for row in admin_rows {
        let identity = identity_id(row.try_get("identity_id")?)?;
        if row.try_get::<bool, _>("active")? {
            administrators.push(identity);
        }
        administrator_authorization_generations.push((
            identity,
            revision(row.try_get("authorization_generation")?)?,
        ));
    }

    let member_rows = sqlx::query(
        "SELECT identity_id
           FROM groups.members
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY identity_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let members = member_rows
        .into_iter()
        .map(|row| identity_id(row.try_get("identity_id")?))
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    let invite_rows = sqlx::query(
        "SELECT invite_id, issuer_identity_id, target_identity_id, max_uses,
                use_count, reserved_use_count, expires_at_ms, revoked,
                policy_revision, issuer_authority, issuer_authorization_generation
           FROM groups.invites
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY invite_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let invitations = invite_rows
        .into_iter()
        .map(|row| {
            Ok(GroupInvitePersistence {
                invite_id: invite_capability_id(row.try_get("invite_id")?)?,
                issuer_id: identity_id(row.try_get("issuer_identity_id")?)?,
                target_id: row
                    .try_get::<Option<String>, _>("target_identity_id")?
                    .map(identity_id)
                    .transpose()?,
                max_uses: u32::try_from(row.try_get::<i32, _>("max_uses")?)
                    .map_err(|_| GroupPersistenceError::CorruptData("invite max uses"))?,
                use_count: u32::try_from(row.try_get::<i32, _>("use_count")?)
                    .map_err(|_| GroupPersistenceError::CorruptData("invite use count"))?,
                reserved_use_count: u32::try_from(row.try_get::<i32, _>("reserved_use_count")?)
                    .map_err(|_| GroupPersistenceError::CorruptData("invite reserved count"))?,
                expires_at_ms: row.try_get("expires_at_ms")?,
                revoked: row.try_get("revoked")?,
                policy_revision: revision(row.try_get("policy_revision")?)?,
                issuer_authority: authority(
                    row.try_get("issuer_authority")?,
                    row.try_get("issuer_authorization_generation")?,
                )?,
            })
        })
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    let join_rows = sqlx::query(
        "SELECT request_id, candidate_identity_id, invite_id, state, requested_at_ms,
                reserved_by_identity_id, reserved_authority,
                reserved_authorization_generation, reserved_at_ms,
                reservation_policy_revision, approved_by_identity_id,
                approved_at_ms, approval_policy_revision
           FROM groups.join_records
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY request_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let mut pending_joins = Vec::new();
    let mut reserved_joins = Vec::new();
    let mut approved_joins = Vec::new();
    for row in join_rows {
        let request_id = join_request_id(row.try_get("request_id")?)?;
        let candidate_id = identity_id(row.try_get("candidate_identity_id")?)?;
        let invite_id = invite_capability_id(row.try_get("invite_id")?)?;
        match row.try_get::<String, _>("state")?.as_str() {
            PENDING_JOIN_STATE => pending_joins.push(GroupPendingJoinPersistence {
                request_id,
                candidate_id,
                invite_id,
                requested_at_ms: row.try_get("requested_at_ms")?,
            }),
            RESERVED_JOIN_STATE => reserved_joins.push(GroupReservedJoinPersistence {
                request_id,
                candidate_id,
                invite_id,
                reserved_by: identity_id(required_string(
                    row.try_get("reserved_by_identity_id")?,
                    "reserved join actor",
                )?)?,
                reserved_authority: authority(
                    required_string(row.try_get("reserved_authority")?, "reserved authority")?,
                    row.try_get("reserved_authorization_generation")?,
                )?,
                reserved_at_ms: required_i64(row.try_get("reserved_at_ms")?, "reserved time")?,
                policy_revision: revision(required_i64(
                    row.try_get("reservation_policy_revision")?,
                    "reservation policy revision",
                )?)?,
            }),
            APPROVED_JOIN_STATE => approved_joins.push(GroupApprovedJoinPersistence {
                request_id,
                candidate_id,
                invite_id,
                approved_by: identity_id(required_string(
                    row.try_get("approved_by_identity_id")?,
                    "approved join actor",
                )?)?,
                approved_at_ms: required_i64(row.try_get("approved_at_ms")?, "approved time")?,
                policy_revision: revision(required_i64(
                    row.try_get("approval_policy_revision")?,
                    "approval policy revision",
                )?)?,
            }),
            _ => return Err(GroupPersistenceError::CorruptData("join record state")),
        }
    }

    let image = GroupPolicyPersistenceImage {
        scope: key.scope,
        owner_id,
        administrators,
        administrator_authorization_generations,
        members,
        invitations,
        pending_joins,
        reserved_joins,
        approved_joins,
        revision: policy_revision,
    };
    let snapshot = GroupPolicySnapshot::try_from_persistence_image(image)?;
    GroupPolicy::try_from_snapshot(&snapshot)
        .map(Some)
        .map_err(Into::into)
}

async fn load_book(
    connection: &mut PgConnection,
    key: ScopeKey,
) -> Result<MembershipCommandBook, GroupPersistenceError> {
    let scope_id = key.id();
    let command_rows = sqlx::query(
        "SELECT command_id, actor_identity_id, idempotency_key_hash, kind,
                request_digest, workflow_id, terminal_phase, terminal_admission,
                terminal_commit_scope_kind, terminal_commit_scope_id,
                terminal_commit_command_id, terminal_commit_request_digest,
                terminal_committed_digest, terminal_rejection
           FROM groups.membership_commands
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY command_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let commands = command_rows
        .into_iter()
        .map(|row| command_from_row(row, key.scope))
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    let request_commands = commands
        .iter()
        .filter_map(|command| {
            (command.kind == MembershipCommandKind::RequestJoin)
                .then_some((command.workflow_id?, *command))
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let workflow_rows = sqlx::query(
        "SELECT request_id, request_actor_identity_id, request_actor_device_id,
                request_idempotency_key_hash, request_policy_revision,
                request_sequencer_head, candidate_identity_id, candidate_device_id,
                invite_id, state, approval_command_id, approval_actor_identity_id,
                approval_actor_device_id, approval_idempotency_key_hash,
                approval_policy_revision, approval_sequencer_head, authorization_digest,
                admission, commit_scope_kind, commit_scope_id, commit_command_id,
                commit_request_digest, committed_digest, rejection
           FROM groups.membership_workflows
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
          ORDER BY request_id",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(&scope_id)
    .fetch_all(&mut *connection)
    .await?;
    let workflows = workflow_rows
        .into_iter()
        .map(|row| workflow_from_row(row, key.scope, &request_commands))
        .collect::<Result<Vec<_>, GroupPersistenceError>>()?;

    MembershipCommandBook::try_from_snapshot(MembershipCommandBookSnapshot {
        commands,
        workflows,
    })
    .map_err(Into::into)
}

#[allow(clippy::needless_pass_by_value)] // SQLx yields each row by value from the result iterator.
fn command_from_row(
    row: sqlx::postgres::PgRow,
    scope: GroupScope,
) -> Result<MembershipCommandPersistence, GroupPersistenceError> {
    let command_id = membership_command_id(row.try_get("command_id")?)?;
    let terminal_phase = terminal_phase_from_fields(
        row.try_get("terminal_phase")?,
        row.try_get("terminal_admission")?,
        row.try_get("terminal_commit_scope_kind")?,
        row.try_get("terminal_commit_scope_id")?,
        row.try_get("terminal_commit_command_id")?,
        row.try_get("terminal_commit_request_digest")?,
        row.try_get("terminal_committed_digest")?,
        row.try_get("terminal_rejection")?,
    )?;
    Ok(MembershipCommandPersistence {
        command_id,
        kind: command_kind(row.try_get::<String, _>("kind")?.as_str())?,
        request_digest: digest(row.try_get("request_digest")?, "membership command digest")?,
        workflow_id: row
            .try_get::<Option<Uuid>, _>("workflow_id")?
            .map(join_request_id)
            .transpose()?,
        terminal_phase,
        idempotency: MembershipIdempotencyPersistence {
            scope,
            actor_identity_id: identity_id(row.try_get("actor_identity_id")?)?,
            idempotency_key_hash: digest(
                row.try_get("idempotency_key_hash")?,
                "membership idempotency key",
            )?,
        },
    })
}

#[allow(clippy::needless_pass_by_value)] // SQLx yields each row by value from the result iterator.
fn workflow_from_row(
    row: sqlx::postgres::PgRow,
    scope: GroupScope,
    request_commands: &std::collections::BTreeMap<JoinRequestId, MembershipCommandPersistence>,
) -> Result<MembershipWorkflowPersistence, GroupPersistenceError> {
    let join_request_id = join_request_id(row.try_get("request_id")?)?;
    let request_command = request_commands.get(&join_request_id).copied().ok_or(
        GroupPersistenceError::CorruptData("workflow request command missing"),
    )?;
    let request_actor_identity_id = identity_id(row.try_get("request_actor_identity_id")?)?;
    let request_context = MembershipCommandContext::new(
        request_command.command_id,
        digest(
            row.try_get("request_idempotency_key_hash")?,
            "workflow request idempotency key",
        )?,
        scope,
        request_actor_identity_id,
        device_id(row.try_get("request_actor_device_id")?)?,
        join_request_id,
        identity_id(row.try_get("candidate_identity_id")?)?,
        device_id(row.try_get("candidate_device_id")?)?,
        invite_capability_id(row.try_get("invite_id")?)?,
        MembershipFence::new(
            revision(row.try_get("request_policy_revision")?)?,
            digest(
                row.try_get("request_sequencer_head")?,
                "workflow request Sequencer head",
            )?,
        ),
    );
    if request_command.idempotency.actor_identity_id != request_actor_identity_id
        || request_command.idempotency.idempotency_key_hash
            != request_context.idempotency_key_hash()
    {
        return Err(GroupPersistenceError::CorruptData(
            "workflow request idempotency drift",
        ));
    }

    let phase = workflow_phase_from_row(&row, scope, request_context)?;
    Ok(MembershipWorkflowPersistence {
        join_request_id,
        context: request_context,
        phase,
    })
}

fn workflow_phase_from_row(
    row: &sqlx::postgres::PgRow,
    scope: GroupScope,
    request_context: MembershipCommandContext,
) -> Result<MembershipWorkflowPersistencePhase, GroupPersistenceError> {
    match row.try_get::<String, _>("state")?.as_str() {
        PENDING_APPROVAL_STATE => Ok(MembershipWorkflowPersistencePhase::PendingApproval),
        PENDING_COMMIT_STATE | RECONCILING_STATE => {
            let approval_context = approval_context_from_row(row, scope, request_context)?;
            let approval_command_id = membership_command_id(required_uuid(
                row.try_get("approval_command_id")?,
                "workflow approval command",
            )?)?;
            let authorization_digest = digest(
                required_bytes(
                    row.try_get("authorization_digest")?,
                    "workflow authorization",
                )?,
                "workflow authorization",
            )?;
            if row.try_get::<String, _>("state")? == PENDING_COMMIT_STATE {
                Ok(MembershipWorkflowPersistencePhase::PendingCommit {
                    approval_command_id,
                    approval_context,
                    authorization_digest,
                })
            } else {
                Ok(MembershipWorkflowPersistencePhase::Reconciling {
                    approval_command_id,
                    approval_context,
                    authorization_digest,
                })
            }
        }
        COMMITTED_STATE => Ok(MembershipWorkflowPersistencePhase::Committed(
            admission_from_fields(
                required_string(row.try_get("admission")?, "workflow admission")?,
                required_string(
                    row.try_get("commit_scope_kind")?,
                    "workflow commit scope kind",
                )?,
                required_string(row.try_get("commit_scope_id")?, "workflow commit scope id")?,
                required_uuid(row.try_get("commit_command_id")?, "workflow commit command")?,
                required_bytes(
                    row.try_get("commit_request_digest")?,
                    "workflow commit request digest",
                )?,
                required_bytes(
                    row.try_get("committed_digest")?,
                    "workflow committed digest",
                )?,
            )?,
        )),
        REJECTED_STATE => {
            let rejection_value = required_string(row.try_get("rejection")?, "workflow rejection")?;
            Ok(MembershipWorkflowPersistencePhase::Rejected(rejection(
                &rejection_value,
            )?))
        }
        _ => Err(GroupPersistenceError::CorruptData("workflow state")),
    }
}

fn approval_context_from_row(
    row: &sqlx::postgres::PgRow,
    scope: GroupScope,
    request_context: MembershipCommandContext,
) -> Result<MembershipCommandContext, GroupPersistenceError> {
    Ok(MembershipCommandContext::new(
        membership_command_id(required_uuid(
            row.try_get("approval_command_id")?,
            "workflow approval command",
        )?)?,
        digest(
            required_bytes(
                row.try_get("approval_idempotency_key_hash")?,
                "workflow approval idempotency key",
            )?,
            "workflow approval idempotency key",
        )?,
        scope,
        identity_id(required_string(
            row.try_get("approval_actor_identity_id")?,
            "workflow approval actor",
        )?)?,
        device_id(required_uuid(
            row.try_get("approval_actor_device_id")?,
            "workflow approval device",
        )?)?,
        request_context.join_request_id(),
        request_context.candidate_identity_id(),
        request_context.candidate_device_id(),
        request_context.invite_id(),
        MembershipFence::new(
            revision(required_i64(
                row.try_get("approval_policy_revision")?,
                "workflow approval policy revision",
            )?)?,
            digest(
                required_bytes(
                    row.try_get("approval_sequencer_head")?,
                    "workflow approval Sequencer head",
                )?,
                "workflow approval Sequencer head",
            )?,
        ),
    ))
}

#[allow(clippy::too_many_lines)] // Policy state writes share one transaction and one normalized image.
pub(crate) async fn persist_policy(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    policy: &GroupPolicy,
    now_ms: i64,
    creating: bool,
) -> Result<(), GroupPersistenceError> {
    let image = policy.snapshot().persistence_image();
    let key = ScopeKey::from_scope(tenant_id, image.scope);
    let scope_id = key.id();
    if creating {
        let inserted = sqlx::query(
            "INSERT INTO groups.policy_heads
                 (tenant_id, scope_kind, scope_id, owner_identity_id, policy_revision,
                  created_at_ms, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $6)
             ON CONFLICT (tenant_id, scope_kind, scope_id) DO NOTHING",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(image.owner_id.to_string())
        .bind(revision_i64(image.revision)?)
        .bind(now_ms)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if inserted != 1 {
            return Err(GroupPersistenceError::GroupBootstrapConflict);
        }
    } else {
        let updated = sqlx::query(
            "UPDATE groups.policy_heads
                SET policy_revision=$5, updated_at_ms=$6
              WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND owner_identity_id=$4",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(image.owner_id.to_string())
        .bind(revision_i64(image.revision)?)
        .bind(now_ms)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(GroupPersistenceError::CorruptData(
                "group policy head drift",
            ));
        }
    }

    for (identity_id, generation) in &image.administrator_authorization_generations {
        let active = image.administrators.contains(identity_id);
        sqlx::query(
            "INSERT INTO groups.admin_terms
                 (tenant_id, scope_kind, scope_id, identity_id, authorization_generation, active)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, scope_kind, scope_id, identity_id) DO UPDATE
                 SET authorization_generation=EXCLUDED.authorization_generation,
                     active=EXCLUDED.active",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(identity_id.to_string())
        .bind(revision_i64(*generation)?)
        .bind(active)
        .execute(&mut *connection)
        .await?;
    }

    for member in &image.members {
        sqlx::query(
            "INSERT INTO groups.members
                 (tenant_id, scope_kind, scope_id, identity_id, admitted_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, scope_kind, scope_id, identity_id) DO NOTHING",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(member.to_string())
        .bind(now_ms)
        .execute(&mut *connection)
        .await?;
    }

    for invite in &image.invitations {
        let (authority, generation) = authority_to_columns(invite.issuer_authority)?;
        sqlx::query(
            "INSERT INTO groups.invites
                 (tenant_id, scope_kind, scope_id, invite_id, issuer_identity_id, target_identity_id,
                  max_uses, use_count, reserved_use_count, expires_at_ms, revoked,
                  policy_revision, issuer_authority, issuer_authorization_generation)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (tenant_id, scope_kind, scope_id, invite_id) DO UPDATE
                 SET issuer_identity_id=EXCLUDED.issuer_identity_id,
                     target_identity_id=EXCLUDED.target_identity_id,
                     max_uses=EXCLUDED.max_uses,
                     use_count=EXCLUDED.use_count,
                     reserved_use_count=EXCLUDED.reserved_use_count,
                     expires_at_ms=EXCLUDED.expires_at_ms,
                     revoked=EXCLUDED.revoked,
                     policy_revision=EXCLUDED.policy_revision,
                     issuer_authority=EXCLUDED.issuer_authority,
                     issuer_authorization_generation=EXCLUDED.issuer_authorization_generation",
        )
        .bind(key.tenant_id())
        .bind(key.kind)
        .bind(&scope_id)
        .bind(uuid_from(invite.invite_id))
        .bind(invite.issuer_id.to_string())
        .bind(invite.target_id.map(|target| target.to_string()))
        .bind(
            i32::try_from(invite.max_uses)
                .map_err(|_| GroupPersistenceError::CorruptData("invite maximum use count"))?,
        )
        .bind(
            i32::try_from(invite.use_count)
                .map_err(|_| GroupPersistenceError::CorruptData("invite use count"))?,
        )
        .bind(
            i32::try_from(invite.reserved_use_count)
                .map_err(|_| GroupPersistenceError::CorruptData("invite reserved use count"))?,
        )
        .bind(invite.expires_at_ms)
        .bind(invite.revoked)
        .bind(revision_i64(invite.policy_revision)?)
        .bind(authority)
        .bind(generation)
        .execute(&mut *connection)
        .await?;
    }

    for pending in &image.pending_joins {
        persist_pending_join(connection, key, pending).await?;
    }
    for reserved in &image.reserved_joins {
        persist_reserved_join(connection, key, reserved).await?;
    }
    for approved in &image.approved_joins {
        persist_approved_join(connection, key, approved).await?;
    }
    Ok(())
}

async fn persist_pending_join(
    connection: &mut PgConnection,
    key: ScopeKey,
    pending: &GroupPendingJoinPersistence,
) -> Result<(), GroupPersistenceError> {
    sqlx::query(
        "INSERT INTO groups.join_records
             (tenant_id, scope_kind, scope_id, request_id, candidate_identity_id, invite_id, state,
              requested_at_ms, reserved_by_identity_id, reserved_authority,
              reserved_authorization_generation, reserved_at_ms, reservation_policy_revision,
              approved_by_identity_id, approved_at_ms, approval_policy_revision)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7,
                 NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET state='pending', candidate_identity_id=EXCLUDED.candidate_identity_id,
                 invite_id=EXCLUDED.invite_id, requested_at_ms=EXCLUDED.requested_at_ms,
                 reserved_by_identity_id=NULL, reserved_authority=NULL,
                 reserved_authorization_generation=NULL, reserved_at_ms=NULL,
                 reservation_policy_revision=NULL, approved_by_identity_id=NULL,
                 approved_at_ms=NULL, approval_policy_revision=NULL",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(pending.request_id))
    .bind(pending.candidate_id.to_string())
    .bind(uuid_from(pending.invite_id))
    .bind(pending.requested_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn persist_reserved_join(
    connection: &mut PgConnection,
    key: ScopeKey,
    reserved: &GroupReservedJoinPersistence,
) -> Result<(), GroupPersistenceError> {
    let (authority, generation) = authority_to_columns(reserved.reserved_authority)?;
    sqlx::query(
        "INSERT INTO groups.join_records
             (tenant_id, scope_kind, scope_id, request_id, candidate_identity_id, invite_id, state,
              requested_at_ms, reserved_by_identity_id, reserved_authority,
              reserved_authorization_generation, reserved_at_ms, reservation_policy_revision,
              approved_by_identity_id, approved_at_ms, approval_policy_revision)
         VALUES ($1, $2, $3, $4, $5, $6, 'reserved', $7, $8, $9, $10, $7, $11,
                 NULL, NULL, NULL)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET state='reserved', candidate_identity_id=EXCLUDED.candidate_identity_id,
                 invite_id=EXCLUDED.invite_id, reserved_by_identity_id=EXCLUDED.reserved_by_identity_id,
                 reserved_authority=EXCLUDED.reserved_authority,
                 reserved_authorization_generation=EXCLUDED.reserved_authorization_generation,
                 reserved_at_ms=EXCLUDED.reserved_at_ms,
                 reservation_policy_revision=EXCLUDED.reservation_policy_revision,
                 approved_by_identity_id=NULL, approved_at_ms=NULL,
                 approval_policy_revision=NULL",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(reserved.request_id))
    .bind(reserved.candidate_id.to_string())
    .bind(uuid_from(reserved.invite_id))
    .bind(reserved.reserved_at_ms)
    .bind(reserved.reserved_by.to_string())
    .bind(authority)
    .bind(generation)
    .bind(revision_i64(reserved.policy_revision)?)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn persist_approved_join(
    connection: &mut PgConnection,
    key: ScopeKey,
    approved: &GroupApprovedJoinPersistence,
) -> Result<(), GroupPersistenceError> {
    sqlx::query(
        "INSERT INTO groups.join_records
             (tenant_id, scope_kind, scope_id, request_id, candidate_identity_id, invite_id, state,
              requested_at_ms, reserved_by_identity_id, reserved_authority,
              reserved_authorization_generation, reserved_at_ms, reservation_policy_revision,
              approved_by_identity_id, approved_at_ms, approval_policy_revision)
         VALUES ($1, $2, $3, $4, $5, $6, 'approved', $7,
                 NULL, NULL, NULL, NULL, NULL, $8, $7, $9)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET state='approved', candidate_identity_id=EXCLUDED.candidate_identity_id,
                 invite_id=EXCLUDED.invite_id, reserved_by_identity_id=NULL,
                 reserved_authority=NULL, reserved_authorization_generation=NULL,
                 reserved_at_ms=NULL, reservation_policy_revision=NULL,
                 approved_by_identity_id=EXCLUDED.approved_by_identity_id,
                 approved_at_ms=EXCLUDED.approved_at_ms,
                 approval_policy_revision=EXCLUDED.approval_policy_revision",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(approved.request_id))
    .bind(approved.candidate_id.to_string())
    .bind(uuid_from(approved.invite_id))
    .bind(approved.approved_at_ms)
    .bind(approved.approved_by.to_string())
    .bind(revision_i64(approved.policy_revision)?)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn persist_book(
    connection: &mut PgConnection,
    book: &MembershipCommandBook,
    tenant_id: TenantId,
    scope: GroupScope,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let snapshot = book.snapshot()?;
    let key = ScopeKey::from_scope(tenant_id, scope);
    for command in &snapshot.commands {
        if command.idempotency.scope != scope {
            return Err(GroupPersistenceError::ScopeMismatch);
        }
        let terminal = terminal_columns(command.terminal_phase)?;
        sqlx::query(
            "INSERT INTO groups.membership_commands
                 (tenant_id, command_id, scope_kind, scope_id, actor_identity_id, idempotency_key_hash,
                  kind, request_digest, workflow_id, terminal_phase, terminal_admission,
                  terminal_commit_scope_kind, terminal_commit_scope_id,
                  terminal_commit_command_id, terminal_commit_request_digest,
                  terminal_committed_digest, terminal_rejection, created_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                     $16, $17, $18)
             ON CONFLICT (tenant_id, command_id) DO NOTHING",
        )
        .bind(key.tenant_id())
        .bind(uuid_from(command.command_id.request_id()))
        .bind(key.kind)
        .bind(key.id())
        .bind(command.idempotency.actor_identity_id.to_string())
        .bind(
            command
                .idempotency
                .idempotency_key_hash
                .as_bytes()
                .as_slice(),
        )
        .bind(command_kind_code(command.kind))
        .bind(command.request_digest.as_bytes().as_slice())
        .bind(command.workflow_id.map(uuid_from))
        .bind(terminal.phase)
        .bind(terminal.admission)
        .bind(terminal.commit_scope_kind)
        .bind(terminal.commit_scope_id)
        .bind(terminal.commit_command_id)
        .bind(terminal.commit_request_digest)
        .bind(terminal.committed_digest)
        .bind(terminal.rejection)
        .bind(now_ms)
        .execute(&mut *connection)
        .await?;
    }
    for workflow in &snapshot.workflows {
        if workflow.context.scope() != scope {
            return Err(GroupPersistenceError::ScopeMismatch);
        }
        persist_workflow(connection, key, workflow).await?;
    }
    Ok(())
}

async fn persist_workflow(
    connection: &mut PgConnection,
    key: ScopeKey,
    workflow: &MembershipWorkflowPersistence,
) -> Result<(), GroupPersistenceError> {
    let context = workflow.context;
    let columns = workflow_columns(&workflow.phase)?;
    sqlx::query(
        "INSERT INTO groups.membership_workflows
             (tenant_id, scope_kind, scope_id, request_id, request_actor_identity_id,
              request_actor_device_id, request_idempotency_key_hash,
              request_policy_revision, request_sequencer_head,
              candidate_identity_id, candidate_device_id, invite_id, state,
              approval_command_id, approval_actor_identity_id, approval_actor_device_id,
              approval_idempotency_key_hash, approval_policy_revision,
              approval_sequencer_head, authorization_digest, admission,
              commit_scope_kind, commit_scope_id, commit_command_id,
              commit_request_digest, committed_digest, rejection)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                 $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
                 $25, $26, $27)
         ON CONFLICT (tenant_id, scope_kind, scope_id, request_id) DO UPDATE
             SET request_actor_identity_id=EXCLUDED.request_actor_identity_id,
                 request_actor_device_id=EXCLUDED.request_actor_device_id,
                 request_idempotency_key_hash=EXCLUDED.request_idempotency_key_hash,
                 request_policy_revision=EXCLUDED.request_policy_revision,
                 request_sequencer_head=EXCLUDED.request_sequencer_head,
                 candidate_identity_id=EXCLUDED.candidate_identity_id,
                 candidate_device_id=EXCLUDED.candidate_device_id,
                 invite_id=EXCLUDED.invite_id,
                 state=EXCLUDED.state,
                 approval_command_id=EXCLUDED.approval_command_id,
                 approval_actor_identity_id=EXCLUDED.approval_actor_identity_id,
                 approval_actor_device_id=EXCLUDED.approval_actor_device_id,
                 approval_idempotency_key_hash=EXCLUDED.approval_idempotency_key_hash,
                 approval_policy_revision=EXCLUDED.approval_policy_revision,
                 approval_sequencer_head=EXCLUDED.approval_sequencer_head,
                 authorization_digest=EXCLUDED.authorization_digest,
                 admission=EXCLUDED.admission,
                 commit_scope_kind=EXCLUDED.commit_scope_kind,
                 commit_scope_id=EXCLUDED.commit_scope_id,
                 commit_command_id=EXCLUDED.commit_command_id,
                 commit_request_digest=EXCLUDED.commit_request_digest,
                 committed_digest=EXCLUDED.committed_digest,
                 rejection=EXCLUDED.rejection",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(workflow.join_request_id))
    .bind(context.actor_identity_id().to_string())
    .bind(uuid_from(context.actor_device_id()))
    .bind(context.idempotency_key_hash().as_bytes().as_slice())
    .bind(revision_i64(context.fence().policy_revision())?)
    .bind(context.fence().sequencer_head().as_bytes().as_slice())
    .bind(context.candidate_identity_id().to_string())
    .bind(uuid_from(context.candidate_device_id()))
    .bind(uuid_from(context.invite_id()))
    .bind(columns.state)
    .bind(columns.approval_command_id)
    .bind(columns.approval_actor_identity_id)
    .bind(columns.approval_actor_device_id)
    .bind(columns.approval_idempotency_key_hash)
    .bind(columns.approval_policy_revision)
    .bind(columns.approval_sequencer_head)
    .bind(columns.authorization_digest)
    .bind(columns.admission)
    .bind(columns.commit_scope_kind)
    .bind(columns.commit_scope_id)
    .bind(columns.commit_command_id)
    .bind(columns.commit_request_digest)
    .bind(columns.committed_digest)
    .bind(columns.rejection)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_outbox(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    command_id: MembershipCommandId,
    request_id: JoinRequestId,
    action: &str,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let key = ScopeKey::from_scope(tenant_id, scope);
    let inserted = sqlx::query(
        "INSERT INTO groups.sequencer_outbox
             (tenant_id, scope_kind, scope_id, command_id, request_id, action, state,
              available_at_ms, attempt_count, leased_action, lease_token, lease_expires_at_ms,
              completed_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, 0, NULL, NULL, NULL, NULL)
         ON CONFLICT (tenant_id, scope_kind, scope_id, command_id) DO NOTHING",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(uuid_from(request_id))
    .bind(action)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Err(GroupPersistenceError::CorruptData(
            "duplicate membership outbox",
        ));
    }
    Ok(())
}

async fn lock_next_outbox(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    now_ms: i64,
) -> Result<Option<OutboxRow>, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT scope_kind, scope_id, command_id, request_id, action, leased_action,
                COALESCE(lease_expires_at_ms, $2) AS lease_expires_at_ms
           FROM groups.sequencer_outbox
          WHERE tenant_id=$1 AND state='active' AND available_at_ms <= $2
            AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= $2)
          ORDER BY available_at_ms, scope_kind, scope_id, command_id
          FOR UPDATE SKIP LOCKED
          LIMIT 1",
    )
    .bind(Uuid::from(tenant_id))
    .bind(now_ms)
    .fetch_optional(&mut *connection)
    .await?;
    row.map(outbox_from_row).transpose()
}

async fn lock_leased_outbox(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    lease: SequencerActionLease,
) -> Result<OutboxRow, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT scope_kind, scope_id, command_id, request_id, action, leased_action,
                lease_expires_at_ms
           FROM groups.sequencer_outbox
          WHERE tenant_id=$1 AND lease_token=$2 AND state='active'
          FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(lease.token)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::LeaseLost)?;
    outbox_from_row(row)
}

#[allow(clippy::too_many_arguments)] // The lease claim writes every fence coordinate explicitly.
async fn update_outbox_claim(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    action: &str,
    leased_action: &str,
    lease: SequencerActionLease,
    lease_expires_at_ms: i64,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let changed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET action=$5, leased_action=$6, lease_token=$7, lease_expires_at_ms=$8,
                attempt_count=attempt_count+1, available_at_ms=$9
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(action)
    .bind(leased_action)
    .bind(lease.token)
    .bind(lease_expires_at_ms)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

async fn complete_outbox(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    lease: SequencerActionLease,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let changed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET state='completed', completed_at_ms=$6, leased_action=NULL,
                lease_token=NULL, lease_expires_at_ms=NULL
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND lease_token=$5 AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(lease.token)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

async fn complete_unleased_outbox(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let completed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET state='completed', completed_at_ms=$5, leased_action=NULL,
                lease_token=NULL, lease_expires_at_ms=NULL
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if completed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

async fn release_outbox_for_recovery(
    connection: &mut PgConnection,
    key: ScopeKey,
    command_id: MembershipCommandId,
    lease: SequencerActionLease,
    action: &str,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let changed = sqlx::query(
        "UPDATE groups.sequencer_outbox
            SET action=$6, available_at_ms=$7, leased_action=NULL,
                lease_token=NULL, lease_expires_at_ms=NULL
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND command_id=$4
            AND lease_token=$5 AND state='active'",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(uuid_from(command_id.request_id()))
    .bind(lease.token)
    .bind(action)
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(GroupPersistenceError::LeaseLost);
    }
    Ok(())
}

struct TerminalColumns {
    phase: Option<&'static str>,
    admission: Option<&'static str>,
    commit_scope_kind: Option<&'static str>,
    commit_scope_id: Option<String>,
    commit_command_id: Option<Uuid>,
    commit_request_digest: Option<Vec<u8>>,
    committed_digest: Option<Vec<u8>>,
    rejection: Option<&'static str>,
}

fn terminal_columns(
    phase: Option<MembershipCommandPhase>,
) -> Result<TerminalColumns, GroupPersistenceError> {
    match phase {
        None => Ok(TerminalColumns {
            phase: None,
            admission: None,
            commit_scope_kind: None,
            commit_scope_id: None,
            commit_command_id: None,
            commit_request_digest: None,
            committed_digest: None,
            rejection: None,
        }),
        Some(MembershipCommandPhase::Committed(admission)) => {
            let reference = admission.commit_reference();
            let (commit_scope_kind, commit_scope_id) = scope_columns(reference.scope());
            Ok(TerminalColumns {
                phase: Some(COMMITTED_STATE),
                admission: Some(admission_code(admission)),
                commit_scope_kind: Some(commit_scope_kind),
                commit_scope_id: Some(commit_scope_id),
                commit_command_id: Some(uuid_from(reference.command_id().request_id())),
                commit_request_digest: Some(reference.request_digest().as_bytes().to_vec()),
                committed_digest: Some(reference.committed_digest().as_bytes().to_vec()),
                rejection: None,
            })
        }
        Some(MembershipCommandPhase::Rejected(rejection)) => Ok(TerminalColumns {
            phase: Some(REJECTED_STATE),
            admission: None,
            commit_scope_kind: None,
            commit_scope_id: None,
            commit_command_id: None,
            commit_request_digest: None,
            committed_digest: None,
            rejection: Some(rejection_code(rejection)),
        }),
        Some(
            MembershipCommandPhase::PendingApproval
            | MembershipCommandPhase::PendingCommit
            | MembershipCommandPhase::Reconciling,
        ) => Err(GroupPersistenceError::CorruptData(
            "non-terminal command phase",
        )),
    }
}

struct WorkflowColumns {
    state: &'static str,
    approval_command_id: Option<Uuid>,
    approval_actor_identity_id: Option<String>,
    approval_actor_device_id: Option<Uuid>,
    approval_idempotency_key_hash: Option<Vec<u8>>,
    approval_policy_revision: Option<i64>,
    approval_sequencer_head: Option<Vec<u8>>,
    authorization_digest: Option<Vec<u8>>,
    admission: Option<&'static str>,
    commit_scope_kind: Option<&'static str>,
    commit_scope_id: Option<String>,
    commit_command_id: Option<Uuid>,
    commit_request_digest: Option<Vec<u8>>,
    committed_digest: Option<Vec<u8>>,
    rejection: Option<&'static str>,
}

fn workflow_columns(
    phase: &MembershipWorkflowPersistencePhase,
) -> Result<WorkflowColumns, GroupPersistenceError> {
    let empty = || WorkflowColumns {
        state: PENDING_APPROVAL_STATE,
        approval_command_id: None,
        approval_actor_identity_id: None,
        approval_actor_device_id: None,
        approval_idempotency_key_hash: None,
        approval_policy_revision: None,
        approval_sequencer_head: None,
        authorization_digest: None,
        admission: None,
        commit_scope_kind: None,
        commit_scope_id: None,
        commit_command_id: None,
        commit_request_digest: None,
        committed_digest: None,
        rejection: None,
    };
    match *phase {
        MembershipWorkflowPersistencePhase::PendingApproval => Ok(empty()),
        MembershipWorkflowPersistencePhase::PendingCommit {
            approval_command_id,
            approval_context,
            authorization_digest,
        }
        | MembershipWorkflowPersistencePhase::Reconciling {
            approval_command_id,
            approval_context,
            authorization_digest,
        } => {
            let state = match *phase {
                MembershipWorkflowPersistencePhase::PendingCommit { .. } => PENDING_COMMIT_STATE,
                MembershipWorkflowPersistencePhase::Reconciling { .. } => RECONCILING_STATE,
                MembershipWorkflowPersistencePhase::PendingApproval
                | MembershipWorkflowPersistencePhase::Committed(_)
                | MembershipWorkflowPersistencePhase::Rejected(_) => {
                    return Err(GroupPersistenceError::CorruptData(
                        "workflow state encoding",
                    ));
                }
            };
            Ok(WorkflowColumns {
                state,
                approval_command_id: Some(uuid_from(approval_command_id.request_id())),
                approval_actor_identity_id: Some(approval_context.actor_identity_id().to_string()),
                approval_actor_device_id: Some(uuid_from(approval_context.actor_device_id())),
                approval_idempotency_key_hash: Some(
                    approval_context.idempotency_key_hash().as_bytes().to_vec(),
                ),
                approval_policy_revision: Some(revision_i64(
                    approval_context.fence().policy_revision(),
                )?),
                approval_sequencer_head: Some(
                    approval_context
                        .fence()
                        .sequencer_head()
                        .as_bytes()
                        .to_vec(),
                ),
                authorization_digest: Some(authorization_digest.as_bytes().to_vec()),
                ..empty()
            })
        }
        MembershipWorkflowPersistencePhase::Committed(admission) => {
            let reference = admission.commit_reference();
            let (commit_scope_kind, commit_scope_id) = scope_columns(reference.scope());
            Ok(WorkflowColumns {
                state: COMMITTED_STATE,
                admission: Some(admission_code(admission)),
                commit_scope_kind: Some(commit_scope_kind),
                commit_scope_id: Some(commit_scope_id),
                commit_command_id: Some(uuid_from(reference.command_id().request_id())),
                commit_request_digest: Some(reference.request_digest().as_bytes().to_vec()),
                committed_digest: Some(reference.committed_digest().as_bytes().to_vec()),
                ..empty()
            })
        }
        MembershipWorkflowPersistencePhase::Rejected(rejection) => Ok(WorkflowColumns {
            state: REJECTED_STATE,
            rejection: Some(rejection_code(rejection)),
            ..empty()
        }),
    }
}

#[allow(clippy::needless_pass_by_value)] // SQLx yields each row by value from the result iterator.
fn outbox_from_row(row: sqlx::postgres::PgRow) -> Result<OutboxRow, GroupPersistenceError> {
    Ok(OutboxRow {
        scope_kind: row.try_get("scope_kind")?,
        scope_id: row.try_get("scope_id")?,
        command_id: row.try_get("command_id")?,
        request_id: join_request_id(row.try_get("request_id")?)?,
        action: row.try_get("action")?,
        leased_action: row.try_get("leased_action")?,
        lease_expires_at_ms: required_i64(
            row.try_get("lease_expires_at_ms")?,
            "outbox lease expiry",
        )?,
    })
}

fn action_code(action: &SequencerAction) -> &'static str {
    match action {
        SequencerAction::Submit(_) => SUBMIT_ACTION,
        SequencerAction::Query(_) => QUERY_ACTION,
    }
}

fn local_policy_rejection(error: GroupPolicyError) -> Option<MembershipRejection> {
    match error {
        GroupPolicyError::RevisionConflict { .. } => Some(MembershipRejection::StaleFence),
        GroupPolicyError::Unauthorized
        | GroupPolicyError::InviteRevoked
        | GroupPolicyError::InviteExpired
        | GroupPolicyError::InviteIssuerNoLongerAuthorized => {
            Some(MembershipRejection::PolicyDenied)
        }
        GroupPolicyError::CounterExhausted | GroupPolicyError::ReservationInvariantViolation => {
            None
        }
        GroupPolicyError::OwnerCannotBeAdmin
        | GroupPolicyError::AlreadyAdmin
        | GroupPolicyError::NotAdmin
        | GroupPolicyError::AdminLimitReached
        | GroupPolicyError::InviteAlreadyExists
        | GroupPolicyError::InvalidInviteUseLimit
        | GroupPolicyError::InvalidInviteExpiry
        | GroupPolicyError::InviteNotFound
        | GroupPolicyError::InviteAlreadyRevoked
        | GroupPolicyError::AlreadyMember
        | GroupPolicyError::JoinRequestAlreadyPending
        | GroupPolicyError::CandidateJoinInFlight
        | GroupPolicyError::PendingJoinNotFound
        | GroupPolicyError::AlreadyApproved
        | GroupPolicyError::JoinAlreadyReserved
        | GroupPolicyError::ReservedJoinNotFound
        | GroupPolicyError::InviteTargetMismatch
        | GroupPolicyError::InviteUseLimitReached => Some(MembershipRejection::AdmissionDenied),
    }
}

fn command_kind_code(kind: MembershipCommandKind) -> &'static str {
    match kind {
        MembershipCommandKind::RequestJoin => REQUEST_JOIN_KIND,
        MembershipCommandKind::ApproveJoin => APPROVE_JOIN_KIND,
    }
}

fn command_kind(value: &str) -> Result<MembershipCommandKind, GroupPersistenceError> {
    match value {
        REQUEST_JOIN_KIND => Ok(MembershipCommandKind::RequestJoin),
        APPROVE_JOIN_KIND => Ok(MembershipCommandKind::ApproveJoin),
        _ => Err(GroupPersistenceError::CorruptData(
            "membership command kind",
        )),
    }
}

fn admission_code(admission: MembershipAdmission) -> &'static str {
    match admission {
        MembershipAdmission::Applied(_) => APPLIED_ADMISSION,
        MembershipAdmission::AlreadyMember(_) => ALREADY_MEMBER_ADMISSION,
    }
}

fn rejection_code(rejection: MembershipRejection) -> &'static str {
    match rejection {
        MembershipRejection::PolicyDenied => POLICY_DENIED_REJECTION,
        MembershipRejection::StaleFence => STALE_FENCE_REJECTION,
        MembershipRejection::AdmissionDenied => ADMISSION_DENIED_REJECTION,
    }
}

fn rejection(value: &str) -> Result<MembershipRejection, GroupPersistenceError> {
    match value {
        POLICY_DENIED_REJECTION => Ok(MembershipRejection::PolicyDenied),
        STALE_FENCE_REJECTION => Ok(MembershipRejection::StaleFence),
        ADMISSION_DENIED_REJECTION => Ok(MembershipRejection::AdmissionDenied),
        _ => Err(GroupPersistenceError::CorruptData("membership rejection")),
    }
}

fn authority_to_columns(
    authority: GroupAuthorityPersistence,
) -> Result<(&'static str, Option<i64>), GroupPersistenceError> {
    match authority {
        GroupAuthorityPersistence::Owner => Ok((OWNER_AUTHORITY, None)),
        GroupAuthorityPersistence::Admin {
            authorization_generation,
        } => Ok((
            ADMIN_AUTHORITY,
            Some(revision_i64(authorization_generation)?),
        )),
    }
}

#[allow(clippy::needless_pass_by_value)] // The row decoder owns the string and validates it immediately.
fn authority(
    authority: String,
    generation: Option<i64>,
) -> Result<GroupAuthorityPersistence, GroupPersistenceError> {
    match (authority.as_str(), generation) {
        (OWNER_AUTHORITY, None) => Ok(GroupAuthorityPersistence::Owner),
        (ADMIN_AUTHORITY, Some(generation)) => Ok(GroupAuthorityPersistence::Admin {
            authorization_generation: revision(generation)?,
        }),
        _ => Err(GroupPersistenceError::CorruptData("group authority term")),
    }
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn terminal_phase_from_fields(
    phase: Option<String>,
    admission: Option<String>,
    commit_scope_kind: Option<String>,
    commit_scope_id: Option<String>,
    commit_command_id: Option<Uuid>,
    commit_request_digest: Option<Vec<u8>>,
    committed_digest: Option<Vec<u8>>,
    rejection_value: Option<String>,
) -> Result<Option<MembershipCommandPhase>, GroupPersistenceError> {
    match phase.as_deref() {
        None => {
            if admission.is_some()
                || commit_scope_kind.is_some()
                || commit_scope_id.is_some()
                || commit_command_id.is_some()
                || commit_request_digest.is_some()
                || committed_digest.is_some()
                || rejection_value.is_some()
            {
                return Err(GroupPersistenceError::CorruptData(
                    "command terminal columns",
                ));
            }
            Ok(None)
        }
        Some(COMMITTED_STATE) => Ok(Some(MembershipCommandPhase::Committed(
            admission_from_fields(
                required_string(admission, "command terminal admission")?,
                required_string(commit_scope_kind, "command terminal scope kind")?,
                required_string(commit_scope_id, "command terminal scope id")?,
                required_uuid(commit_command_id, "command terminal commit ID")?,
                required_bytes(commit_request_digest, "command terminal request digest")?,
                required_bytes(committed_digest, "command terminal committed digest")?,
            )?,
        ))),
        Some(REJECTED_STATE) => {
            let rejection_value = required_string(rejection_value, "command terminal rejection")?;
            Ok(Some(MembershipCommandPhase::Rejected(rejection(
                &rejection_value,
            )?)))
        }
        _ => Err(GroupPersistenceError::CorruptData("command terminal phase")),
    }
}

#[allow(clippy::needless_pass_by_value)] // The row decoder owns each terminal column and validates it immediately.
fn admission_from_fields(
    admission: String,
    scope_kind: String,
    scope_id: String,
    command_id: Uuid,
    request_digest: Vec<u8>,
    committed_digest: Vec<u8>,
) -> Result<MembershipAdmission, GroupPersistenceError> {
    let reference = MembershipCommitReference::new(
        scope_from_storage(&scope_kind, &scope_id)?,
        membership_command_id(command_id)?,
        digest(request_digest, "membership commit request digest")?,
        digest(committed_digest, "membership committed digest")?,
    );
    match admission.as_str() {
        APPLIED_ADMISSION => Ok(MembershipAdmission::Applied(reference)),
        ALREADY_MEMBER_ADMISSION => Ok(MembershipAdmission::AlreadyMember(reference)),
        _ => Err(GroupPersistenceError::CorruptData("membership admission")),
    }
}

fn scope_from_storage(kind: &str, id: &str) -> Result<GroupScope, GroupPersistenceError> {
    match kind {
        PRIVATE_CONVERSATION_SCOPE => ConversationId::from_str(id)
            .map(GroupScope::PrivateConversation)
            .map_err(|_| GroupPersistenceError::CorruptData("private group scope")),
        CONTROLLED_PUBLIC_CHANNEL_SCOPE => ChannelId::from_str(id)
            .map(GroupScope::ControlledPublicChannel)
            .map_err(|_| GroupPersistenceError::CorruptData("public group scope")),
        _ => Err(GroupPersistenceError::CorruptData("group scope kind")),
    }
}

#[allow(clippy::needless_pass_by_value)] // The row decoder owns the string and validates it immediately.
fn identity_id(value: String) -> Result<IdentityId, GroupPersistenceError> {
    IdentityId::from_str(&value).map_err(|_| GroupPersistenceError::CorruptData("identity ID"))
}

fn device_id(value: Uuid) -> Result<DeviceId, GroupPersistenceError> {
    DeviceId::try_from(value).map_err(|_| GroupPersistenceError::CorruptData("device ID"))
}

fn invite_capability_id(value: Uuid) -> Result<InviteCapabilityId, GroupPersistenceError> {
    InviteCapabilityId::try_from(value)
        .map_err(|_| GroupPersistenceError::CorruptData("invite capability ID"))
}

fn join_request_id(value: Uuid) -> Result<JoinRequestId, GroupPersistenceError> {
    JoinRequestId::try_from(value)
        .map_err(|_| GroupPersistenceError::CorruptData("join request ID"))
}

fn membership_command_id(value: Uuid) -> Result<MembershipCommandId, GroupPersistenceError> {
    RequestId::try_from(value)
        .map(MembershipCommandId::new)
        .map_err(|_| GroupPersistenceError::CorruptData("membership command ID"))
}

fn uuid_from<T>(value: T) -> Uuid
where
    Uuid: From<T>,
{
    Uuid::from(value)
}

fn revision(value: i64) -> Result<Revision, GroupPersistenceError> {
    let value =
        u64::try_from(value).map_err(|_| GroupPersistenceError::CorruptData("policy revision"))?;
    Revision::new(value).map_err(|_| GroupPersistenceError::CorruptData("policy revision"))
}

fn revision_i64(value: Revision) -> Result<i64, GroupPersistenceError> {
    i64::try_from(value.get()).map_err(|_| GroupPersistenceError::CorruptData("policy revision"))
}

fn digest(value: Vec<u8>, label: &'static str) -> Result<Sha256Digest, GroupPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn required_string(
    value: Option<String>,
    label: &'static str,
) -> Result<String, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}

fn required_uuid(value: Option<Uuid>, label: &'static str) -> Result<Uuid, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}

fn required_i64(value: Option<i64>, label: &'static str) -> Result<i64, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}

fn required_bytes(
    value: Option<Vec<u8>>,
    label: &'static str,
) -> Result<Vec<u8>, GroupPersistenceError> {
    value.ok_or(GroupPersistenceError::CorruptData(label))
}
