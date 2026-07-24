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
    candidate_key_package_digest: Option<Sha256Digest>,
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

    /// Returns the V30 candidate `KeyPackage` digest. Historical V17/V18
    /// workflows return `None` and must fail closed on the V2 discovery path.
    #[must_use]
    pub const fn candidate_key_package_digest(&self) -> Option<Sha256Digest> {
        self.candidate_key_package_digest
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
