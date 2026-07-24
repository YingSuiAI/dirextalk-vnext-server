use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use dtx_domain::{
    ChannelId, ConversationId, IdentityId, InviteCapabilityId, JoinRequestId, Revision,
};

/// Maximum number of administrator identities in addition to the owner.
pub const MAX_ADMINS: usize = 5;

/// Strongly typed boundary for a group authorization policy.
///
/// A private MLS conversation and a controlled public channel cannot be
/// accidentally exchanged as strings or UUIDs at this domain boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GroupScope {
    /// A private group whose membership is later applied to an MLS conversation.
    PrivateConversation(ConversationId),
    /// A public channel with controlled subscription or discussion membership.
    ControlledPublicChannel(ChannelId),
}

/// Effective group role for one identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupRole {
    /// The sole group owner, who automatically has invite and approval authority.
    Owner,
    /// One of at most five additional group administrators.
    Admin,
    /// A regular admitted group member.
    Member,
}

/// The authority term under which an invitation issuer was allowed to act.
///
/// Owner authority is continuous in this aggregate. Each administrator grant
/// receives a fresh, identity-scoped generation so that revocation cannot be
/// undone by granting the same identity a later administrator term.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InviteIssuerAuthority {
    Owner,
    Admin { authorization_generation: Revision },
}

/// A group-bound, non-secret invitation capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteCapability {
    invite_id: InviteCapabilityId,
    scope: GroupScope,
    issuer_id: IdentityId,
    target_id: Option<IdentityId>,
    max_uses: u32,
    use_count: u32,
    reserved_use_count: u32,
    expires_at_ms: i64,
    revoked: bool,
    policy_revision: Revision,
    issuer_authority: InviteIssuerAuthority,
}

impl InviteCapability {
    /// Returns the invitation capability identity.
    #[must_use]
    pub const fn invite_id(self) -> InviteCapabilityId {
        self.invite_id
    }

    /// Returns the strongly typed group boundary to which this capability is bound.
    #[must_use]
    pub const fn scope(self) -> GroupScope {
        self.scope
    }

    /// Returns the verified owner or administrator that issued this capability.
    #[must_use]
    pub const fn issuer_id(self) -> IdentityId {
        self.issuer_id
    }

    /// Returns the optional identity to which this capability is restricted.
    #[must_use]
    pub const fn target_id(self) -> Option<IdentityId> {
        self.target_id
    }

    /// Returns the maximum number of memberships this capability can authorize.
    #[must_use]
    pub const fn max_uses(self) -> u32 {
        self.max_uses
    }

    /// Returns the number of approved memberships that consumed this capability.
    #[must_use]
    pub const fn use_count(self) -> u32 {
        self.use_count
    }

    /// Returns the number of uses durably reserved for a pending membership commit.
    #[must_use]
    pub const fn reserved_use_count(self) -> u32 {
        self.reserved_use_count
    }

    /// Returns the exclusive capability expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(self) -> i64 {
        self.expires_at_ms
    }

    /// Reports whether the capability has been explicitly revoked.
    #[must_use]
    pub const fn is_revoked(self) -> bool {
        self.revoked
    }

    /// Returns the group policy revision that authorized issuance.
    #[must_use]
    pub const fn policy_revision(self) -> Revision {
        self.policy_revision
    }

    /// Returns the administrator authorization generation bound at issuance.
    ///
    /// Owner-issued invitations return `None`, because an owner's authority is
    /// not an administrator term and must not be invalidated by administrator
    /// grants or revocations.
    #[must_use]
    pub const fn issuer_admin_authorization_generation(self) -> Option<Revision> {
        match self.issuer_authority {
            InviteIssuerAuthority::Owner => None,
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => Some(authorization_generation),
        }
    }
}

/// One candidate's pending request to consume a group invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingJoinRequest {
    request_id: JoinRequestId,
    candidate_id: IdentityId,
    invite_id: InviteCapabilityId,
    requested_at_ms: i64,
}

impl PendingJoinRequest {
    /// Returns the unique pending request identity.
    #[must_use]
    pub const fn request_id(self) -> JoinRequestId {
        self.request_id
    }

    /// Returns the verified candidate identity.
    #[must_use]
    pub const fn candidate_id(self) -> IdentityId {
        self.candidate_id
    }

    /// Returns the invitation capability that the candidate presented.
    #[must_use]
    pub const fn invite_id(self) -> InviteCapabilityId {
        self.invite_id
    }

    /// Returns when the candidate submitted this pending request.
    #[must_use]
    pub const fn requested_at_ms(self) -> i64 {
        self.requested_at_ms
    }
}

/// A durable invitation-use reservation made before an external membership commit.
///
/// The candidate is not yet a member while this record exists. A later
/// Sequencer result must either finalize it into [`ApprovedJoin`] or explicitly
/// release it; timeout and response loss must leave it reserved for recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedJoin {
    request_id: JoinRequestId,
    candidate_id: IdentityId,
    invite_id: InviteCapabilityId,
    reserved_by: IdentityId,
    reserved_authority: InviteIssuerAuthority,
    reserved_at_ms: i64,
    policy_revision: Revision,
}

impl ReservedJoin {
    /// Returns the original candidate request identity.
    #[must_use]
    pub const fn request_id(self) -> JoinRequestId {
        self.request_id
    }

    /// Returns the candidate identity whose membership is pending remotely.
    #[must_use]
    pub const fn candidate_id(self) -> IdentityId {
        self.candidate_id
    }

    /// Returns the invitation whose one use is reserved.
    #[must_use]
    pub const fn invite_id(self) -> InviteCapabilityId {
        self.invite_id
    }

    /// Returns the Owner/Admin identity that authorized the reservation.
    #[must_use]
    pub const fn reserved_by(self) -> IdentityId {
        self.reserved_by
    }

    /// Returns the administrator authority generation when an Admin reserved it.
    ///
    /// Owner reservations return `None`; a retained generation lets snapshot
    /// rehydration distinguish a historical valid Admin term from an invented
    /// reservation after that identity was revoked or regranted.
    #[must_use]
    pub const fn reserved_admin_authorization_generation(self) -> Option<Revision> {
        match self.reserved_authority {
            InviteIssuerAuthority::Owner => None,
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => Some(authorization_generation),
        }
    }

    /// Returns the trusted server timestamp at reservation time.
    #[must_use]
    pub const fn reserved_at_ms(self) -> i64 {
        self.reserved_at_ms
    }

    /// Returns the group policy revision revalidated for the external intent.
    #[must_use]
    pub const fn policy_revision(self) -> Revision {
        self.policy_revision
    }
}

/// Immutable record that a pending request has already admitted its candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedJoin {
    request_id: JoinRequestId,
    candidate_id: IdentityId,
    invite_id: InviteCapabilityId,
    approved_by: IdentityId,
    approved_at_ms: i64,
    policy_revision: Revision,
}

impl ApprovedJoin {
    /// Returns the original pending request identity.
    #[must_use]
    pub const fn request_id(self) -> JoinRequestId {
        self.request_id
    }

    /// Returns the member admitted by this approval.
    #[must_use]
    pub const fn candidate_id(self) -> IdentityId {
        self.candidate_id
    }

    /// Returns the invitation capability consumed by this approval.
    #[must_use]
    pub const fn invite_id(self) -> InviteCapabilityId {
        self.invite_id
    }

    /// Returns the current owner or administrator who approved the request.
    #[must_use]
    pub const fn approved_by(self) -> IdentityId {
        self.approved_by
    }

    /// Returns the approval timestamp supplied by the trusted integration layer.
    #[must_use]
    pub const fn approved_at_ms(self) -> i64 {
        self.approved_at_ms
    }

    /// Returns the group revision revalidated before the approval transition.
    #[must_use]
    pub const fn policy_revision(self) -> Revision {
        self.policy_revision
    }
}

/// Complete, non-secret persistence image of one group-policy aggregate.
///
/// Collections are sorted when produced by [`GroupPolicy::snapshot`], and are
/// fully validated before [`GroupPolicy::try_from_snapshot`] accepts them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPolicySnapshot {
    /// Strongly typed private or controlled-public scope.
    pub scope: GroupScope,
    /// Sole owner identity.
    pub owner_id: IdentityId,
    /// Current additional administrator identities, excluding the owner.
    pub administrators: Vec<IdentityId>,
    /// Current and retired administrator authority generations.
    pub administrator_authorization_generations: Vec<(IdentityId, Revision)>,
    /// Current identity-level member set.
    pub members: Vec<IdentityId>,
    /// All issued invitation capabilities, including expired or revoked history.
    pub invitations: Vec<InviteCapability>,
    /// Candidate requests awaiting an Owner/Admin decision.
    pub pending_joins: Vec<PendingJoinRequest>,
    /// Durable membership intents awaiting a remote result.
    pub reserved_joins: Vec<ReservedJoin>,
    /// Immutable finalized admission history.
    pub approved_joins: Vec<ApprovedJoin>,
    /// Current policy revision.
    pub revision: Revision,
}

/// Storage-neutral authority term retained for a group invitation or reservation.
///
/// This mirrors the private reducer authority marker without exposing the
/// reducer's internal representation to SQL adapters. A historical
/// administrator generation remains meaningful after that administrator is
/// revoked or regranted, so it is retained rather than inferred from current
/// role membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupAuthorityPersistence {
    /// The sole group owner authorized the action.
    Owner,
    /// An administrator authorized the action during one exact grant term.
    Admin {
        /// The administrator's exact authorization generation.
        authorization_generation: Revision,
    },
}

/// Storage-neutral durable representation of one invitation capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupInvitePersistence {
    /// Invitation capability identity.
    pub invite_id: InviteCapabilityId,
    /// Actor that issued the capability.
    pub issuer_id: IdentityId,
    /// Optional identity restriction.
    pub target_id: Option<IdentityId>,
    /// Maximum total approved uses.
    pub max_uses: u32,
    /// Finalized uses.
    pub use_count: u32,
    /// Durable uses held by remote-commit intents.
    pub reserved_use_count: u32,
    /// Exclusive expiry time in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Whether an authorized actor explicitly revoked the capability.
    pub revoked: bool,
    /// Policy revision at issuance.
    pub policy_revision: Revision,
    /// Exact owner or administrator term that issued the capability.
    pub issuer_authority: GroupAuthorityPersistence,
}

/// Storage-neutral durable representation of a pending join request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupPendingJoinPersistence {
    /// Stable join request identity.
    pub request_id: JoinRequestId,
    /// Candidate identity awaiting a decision.
    pub candidate_id: IdentityId,
    /// Invitation presented by the candidate.
    pub invite_id: InviteCapabilityId,
    /// Trusted server request timestamp.
    pub requested_at_ms: i64,
}

/// Storage-neutral durable representation of an external-commit reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupReservedJoinPersistence {
    /// Stable join request identity.
    pub request_id: JoinRequestId,
    /// Candidate identity awaiting the remote result.
    pub candidate_id: IdentityId,
    /// Invitation whose capacity is held.
    pub invite_id: InviteCapabilityId,
    /// Owner or administrator that created the reservation.
    pub reserved_by: IdentityId,
    /// Exact authority term used for the reservation.
    pub reserved_authority: GroupAuthorityPersistence,
    /// Trusted server reservation timestamp.
    pub reserved_at_ms: i64,
    /// Policy revision revalidated before external submission.
    pub policy_revision: Revision,
}

/// Storage-neutral durable representation of a finalized admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupApprovedJoinPersistence {
    /// Stable join request identity.
    pub request_id: JoinRequestId,
    /// Admitted identity.
    pub candidate_id: IdentityId,
    /// Invitation that was consumed.
    pub invite_id: InviteCapabilityId,
    /// Owner or administrator that approved the reservation.
    pub approved_by: IdentityId,
    /// Trusted server finalization timestamp.
    pub approved_at_ms: i64,
    /// Policy revision revalidated before the external intent.
    pub policy_revision: Revision,
}

/// Complete storage-neutral persistence image for [`GroupPolicy`].
///
/// SQL adapters reconstruct this image from normalized rows, then hand it back
/// to the pure aggregate for validation. This keeps row mapping out of the
/// authorization reducer and prevents adapters from reimplementing invite,
/// administrator-term, or reservation invariants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPolicyPersistenceImage {
    /// Strongly typed private or controlled-public scope.
    pub scope: GroupScope,
    /// Sole group owner.
    pub owner_id: IdentityId,
    /// Current additional administrator identities.
    pub administrators: Vec<IdentityId>,
    /// Current and historical administrator authorization generations.
    pub administrator_authorization_generations: Vec<(IdentityId, Revision)>,
    /// Current identity-level member set.
    pub members: Vec<IdentityId>,
    /// Invitation history.
    pub invitations: Vec<GroupInvitePersistence>,
    /// Candidate requests awaiting a decision.
    pub pending_joins: Vec<GroupPendingJoinPersistence>,
    /// External membership intents awaiting a remote result.
    pub reserved_joins: Vec<GroupReservedJoinPersistence>,
    /// Finalized admission history.
    pub approved_joins: Vec<GroupApprovedJoinPersistence>,
    /// Current optimistic-concurrency revision.
    pub revision: Revision,
}

impl GroupPolicySnapshot {
    /// Converts this validated-in-memory image into a storage-neutral form.
    #[must_use]
    pub fn persistence_image(&self) -> GroupPolicyPersistenceImage {
        GroupPolicyPersistenceImage {
            scope: self.scope,
            owner_id: self.owner_id,
            administrators: self.administrators.clone(),
            administrator_authorization_generations: self
                .administrator_authorization_generations
                .clone(),
            members: self.members.clone(),
            invitations: self
                .invitations
                .iter()
                .map(|invite| GroupInvitePersistence {
                    invite_id: invite.invite_id,
                    issuer_id: invite.issuer_id,
                    target_id: invite.target_id,
                    max_uses: invite.max_uses,
                    use_count: invite.use_count,
                    reserved_use_count: invite.reserved_use_count,
                    expires_at_ms: invite.expires_at_ms,
                    revoked: invite.revoked,
                    policy_revision: invite.policy_revision,
                    issuer_authority: authority_persistence(invite.issuer_authority),
                })
                .collect(),
            pending_joins: self
                .pending_joins
                .iter()
                .map(|pending| GroupPendingJoinPersistence {
                    request_id: pending.request_id,
                    candidate_id: pending.candidate_id,
                    invite_id: pending.invite_id,
                    requested_at_ms: pending.requested_at_ms,
                })
                .collect(),
            reserved_joins: self
                .reserved_joins
                .iter()
                .map(|reserved| GroupReservedJoinPersistence {
                    request_id: reserved.request_id,
                    candidate_id: reserved.candidate_id,
                    invite_id: reserved.invite_id,
                    reserved_by: reserved.reserved_by,
                    reserved_authority: authority_persistence(reserved.reserved_authority),
                    reserved_at_ms: reserved.reserved_at_ms,
                    policy_revision: reserved.policy_revision,
                })
                .collect(),
            approved_joins: self
                .approved_joins
                .iter()
                .map(|approved| GroupApprovedJoinPersistence {
                    request_id: approved.request_id,
                    candidate_id: approved.candidate_id,
                    invite_id: approved.invite_id,
                    approved_by: approved.approved_by,
                    approved_at_ms: approved.approved_at_ms,
                    policy_revision: approved.policy_revision,
                })
                .collect(),
            revision: self.revision,
        }
    }

    /// Rebuilds the reducer-owned snapshot from a normalized storage image.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied rows cannot form one valid group
    /// policy aggregate. The result must still be passed through
    /// [`GroupPolicy::try_from_snapshot`] before it becomes authorization fact.
    pub fn try_from_persistence_image(
        image: GroupPolicyPersistenceImage,
    ) -> Result<Self, GroupPolicySnapshotError> {
        let snapshot = Self {
            scope: image.scope,
            owner_id: image.owner_id,
            administrators: image.administrators,
            administrator_authorization_generations: image.administrator_authorization_generations,
            members: image.members,
            invitations: image
                .invitations
                .into_iter()
                .map(|invite| InviteCapability {
                    invite_id: invite.invite_id,
                    scope: image.scope,
                    issuer_id: invite.issuer_id,
                    target_id: invite.target_id,
                    max_uses: invite.max_uses,
                    use_count: invite.use_count,
                    reserved_use_count: invite.reserved_use_count,
                    expires_at_ms: invite.expires_at_ms,
                    revoked: invite.revoked,
                    policy_revision: invite.policy_revision,
                    issuer_authority: authority_from_persistence(invite.issuer_authority),
                })
                .collect(),
            pending_joins: image
                .pending_joins
                .into_iter()
                .map(|pending| PendingJoinRequest {
                    request_id: pending.request_id,
                    candidate_id: pending.candidate_id,
                    invite_id: pending.invite_id,
                    requested_at_ms: pending.requested_at_ms,
                })
                .collect(),
            reserved_joins: image
                .reserved_joins
                .into_iter()
                .map(|reserved| ReservedJoin {
                    request_id: reserved.request_id,
                    candidate_id: reserved.candidate_id,
                    invite_id: reserved.invite_id,
                    reserved_by: reserved.reserved_by,
                    reserved_authority: authority_from_persistence(reserved.reserved_authority),
                    reserved_at_ms: reserved.reserved_at_ms,
                    policy_revision: reserved.policy_revision,
                })
                .collect(),
            approved_joins: image
                .approved_joins
                .into_iter()
                .map(|approved| ApprovedJoin {
                    request_id: approved.request_id,
                    candidate_id: approved.candidate_id,
                    invite_id: approved.invite_id,
                    approved_by: approved.approved_by,
                    approved_at_ms: approved.approved_at_ms,
                    policy_revision: approved.policy_revision,
                })
                .collect(),
            revision: image.revision,
        };
        GroupPolicy::try_from_snapshot(&snapshot)?;
        Ok(snapshot)
    }
}

/// Rehydration failure for a malformed group-policy persistence image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupPolicySnapshotError {
    /// The stored state cannot represent one unambiguous valid policy aggregate.
    InvalidSnapshot(&'static str),
}

impl fmt::Display for GroupPolicySnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "invalid group policy snapshot: {reason}")
            }
        }
    }
}

impl Error for GroupPolicySnapshotError {}

/// Stable rejection from the group-role authorization aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupPolicyError {
    /// The caller acted on an outdated aggregate revision.
    RevisionConflict {
        /// The current revision that must be observed before retrying.
        current: Revision,
    },
    /// The verified actor lacks authority for the attempted action.
    Unauthorized,
    /// The sole owner cannot also occupy an administrator slot.
    OwnerCannotBeAdmin,
    /// The sole owner cannot be removed by a membership command.
    OwnerCannotBeRemoved,
    /// The identity already occupies an administrator slot.
    AlreadyAdmin,
    /// The identity does not occupy an administrator slot.
    NotAdmin,
    /// Adding another administrator would exceed [`MAX_ADMINS`].
    AdminLimitReached,
    /// The aggregate revision cannot advance safely.
    CounterExhausted,
    /// The caller attempted to create an already recorded invitation identity.
    InviteAlreadyExists,
    /// An invitation must authorize at least one membership.
    InvalidInviteUseLimit,
    /// An invitation must expire strictly after its issuance time.
    InvalidInviteExpiry,
    /// No invitation exists for the supplied capability identity.
    InviteNotFound,
    /// The invitation has already been revoked.
    InviteAlreadyRevoked,
    /// The candidate already belongs to the group.
    AlreadyMember,
    /// The requested removal target is not a current group member.
    MemberNotFound,
    /// The request identity is already pending for a candidate.
    JoinRequestAlreadyPending,
    /// The candidate already has another pending or reserved admission workflow.
    CandidateJoinInFlight,
    /// No pending request exists for the supplied identity.
    PendingJoinNotFound,
    /// The request has already been approved and cannot admit another member.
    AlreadyApproved,
    /// An Owner/Admin has already reserved this request for an external commit.
    JoinAlreadyReserved,
    /// No durable reservation exists for the supplied request identity.
    ReservedJoinNotFound,
    /// A rehydrated reservation count cannot be reconciled with invitation state.
    ReservationInvariantViolation,
    /// A targeted invitation was presented by a different candidate identity.
    InviteTargetMismatch,
    /// The invitation is expired at the supplied trusted time.
    InviteExpired,
    /// The invitation has been revoked and cannot authorize a new membership.
    InviteRevoked,
    /// The invitation has already authorized all of its allowed memberships.
    InviteUseLimitReached,
    /// The owner or administrator that issued the invitation no longer has invite authority.
    InviteIssuerNoLongerAuthorized,
}

impl fmt::Display for GroupPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RevisionConflict { current } => {
                write!(
                    formatter,
                    "group revision conflict; current revision is {}",
                    current.get()
                )
            }
            Self::Unauthorized => {
                formatter.write_str("actor is not authorized for this group action")
            }
            Self::OwnerCannotBeAdmin => {
                formatter.write_str("group owner cannot also be an administrator")
            }
            Self::OwnerCannotBeRemoved => formatter.write_str("group owner cannot be removed"),
            Self::AlreadyAdmin => formatter.write_str("identity is already a group administrator"),
            Self::NotAdmin => formatter.write_str("identity is not a group administrator"),
            Self::AdminLimitReached => formatter.write_str("group administrator limit reached"),
            Self::CounterExhausted => formatter.write_str("group revision cannot advance further"),
            Self::InviteAlreadyExists => formatter.write_str("group invitation already exists"),
            Self::InvalidInviteUseLimit => {
                formatter.write_str("group invitation use limit must be positive")
            }
            Self::InvalidInviteExpiry => {
                formatter.write_str("group invitation expiry must be in the future")
            }
            Self::InviteNotFound => formatter.write_str("group invitation was not found"),
            Self::InviteAlreadyRevoked => {
                formatter.write_str("group invitation is already revoked")
            }
            Self::AlreadyMember => formatter.write_str("candidate is already a group member"),
            Self::MemberNotFound => formatter.write_str("group member was not found"),
            Self::JoinRequestAlreadyPending => {
                formatter.write_str("group join request is already pending")
            }
            Self::CandidateJoinInFlight => {
                formatter.write_str("candidate already has an active group admission workflow")
            }
            Self::PendingJoinNotFound => {
                formatter.write_str("pending group join request was not found")
            }
            Self::AlreadyApproved => formatter.write_str("group join request is already approved"),
            Self::JoinAlreadyReserved => {
                formatter.write_str("group join request already has a membership reservation")
            }
            Self::ReservedJoinNotFound => {
                formatter.write_str("group membership reservation was not found")
            }
            Self::ReservationInvariantViolation => {
                formatter.write_str("group invitation reservation state is inconsistent")
            }
            Self::InviteTargetMismatch => {
                formatter.write_str("group invitation is bound to a different candidate")
            }
            Self::InviteExpired => formatter.write_str("group invitation is expired"),
            Self::InviteRevoked => formatter.write_str("group invitation is revoked"),
            Self::InviteUseLimitReached => {
                formatter.write_str("group invitation use limit is exhausted")
            }
            Self::InviteIssuerNoLongerAuthorized => {
                formatter.write_str("group invitation issuer no longer has invite authority")
            }
        }
    }
}

impl Error for GroupPolicyError {}

/// In-memory authorization and membership state for one group conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPolicy {
    scope: GroupScope,
    owner_id: IdentityId,
    administrators: BTreeSet<IdentityId>,
    administrator_authorization_generations: BTreeMap<IdentityId, Revision>,
    members: BTreeSet<IdentityId>,
    invitations: BTreeMap<InviteCapabilityId, InviteCapability>,
    pending_joins: BTreeMap<JoinRequestId, PendingJoinRequest>,
    reserved_joins: BTreeMap<JoinRequestId, ReservedJoin>,
    approved_joins: BTreeMap<JoinRequestId, ApprovedJoin>,
    revision: Revision,
}
