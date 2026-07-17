#![forbid(unsafe_code)]

//! Pure group-role authorization aggregate.
//!
//! Callers supply an already verified actor identity. Persistent command receipts,
//! signed device proofs, MLS epoch/head fencing, and storage transactions belong to
//! later integration layers and are deliberately not modeled here.

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

impl GroupPolicy {
    /// Creates a group with its owner admitted as the first member.
    #[must_use]
    pub fn new(scope: GroupScope, owner_id: IdentityId) -> Self {
        let mut members = BTreeSet::new();
        members.insert(owner_id);
        Self {
            scope,
            owner_id,
            administrators: BTreeSet::new(),
            administrator_authorization_generations: BTreeMap::new(),
            members,
            invitations: BTreeMap::new(),
            pending_joins: BTreeMap::new(),
            reserved_joins: BTreeMap::new(),
            approved_joins: BTreeMap::new(),
            revision: Revision::INITIAL,
        }
    }

    /// Returns the strongly typed private-conversation or controlled-public-channel boundary.
    #[must_use]
    pub const fn scope(&self) -> GroupScope {
        self.scope
    }

    /// Returns the sole owner identity.
    #[must_use]
    pub const fn owner_id(&self) -> IdentityId {
        self.owner_id
    }

    /// Returns the current optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the effective role, if the identity belongs to this group.
    #[must_use]
    pub fn role_of(&self, identity_id: IdentityId) -> Option<GroupRole> {
        if identity_id == self.owner_id {
            Some(GroupRole::Owner)
        } else if self.administrators.contains(&identity_id) {
            Some(GroupRole::Admin)
        } else if self.members.contains(&identity_id) {
            Some(GroupRole::Member)
        } else {
            None
        }
    }

    /// Reports whether an identity is an admitted member.
    #[must_use]
    pub fn is_member(&self, identity_id: IdentityId) -> bool {
        self.members.contains(&identity_id)
    }

    /// Returns the count of additional administrators, excluding the owner.
    #[must_use]
    pub fn admin_count(&self) -> usize {
        self.administrators.len()
    }

    /// Reports whether the verified identity may issue or revoke invitations.
    #[must_use]
    pub fn can_issue_invite(&self, identity_id: IdentityId) -> bool {
        matches!(
            self.role_of(identity_id),
            Some(GroupRole::Owner | GroupRole::Admin)
        )
    }

    /// Reports whether the verified identity may approve a pending join request.
    #[must_use]
    pub fn can_approve_join(&self, identity_id: IdentityId) -> bool {
        self.can_issue_invite(identity_id)
    }

    /// Looks up an invitation without exposing any mutable state.
    #[must_use]
    pub fn invite(&self, invite_id: InviteCapabilityId) -> Option<&InviteCapability> {
        self.invitations.get(&invite_id)
    }

    /// Looks up a currently pending join request.
    #[must_use]
    pub fn pending_join(&self, request_id: JoinRequestId) -> Option<&PendingJoinRequest> {
        self.pending_joins.get(&request_id)
    }

    /// Looks up a durable membership reservation awaiting a remote result.
    #[must_use]
    pub fn reserved_join(&self, request_id: JoinRequestId) -> Option<&ReservedJoin> {
        self.reserved_joins.get(&request_id)
    }

    /// Looks up an immutable approval record.
    #[must_use]
    pub fn approved_join(&self, request_id: JoinRequestId) -> Option<&ApprovedJoin> {
        self.approved_joins.get(&request_id)
    }

    /// Captures a complete, deterministic, non-secret persistence image.
    #[must_use]
    pub fn snapshot(&self) -> GroupPolicySnapshot {
        GroupPolicySnapshot {
            scope: self.scope,
            owner_id: self.owner_id,
            administrators: self.administrators.iter().copied().collect(),
            administrator_authorization_generations: self
                .administrator_authorization_generations
                .iter()
                .map(|(identity_id, generation)| (*identity_id, *generation))
                .collect(),
            members: self.members.iter().copied().collect(),
            invitations: self.invitations.values().copied().collect(),
            pending_joins: self.pending_joins.values().copied().collect(),
            reserved_joins: self.reserved_joins.values().copied().collect(),
            approved_joins: self.approved_joins.values().copied().collect(),
            revision: self.revision,
        }
    }

    /// Rehydrates a validated policy aggregate without replaying external effects.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicated, cross-linked, or otherwise inconsistent
    /// durable facts. It never silently repairs an authorization image.
    pub fn try_from_snapshot(
        snapshot: &GroupPolicySnapshot,
    ) -> Result<Self, GroupPolicySnapshotError> {
        group_policy_from_snapshot(snapshot)
    }

    /// Grants one additional administrator slot to an identity.
    ///
    /// The supplied actor must be the owner at the exact current revision. An
    /// administrator is admitted as a member if not already present.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is stale, the actor is not the owner,
    /// the target is the owner or already an administrator, or all five slots
    /// are occupied.
    pub fn grant_admin(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        administrator_id: IdentityId,
    ) -> Result<Revision, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        self.ensure_owner(actor_id)?;
        if administrator_id == self.owner_id {
            return Err(GroupPolicyError::OwnerCannotBeAdmin);
        }
        if self.administrators.contains(&administrator_id) {
            return Err(GroupPolicyError::AlreadyAdmin);
        }
        if self.administrators.len() >= MAX_ADMINS {
            return Err(GroupPolicyError::AdminLimitReached);
        }
        let authorization_generation =
            self.next_admin_authorization_generation(administrator_id)?;

        self.administrators.insert(administrator_id);
        self.administrator_authorization_generations
            .insert(administrator_id, authorization_generation);
        self.members.insert(administrator_id);
        self.revision = next_revision;
        Ok(next_revision)
    }

    /// Revokes one additional administrator slot while preserving membership.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is stale, the actor is not the owner,
    /// the target is the owner, or the target is not currently an administrator.
    pub fn revoke_admin(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        administrator_id: IdentityId,
    ) -> Result<Revision, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        self.ensure_owner(actor_id)?;
        if administrator_id == self.owner_id {
            return Err(GroupPolicyError::OwnerCannotBeAdmin);
        }
        if !self.administrators.contains(&administrator_id) {
            return Err(GroupPolicyError::NotAdmin);
        }

        self.administrators.remove(&administrator_id);
        self.revision = next_revision;
        Ok(next_revision)
    }

    /// Removes one non-owner identity from the group at the exact policy revision.
    ///
    /// A current administrator loses that term in the same state transition.
    /// Historical authorization generations and invitations remain auditable;
    /// their issuer-authority checks fail closed once the term is inactive.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is stale, the actor is not the owner,
    /// the target is the owner, or the target is not a current member.
    pub fn remove_member(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        member_id: IdentityId,
    ) -> Result<Revision, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        self.ensure_owner(actor_id)?;
        if member_id == self.owner_id {
            return Err(GroupPolicyError::OwnerCannotBeRemoved);
        }
        if !self.members.contains(&member_id) {
            return Err(GroupPolicyError::MemberNotFound);
        }

        self.administrators.remove(&member_id);
        self.members.remove(&member_id);
        self.revision = next_revision;
        Ok(next_revision)
    }

    /// Issues a non-secret invitation bound to this group and the current policy.
    ///
    /// The actor must be the owner or a current administrator at the supplied
    /// revision. The capability is deliberately just authorization metadata;
    /// signatures, device proofs, and distribution are integration concerns.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale revision, unauthorized actor, duplicate
    /// capability ID, zero use limit, or expiry that is not in the future.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_invite(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        invite_id: InviteCapabilityId,
        target_id: Option<IdentityId>,
        max_uses: u32,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<InviteCapability, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        let issuer_authority = self.invite_issuer_authority(actor_id)?;
        if self.invitations.contains_key(&invite_id) {
            return Err(GroupPolicyError::InviteAlreadyExists);
        }
        if max_uses == 0 {
            return Err(GroupPolicyError::InvalidInviteUseLimit);
        }
        if expires_at_ms <= now_ms {
            return Err(GroupPolicyError::InvalidInviteExpiry);
        }

        let invite = InviteCapability {
            invite_id,
            scope: self.scope,
            issuer_id: actor_id,
            target_id,
            max_uses,
            use_count: 0,
            reserved_use_count: 0,
            expires_at_ms,
            revoked: false,
            policy_revision: expected_revision,
            issuer_authority,
        };
        self.invitations.insert(invite_id, invite);
        self.revision = next_revision;
        Ok(invite)
    }

    /// Revokes an invitation at the exact current group revision.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale revision, unauthorized actor, unknown
    /// invitation, or an invitation that was already revoked.
    pub fn revoke_invite(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        invite_id: InviteCapabilityId,
    ) -> Result<Revision, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        self.ensure_invite_authority(actor_id)?;
        let invite = self
            .invitations
            .get_mut(&invite_id)
            .ok_or(GroupPolicyError::InviteNotFound)?;
        if invite.revoked {
            return Err(GroupPolicyError::InviteAlreadyRevoked);
        }

        invite.revoked = true;
        self.revision = next_revision;
        Ok(next_revision)
    }

    /// Records a candidate's pending request to consume one invitation use.
    ///
    /// A pending request does not consume an invitation use. Consumption occurs
    /// only when an authorized actor approves the request at a current revision.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale revision, a caller that does not match the
    /// candidate, an already admitted candidate, reused request ID, or an
    /// invitation that is missing, revoked, expired, exhausted, targeted to
    /// another identity, or issued by a no-longer authorized actor.
    pub fn request_join(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        candidate_id: IdentityId,
        request_id: JoinRequestId,
        invite_id: InviteCapabilityId,
        now_ms: i64,
    ) -> Result<PendingJoinRequest, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        if actor_id != candidate_id {
            return Err(GroupPolicyError::Unauthorized);
        }
        if self.members.contains(&candidate_id) {
            return Err(GroupPolicyError::AlreadyMember);
        }
        if self.pending_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::JoinRequestAlreadyPending);
        }
        if self.reserved_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::JoinAlreadyReserved);
        }
        if self.approved_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::AlreadyApproved);
        }
        if self.candidate_has_active_join(candidate_id) {
            return Err(GroupPolicyError::CandidateJoinInFlight);
        }
        let invite = self
            .invitations
            .get(&invite_id)
            .copied()
            .ok_or(GroupPolicyError::InviteNotFound)?;
        self.ensure_invite_usable(invite, candidate_id, now_ms)?;

        let pending = PendingJoinRequest {
            request_id,
            candidate_id,
            invite_id,
            requested_at_ms: now_ms,
        };
        self.pending_joins.insert(request_id, pending);
        self.revision = next_revision;
        Ok(pending)
    }

    /// Reserves exactly one invitation use before an external membership commit.
    ///
    /// This is the durable-intent authorization boundary: the candidate remains
    /// outside the member set and the invitation remains unconsumed until a
    /// verified Sequencer result calls [`Self::finalize_reserved_join`]. A
    /// timeout or response loss must retain this reservation for reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale revision, unauthorized actor, missing or
    /// terminal request, already admitted candidate, or currently invalid or
    /// exhausted invitation.
    pub fn reserve_join(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        request_id: JoinRequestId,
        now_ms: i64,
    ) -> Result<ReservedJoin, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        self.ensure_approval_authority(actor_id)?;
        let reservation_authority = self.invite_issuer_authority(actor_id)?;
        if self.approved_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::AlreadyApproved);
        }
        if self.reserved_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::JoinAlreadyReserved);
        }
        let pending = self
            .pending_joins
            .get(&request_id)
            .copied()
            .ok_or(GroupPolicyError::PendingJoinNotFound)?;
        if self.members.contains(&pending.candidate_id) {
            return Err(GroupPolicyError::AlreadyMember);
        }
        let invite = self
            .invitations
            .get(&pending.invite_id)
            .copied()
            .ok_or(GroupPolicyError::InviteNotFound)?;
        self.ensure_invite_usable(invite, pending.candidate_id, now_ms)?;

        let invite = self
            .invitations
            .get_mut(&pending.invite_id)
            .ok_or(GroupPolicyError::InviteNotFound)?;
        invite.reserved_use_count = invite
            .reserved_use_count
            .checked_add(1)
            .ok_or(GroupPolicyError::InviteUseLimitReached)?;
        self.pending_joins.remove(&request_id);
        let reservation = ReservedJoin {
            request_id,
            candidate_id: pending.candidate_id,
            invite_id: pending.invite_id,
            reserved_by: actor_id,
            reserved_authority: reservation_authority,
            reserved_at_ms: now_ms,
            policy_revision: expected_revision,
        };
        self.reserved_joins.insert(request_id, reservation);
        self.revision = next_revision;
        Ok(reservation)
    }

    /// Revalidates the Owner/Admin term that authorized a durable reservation
    /// immediately before an external membership submit.
    ///
    /// A reservation intentionally survives ordinary invite expiry or invite
    /// revocation once it has reserved capacity. It must not, however, let an
    /// administrator submit after that administrator has been revoked (or
    /// revoked and later re-granted under a different authorization generation).
    /// Callers must reject the never-dispatched local intent rather than issue
    /// an external submit when this returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is absent or its stored
    /// Owner/Admin authority is no longer current.
    pub fn validate_reserved_join_authority(
        &self,
        request_id: JoinRequestId,
    ) -> Result<(), GroupPolicyError> {
        let reservation = self
            .reserved_joins
            .get(&request_id)
            .copied()
            .ok_or(GroupPolicyError::ReservedJoinNotFound)?;
        let still_authorized = match reservation.reserved_authority {
            InviteIssuerAuthority::Owner => reservation.reserved_by == self.owner_id,
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => {
                self.administrators.contains(&reservation.reserved_by)
                    && self
                        .administrator_authorization_generations
                        .get(&reservation.reserved_by)
                        .is_some_and(|current| *current == authorization_generation)
            }
        };
        if still_authorized {
            Ok(())
        } else {
            Err(GroupPolicyError::InviteIssuerNoLongerAuthorized)
        }
    }

    /// Finalizes a verified remote membership commit without rechecking invite expiry.
    ///
    /// The caller must validate the remote commit's exact command, candidate,
    /// and predecessor fence before this transition. A reservation survives
    /// invite expiry or revocation because it was already authorized and held
    /// capacity; only a definite remote rejection may release it.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale revision, absent reservation, already
    /// admitted candidate, duplicate finalization, or inconsistent invitation
    /// reservation state.
    pub fn finalize_reserved_join(
        &mut self,
        expected_revision: Revision,
        request_id: JoinRequestId,
        finalized_at_ms: i64,
    ) -> Result<ApprovedJoin, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        if self.approved_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::AlreadyApproved);
        }
        let reservation = self
            .reserved_joins
            .get(&request_id)
            .copied()
            .ok_or(GroupPolicyError::ReservedJoinNotFound)?;
        if self.members.contains(&reservation.candidate_id) {
            return Err(GroupPolicyError::AlreadyMember);
        }
        let invite = self
            .invitations
            .get_mut(&reservation.invite_id)
            .ok_or(GroupPolicyError::ReservationInvariantViolation)?;
        invite.reserved_use_count = invite
            .reserved_use_count
            .checked_sub(1)
            .ok_or(GroupPolicyError::ReservationInvariantViolation)?;
        invite.use_count = invite
            .use_count
            .checked_add(1)
            .ok_or(GroupPolicyError::InviteUseLimitReached)?;
        self.reserved_joins.remove(&request_id);
        self.members.insert(reservation.candidate_id);
        let approved = ApprovedJoin {
            request_id,
            candidate_id: reservation.candidate_id,
            invite_id: reservation.invite_id,
            approved_by: reservation.reserved_by,
            approved_at_ms: finalized_at_ms,
            policy_revision: reservation.policy_revision,
        };
        self.approved_joins.insert(request_id, approved);
        self.revision = next_revision;
        Ok(approved)
    }

    /// Releases a reservation only after a definite non-commit outcome.
    ///
    /// This does not re-open the original request. The membership-command saga
    /// retains the terminal rejection receipt and any later user action must
    /// create a fresh request ID.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale revision, absent reservation, or an
    /// inconsistent invitation reservation count.
    pub fn release_join_reservation(
        &mut self,
        expected_revision: Revision,
        request_id: JoinRequestId,
    ) -> Result<ReservedJoin, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        let reservation = self
            .reserved_joins
            .get(&request_id)
            .copied()
            .ok_or(GroupPolicyError::ReservedJoinNotFound)?;
        let invite = self
            .invitations
            .get_mut(&reservation.invite_id)
            .ok_or(GroupPolicyError::ReservationInvariantViolation)?;
        invite.reserved_use_count = invite
            .reserved_use_count
            .checked_sub(1)
            .ok_or(GroupPolicyError::ReservationInvariantViolation)?;
        self.reserved_joins.remove(&request_id);
        self.revision = next_revision;
        Ok(reservation)
    }

    /// Revalidates and approves one pending request, admitting its candidate.
    ///
    /// The actor authority and all invitation conditions are checked against the
    /// exact current aggregate revision before any membership change. This is the
    /// in-memory authorization seam; a later integration must add MLS-head,
    /// signature/device-proof, command-receipt, and durable transaction fences.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale revision, unauthorized actor, already
    /// approved request, absent pending request, already admitted candidate, or
    /// a currently invalid invitation.
    pub fn approve_join(
        &mut self,
        expected_revision: Revision,
        actor_id: IdentityId,
        request_id: JoinRequestId,
        now_ms: i64,
    ) -> Result<ApprovedJoin, GroupPolicyError> {
        let next_revision = self.next_mutation_revision(expected_revision)?;
        self.ensure_approval_authority(actor_id)?;
        if self.approved_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::AlreadyApproved);
        }
        let pending = self
            .pending_joins
            .get(&request_id)
            .copied()
            .ok_or(GroupPolicyError::PendingJoinNotFound)?;
        if self.members.contains(&pending.candidate_id) {
            return Err(GroupPolicyError::AlreadyMember);
        }
        let invite = self
            .invitations
            .get(&pending.invite_id)
            .copied()
            .ok_or(GroupPolicyError::InviteNotFound)?;
        self.ensure_invite_usable(invite, pending.candidate_id, now_ms)?;

        let invite = self
            .invitations
            .get_mut(&pending.invite_id)
            .ok_or(GroupPolicyError::InviteNotFound)?;
        invite.use_count = invite
            .use_count
            .checked_add(1)
            .ok_or(GroupPolicyError::InviteUseLimitReached)?;
        self.members.insert(pending.candidate_id);
        self.pending_joins.remove(&request_id);
        let approved = ApprovedJoin {
            request_id,
            candidate_id: pending.candidate_id,
            invite_id: pending.invite_id,
            approved_by: actor_id,
            approved_at_ms: now_ms,
            policy_revision: expected_revision,
        };
        self.approved_joins.insert(request_id, approved);
        self.revision = next_revision;
        Ok(approved)
    }

    fn next_mutation_revision(
        &self,
        expected_revision: Revision,
    ) -> Result<Revision, GroupPolicyError> {
        if expected_revision != self.revision {
            return Err(GroupPolicyError::RevisionConflict {
                current: self.revision,
            });
        }
        self.revision
            .checked_next()
            .map_err(|_| GroupPolicyError::CounterExhausted)
    }

    fn ensure_owner(&self, actor_id: IdentityId) -> Result<(), GroupPolicyError> {
        if actor_id == self.owner_id {
            Ok(())
        } else {
            Err(GroupPolicyError::Unauthorized)
        }
    }

    fn ensure_invite_authority(&self, actor_id: IdentityId) -> Result<(), GroupPolicyError> {
        if self.can_issue_invite(actor_id) {
            Ok(())
        } else {
            Err(GroupPolicyError::Unauthorized)
        }
    }

    fn ensure_approval_authority(&self, actor_id: IdentityId) -> Result<(), GroupPolicyError> {
        if self.can_approve_join(actor_id) {
            Ok(())
        } else {
            Err(GroupPolicyError::Unauthorized)
        }
    }

    fn candidate_has_active_join(&self, candidate_id: IdentityId) -> bool {
        self.pending_joins
            .values()
            .any(|pending| pending.candidate_id == candidate_id)
            || self
                .reserved_joins
                .values()
                .any(|reserved| reserved.candidate_id == candidate_id)
    }

    fn ensure_invite_usable(
        &self,
        invite: InviteCapability,
        candidate_id: IdentityId,
        now_ms: i64,
    ) -> Result<(), GroupPolicyError> {
        if invite.revoked {
            return Err(GroupPolicyError::InviteRevoked);
        }
        if now_ms >= invite.expires_at_ms {
            return Err(GroupPolicyError::InviteExpired);
        }
        if invite
            .target_id
            .is_some_and(|target| target != candidate_id)
        {
            return Err(GroupPolicyError::InviteTargetMismatch);
        }
        if !self.invite_issuer_authority_is_current(invite) {
            return Err(GroupPolicyError::InviteIssuerNoLongerAuthorized);
        }
        let occupied_uses = invite
            .use_count
            .checked_add(invite.reserved_use_count)
            .ok_or(GroupPolicyError::InviteUseLimitReached)?;
        if occupied_uses >= invite.max_uses {
            return Err(GroupPolicyError::InviteUseLimitReached);
        }
        Ok(())
    }

    fn invite_issuer_authority(
        &self,
        actor_id: IdentityId,
    ) -> Result<InviteIssuerAuthority, GroupPolicyError> {
        if actor_id == self.owner_id {
            return Ok(InviteIssuerAuthority::Owner);
        }
        if self.administrators.contains(&actor_id) {
            return self
                .administrator_authorization_generations
                .get(&actor_id)
                .copied()
                .map(|authorization_generation| InviteIssuerAuthority::Admin {
                    authorization_generation,
                })
                .ok_or(GroupPolicyError::Unauthorized);
        }
        Err(GroupPolicyError::Unauthorized)
    }

    fn next_admin_authorization_generation(
        &self,
        administrator_id: IdentityId,
    ) -> Result<Revision, GroupPolicyError> {
        self.administrator_authorization_generations
            .get(&administrator_id)
            .copied()
            .map_or(Ok(Revision::INITIAL), |generation| {
                generation
                    .checked_next()
                    .map_err(|_| GroupPolicyError::CounterExhausted)
            })
    }

    fn invite_issuer_authority_is_current(&self, invite: InviteCapability) -> bool {
        match invite.issuer_authority {
            InviteIssuerAuthority::Owner => invite.issuer_id == self.owner_id,
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => {
                self.administrators.contains(&invite.issuer_id)
                    && self
                        .administrator_authorization_generations
                        .get(&invite.issuer_id)
                        .is_some_and(|current| *current == authorization_generation)
            }
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one sequential validator makes every cross-collection invariant visible at rehydration"
)]
fn group_policy_from_snapshot(
    snapshot: &GroupPolicySnapshot,
) -> Result<GroupPolicy, GroupPolicySnapshotError> {
    let members = collect_snapshot_set(&snapshot.members, "duplicate member")?;
    if !members.contains(&snapshot.owner_id) {
        return Err(invalid_snapshot("owner is not a member"));
    }
    let administrators = collect_snapshot_set(&snapshot.administrators, "duplicate administrator")?;
    if administrators.len() > MAX_ADMINS {
        return Err(invalid_snapshot("administrator limit exceeded"));
    }
    if administrators.contains(&snapshot.owner_id) {
        return Err(invalid_snapshot("owner is an administrator"));
    }
    if !administrators.is_subset(&members) {
        return Err(invalid_snapshot("administrator is not a member"));
    }

    let mut administrator_authorization_generations = BTreeMap::new();
    for (identity_id, generation) in &snapshot.administrator_authorization_generations {
        if *identity_id == snapshot.owner_id
            || administrator_authorization_generations
                .insert(*identity_id, *generation)
                .is_some()
        {
            return Err(invalid_snapshot(
                "duplicate or owner administrator generation",
            ));
        }
    }
    if administrators
        .iter()
        .any(|identity_id| !administrator_authorization_generations.contains_key(identity_id))
    {
        return Err(invalid_snapshot("administrator lacks authority generation"));
    }

    let mut invitations = BTreeMap::new();
    for invite in &snapshot.invitations {
        if invite.scope != snapshot.scope || invite.max_uses == 0 {
            return Err(invalid_snapshot("invalid invitation scope or use limit"));
        }
        let occupied_uses = invite
            .use_count
            .checked_add(invite.reserved_use_count)
            .ok_or_else(|| invalid_snapshot("invitation use count overflow"))?;
        if occupied_uses > invite.max_uses || invite.policy_revision > snapshot.revision {
            return Err(invalid_snapshot(
                "invalid invitation use or policy revision",
            ));
        }
        match invite.issuer_authority {
            InviteIssuerAuthority::Owner if invite.issuer_id != snapshot.owner_id => {
                return Err(invalid_snapshot("owner invitation has another issuer"));
            }
            InviteIssuerAuthority::Owner => {}
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => {
                if administrator_authorization_generations
                    .get(&invite.issuer_id)
                    .is_none_or(|current| *current < authorization_generation)
                {
                    return Err(invalid_snapshot("invitation authority generation mismatch"));
                }
            }
        }
        if invitations.insert(invite.invite_id, *invite).is_some() {
            return Err(invalid_snapshot("duplicate invitation"));
        }
    }

    let mut seen_join_ids = BTreeSet::new();
    let mut active_candidates = BTreeSet::new();
    let mut pending_joins = BTreeMap::new();
    for pending in &snapshot.pending_joins {
        if !seen_join_ids.insert(pending.request_id)
            || !invitations.contains_key(&pending.invite_id)
            || members.contains(&pending.candidate_id)
            || !active_candidates.insert(pending.candidate_id)
        {
            return Err(invalid_snapshot("invalid pending join"));
        }
        pending_joins.insert(pending.request_id, *pending);
    }

    let mut expected_reservations = BTreeMap::<InviteCapabilityId, u32>::new();
    let mut reserved_joins = BTreeMap::new();
    for reserved in &snapshot.reserved_joins {
        if !seen_join_ids.insert(reserved.request_id)
            || !invitations.contains_key(&reserved.invite_id)
            || members.contains(&reserved.candidate_id)
            || !active_candidates.insert(reserved.candidate_id)
            || reserved.policy_revision > snapshot.revision
        {
            return Err(invalid_snapshot("invalid membership reservation"));
        }
        match reserved.reserved_authority {
            InviteIssuerAuthority::Owner if reserved.reserved_by != snapshot.owner_id => {
                return Err(invalid_snapshot("owner reservation has another issuer"));
            }
            InviteIssuerAuthority::Owner => {}
            InviteIssuerAuthority::Admin {
                authorization_generation,
            } => {
                if administrator_authorization_generations
                    .get(&reserved.reserved_by)
                    .is_none_or(|current| *current < authorization_generation)
                {
                    return Err(invalid_snapshot(
                        "reservation authority generation mismatch",
                    ));
                }
            }
        }
        increment_snapshot_count(
            &mut expected_reservations,
            reserved.invite_id,
            "reservation count overflow",
        )?;
        reserved_joins.insert(reserved.request_id, *reserved);
    }

    let mut expected_uses = BTreeMap::<InviteCapabilityId, u32>::new();
    let mut approved_joins = BTreeMap::new();
    for approved in &snapshot.approved_joins {
        if !seen_join_ids.insert(approved.request_id)
            || !invitations.contains_key(&approved.invite_id)
            || !members.contains(&approved.candidate_id)
            || approved.policy_revision > snapshot.revision
        {
            return Err(invalid_snapshot("invalid approved join"));
        }
        increment_snapshot_count(
            &mut expected_uses,
            approved.invite_id,
            "approved use count overflow",
        )?;
        approved_joins.insert(approved.request_id, *approved);
    }

    for (invite_id, invite) in &invitations {
        if expected_reservations.get(invite_id).copied().unwrap_or(0) != invite.reserved_use_count
            || expected_uses.get(invite_id).copied().unwrap_or(0) != invite.use_count
        {
            return Err(invalid_snapshot(
                "invitation counters do not match join history",
            ));
        }
    }

    Ok(GroupPolicy {
        scope: snapshot.scope,
        owner_id: snapshot.owner_id,
        administrators,
        administrator_authorization_generations,
        members,
        invitations,
        pending_joins,
        reserved_joins,
        approved_joins,
        revision: snapshot.revision,
    })
}

fn collect_snapshot_set<T>(
    values: &[T],
    duplicate_reason: &'static str,
) -> Result<BTreeSet<T>, GroupPolicySnapshotError>
where
    T: Copy + Ord,
{
    let mut values_by_key = BTreeSet::new();
    for value in values {
        if !values_by_key.insert(*value) {
            return Err(invalid_snapshot(duplicate_reason));
        }
    }
    Ok(values_by_key)
}

fn increment_snapshot_count(
    counts: &mut BTreeMap<InviteCapabilityId, u32>,
    invite_id: InviteCapabilityId,
    overflow_reason: &'static str,
) -> Result<(), GroupPolicySnapshotError> {
    let count = counts.entry(invite_id).or_insert(0);
    *count = count
        .checked_add(1)
        .ok_or_else(|| invalid_snapshot(overflow_reason))?;
    Ok(())
}

const fn authority_persistence(authority: InviteIssuerAuthority) -> GroupAuthorityPersistence {
    match authority {
        InviteIssuerAuthority::Owner => GroupAuthorityPersistence::Owner,
        InviteIssuerAuthority::Admin {
            authorization_generation,
        } => GroupAuthorityPersistence::Admin {
            authorization_generation,
        },
    }
}

const fn authority_from_persistence(authority: GroupAuthorityPersistence) -> InviteIssuerAuthority {
    match authority {
        GroupAuthorityPersistence::Owner => InviteIssuerAuthority::Owner,
        GroupAuthorityPersistence::Admin {
            authorization_generation,
        } => InviteIssuerAuthority::Admin {
            authorization_generation,
        },
    }
}

const fn invalid_snapshot(reason: &'static str) -> GroupPolicySnapshotError {
    GroupPolicySnapshotError::InvalidSnapshot(reason)
}
