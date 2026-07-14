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
    /// The request identity is already pending for a candidate.
    JoinRequestAlreadyPending,
    /// No pending request exists for the supplied identity.
    PendingJoinNotFound,
    /// The request has already been approved and cannot admit another member.
    AlreadyApproved,
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
            Self::JoinRequestAlreadyPending => {
                formatter.write_str("group join request is already pending")
            }
            Self::PendingJoinNotFound => {
                formatter.write_str("pending group join request was not found")
            }
            Self::AlreadyApproved => formatter.write_str("group join request is already approved"),
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

    /// Looks up an immutable approval record.
    #[must_use]
    pub fn approved_join(&self, request_id: JoinRequestId) -> Option<&ApprovedJoin> {
        self.approved_joins.get(&request_id)
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
        if self.approved_joins.contains_key(&request_id) {
            return Err(GroupPolicyError::AlreadyApproved);
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
        if invite.use_count >= invite.max_uses {
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
