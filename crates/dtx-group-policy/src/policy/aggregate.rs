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
