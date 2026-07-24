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
            ensure_authenticated_actor(authenticated.session(), &command.context())?;
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
            ensure_verified_actor(actor, &command.context())?;
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
            ensure_authenticated_actor(authenticated, &command.context())?;
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
            ensure_authenticated_actor(authenticated.session(), &command.context())?;
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
            ensure_verified_actor(actor, &command.context())?;
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

/// Applies the product-policy half of an Owner-authored member removal in the
/// caller's MLS Sequencer transaction.
///
/// The normalized member row is explicitly deleted because the canonical
/// policy persistence path is otherwise append/update oriented. Its V4 intent
/// must already exist in this transaction so the database removal guard can
/// bind the DELETE to the exact product and parent-MLS heads. A current
/// administrator term is deactivated by the same persisted policy image.
pub(crate) async fn remove_group_member_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    expected_revision: Revision,
    actor_identity_id: IdentityId,
    target_identity_id: IdentityId,
    now_ms: i64,
) -> Result<Revision, GroupPersistenceError> {
    let key = ScopeKey::from_scope(tenant_id, scope);
    let mut policy = load_policy(connection, key, true)
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound)?;
    let revision =
        policy.remove_member(expected_revision, actor_identity_id, target_identity_id)?;
    persist_policy(connection, tenant_id, &policy, now_ms, false).await?;
    let deleted = sqlx::query(
        "DELETE FROM groups.members
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4",
    )
    .bind(key.tenant_id())
    .bind(key.kind)
    .bind(key.id())
    .bind(target_identity_id.to_string())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if deleted != 1 {
        return Err(GroupPersistenceError::CorruptData(
            "group removal target membership",
        ));
    }
    Ok(revision)
}
