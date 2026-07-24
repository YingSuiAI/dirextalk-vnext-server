#[allow(clippy::missing_errors_doc, clippy::too_many_arguments)]
impl MlsCommitSequencerRepository {
    /// Authenticates a local active member device, verifies its fresh
    /// route/query proof, and returns a bounded consecutive V30 commit page.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_feed_authenticated_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        scope: GroupScope,
        after_epoch: u64,
        limit: usize,
        now_ms: i64,
        expected_signing_key: SigningPublicKey,
        verify_proof: F,
    ) -> Result<MlsCommitFeedPage, GroupPersistenceError>
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
            load_commit_feed_in_transaction(
                session.connection(),
                tenant_id,
                scope,
                actor_identity_id,
                actor_device_id,
                after_epoch,
                limit,
                expected_signing_key,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Verifies a federated active device's fresh route/query proof, then
    /// rechecks local active membership before reading the V30 commit page.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_feed_verified_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        scope: GroupScope,
        after_epoch: u64,
        limit: usize,
        expected_signing_key: SigningPublicKey,
        verify_proof: F,
    ) -> Result<MlsCommitFeedPage, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            verify_proof(actor.signing_key())?;
            load_commit_feed_in_transaction(
                session.connection(),
                tenant_id,
                scope,
                actor.identity_id(),
                actor.device_id(),
                after_epoch,
                limit,
                expected_signing_key,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates the exact actor, recomputes both V2 proof transcripts,
    /// persists the sequencer receipt, and (for an approved identity join)
    /// finalizes the canonical GM1 workflow in the same transaction.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn submit_authenticated<FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: &MlsCommitCommand,
        candidate_signature: Ed25519Signature,
        controller_signature: Option<Ed25519Signature>,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let authenticated_session = authenticated.session();
        if authenticated_session.identity_id() != command.actor_identity_id
            || authenticated_session.device_id() != command.actor_device_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let candidate_key = DeviceSessionRepository::active_device_signing_key_in_transaction(
            session.connection(),
            command.candidate_identity_id,
            command.candidate_device_id,
        )
        .await
        .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
        let expected_candidate_digest = mls_candidate_proof_digest(command)?;
        if expected_candidate_digest != command.candidate_proof_digest {
            return settle(
                session,
                Err(GroupPersistenceError::MlsAuthorizationRejected),
            )
            .await;
        }
        verify_signature(
            candidate_key,
            &mls_candidate_proof_signature_input(command)?,
            candidate_signature,
        )
        .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;

        let authorization_result = match command.authorization {
            MlsCommitAuthorization::ExistingMemberDeviceAdd {
                controller_device_id,
                controller_consent_digest,
            } => {
                let controller_signature =
                    controller_signature.ok_or(GroupPersistenceError::MlsAuthorizationRejected)?;
                let expected = mls_controller_consent_digest(command)?;
                if expected == controller_consent_digest {
                    let controller_key =
                        DeviceSessionRepository::active_device_signing_key_in_transaction(
                            session.connection(),
                            command.candidate_identity_id,
                            controller_device_id,
                        )
                        .await
                        .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
                    verify_signature(
                        controller_key,
                        &mls_controller_consent_signature_input(command)?,
                        controller_signature,
                    )
                    .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)
                } else {
                    Err(GroupPersistenceError::MlsAuthorizationRejected)
                }
            }
            _ if controller_signature.is_some() => {
                Err(GroupPersistenceError::MlsAuthorizationRejected)
            }
            _ => Ok(()),
        };
        if let Err(error) = authorization_result {
            return settle(session, Err(error)).await;
        }
        let result = async {
            let execution = submit_in_transaction(
                session.connection(),
                tenant_id,
                command,
                now_ms,
                sequencer_signing_key,
                |_| Ok(()),
                |_| Ok(()),
                sign_receipt,
            )
            .await?;
            if let MlsCommitAuthorization::ApprovedIdentityJoin {
                membership_command_id,
                ..
            } = command.authorization
            {
                resolve_mls_commit_in_transaction(
                    session.connection(),
                    tenant_id,
                    command.scope,
                    membership_command_id,
                    execution.receipt.receipt_digest,
                    now_ms,
                )
                .await?;
            }
            Ok(execution)
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates the Owner/Admin actor and accepts a V30 approved join
    /// using only the durable candidate join and approval facts. No candidate
    /// signature or private authority is accepted at this boundary.
    pub async fn submit_authenticated_v3<FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: &MlsCommitCommand,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        if command.protocol_version != 3
            || !matches!(
                command.authorization,
                MlsCommitAuthorization::ApprovedIdentityJoinV3 { .. }
            )
        {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        if authenticated.session().identity_id() != command.actor_identity_id
            || authenticated.session().device_id() != command.actor_device_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let result = submit_v3_in_transaction(
            session.connection(),
            tenant_id,
            command,
            now_ms,
            sequencer_signing_key,
            sign_receipt,
        )
        .await;
        settle(session, result).await
    }

    /// Accepts a V30 approved join from a freshly resolved federated active
    /// device. The route/request proof is verified inside the same database
    /// transaction that checks the actor, replays or persists the commit, and
    /// finalizes the exact GM1 approval.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_verified_v3_with_proof<FP, FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        command: &MlsCommitCommand,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        verify_proof: FP,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FP: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        if command.protocol_version != 3
            || !matches!(
                command.authorization,
                MlsCommitAuthorization::ApprovedIdentityJoinV3 { .. }
            )
        {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            if actor.identity_id() != command.actor_identity_id
                || actor.device_id() != command.actor_device_id
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            verify_proof(actor.signing_key())?;
            submit_v3_in_transaction(
                session.connection(),
                tenant_id,
                command,
                now_ms,
                sequencer_signing_key,
                sign_receipt,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates the exact local Owner device and atomically accepts a V4
    /// MLS removal together with the product membership transition.
    pub async fn submit_authenticated_v4<FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: &MlsCommitCommand,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        if command.protocol_version != 4
            || !matches!(
                command.authorization,
                MlsCommitAuthorization::MemberRemovalV4 { .. }
            )
        {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        if authenticated.session().identity_id() != command.actor_identity_id
            || authenticated.session().device_id() != command.actor_device_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let result = submit_in_transaction(
            session.connection(),
            tenant_id,
            command,
            now_ms,
            sequencer_signing_key,
            |_| Ok(()),
            |_| Ok(()),
            sign_receipt,
        )
        .await;
        settle(session, result).await
    }

    /// Verifies a freshly resolved federated Owner device proof and accepts
    /// the same V4 removal transaction used by local sessions.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_verified_v4_with_proof<FP, FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        command: &MlsCommitCommand,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        verify_proof: FP,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FP: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        if command.protocol_version != 4
            || !matches!(
                command.authorization,
                MlsCommitAuthorization::MemberRemovalV4 { .. }
            )
        {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            if actor.identity_id() != command.actor_identity_id
                || actor.device_id() != command.actor_device_id
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            verify_proof(actor.signing_key())?;
            submit_in_transaction(
                session.connection(),
                tenant_id,
                command,
                now_ms,
                sequencer_signing_key,
                |_| Ok(()),
                |_| Ok(()),
                sign_receipt,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Accepts a federated V40 recovery add or exact revoked-leaf removal.
    ///
    /// The caller must resolve the controller from the authoritative identity
    /// origin and validate the operation-specific fresh origin facts. This
    /// transaction then verifies the route proof and controller consent before
    /// replay lookup or persistence. It never reads an `identity.*` table.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_verified_v5_with_proof<FP, FA, FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        command: &MlsCommitCommand,
        controller_signature: Ed25519Signature,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        verify_proof: FP,
        verify_origin_authorization: FA,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FP: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
        FA: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        if command.protocol_version != 5
            || !matches!(
                command.authorization,
                MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd { .. }
                    | MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
            )
        {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            if actor.identity_id() != command.actor_identity_id
                || actor.device_id() != command.actor_device_id
                || command.actor_identity_id != command.candidate_identity_id
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            verify_proof(actor.signing_key())?;
            let zero = Sha256Digest::from_bytes([0; 32]);
            let expected_controller_digest = mls_v5_controller_consent_digest(command)?;
            match command.authorization {
                MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                    controller_device_id,
                    controller_consent_digest,
                    recovery_scope_digest,
                    ..
                } => {
                    if controller_device_id != command.actor_device_id
                        || controller_consent_digest != expected_controller_digest
                        || recovery_scope_digest != mls_recovery_scope_digest(command.scope)?
                        || command.candidate_key_package_digest == zero
                        || command.welcome_digest == zero
                    {
                        return Err(GroupPersistenceError::MlsAuthorizationRejected);
                    }
                }
                MlsCommitAuthorization::ExistingMemberDeviceRemove { .. } => {
                    if command.actor_device_id == command.candidate_device_id
                        || command.candidate_key_package_digest != zero
                        || command.candidate_proof_digest != zero
                        || command.welcome_digest != zero
                    {
                        return Err(GroupPersistenceError::MlsAuthorizationRejected);
                    }
                }
                _ => return Err(GroupPersistenceError::MlsAuthorizationRejected),
            }
            verify_origin_authorization(command)?;
            verify_signature(
                actor.signing_key(),
                &mls_v5_controller_consent_signature_input(command)?,
                controller_signature,
            )
            .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
            submit_in_transaction(
                session.connection(),
                tenant_id,
                command,
                now_ms,
                sequencer_signing_key,
                |_| Ok(()),
                |_| Ok(()),
                sign_receipt,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates an active same-identity controller and accepts a V40
    /// recovery add or revoked-leaf removal. No candidate final-transcript
    /// signature is accepted at this boundary.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn submit_authenticated_v5<FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: &MlsCommitCommand,
        controller_signature: Ed25519Signature,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        if command.protocol_version != 5
            || !matches!(
                command.authorization,
                MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd { .. }
                    | MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
            )
        {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        if authenticated.session().identity_id() != command.actor_identity_id
            || authenticated.session().device_id() != command.actor_device_id
            || command.actor_identity_id != command.candidate_identity_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let expected_controller_digest = mls_v5_controller_consent_digest(command)?;
        let authorization = async {
            match command.authorization {
                MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                    controller_device_id,
                    controller_consent_digest,
                    recovery_request_id,
                    recovery_request_digest,
                    recovery_scope_digest,
                } => {
                    if controller_device_id != command.actor_device_id
                        || controller_consent_digest != expected_controller_digest
                        || recovery_scope_digest != mls_recovery_scope_digest(command.scope)?
                        || command.candidate_key_package_digest == Sha256Digest::from_bytes([0; 32])
                        || command.welcome_digest == Sha256Digest::from_bytes([0; 32])
                    {
                        return Err(GroupPersistenceError::MlsAuthorizationRejected);
                    }
                    DeviceSessionRepository::active_device_signing_key_in_transaction(
                        session.connection(),
                        command.candidate_identity_id,
                        command.candidate_device_id,
                    )
                    .await
                    .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
                    let approved_head: Option<Vec<u8>> = sqlx::query_scalar(
                        "SELECT approved_head_hash
                           FROM identity.history_recovery_request_authorized($1,$2,$3,$4,$5)",
                    )
                    .bind(command.candidate_identity_id.to_string())
                    .bind(*recovery_request_id.as_uuid())
                    .bind(recovery_request_digest.as_bytes().as_slice())
                    .bind(*command.candidate_device_id.as_uuid())
                    .bind(now_ms)
                    .fetch_optional(&mut *session.connection())
                    .await?;
                    let current_snapshot = lock_and_load_active_snapshot(
                        session.connection(),
                        command.candidate_identity_id,
                    )
                    .await
                    .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
                    let request_ok = approved_head
                        .map(|head| digest(head, "history recovery approved head"))
                        .transpose()?
                        == Some(current_snapshot.head().hash());
                    let package_ok: bool = sqlx::query_scalar(
                        "SELECT identity.scoped_key_package_claim_authorized($1,$2,$3,$4,$5,$6)",
                    )
                    .bind(command.candidate_identity_id.to_string())
                    .bind(*command.candidate_device_id.as_uuid())
                    .bind(command.candidate_key_package_digest.as_bytes().as_slice())
                    .bind(recovery_request_digest.as_bytes().as_slice())
                    .bind(recovery_scope_digest.as_bytes().as_slice())
                    .bind(*controller_device_id.as_uuid())
                    .fetch_one(&mut *session.connection())
                    .await?;
                    if !request_ok || !package_ok {
                        return Err(GroupPersistenceError::MlsAuthorizationRejected);
                    }
                }
                MlsCommitAuthorization::ExistingMemberDeviceRemove {
                    identity_revoke_head_digest,
                } => {
                    if command.welcome_digest != Sha256Digest::from_bytes([0; 32]) {
                        return Err(GroupPersistenceError::MlsAuthorizationRejected);
                    }
                    let snapshot = lock_and_load_active_snapshot(
                        session.connection(),
                        command.candidate_identity_id,
                    )
                    .await
                    .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
                    let exact_head_event: Vec<u8> = sqlx::query_scalar(
                        "SELECT event_bytes FROM identity.log_entries
                          WHERE identity_id=$1 AND sequence=$2",
                    )
                    .bind(command.candidate_identity_id.to_string())
                    .bind(
                        i64::try_from(snapshot.head().sequence().get()).map_err(|_| {
                            GroupPersistenceError::CorruptData("identity revoke head sequence")
                        })?,
                    )
                    .fetch_one(&mut *session.connection())
                    .await?;
                    let head_event = IdentityLogEventV1::decode_and_verify(&exact_head_event)
                        .map_err(|_| {
                            GroupPersistenceError::CorruptData("identity revoke head event")
                        })?;
                    let exact_target_revoke = head_event.identity_id()
                        == command.candidate_identity_id
                        && head_event.sequence() == snapshot.head().sequence()
                        && head_event.entry_hash().map_err(|_| {
                            GroupPersistenceError::CorruptData("identity revoke head digest")
                        })? == snapshot.head().hash()
                        && matches!(
                            head_event.payload(),
                            IdentityLogEventPayloadV1::DeviceRevoke { device_id }
                                if *device_id == command.candidate_device_id
                        );
                    if snapshot.head().hash() != identity_revoke_head_digest
                        || snapshot
                            .projection()
                            .device_status(command.candidate_device_id)
                            != Some(DeviceStatusV1::Revoked)
                        || !exact_target_revoke
                    {
                        return Err(GroupPersistenceError::MlsAuthorizationRejected);
                    }
                }
                _ => return Err(GroupPersistenceError::MlsAuthorizationRejected),
            }
            verify_signature(
                authenticated.signing_key(),
                &mls_v5_controller_consent_signature_input(command)?,
                controller_signature,
            )
            .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)
        }
        .await;
        if let Err(error) = authorization {
            return settle(session, Err(error)).await;
        }
        let result = submit_in_transaction(
            session.connection(),
            tenant_id,
            command,
            now_ms,
            sequencer_signing_key,
            |_| Ok(()),
            |_| Ok(()),
            sign_receipt,
        )
        .await;
        settle(session, result).await
    }
}
