#[allow(clippy::missing_errors_doc, clippy::too_many_arguments)]
impl MlsCommitSequencerRepository {
    /// Authenticates an actor or candidate before returning an immutable receipt.
    pub async fn receipt_authenticated(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        scope: GroupScope,
        submission_id: RequestId,
        now_ms: i64,
        expected_signing_key: SigningPublicKey,
    ) -> Result<MlsCommitReceipt, GroupPersistenceError> {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let result = async {
            let receipt = load_receipt(
                session.connection(),
                tenant_id,
                scope,
                submission_id,
                expected_signing_key,
            )
            .await?
            .ok_or(GroupPersistenceError::GroupNotFound)?;
            let allowed: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_commit_intents
                  WHERE tenant_id=$1 AND submission_id=$2 AND scope_kind=$3 AND scope_id=$4
                    AND ((actor_identity_id=$5 AND actor_device_id=$6)
                      OR (candidate_identity_id=$5 AND candidate_device_id=$6)))",
            )
            .bind(Uuid::from(tenant_id))
            .bind(Uuid::from(submission_id))
            .bind(scope_columns(scope).0)
            .bind(scope_columns(scope).1)
            .bind(authenticated.session().identity_id().to_string())
            .bind(Uuid::from(authenticated.session().device_id()))
            .fetch_one(session.connection())
            .await?;
            if !allowed {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            Ok(receipt)
        }
        .await;
        settle(session, result).await
    }

    /// Returns an immutable V30/V32/V40 receipt to the freshly resolved federated
    /// submission actor. Proof verification and durable actor/request/key
    /// binding are checked in the same transaction as receipt readback.
    #[allow(clippy::too_many_arguments)]
    pub async fn receipt_verified_v3_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        scope: GroupScope,
        submission_id: RequestId,
        expected_request_digest: Sha256Digest,
        expected_idempotency_key_hash: Sha256Digest,
        expected_signing_key: SigningPublicKey,
        verify_proof: F,
    ) -> Result<MlsCommitReceipt, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            verify_proof(actor.signing_key())?;
            let (kind, id) = scope_columns(scope);
            let allowed: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_commit_intents
                  WHERE tenant_id=$1 AND submission_id=$2 AND scope_kind=$3 AND scope_id=$4
                    AND protocol_version IN (3,4) AND actor_identity_id=$5 AND actor_device_id=$6
                    AND request_digest=$7 AND idempotency_key_hash=$8)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(Uuid::from(submission_id))
            .bind(kind)
            .bind(id)
            .bind(actor.identity_id().to_string())
            .bind(Uuid::from(actor.device_id()))
            .bind(expected_request_digest.as_bytes().as_slice())
            .bind(expected_idempotency_key_hash.as_bytes().as_slice())
            .fetch_one(session.connection())
            .await?;
            if !allowed {
                return Err(GroupPersistenceError::ActionProofRejected);
            }
            load_receipt(
                session.connection(),
                tenant_id,
                scope,
                submission_id,
                expected_signing_key,
            )
            .await?
            .filter(|receipt| matches!(receipt.protocol_version(), 3 | 4))
            .ok_or(GroupPersistenceError::ActionProofRejected)
        }
        .await;
        settle(session, result).await
    }

    /// Returns a federated V40 receipt together with the exact immutable
    /// coordinates that the HTTP boundary must revalidate at the identity
    /// origin before emitting that receipt.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one transactional read validates every persisted V5 replay coordinate"
    )]
    pub async fn receipt_verified_v5_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        scope: GroupScope,
        submission_id: RequestId,
        expected_request_digest: Sha256Digest,
        expected_idempotency_key_hash: Sha256Digest,
        expected_signing_key: SigningPublicKey,
        verify_proof: F,
    ) -> Result<(MlsCommitReceipt, MlsV5FederatedAuthorizationFacts), GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            verify_proof(actor.signing_key())?;
            let (kind, id) = scope_columns(scope);
            let row = sqlx::query(
                "SELECT authorization_kind,candidate_identity_id,candidate_device_id,
                        candidate_key_package_digest,controller_device_id,
                        history_recovery_request_id,recovery_request_digest,
                        recovery_scope_digest,identity_revoke_head_digest
                   FROM groups.mls_commit_intents
                  WHERE tenant_id=$1 AND submission_id=$2 AND scope_kind=$3 AND scope_id=$4
                    AND protocol_version=5 AND actor_identity_id=$5 AND actor_device_id=$6
                    AND request_digest=$7 AND idempotency_key_hash=$8",
            )
            .bind(Uuid::from(tenant_id))
            .bind(Uuid::from(submission_id))
            .bind(kind)
            .bind(id)
            .bind(actor.identity_id().to_string())
            .bind(Uuid::from(actor.device_id()))
            .bind(expected_request_digest.as_bytes().as_slice())
            .bind(expected_idempotency_key_hash.as_bytes().as_slice())
            .fetch_optional(session.connection())
            .await?
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
            let identity_id = row
                .try_get::<String, _>("candidate_identity_id")?
                .parse::<IdentityId>()
                .map_err(|_| GroupPersistenceError::CorruptData("MLS V5 identity"))?;
            let candidate_device_id =
                DeviceId::try_from(row.try_get::<Uuid, _>("candidate_device_id")?)
                    .map_err(|_| GroupPersistenceError::CorruptData("MLS V5 candidate device"))?;
            let candidate_key_package_digest = digest(
                row.try_get("candidate_key_package_digest")?,
                "MLS V5 key package",
            )?;
            let authorization_kind: String = row.try_get("authorization_kind")?;
            let (controller_device_id, authorization) = match authorization_kind.as_str() {
                "existing_member_device_add" => {
                    let controller_device_id =
                        DeviceId::try_from(row.try_get::<Uuid, _>("controller_device_id")?)
                            .map_err(|_| {
                                GroupPersistenceError::CorruptData("MLS V5 controller device")
                            })?;
                    let recovery_request_id = DeviceEnrollmentChallengeId::try_from(
                        row.try_get::<Uuid, _>("history_recovery_request_id")?,
                    )
                    .map_err(|_| GroupPersistenceError::CorruptData("MLS V5 recovery request"))?;
                    let recovery_request_digest = digest(
                        row.try_get("recovery_request_digest")?,
                        "MLS V5 recovery request",
                    )?;
                    let recovery_scope_digest = digest(
                        row.try_get("recovery_scope_digest")?,
                        "MLS V5 recovery scope",
                    )?;
                    (
                        controller_device_id,
                        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                            controller_device_id,
                            controller_consent_digest: Sha256Digest::from_bytes([0; 32]),
                            recovery_request_id,
                            recovery_request_digest,
                            recovery_scope_digest,
                        },
                    )
                }
                "existing_member_device_remove" => {
                    let identity_revoke_head_digest = digest(
                        row.try_get("identity_revoke_head_digest")?,
                        "MLS V5 identity revoke head",
                    )?;
                    (
                        actor.device_id(),
                        MlsCommitAuthorization::ExistingMemberDeviceRemove {
                            identity_revoke_head_digest,
                        },
                    )
                }
                _ => {
                    return Err(GroupPersistenceError::CorruptData(
                        "MLS V5 authorization kind",
                    ));
                }
            };
            if identity_id != actor.identity_id() || controller_device_id != actor.device_id() {
                return Err(GroupPersistenceError::ActionProofRejected);
            }
            let receipt = load_receipt(
                session.connection(),
                tenant_id,
                scope,
                submission_id,
                expected_signing_key,
            )
            .await?
            .filter(|receipt| receipt.protocol_version() == 5)
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
            Ok((
                receipt,
                MlsV5FederatedAuthorizationFacts {
                    identity_id,
                    controller_device_id,
                    candidate_device_id,
                    candidate_key_package_digest,
                    authorization,
                },
            ))
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates the exact candidate device before activating its leaf.
    pub async fn confirm_authenticated(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        confirmation: MlsDeviceJoinConfirmation,
        now_ms: i64,
    ) -> Result<bool, GroupPersistenceError> {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let authenticated_session = authenticated.session();
        if authenticated_session.identity_id() != confirmation.identity_id
            || authenticated_session.device_id() != confirmation.device_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let result = confirm_in_transaction(
            session.connection(),
            tenant_id,
            confirmation,
            now_ms,
            authenticated.signing_key(),
        )
        .await;
        settle(session, result).await
    }

    /// Confirms a V30 leaf after the Group Node has freshly resolved the exact
    /// federated candidate device and verified its route/body-bound proof.
    pub async fn confirm_verified(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        confirmation: MlsDeviceJoinConfirmation,
        now_ms: i64,
        candidate_signing_key: SigningPublicKey,
    ) -> Result<bool, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = confirm_in_transaction(
            session.connection(),
            tenant_id,
            confirmation,
            now_ms,
            candidate_signing_key,
        )
        .await;
        settle(session, result).await
    }

    /// CAS-submits an opaque commit, writes intent/outbox first, then signs and stores its receipt.
    ///
    /// For [`MlsCommitAuthorization::ApprovedIdentityJoin`], the worker that
    /// delivers this outbox receipt must next feed its commit reference into
    /// [`crate::GroupMembershipRepository::resolve_action`] as
    /// `SequencerResolution::Committed`. Until that GM1 transaction adds the
    /// identity to `groups.members`, [`Self::is_device_active`] remains false
    /// even after device confirmation. This repository intentionally does not
    /// forge that terminal policy transition.
    pub async fn submit<FC, FA, FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        command: &MlsCommitCommand,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        verify_candidate_proof: FC,
        verify_authorization_proof: FA,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FC: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
        FA: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = submit_in_transaction(
            session.connection(),
            tenant_id,
            command,
            now_ms,
            sequencer_signing_key,
            verify_candidate_proof,
            verify_authorization_proof,
            sign_receipt,
        )
        .await;
        settle(session, result).await
    }

    /// Queries the original immutable receipt after any lost response.
    pub async fn receipt(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        scope: GroupScope,
        submission_id: RequestId,
        expected_signing_key: SigningPublicKey,
    ) -> Result<MlsCommitReceipt, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = load_receipt(
            session.connection(),
            tenant_id,
            scope,
            submission_id,
            expected_signing_key,
        )
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound);
        settle(session, result).await
    }

    /// Confirms that the exact new device processed the signed receipt/head.
    pub async fn confirm(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        confirmation: MlsDeviceJoinConfirmation,
        now_ms: i64,
        candidate_signing_key: SigningPublicKey,
    ) -> Result<bool, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = confirm_in_transaction(
            session.connection(),
            tenant_id,
            confirmation,
            now_ms,
            candidate_signing_key,
        )
        .await;
        settle(session, result).await
    }

    /// Exact Router admission query. Identity-level membership alone is insufficient.
    pub async fn is_device_active(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        scope: GroupScope,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<bool, GroupPersistenceError> {
        let (kind, id) = scope_columns(scope);
        let mut session = store.begin(tenant_id).await?;
        let result = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM groups.mls_device_members device
                 JOIN groups.members member USING (tenant_id,scope_kind,scope_id,identity_id)
                  WHERE device.tenant_id=$1 AND device.scope_kind=$2 AND device.scope_id=$3
                    AND device.identity_id=$4 AND device.device_id=$5 AND device.state='active')",
        )
        .bind(Uuid::from(tenant_id))
        .bind(kind)
        .bind(id)
        .bind(identity_id.to_string())
        .bind(Uuid::from(device_id))
        .fetch_one(session.connection())
        .await
        .map_err(Into::into);
        settle(session, result).await
    }
}
