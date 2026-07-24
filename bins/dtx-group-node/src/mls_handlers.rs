#[allow(
    clippy::too_many_lines,
    reason = "one submission boundary dispatches the versioned local and federated authentication paths"
)]
async fn submit_mls_commit(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, submission_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let submission_id = parse_request_id(&submission_id)?;
        let expected_path = format!(
            "{}/mls-commits/{submission_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let idempotency_key_hash = mls_idempotency_key_hash(&parts.headers)?;
        let parsed = parse_mls_commit_body(
            &parts.headers,
            body,
            scope,
            submission_id,
            idempotency_key_hash,
        )
        .await?;
        let now = state.now()?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let signing_public_key = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes())
            .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        let execution = if let Some(identity_origin) =
            single_optional_header(&parts.headers, IDENTITY_ORIGIN_HEADER)?
        {
            submit_federated_mls_commit(
                &state,
                &parts.headers,
                identity_origin,
                &expected_path,
                &parsed.command,
                parsed.controller_signature,
                now,
                signing_public_key,
                Arc::clone(signing_key),
            )
            .await
        } else if matches!(parsed.command.protocol_version(), 3..=5) {
            if parts.headers.contains_key(MLS_COMMIT_PROOF_HEADER) {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            let signer = Arc::clone(signing_key);
            if parsed.command.protocol_version() == 5 {
                state
                    .mls_repository
                    .submit_authenticated_v5(
                        &state.store,
                        state.tenant_id,
                        &credential,
                        &parsed.command,
                        parsed
                            .controller_signature
                            .ok_or(GroupFailure::InvalidRequest)?,
                        now.get(),
                        signing_public_key,
                        move |input| {
                            Ok(Ed25519Signature::from_bytes(signer.sign(input).to_bytes()))
                        },
                    )
                    .await
                    .map_err(|error| map_persistence_error(&error))
            } else if parsed.command.protocol_version() == 4 {
                state
                    .mls_repository
                    .submit_authenticated_v4(
                        &state.store,
                        state.tenant_id,
                        &credential,
                        &parsed.command,
                        now.get(),
                        signing_public_key,
                        move |input| {
                            Ok(Ed25519Signature::from_bytes(signer.sign(input).to_bytes()))
                        },
                    )
                    .await
                    .map_err(|error| map_persistence_error(&error))
            } else {
                state
                    .mls_repository
                    .submit_authenticated_v3(
                        &state.store,
                        state.tenant_id,
                        &credential,
                        &parsed.command,
                        now.get(),
                        signing_public_key,
                        move |input| {
                            Ok(Ed25519Signature::from_bytes(signer.sign(input).to_bytes()))
                        },
                    )
                    .await
                    .map_err(|error| map_persistence_error(&error))
            }
        } else {
            if parts.headers.contains_key(MLS_COMMIT_PROOF_HEADER) {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            let signer = Arc::clone(signing_key);
            state
                .mls_repository
                .submit_authenticated(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    &parsed.command,
                    parsed
                        .candidate_signature
                        .ok_or(GroupFailure::InvalidRequest)?,
                    parsed.controller_signature,
                    now.get(),
                    signing_public_key,
                    move |input| Ok(Ed25519Signature::from_bytes(signer.sign(input).to_bytes())),
                )
                .await
                .map_err(|error| map_persistence_error(&error))
        }?;
        mls_commit_response(&execution)
    }
    .await;
    finish(result, request_id)
}

async fn get_mls_commit_receipt(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, submission_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let submission_id = parse_request_id(&submission_id)?;
        let expected_path = format!(
            "{}/mls-commits/{submission_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        require_empty_get(&parts.headers, body).await?;
        let now = state.now()?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let signing_public_key = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes())
            .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        let receipt = if let Some(identity_origin) =
            single_optional_header(&parts.headers, IDENTITY_ORIGIN_HEADER)?
        {
            load_federated_mls_commit_receipt(
                &state,
                &parts.headers,
                identity_origin,
                &expected_path,
                scope,
                submission_id,
                now,
                signing_public_key,
            )
            .await
        } else {
            if parts.headers.contains_key(MLS_COMMIT_PROOF_HEADER) {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            state
                .mls_repository
                .receipt_authenticated(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    scope,
                    submission_id,
                    now.get(),
                    signing_public_key,
                )
                .await
                .map_err(|error| map_persistence_error(&error))
        }?;
        Ok(cbor_response(
            StatusCode::OK,
            encode_mls_commit_receipt(&receipt)?,
            mls_commit_receipt_content_type(receipt.protocol_version()),
        ))
    }
    .await;
    finish(result, request_id)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the V3/V4/V5 federated proof dispatch stays contiguous at the HTTP boundary"
)]
async fn submit_federated_mls_commit(
    state: &GroupNodeState,
    headers: &HeaderMap,
    identity_origin: &str,
    expected_path: &str,
    command: &MlsCommitCommand,
    controller_signature: Option<Ed25519Signature>,
    now: UtcMillis,
    signing_public_key: SigningPublicKey,
    signing_key: Arc<SigningKey>,
) -> Result<MlsCommitExecution, GroupFailure> {
    if !matches!(command.protocol_version(), 3..=5) || headers.contains_key(header::AUTHORIZATION) {
        return Err(GroupFailure::ActionProofInvalid);
    }
    let proof = parse_mls_commit_proof_header(headers)?;
    if proof.identity_origin != identity_origin {
        return Err(GroupFailure::ActionProofInvalid);
    }
    if command.protocol_version() == 5 {
        return submit_federated_mls_v5_commit(
            state,
            identity_origin,
            expected_path,
            command,
            controller_signature.ok_or(GroupFailure::InvalidRequest)?,
            proof,
            now,
            signing_public_key,
            signing_key,
        )
        .await;
    }
    let actor_signing_key = state
        .federated_identity
        .active_device_signing_key(
            identity_origin,
            proof.actor_identity_id,
            proof.actor_device_id,
        )
        .await
        .map_err(map_federated_identity_error)?;
    let actor = VerifiedDeviceActor::new(
        proof.actor_identity_id,
        proof.actor_device_id,
        actor_signing_key,
    );
    let expected_path = expected_path.to_owned();
    let expected_origin = identity_origin.to_owned();
    let expected_scope = command.scope();
    let expected_submission_id = command.submission_id();
    let expected_actor_identity_id = command.actor_identity_id();
    let expected_actor_device_id = command.actor_device_id();
    let expected_request_digest = command.request_digest();
    let expected_idempotency_key_hash = command.idempotency_key_hash();
    let result = if command.protocol_version() == 4 {
        state
            .mls_repository
            .submit_verified_v4_with_proof(
                &state.store,
                state.tenant_id,
                actor,
                command,
                now.get(),
                signing_public_key,
                move |device_signing_key| {
                    proof.verify(
                        MlsCommitProofAction::Submit,
                        &expected_path,
                        expected_scope,
                        expected_submission_id,
                        expected_actor_identity_id,
                        expected_actor_device_id,
                        expected_request_digest,
                        expected_idempotency_key_hash,
                        &expected_origin,
                        now,
                        device_signing_key,
                    )
                },
                move |input| {
                    Ok(Ed25519Signature::from_bytes(
                        signing_key.sign(input).to_bytes(),
                    ))
                },
            )
            .await
    } else {
        state
            .mls_repository
            .submit_verified_v3_with_proof(
                &state.store,
                state.tenant_id,
                actor,
                command,
                now.get(),
                signing_public_key,
                move |device_signing_key| {
                    proof.verify(
                        MlsCommitProofAction::Submit,
                        &expected_path,
                        expected_scope,
                        expected_submission_id,
                        expected_actor_identity_id,
                        expected_actor_device_id,
                        expected_request_digest,
                        expected_idempotency_key_hash,
                        &expected_origin,
                        now,
                        device_signing_key,
                    )
                },
                move |input| {
                    Ok(Ed25519Signature::from_bytes(
                        signing_key.sign(input).to_bytes(),
                    ))
                },
            )
            .await
    };
    result.map_err(|error| map_persistence_error(&error))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "fresh origin facts and controller proof are validated in one fail-closed V5 path"
)]
async fn submit_federated_mls_v5_commit(
    state: &GroupNodeState,
    identity_origin: &str,
    expected_path: &str,
    command: &MlsCommitCommand,
    controller_signature: Ed25519Signature,
    proof: MlsCommitProof,
    now: UtcMillis,
    signing_public_key: SigningPublicKey,
    signing_key: Arc<SigningKey>,
) -> Result<MlsCommitExecution, GroupFailure> {
    let (active_controller, recovery_authorization) = match command.authorization() {
        MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
            controller_device_id,
            recovery_request_id,
            recovery_request_digest,
            recovery_scope_digest,
            ..
        } => {
            let active_controller = state
                .federated_identity
                .active_device(
                    identity_origin,
                    command.candidate_identity_id(),
                    controller_device_id,
                )
                .await
                .map_err(map_federated_identity_error)?;
            let query = MlsV5RecoveryAuthorizationQuery::new(
                command.candidate_identity_id(),
                recovery_request_id,
                command.candidate_device_id(),
                controller_device_id,
                active_controller.head_digest(),
                command.candidate_key_package_digest(),
                recovery_request_digest,
                recovery_scope_digest,
            );
            let projection = state
                .federated_identity
                .mls_v5_recovery_authorization(identity_origin, query, now)
                .await
                .map_err(map_federated_identity_error)?;
            (active_controller, Some((query, projection)))
        }
        MlsCommitAuthorization::ExistingMemberDeviceRemove {
            identity_revoke_head_digest,
        } => (
            state
                .federated_identity
                .active_device_with_terminal_revoke(
                    identity_origin,
                    command.candidate_identity_id(),
                    command.actor_device_id(),
                    command.candidate_device_id(),
                    identity_revoke_head_digest,
                )
                .await
                .map_err(map_federated_identity_error)?,
            None,
        ),
        _ => return Err(GroupFailure::ActionProofInvalid),
    };
    let actor = VerifiedDeviceActor::new(
        active_controller.identity_id(),
        active_controller.device_id(),
        active_controller.signing_key(),
    );
    let expected_path = expected_path.to_owned();
    let expected_origin = identity_origin.to_owned();
    let expected_scope = command.scope();
    let expected_submission_id = command.submission_id();
    let expected_actor_identity_id = command.actor_identity_id();
    let expected_actor_device_id = command.actor_device_id();
    let expected_request_digest = command.request_digest();
    let expected_idempotency_key_hash = command.idempotency_key_hash();
    state
        .mls_repository
        .submit_verified_v5_with_proof(
            &state.store,
            state.tenant_id,
            actor,
            command,
            controller_signature,
            now.get(),
            signing_public_key,
            move |device_signing_key| {
                proof.verify(
                    MlsCommitProofAction::Submit,
                    &expected_path,
                    expected_scope,
                    expected_submission_id,
                    expected_actor_identity_id,
                    expected_actor_device_id,
                    expected_request_digest,
                    expected_idempotency_key_hash,
                    &expected_origin,
                    now,
                    device_signing_key,
                )
            },
            move |verified_command| match (
                verified_command.authorization(),
                recovery_authorization.as_ref(),
            ) {
                (
                    MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                        controller_device_id,
                        recovery_request_id,
                        recovery_request_digest,
                        recovery_scope_digest,
                        ..
                    },
                    Some((query, projection)),
                ) => {
                    let expected_query = MlsV5RecoveryAuthorizationQuery::new(
                        verified_command.candidate_identity_id(),
                        recovery_request_id,
                        verified_command.candidate_device_id(),
                        controller_device_id,
                        active_controller.head_digest(),
                        verified_command.candidate_key_package_digest(),
                        recovery_request_digest,
                        recovery_scope_digest,
                    );
                    if *query == expected_query
                        && projection.query() == expected_query
                        && projection.expires_at() > now
                    {
                        Ok(())
                    } else {
                        Err(GroupPersistenceError::MlsAuthorizationRejected)
                    }
                }
                (
                    MlsCommitAuthorization::ExistingMemberDeviceRemove {
                        identity_revoke_head_digest,
                    },
                    None,
                ) if identity_revoke_head_digest == active_controller.head_digest() => Ok(()),
                _ => Err(GroupPersistenceError::MlsAuthorizationRejected),
            },
            move |input| {
                Ok(Ed25519Signature::from_bytes(
                    signing_key.sign(input).to_bytes(),
                ))
            },
        )
        .await
        .map_err(|error| map_persistence_error(&error))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "receipt proof and version-specific origin revalidation stay contiguous"
)]
async fn load_federated_mls_commit_receipt(
    state: &GroupNodeState,
    headers: &HeaderMap,
    identity_origin: &str,
    expected_path: &str,
    scope: GroupScope,
    submission_id: RequestId,
    now: UtcMillis,
    signing_public_key: SigningPublicKey,
) -> Result<MlsCommitReceipt, GroupFailure> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(GroupFailure::ActionProofInvalid);
    }
    let expected_protocol_version = if has_exact_accept(headers, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE)
    {
        5
    } else if has_exact_accept(headers, MLS_COMMIT_RECEIPT_V4_CONTENT_TYPE) {
        4
    } else {
        require_exact_accept(headers, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE)?;
        3
    };
    let proof = parse_mls_commit_proof_header(headers)?;
    if proof.identity_origin != identity_origin {
        return Err(GroupFailure::ActionProofInvalid);
    }
    let active_actor = state
        .federated_identity
        .active_device(
            identity_origin,
            proof.actor_identity_id,
            proof.actor_device_id,
        )
        .await
        .map_err(map_federated_identity_error)?;
    let actor = VerifiedDeviceActor::new(
        proof.actor_identity_id,
        proof.actor_device_id,
        active_actor.signing_key(),
    );
    let proof_request_digest = proof.request_digest;
    let proof_idempotency_key_hash = proof.idempotency_key_hash;
    let expected_path = expected_path.to_owned();
    let expected_origin = identity_origin.to_owned();
    if expected_protocol_version == 5 {
        let (receipt, facts) = state
            .mls_repository
            .receipt_verified_v5_with_proof(
                &state.store,
                state.tenant_id,
                actor,
                scope,
                submission_id,
                proof_request_digest,
                proof_idempotency_key_hash,
                signing_public_key,
                move |device_signing_key| {
                    proof.verify(
                        MlsCommitProofAction::Query,
                        &expected_path,
                        scope,
                        submission_id,
                        actor.identity_id(),
                        actor.device_id(),
                        proof_request_digest,
                        proof_idempotency_key_hash,
                        &expected_origin,
                        now,
                        device_signing_key,
                    )
                },
            )
            .await
            .map_err(|error| map_persistence_error(&error))?;
        match facts.authorization() {
            MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                controller_device_id,
                recovery_request_id,
                recovery_request_digest,
                recovery_scope_digest,
                ..
            } => {
                let query = MlsV5RecoveryAuthorizationQuery::new(
                    facts.identity_id(),
                    recovery_request_id,
                    facts.candidate_device_id(),
                    controller_device_id,
                    active_actor.head_digest(),
                    facts.candidate_key_package_digest(),
                    recovery_request_digest,
                    recovery_scope_digest,
                );
                let projection = state
                    .federated_identity
                    .mls_v5_recovery_authorization(identity_origin, query, now)
                    .await
                    .map_err(map_federated_identity_error)?;
                if projection.query() != query || projection.expires_at() <= now {
                    return Err(GroupFailure::AuthenticationRejected);
                }
            }
            MlsCommitAuthorization::ExistingMemberDeviceRemove {
                identity_revoke_head_digest,
            } => {
                let current = state
                    .federated_identity
                    .active_device_with_terminal_revoke(
                        identity_origin,
                        facts.identity_id(),
                        facts.controller_device_id(),
                        facts.candidate_device_id(),
                        identity_revoke_head_digest,
                    )
                    .await
                    .map_err(map_federated_identity_error)?;
                if current.signing_key() != active_actor.signing_key() {
                    return Err(GroupFailure::AuthenticationRejected);
                }
            }
            _ => return Err(GroupFailure::AuthenticationRejected),
        }
        return Ok(receipt);
    }
    let receipt = state
        .mls_repository
        .receipt_verified_v3_with_proof(
            &state.store,
            state.tenant_id,
            actor,
            scope,
            submission_id,
            proof_request_digest,
            proof_idempotency_key_hash,
            signing_public_key,
            move |device_signing_key| {
                proof.verify(
                    MlsCommitProofAction::Query,
                    &expected_path,
                    scope,
                    submission_id,
                    actor.identity_id(),
                    actor.device_id(),
                    proof_request_digest,
                    proof_idempotency_key_hash,
                    &expected_origin,
                    now,
                    device_signing_key,
                )
            },
        )
        .await
        .map_err(|error| map_persistence_error(&error))?;
    if receipt.protocol_version() != expected_protocol_version {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(receipt)
}

#[allow(
    clippy::too_many_lines,
    reason = "one feed boundary keeps media negotiation and final-epoch authorization coupled"
)]
async fn get_mls_commit_feed(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let collection_path = format!("{}/mls-commits", canonical_scope_path(scope));
        let query = parse_mls_commit_feed_query(&parts.uri, &collection_path)?;
        let feed_version = if has_exact_accept(&parts.headers, MLS_COMMIT_FEED_V3_CONTENT_TYPE) {
            3
        } else if has_exact_accept(&parts.headers, MLS_COMMIT_FEED_V2_CONTENT_TYPE) {
            2
        } else {
            require_exact_accept(&parts.headers, MLS_COMMIT_FEED_CONTENT_TYPE)?;
            1
        };
        require_empty_get(&parts.headers, body).await?;
        let proof = parse_group_query_proof_header(&parts.headers)?;
        let now = state.now()?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let signing_public_key = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes())
            .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        let page = if let Some(identity_origin) =
            single_optional_header(&parts.headers, IDENTITY_ORIGIN_HEADER)?
        {
            if parts.headers.contains_key(header::AUTHORIZATION)
                || proof.identity_origin != identity_origin
            {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let device_signing_key = state
                .federated_identity
                .active_device_signing_key(
                    identity_origin,
                    proof.actor_identity_id,
                    proof.actor_device_id,
                )
                .await
                .map_err(map_federated_identity_error)?;
            let actor = VerifiedDeviceActor::new(
                proof.actor_identity_id,
                proof.actor_device_id,
                device_signing_key,
            );
            state
                .mls_repository
                .commit_feed_verified_with_proof(
                    &state.store,
                    state.tenant_id,
                    actor,
                    scope,
                    query.after_epoch,
                    query.limit,
                    signing_public_key,
                    move |device_signing_key| {
                        proof.verify(
                            GroupQueryAction::ListMlsCommits,
                            &query.canonical_target,
                            scope,
                            now,
                            device_signing_key,
                        )
                    },
                )
                .await
        } else {
            let public_origin = state
                .public_origin
                .as_deref()
                .ok_or(GroupFailure::TemporarilyUnavailable)?;
            if proof.identity_origin != public_origin {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            state
                .mls_repository
                .commit_feed_authenticated_with_proof(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    proof.actor_identity_id,
                    proof.actor_device_id,
                    scope,
                    query.after_epoch,
                    query.limit,
                    now.get(),
                    signing_public_key,
                    move |device_signing_key| {
                        proof.verify(
                            GroupQueryAction::ListMlsCommits,
                            &query.canonical_target,
                            scope,
                            now,
                            device_signing_key,
                        )
                    },
                )
                .await
        }
        .map_err(|error| map_persistence_error(&error))?;
        Ok(cbor_response(
            StatusCode::OK,
            encode_mls_commit_feed(&page, feed_version)?,
            match feed_version {
                3 => MLS_COMMIT_FEED_V3_CONTENT_TYPE,
                2 => MLS_COMMIT_FEED_V2_CONTENT_TYPE,
                _ => MLS_COMMIT_FEED_CONTENT_TYPE,
            },
        ))
    }
    .await;
    finish(result, request_id)
}

async fn confirm_mls_device_join(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, submission_id, device_id)): Path<(String, String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let submission_id = parse_request_id(&submission_id)?;
        let device_id = parse_device_id(&device_id)?;
        let expected_path = format!(
            "{}/mls-commits/{submission_id}/confirmations/{device_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let protocol_version =
            if has_exact_content_type(&parts.headers, MLS_CONFIRMATION_V3_CONTENT_TYPE) {
                3
            } else if has_exact_content_type(&parts.headers, MLS_CONFIRMATION_CONTENT_TYPE) {
                2
            } else {
                return Err(GroupFailure::InvalidRequest);
            };
        let (confirmation, body_digest) =
            parse_mls_confirmation_body(&parts.headers, body, submission_id, device_id).await?;
        let now = state.now()?;
        if protocol_version == 3
            && let Some(identity_origin) =
                single_optional_header(&parts.headers, IDENTITY_ORIGIN_HEADER)?
        {
            if parts.headers.contains_key(header::AUTHORIZATION) {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let proof = parse_mls_confirmation_proof_header(&parts.headers)?;
            if proof.identity_origin != identity_origin
                || proof.identity_id != confirmation.identity_id
                || proof.device_id != confirmation.device_id
            {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let signing_key = state
                .federated_identity
                .active_device_signing_key(
                    identity_origin,
                    confirmation.identity_id,
                    confirmation.device_id,
                )
                .await
                .map_err(map_federated_identity_error)?;
            proof
                .verify(
                    &expected_path,
                    scope,
                    submission_id,
                    body_digest,
                    now,
                    signing_key,
                )
                .map_err(|_| GroupFailure::ActionProofInvalid)?;
            state
                .mls_repository
                .confirm_verified(
                    &state.store,
                    state.tenant_id,
                    confirmation,
                    now.get(),
                    signing_key,
                )
                .await
                .map_err(|error| map_persistence_error(&error))?;
        } else {
            if parts.headers.contains_key(IDENTITY_ORIGIN_HEADER)
                || parts.headers.contains_key(MLS_CONFIRMATION_PROOF_HEADER)
            {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            state
                .mls_repository
                .confirm_authenticated(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    confirmation,
                    now.get(),
                )
                .await
                .map_err(|error| map_persistence_error(&error))?;
        }
        Ok(StatusCode::NO_CONTENT.into_response())
    }
    .await;
    finish(result, request_id)
}
