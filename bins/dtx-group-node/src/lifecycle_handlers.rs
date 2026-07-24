async fn get_mls_sequencer_descriptor(
    State(state): State<GroupNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        require_exact_route(&parts.uri, MLS_SEQUENCER_DESCRIPTOR_PATH)?;
        require_empty_get(&parts.headers, body).await?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(signing_key.verifying_key().to_bytes().to_vec()),
            ),
        ]))
        .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        Ok(cbor_response(
            StatusCode::OK,
            body,
            "application/vnd.dirextalk.mls-sequencer-descriptor.v2+cbor",
        ))
    }
    .await;
    finish(result, request_id)
}

async fn get_group_service_descriptor(
    State(state): State<GroupNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        require_exact_route(&parts.uri, GROUP_SERVICE_DESCRIPTOR_PATH)?;
        require_empty_get(&parts.headers, body).await?;
        let public_origin = state
            .public_origin
            .as_deref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let signing_key = state
            .mls_signing_key
            .as_ref()
            .ok_or(GroupFailure::TemporarilyUnavailable)?;
        let descriptor = encode_deterministic_cbor(&numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(public_origin.to_owned()),
            CanonicalValue::Array(vec![CanonicalValue::Text(
                "membership-discovery-v1".to_owned(),
            )]),
            CanonicalValue::Unsigned(MAX_ADMINS as u64),
            CanonicalValue::Unsigned(MAX_GROUP_JOIN_REQUEST_PAGE_SIZE as u64),
            CanonicalValue::Bytes(signing_key.verifying_key().to_bytes().to_vec()),
        ]))
        .map_err(|_| GroupFailure::TemporarilyUnavailable)?;
        let etag = representation_etag(&descriptor);
        let not_modified = if_none_match(&parts.headers, &etag)?;
        let mut response = if not_modified {
            StatusCode::NOT_MODIFIED.into_response()
        } else {
            cbor_response(
                StatusCode::OK,
                descriptor,
                GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE,
            )
        };
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&etag).expect("generated Group Service ETag is valid"),
        );
        Ok(response)
    }
    .await;
    finish_public_descriptor(result, request_id)
}

async fn create_group(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let expected_path = canonical_scope_path(scope);
        require_exact_route(&parts.uri, &expected_path)?;
        let proof = parse_create_body(
            &parts.headers,
            body,
            GROUP_CREATE_CONTENT_TYPE,
            MAX_CONTROL_BODY_BYTES,
        )
        .await?;
        let now = state.now()?;
        let operation = GroupControlOperation::CreateGroup {
            scope,
            owner_identity_id: proof.actor_identity_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::CreateGroup,
                scope,
                expected_path,
                create_group_signable(),
                proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::CreateGroup, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn grant_admin(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, administrator_identity_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let administrator_identity_id = parse_identity_id(&administrator_identity_id)?;
        let expected_path = format!(
            "{}/admins/{administrator_identity_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed =
            parse_role_change_body(&parts.headers, body, GROUP_GRANT_ADMIN_CONTENT_TYPE).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::GrantAdmin {
            scope,
            expected_revision: parsed.expected_revision,
            administrator_identity_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::GrantAdmin,
                scope,
                expected_path,
                role_change_signable(parsed.expected_revision),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::GrantAdmin, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn revoke_admin(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, administrator_identity_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let administrator_identity_id = parse_identity_id(&administrator_identity_id)?;
        let expected_path = format!(
            "{}/admins/{administrator_identity_id}/revoke",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed =
            parse_role_change_body(&parts.headers, body, GROUP_REVOKE_ADMIN_CONTENT_TYPE).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::RevokeAdmin {
            scope,
            expected_revision: parsed.expected_revision,
            administrator_identity_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::RevokeAdmin,
                scope,
                expected_path,
                role_change_signable(parsed.expected_revision),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::RevokeAdmin, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn issue_invite(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, invite_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let invite_id = parse_invite_id(&invite_id)?;
        let expected_path = format!("{}/invites/{invite_id}", canonical_scope_path(scope));
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed = parse_issue_invite_body(&parts.headers, body).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::IssueInvite {
            scope,
            expected_revision: parsed.expected_revision,
            invite_id,
            target_identity_id: parsed.target_identity_id,
            max_uses: parsed.max_uses,
            expires_at_ms: parsed.expires_at.get(),
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::IssueInvite,
                scope,
                expected_path,
                issue_invite_signable(&parsed),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::IssueInvite, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn revoke_invite(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, invite_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let invite_id = parse_invite_id(&invite_id)?;
        let expected_path = format!("{}/invites/{invite_id}/revoke", canonical_scope_path(scope));
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed =
            parse_role_change_body(&parts.headers, body, GROUP_REVOKE_INVITE_CONTENT_TYPE).await?;
        let now = state.now()?;
        let operation = GroupControlOperation::RevokeInvite {
            scope,
            expected_revision: parsed.expected_revision,
            invite_id,
        };
        let execution = state
            .execute_control(
                &parts.headers,
                GroupAction::RevokeInvite,
                scope,
                expected_path,
                role_change_signable(parsed.expected_revision),
                parsed.proof,
                operation,
                now,
            )
            .await?;
        control_response(GroupAction::RevokeInvite, scope, execution)
    }
    .await;
    finish(result, request_id)
}

async fn request_join(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, join_request_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let join_request_id = parse_join_request_id(&join_request_id)?;
        let expected_path = format!(
            "{}/join-requests/{join_request_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed = parse_join_request_body(&parts.headers, body, join_request_id).await?;
        let protocol_version = parsed.protocol_version;
        let now = state.now()?;
        let execution = state
            .request_join(&parts.headers, scope, expected_path, parsed, now)
            .await?;
        membership_response(execution, protocol_version)
    }
    .await;
    finish(result, request_id)
}

#[allow(
    clippy::too_many_lines,
    reason = "one handler keeps local and federated pending-join authorization symmetric"
)]
async fn list_join_requests(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let collection_path = format!("{}/join-requests", canonical_scope_path(scope));
        let query = parse_join_request_query(&parts.uri, &collection_path)?;
        let protocol_version = requested_membership_version(
            &parts.headers,
            GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE,
            GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE,
        )?;
        require_empty_get(&parts.headers, body).await?;
        let proof = parse_group_query_proof_header(&parts.headers)?;
        let now = state.now()?;
        let page = if let Some(identity_origin) =
            single_optional_header(&parts.headers, IDENTITY_ORIGIN_HEADER)?
        {
            if parts.headers.contains_key(header::AUTHORIZATION)
                || proof.identity_origin != identity_origin
            {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let signing_key = state
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
                signing_key,
            );
            state
                .membership_repository
                .list_pending_join_requests_verified_with_proof(
                    &state.store,
                    state.tenant_id,
                    actor,
                    scope,
                    query.after,
                    query.limit,
                    move |signing_key| {
                        proof.verify(
                            GroupQueryAction::ListJoinRequests,
                            &query.canonical_target,
                            scope,
                            now,
                            signing_key,
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
                .membership_repository
                .list_pending_join_requests_authenticated_with_proof(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    proof.actor_identity_id,
                    proof.actor_device_id,
                    scope,
                    query.after,
                    query.limit,
                    now.get(),
                    move |signing_key| {
                        proof.verify(
                            GroupQueryAction::ListJoinRequests,
                            &query.canonical_target,
                            scope,
                            now,
                            signing_key,
                        )
                    },
                )
                .await
        }
        .map_err(|error| map_persistence_error(&error))?;
        Ok(cbor_response(
            StatusCode::OK,
            encode_pending_join_request_page(scope, &page, protocol_version)?,
            if protocol_version == 2 {
                GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE
            } else {
                GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE
            },
        ))
    }
    .await;
    finish(result, request_id)
}

async fn approve_join(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, join_request_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let join_request_id = parse_join_request_id(&join_request_id)?;
        let expected_path = format!(
            "{}/join-requests/{join_request_id}/approvals",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let parsed = parse_approve_join_body(&parts.headers, body, join_request_id).await?;
        let protocol_version = parsed.protocol_version;
        let now = state.now()?;
        let execution = state
            .approve_join(&parts.headers, scope, expected_path, parsed, now)
            .await?;
        membership_response(execution, protocol_version)
    }
    .await;
    finish(result, request_id)
}

async fn get_membership_receipt(
    State(state): State<GroupNodeState>,
    Path((scope_kind, scope_id, membership_command_id)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = async {
        let scope = parse_scope(&scope_kind, &scope_id)?;
        let command_id = MembershipCommandId::new(parse_request_id(&membership_command_id)?);
        let expected_path = format!(
            "{}/membership-receipts/{membership_command_id}",
            canonical_scope_path(scope)
        );
        require_exact_route(&parts.uri, &expected_path)?;
        let protocol_version = requested_membership_version(
            &parts.headers,
            MEMBERSHIP_RECEIPT_CONTENT_TYPE,
            MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE,
        )?;
        require_empty_get(&parts.headers, body).await?;
        let now = state.now()?;
        let query_proof = parse_receipt_query_proof_header(&parts.headers)?;
        let receipt = if let Some(query_proof) = query_proof {
            let actor = state
                .federated_receipt_actor(
                    &parts.headers,
                    &query_proof,
                    &expected_path,
                    scope,
                    command_id,
                    now,
                )
                .await?
                .ok_or(GroupFailure::ActionProofInvalid)?;
            state
                .membership_repository
                .load_receipt_verified(&state.store, state.tenant_id, actor, scope, command_id)
                .await
        } else {
            if parts.headers.contains_key(IDENTITY_ORIGIN_HEADER) {
                return Err(GroupFailure::ActionProofInvalid);
            }
            let credential = parse_device_session_authorization(&parts.headers)?;
            state
                .membership_repository
                .load_receipt_authenticated(
                    &state.store,
                    state.tenant_id,
                    &credential,
                    scope,
                    command_id,
                    now.get(),
                )
                .await
        }
        .map_err(|error| map_persistence_error(&error))?;
        Ok(cbor_response(
            StatusCode::OK,
            encode_membership_receipt(receipt, protocol_version)?,
            if protocol_version == 2 {
                MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE
            } else {
                MEMBERSHIP_RECEIPT_CONTENT_TYPE
            },
        ))
    }
    .await;
    finish(result, request_id)
}
