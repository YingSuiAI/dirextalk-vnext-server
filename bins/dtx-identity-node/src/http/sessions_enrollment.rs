use super::{
    Body, CreateDeviceEnrollmentChallengeCommand, CreateHistoryRecoveryRequestCommand,
    CreateHistoryRecoveryRequestV4Command, DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE,
    DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN, DEVICE_ENROLLMENT_CAPABILITY_HEADER,
    DEVICE_ENROLLMENT_CONTENT_TYPE, DeviceEnrollmentApprovalCommand,
    DeviceEnrollmentApprovalSuccess, DeviceEnrollmentChallengeOutcome,
    DeviceEnrollmentChallengeStatus, DeviceEnrollmentChallengeSuccess, DeviceEnrollmentFailure,
    DeviceId, DeviceRevokeCommand, DeviceRevokeFailure, DeviceRevokeSuccess,
    DeviceSessionChallengeRequest, DeviceSessionChallengeResponse, DeviceSessionCompletionCommand,
    DeviceSessionCompletionRequest, DeviceSessionFailure, DeviceSessionOutcome,
    DeviceSessionSuccess, FromStr, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
    HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE,
    HTTP_DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_KEY_HASH_DOMAIN,
    HTTP_DEVICE_ENROLLMENT_CHALLENGE_IDEMPOTENCY_KEY_HASH_DOMAIN,
    HTTP_DEVICE_REVOKE_IDEMPOTENCY_KEY_HASH_DOMAIN,
    HTTP_DEVICE_SESSION_IDEMPOTENCY_KEY_HASH_DOMAIN,
    HTTP_HISTORY_RECOVERY_REQUEST_V4_IDEMPOTENCY_KEY_HASH_DOMAIN, HeaderMap,
    HistoryRecoveryRequestV4Success, IDEMPOTENCY_KEY_HEADER, IdentityAppendOutcome,
    IdentityBootstrapState, IdentityId, IdentityLogHead, MAX_DEVICE_ENROLLMENT_CANDIDATE_BYTES,
    MAX_DEVICE_ENROLLMENT_COMPLETION_BYTES, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES, Path,
    RecoveryResponseCapability, Request, RequestId, Response, Sha256Digest, State, StatusCode,
    Zeroize, decode_base64url_32, device_enrollment_approval_success_response,
    device_enrollment_challenge_success_response, device_enrollment_failure_response,
    device_enrollment_status_response, device_revoke_failure_response,
    device_revoke_success_response, device_session_challenge_success_response,
    device_session_failure_response, device_session_success_response,
    expected_device_revoke_head_hash, expected_genesis_hash, fill_random, has_exact_content_type,
    has_exact_event_content_type, has_exact_header, has_exact_json_content_type, header,
    history_recovery_request_v4_success_response, idempotency_key_hash,
    map_device_enrollment_persistence_error, map_device_revoke_persistence_error,
    map_device_session_persistence_error, parse_device_enrollment_candidate,
    parse_device_enrollment_completion, parse_device_enrollment_status_request,
    parse_device_session_authorization, parse_history_recovery_request,
    parse_history_recovery_request_v4, parse_history_recovery_request_v4_identity, parse_json_body,
    parse_recovery_capability_header, parse_recovery_enrollment_capability, to_bytes,
};

pub(crate) async fn create_history_recovery_request_v4(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .create_history_recovery_request_v4(&parts.headers, body)
        .await
    {
        Ok(success) => history_recovery_request_v4_success_response(success, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

pub(crate) async fn create_device_session_challenge(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .create_device_session_challenge(&parts.headers, body)
        .await
    {
        Ok(challenge) => device_session_challenge_success_response(&challenge, request_id),
        Err(failure) => device_session_failure_response(failure, request_id),
    }
}

pub(crate) async fn complete_device_session(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.complete_device_session(&parts.headers, body).await {
        Ok(success) => device_session_success_response(success, request_id),
        Err(failure) => device_session_failure_response(failure, request_id),
    }
}

pub(crate) async fn create_device_enrollment_challenge(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .create_device_enrollment_challenge(&parts.headers, body)
        .await
    {
        Ok(success) => device_enrollment_challenge_success_response(&success, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

pub(crate) async fn get_device_enrollment_challenge(
    State(state): State<IdentityBootstrapState>,
    Path(challenge_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .get_device_enrollment_challenge(&challenge_id, &parts.headers, body)
        .await
    {
        Ok(status) => device_enrollment_status_response(status, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

pub(crate) async fn cancel_device_enrollment_challenge(
    State(state): State<IdentityBootstrapState>,
    Path(challenge_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .cancel_device_enrollment_challenge(&challenge_id, &parts.headers, body)
        .await
    {
        Ok(status) => device_enrollment_status_response(status, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

pub(crate) async fn approve_device_enrollment(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.approve_device_enrollment(&parts.headers, body).await {
        Ok(success) => device_enrollment_approval_success_response(success, request_id),
        Err(failure) => device_enrollment_failure_response(failure, request_id),
    }
}

pub(crate) async fn revoke_device(
    State(state): State<IdentityBootstrapState>,
    Path((identity_id, device_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .revoke_device(&identity_id, &device_id, &parts.headers, body)
        .await
    {
        Ok(success) => device_revoke_success_response(success, request_id),
        Err(failure) => device_revoke_failure_response(failure, request_id),
    }
}

impl IdentityBootstrapState {
    async fn create_history_recovery_request_v4(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<HistoryRecoveryRequestV4Success, DeviceEnrollmentFailure> {
        if !has_exact_content_type(headers, HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE)
            || !has_exact_header(
                headers,
                header::ACCEPT,
                super::HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
            )
            || headers.contains_key(super::header::CONTENT_ENCODING)
            || headers.contains_key(super::header::AUTHORIZATION)
            || headers.contains_key(super::header::IF_MATCH)
        {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        }
        let enrollment_raw =
            parse_recovery_capability_header(headers, super::DEVICE_ENROLLMENT_CAPABILITY_HEADER)
                .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
        let enrollment = parse_recovery_enrollment_capability(headers)
            .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
        let response_raw =
            parse_recovery_capability_header(headers, super::RECOVERY_RESPONSE_CAPABILITY_HEADER)
                .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
        let response_capability = RecoveryResponseCapability::new(response_raw)
            .map_err(|_| DeviceEnrollmentFailure::CapabilityRejected)?;
        let idempotency_digest = idempotency_key_hash(
            headers,
            HTTP_HISTORY_RECOVERY_REQUEST_V4_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let bytes = to_bytes(body, 37_114)
            .await
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let (request_id, identity_id) = parse_history_recovery_request_v4_identity(&bytes)?;
        self.device_enrollments
            .authenticate_history_recovery_request_v4_capability(
                &self.store,
                request_id,
                identity_id,
                Sha256Digest::hash_domain(
                    DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN,
                    &enrollment_raw,
                ),
            )
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))?;
        let request = parse_history_recovery_request_v4(&bytes, enrollment, &response_capability)?;
        if request.response_capability_digest
            != Sha256Digest::hash_domain(
                b"dirextalk.recovery-response-capability.v1\0",
                &response_raw,
            )
            || request.idempotency_digest != idempotency_digest
        {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        }
        let command = CreateHistoryRecoveryRequestV4Command {
            enrollment_capability_digest: Sha256Digest::hash_domain(
                b"dirextalk.device-enrollment-capability.v1\0",
                &enrollment_raw,
            ),
            idempotency_digest,
            response_capability_digest: request.response_capability_digest,
            request_id: request.request_id,
            identity_id: request.identity_id,
            target_device_id: request.target_device_id,
            target_device_signing_key: request.target_device_signing_key,
            recipient_encryption_key: request.recipient_encryption_key,
            pre_head_sequence: request.pre_head_sequence,
            pre_head_hash: request.pre_head_hash,
            post_head_sequence: request.post_head_sequence,
            post_head_hash: request.post_head_hash,
            device_add_bytes: request.device_add_bytes,
            device_add_digest: request.device_add_digest,
            preparation_bytes: request.preparation_bytes,
            preparation_digest: request.preparation_digest,
            manifest_bytes: request.manifest_bytes,
            manifest_digest: request.manifest_digest,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            candidate_signature: request.candidate_signature,
            exact_request_bytes: request.exact_signed_request,
            request_digest: request.request_digest,
        };
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        let (created, receipt) = self
            .device_enrollments
            .create_history_recovery_request_v4(&self.store, command, now)
            .await
            .map_err(|e| map_device_enrollment_persistence_error(&e))?;
        Ok(HistoryRecoveryRequestV4Success {
            status: if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            exact_receipt_bytes: receipt,
        })
    }
    async fn create_device_session_challenge(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceSessionChallengeResponse, DeviceSessionFailure> {
        if !has_exact_json_content_type(headers)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
        {
            return Err(DeviceSessionFailure::InvalidRequest);
        }
        let request: DeviceSessionChallengeRequest = parse_json_body(body).await?;
        let mut nonce = [0_u8; 32];
        fill_random(&mut nonce).map_err(|_| DeviceSessionFailure::TemporarilyUnavailable)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceSessionFailure::TemporarilyUnavailable)?;
        let challenge = self
            .device_sessions
            .issue_challenge(
                &self.store,
                request.identity_id,
                request.device_id,
                nonce,
                &self.device_session_audience,
                now,
            )
            .await
            .map_err(|error| map_device_session_persistence_error(&error))?;
        Ok(DeviceSessionChallengeResponse::from(challenge))
    }

    async fn complete_device_session(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceSessionSuccess, DeviceSessionFailure> {
        if !has_exact_json_content_type(headers)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
        {
            return Err(DeviceSessionFailure::InvalidRequest);
        }
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_DEVICE_SESSION_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
        let mut request: DeviceSessionCompletionRequest = parse_json_body(body).await?;
        let challenge_nonce = decode_base64url_32(&request.challenge_nonce)?;
        let session_secret = decode_base64url_32(&request.session_secret)?;
        request.challenge_nonce.zeroize();
        request.session_secret.zeroize();
        let command = DeviceSessionCompletionCommand::new(
            idempotency_key_hash,
            request.identity_id,
            request.device_id,
            request.challenge_id,
            request.session_id,
            challenge_nonce,
            session_secret,
            request.proof,
        )
        .map_err(|_| DeviceSessionFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceSessionFailure::TemporarilyUnavailable)?;
        match self
            .device_sessions
            .complete(&self.store, &command, now)
            .await
            .map_err(|error| map_device_session_persistence_error(&error))?
        {
            DeviceSessionOutcome::Issued(receipt) => Ok(DeviceSessionSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            DeviceSessionOutcome::Replayed(receipt) => Ok(DeviceSessionSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
        }
    }

    async fn create_device_enrollment_challenge(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentChallengeSuccess, DeviceEnrollmentFailure> {
        let history_recovery =
            has_exact_content_type(headers, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE);
        if (!history_recovery
            && !has_exact_content_type(headers, DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE))
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        }
        let idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_DEVICE_ENROLLMENT_CHALLENGE_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_DEVICE_ENROLLMENT_CANDIDATE_BYTES)
            .await
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        let outcome = if history_recovery {
            let request = parse_history_recovery_request(&bytes)?;
            let command = CreateHistoryRecoveryRequestCommand::new(
                idempotency_key_hash,
                request.request_id,
                request.identity_id,
                request.target_device_id,
                request.target_device_signing_key,
                request.recipient_encryption_key,
                IdentityLogHead::observed(
                    request.identity_id,
                    request.observed_head_sequence,
                    request.observed_head_hash,
                )
                .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?,
                request.issued_at,
                request.expires_at,
                request.capability,
                request.candidate_signature,
                request.exact_signed_request,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
            self.device_enrollments
                .create_history_recovery_request(&self.store, command, now)
                .await
        } else {
            let candidate = parse_device_enrollment_candidate(&bytes)?;
            let command = CreateDeviceEnrollmentChallengeCommand::new(
                idempotency_key_hash,
                candidate.identity_id,
                candidate.target_device_id,
                candidate.target_device_signing_key,
                candidate.target_device_encryption_key,
                candidate.capability,
            )
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
            self.device_enrollments
                .create_challenge(&self.store, command, now)
                .await
        }
        .map_err(|error| map_device_enrollment_persistence_error(&error))?;
        match outcome {
            DeviceEnrollmentChallengeOutcome::Created(challenge) => {
                Ok(DeviceEnrollmentChallengeSuccess {
                    status: StatusCode::CREATED,
                    challenge,
                })
            }
            DeviceEnrollmentChallengeOutcome::Replayed(challenge) => {
                Ok(DeviceEnrollmentChallengeSuccess {
                    status: StatusCode::OK,
                    challenge,
                })
            }
        }
    }

    async fn get_device_enrollment_challenge(
        &self,
        challenge_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentChallengeStatus, DeviceEnrollmentFailure> {
        let (challenge_id, capability) =
            parse_device_enrollment_status_request(challenge_id, headers, body).await?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        self.device_enrollments
            .status(&self.store, challenge_id, capability, now)
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))
    }

    async fn cancel_device_enrollment_challenge(
        &self,
        challenge_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentChallengeStatus, DeviceEnrollmentFailure> {
        let (challenge_id, capability) =
            parse_device_enrollment_status_request(challenge_id, headers, body).await?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        self.device_enrollments
            .cancel(&self.store, challenge_id, capability, now)
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))
    }

    async fn approve_device_enrollment(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceEnrollmentApprovalSuccess, DeviceEnrollmentFailure> {
        if !has_exact_content_type(headers, DEVICE_ENROLLMENT_CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(DeviceEnrollmentFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| DeviceEnrollmentFailure::AuthenticationRejected)?;
        let approval_idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_DEVICE_ENROLLMENT_APPROVAL_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let expected_head_hash =
            expected_genesis_hash(headers).map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_DEVICE_ENROLLMENT_COMPLETION_BYTES)
            .await
            .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let completion = parse_device_enrollment_completion(&bytes)?;
        let command = DeviceEnrollmentApprovalCommand::new(
            approval_idempotency_key_hash,
            completion.challenge_id,
            completion.capability,
            expected_head_hash,
            completion.exact_device_add_bytes,
        )
        .map_err(|_| DeviceEnrollmentFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceEnrollmentFailure::TemporarilyUnavailable)?;
        match self
            .device_enrollments
            .approve(&self.store, command, credential, now)
            .await
            .map_err(|error| map_device_enrollment_persistence_error(&error))?
        {
            IdentityAppendOutcome::Committed(receipt) => Ok(DeviceEnrollmentApprovalSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Replayed(receipt) => Ok(DeviceEnrollmentApprovalSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Forked { .. } => Err(DeviceEnrollmentFailure::IdentityConflict),
        }
    }

    async fn revoke_device(
        &self,
        route_identity_id: &str,
        route_device_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<DeviceRevokeSuccess, DeviceRevokeFailure> {
        if !has_exact_event_content_type(headers)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(DeviceRevokeFailure::InvalidRequest);
        }
        let identity_id = IdentityId::from_str(route_identity_id)
            .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let target_device_id =
            DeviceId::from_str(route_device_id).map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| DeviceRevokeFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_DEVICE_REVOKE_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let expected_head_hash = expected_device_revoke_head_hash(headers)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| DeviceRevokeFailure::InvalidRequest)?
            .to_vec();
        let command = DeviceRevokeCommand::new(
            idempotency_key_hash,
            identity_id,
            target_device_id,
            expected_head_hash,
            exact_event_bytes,
        )
        .map_err(|_| DeviceRevokeFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| DeviceRevokeFailure::TemporarilyUnavailable)?;
        match self
            .repository
            .revoke_device(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_device_revoke_persistence_error(&error))?
        {
            IdentityAppendOutcome::Committed(receipt) => Ok(DeviceRevokeSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Replayed(receipt) => Ok(DeviceRevokeSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            IdentityAppendOutcome::Forked { .. } => Err(DeviceRevokeFailure::IdentityConflict),
        }
    }
}
