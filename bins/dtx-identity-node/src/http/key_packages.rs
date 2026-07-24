use super::*;

pub(crate) async fn publish_key_package(
    State(state): State<IdentityBootstrapState>,
    Path(package_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .publish_key_package(&package_id, &parts.headers, body)
        .await
    {
        Ok(success) => key_package_publish_success_response(success, request_id),
        Err(failure) => key_package_failure_response(failure, request_id),
    }
}

pub(crate) async fn claim_key_package(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.claim_key_package(&parts.headers, body).await {
        Ok(success) => key_package_claim_success_response(success, request_id),
        Err(failure) => key_package_failure_response(failure, request_id),
    }
}

pub(crate) async fn claim_key_package_federated(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .claim_key_package_federated(&parts.uri, &parts.headers, body)
        .await
    {
        Ok(success) => key_package_claim_success_response(success, request_id),
        Err(failure) => key_package_failure_response(failure, request_id),
    }
}

impl IdentityBootstrapState {
    async fn publish_key_package(
        &self,
        route_package_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<KeyPackagePublishSuccess, KeyPackageFailure> {
        let recovery_v2 = has_exact_content_type(headers, KEY_PACKAGE_PUBLISH_V2_CONTENT_TYPE);
        if (!recovery_v2 && !has_exact_content_type(headers, KEY_PACKAGE_PUBLISH_CONTENT_TYPE))
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
        let idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_KEY_PACKAGE_PUBLISH_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let route_package_id = route_package_id
            .parse::<KeyPackageId>()
            .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_KEY_PACKAGE_PUBLISH_BYTES)
            .await
            .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let publish = parse_key_package_publish(&bytes)?;
        if publish.package_id != route_package_id {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        if recovery_v2 != publish.history_recovery_scope.is_some() {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let command = if let Some(scope) = publish.history_recovery_scope {
            KeyPackagePublishCommand::new_history_recovery_v2(
                idempotency_key_hash,
                publish.identity_id,
                publish.device_id,
                publish.package_id,
                publish.published_head_sequence,
                publish.published_head_hash,
                publish.expires_at,
                publish.opaque_key_package,
                scope,
                publish.detached_signature,
                bytes.to_vec(),
            )
        } else {
            KeyPackagePublishCommand::new(
                idempotency_key_hash,
                publish.identity_id,
                publish.device_id,
                publish.package_id,
                publish.published_head_sequence,
                publish.published_head_hash,
                publish.expires_at,
                publish.opaque_key_package,
                publish.detached_signature,
                bytes.to_vec(),
            )
        }
        .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| KeyPackageFailure::TemporarilyUnavailable)?;
        match self
            .key_packages
            .publish(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_key_package_persistence_error(&error))?
        {
            KeyPackagePublishOutcome::Published(receipt) => Ok(KeyPackagePublishSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            KeyPackagePublishOutcome::Replayed(receipt) => Ok(KeyPackagePublishSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
        }
    }

    async fn claim_key_package(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<KeyPackageClaimSuccess, KeyPackageFailure> {
        let recovery_v2 = has_exact_content_type(headers, KEY_PACKAGE_CLAIM_V2_CONTENT_TYPE);
        if (!recovery_v2 && !has_exact_content_type(headers, KEY_PACKAGE_CLAIM_CONTENT_TYPE))
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_KEY_PACKAGE_CLAIM_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_KEY_PACKAGE_CLAIM_BYTES)
            .await
            .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let claim = parse_key_package_claim(&bytes)?;
        if recovery_v2 != claim.history_recovery_scope.is_some() {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let command = if let Some(scope) = claim.history_recovery_scope {
            KeyPackageClaimCommand::new_history_recovery_v2(
                idempotency_key_hash,
                claim.target_identity_id,
                claim.target_device_id,
                scope,
                bytes.to_vec(),
            )
        } else {
            KeyPackageClaimCommand::new(
                idempotency_key_hash,
                claim.target_identity_id,
                claim.target_device_id,
                bytes.to_vec(),
            )
        }
        .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let now = self
            .committed_at()
            .map_err(|()| KeyPackageFailure::TemporarilyUnavailable)?;
        match self
            .key_packages
            .claim(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_key_package_persistence_error(&error))?
        {
            KeyPackageClaimOutcome::Claimed(receipt) => Ok(KeyPackageClaimSuccess {
                status: StatusCode::CREATED,
                exact_publish_bytes: receipt.exact_publish_bytes().to_vec(),
            }),
            KeyPackageClaimOutcome::Replayed(receipt) => Ok(KeyPackageClaimSuccess {
                status: StatusCode::OK,
                exact_publish_bytes: receipt.exact_publish_bytes().to_vec(),
            }),
        }
    }

    async fn claim_key_package_federated(
        &self,
        uri: &axum::http::Uri,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<KeyPackageClaimSuccess, KeyPackageFailure> {
        if uri.path() != KEY_PACKAGE_FEDERATED_CLAIM_PATH
            || uri.query().is_some()
            || !has_exact_content_type(headers, KEY_PACKAGE_FEDERATED_CLAIM_CONTENT_TYPE)
            || !has_exact_header(
                headers,
                header::ACCEPT,
                KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE,
            )
            || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(KeyPackageFailure::InvalidRequest);
        }
        let identity_origin = single_graphic_header(headers, IDENTITY_ORIGIN_HEADER, 8, 512)
            .map_err(|()| KeyPackageFailure::AuthenticationRejected)?;
        if identity_origin == self.public_origin.as_ref() {
            return Err(KeyPackageFailure::AuthenticationRejected);
        }
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_KEY_PACKAGE_CLAIM_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_KEY_PACKAGE_CLAIM_BYTES)
            .await
            .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let claim = parse_key_package_claim(&bytes)?;
        let command = KeyPackageClaimCommand::new(
            idempotency_key_hash,
            claim.target_identity_id,
            claim.target_device_id,
            bytes.to_vec(),
        )
        .map_err(|_| KeyPackageFailure::InvalidRequest)?;
        let proof = parse_federated_key_package_claim_proof(headers)?;
        if proof.requester_identity_origin() != identity_origin {
            return Err(KeyPackageFailure::AuthenticationRejected);
        }
        let now = self
            .committed_at()
            .map_err(|()| KeyPackageFailure::TemporarilyUnavailable)?;
        let signing_key = self
            .federated_identity
            .active_device_signing_key(
                identity_origin,
                proof.requester_identity_id(),
                proof.requester_device_id(),
            )
            .await
            .map_err(map_federated_identity_error)?;
        let claimant = proof
            .verify(&command, now, signing_key)
            .map_err(|_| KeyPackageFailure::AuthenticationRejected)?;
        match self
            .key_packages
            .claim_federated(&self.store, &command, &claimant, now)
            .await
            .map_err(|error| map_key_package_persistence_error(&error))?
        {
            KeyPackageClaimOutcome::Claimed(receipt) => Ok(KeyPackageClaimSuccess {
                status: StatusCode::CREATED,
                exact_publish_bytes: receipt.exact_publish_bytes().to_vec(),
            }),
            KeyPackageClaimOutcome::Replayed(receipt) => Ok(KeyPackageClaimSuccess {
                status: StatusCode::OK,
                exact_publish_bytes: receipt.exact_publish_bytes().to_vec(),
            }),
        }
    }
}
