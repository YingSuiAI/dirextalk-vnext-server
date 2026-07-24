use super::{
    Body, CatalogPreparationCommand, CatalogProviderResponseCommand, CatalogUploadCommand,
    DEVICE_ENROLLMENT_CAPABILITY_HEADER, DeviceEnrollmentChallengeId,
    HTTP_RECOVERY_CATALOG_IDEMPOTENCY_KEY_HASH_DOMAIN,
    HTTP_RECOVERY_PREPARATION_IDEMPOTENCY_KEY_HASH_DOMAIN,
    HTTP_RECOVERY_PROVIDER_IDEMPOTENCY_KEY_HASH_DOMAIN, HeaderMap, IDEMPOTENCY_KEY_HEADER,
    IdentityBootstrapState, MAX_RECOVERY_SCOPE_CATALOG_PREPARATION_BYTES,
    MAX_RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_BYTES, MAX_RECOVERY_SCOPE_CATALOG_UPLOAD_BYTES,
    Path, RECOVERY_RESPONSE_CAPABILITY_HEADER, RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE, RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE, RecoveryCatalogFailure, RecoveryCatalogHeadSuccess,
    RecoveryCatalogReceiptKind, RecoveryCatalogStatusSuccess, Request, RequestId, Response, State,
    StatusCode, has_exact_content_type, has_exact_header, header, idempotency_key_hash,
    map_recovery_catalog_prepare_error, map_recovery_catalog_provider_error,
    map_recovery_catalog_publish_error, map_recovery_catalog_status_error,
    parse_device_session_authorization, parse_recovery_enrollment_capability,
    parse_recovery_response_capability, recovery_catalog_failure_response,
    recovery_catalog_head_response, recovery_catalog_status_response, to_bytes,
};

pub(crate) async fn publish_recovery_scope_catalog(
    State(state): State<IdentityBootstrapState>,
    Path(catalog_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .publish_recovery_scope_catalog(&catalog_id, &parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_head_response(success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
    }
}

pub(crate) async fn prepare_recovery_scope_catalog(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .prepare_recovery_scope_catalog(&parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_status_response(&success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
    }
}

pub(crate) async fn get_recovery_scope_catalog_preparation(
    State(state): State<IdentityBootstrapState>,
    Path(route_request_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .get_recovery_scope_catalog_preparation(&route_request_id, &parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_status_response(&success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
    }
}

pub(crate) async fn put_recovery_scope_catalog_provider_response(
    State(state): State<IdentityBootstrapState>,
    Path(route_request_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .put_recovery_scope_catalog_provider_response(&route_request_id, &parts.headers, body)
        .await
    {
        Ok(success) => recovery_catalog_status_response(&success, request_id),
        Err(failure) => recovery_catalog_failure_response(failure, request_id),
    }
}

impl IdentityBootstrapState {
    async fn publish_recovery_scope_catalog(
        &self,
        route_catalog_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogHeadSuccess, RecoveryCatalogFailure> {
        if !has_exact_header(
            headers,
            header::ACCEPT,
            RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE,
        ) {
            return Err(RecoveryCatalogFailure::NotAcceptable);
        }
        if !has_exact_content_type(headers, RECOVERY_SCOPE_CATALOG_CONTENT_TYPE) {
            return Err(RecoveryCatalogFailure::UnsupportedMedia);
        }
        if content_length_exceeds(headers, MAX_RECOVERY_SCOPE_CATALOG_UPLOAD_BYTES) {
            return Err(RecoveryCatalogFailure::TooLarge);
        }
        if !has_exact_content_type(headers, RECOVERY_SCOPE_CATALOG_CONTENT_TYPE)
            || !has_exact_header(
                headers,
                header::ACCEPT,
                RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE,
            )
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
            || headers.contains_key(RECOVERY_RESPONSE_CAPABILITY_HEADER)
        {
            return Err(RecoveryCatalogFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| RecoveryCatalogFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_RECOVERY_CATALOG_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let catalog_id = uuid::Uuid::parse_str(route_catalog_id)
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_RECOVERY_SCOPE_CATALOG_UPLOAD_BYTES)
            .await
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let command = CatalogUploadCommand::parse_v2(idempotency_key_hash, catalog_id, &bytes)
            .map_err(|error| map_recovery_catalog_publish_error(&error))?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let outcome = self
            .recovery_catalogs
            .publish(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_recovery_catalog_publish_error(&error))?;
        Ok(RecoveryCatalogHeadSuccess {
            status: if outcome.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            outcome,
        })
    }

    async fn prepare_recovery_scope_catalog(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogStatusSuccess, RecoveryCatalogFailure> {
        if !has_exact_header(
            headers,
            header::ACCEPT,
            RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
        ) {
            return Err(RecoveryCatalogFailure::NotAcceptable);
        }
        if !has_exact_content_type(headers, RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE) {
            return Err(RecoveryCatalogFailure::UnsupportedMedia);
        }
        if content_length_exceeds(headers, MAX_RECOVERY_SCOPE_CATALOG_PREPARATION_BYTES) {
            return Err(RecoveryCatalogFailure::TooLarge);
        }
        if !has_exact_content_type(headers, RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE)
            || !has_exact_header(
                headers,
                header::ACCEPT,
                RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
            )
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::AUTHORIZATION)
        {
            return Err(RecoveryCatalogFailure::InvalidRequest);
        }
        let idempotency_key_hash = idempotency_key_hash(
            headers,
            HTTP_RECOVERY_PREPARATION_IDEMPOTENCY_KEY_HASH_DOMAIN,
        )
        .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let enrollment_capability = parse_recovery_enrollment_capability(headers)?;
        let response_capability = parse_recovery_response_capability(headers)?;
        let bytes = to_bytes(body, MAX_RECOVERY_SCOPE_CATALOG_PREPARATION_BYTES)
            .await
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let command = CatalogPreparationCommand::parse_v2(
            idempotency_key_hash,
            bytes.to_vec(),
            enrollment_capability,
            &response_capability,
        )
        .map_err(|error| map_recovery_catalog_prepare_error(&error))?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let (created, outcome) = self
            .recovery_catalogs
            .prepare(&self.store, &command, now)
            .await
            .map_err(|error| map_recovery_catalog_prepare_error(&error))?;
        Ok(RecoveryCatalogStatusSuccess {
            status: if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            outcome,
            receipt: RecoveryCatalogReceiptKind::Preparation,
        })
    }

    async fn get_recovery_scope_catalog_preparation(
        &self,
        route_request_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogStatusSuccess, RecoveryCatalogFailure> {
        if !has_exact_header(
            headers,
            header::ACCEPT,
            RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE,
        ) {
            return Err(RecoveryCatalogFailure::NotAcceptable);
        }
        if !has_exact_content_type(
            headers,
            RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        ) {
            return Err(RecoveryCatalogFailure::UnsupportedMedia);
        }
        if content_length_exceeds(headers, MAX_RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_BYTES) {
            return Err(RecoveryCatalogFailure::TooLarge);
        }
        if headers.contains_key(header::CONTENT_TYPE)
            || !has_exact_header(
                headers,
                header::ACCEPT,
                RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE,
            )
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
        {
            return Err(RecoveryCatalogFailure::CapabilityRejected);
        }
        let body = to_bytes(body, 1)
            .await
            .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
        if !body.is_empty() {
            return Err(RecoveryCatalogFailure::CapabilityRejected);
        }
        let request_id = route_request_id
            .parse::<DeviceEnrollmentChallengeId>()
            .map_err(|_| RecoveryCatalogFailure::CapabilityRejected)?;
        let response_capability = parse_recovery_response_capability(headers)?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let outcome = self
            .recovery_catalogs
            .status(&self.store, request_id, &response_capability, now)
            .await
            .map_err(|error| map_recovery_catalog_status_error(&error))?;
        // Catalog V2 status is an authoritative one-of-five representation;
        // terminal state is carried in the body and GET itself remains 200.
        let status = StatusCode::OK;
        Ok(RecoveryCatalogStatusSuccess {
            status,
            outcome,
            receipt: RecoveryCatalogReceiptKind::None,
        })
    }

    async fn put_recovery_scope_catalog_provider_response(
        &self,
        route_request_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<RecoveryCatalogStatusSuccess, RecoveryCatalogFailure> {
        if !has_exact_header(
            headers,
            header::ACCEPT,
            RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE,
        ) {
            return Err(RecoveryCatalogFailure::NotAcceptable);
        }
        if !has_exact_content_type(
            headers,
            RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        ) || headers.contains_key(header::CONTENT_ENCODING)
            || !has_exact_header(
                headers,
                header::ACCEPT,
                RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE,
            )
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(DEVICE_ENROLLMENT_CAPABILITY_HEADER)
            || headers.contains_key(RECOVERY_RESPONSE_CAPABILITY_HEADER)
        {
            return Err(RecoveryCatalogFailure::InvalidRequest);
        }
        let request_id = route_request_id
            .parse::<DeviceEnrollmentChallengeId>()
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let credential = parse_device_session_authorization(headers)
            .map_err(|_| RecoveryCatalogFailure::AuthenticationRejected)?;
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_RECOVERY_PROVIDER_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let bytes = to_bytes(body, MAX_RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_BYTES)
            .await
            .map_err(|_| RecoveryCatalogFailure::InvalidRequest)?;
        let command = CatalogProviderResponseCommand::parse_v2(
            idempotency_key_hash,
            request_id,
            bytes.to_vec(),
        )
        .map_err(|error| map_recovery_catalog_provider_error(&error))?;
        let now = self
            .committed_at()
            .map_err(|()| RecoveryCatalogFailure::TemporarilyUnavailable)?;
        let outcome = self
            .recovery_catalogs
            .put_provider_response(&self.store, &command, &credential, now)
            .await
            .map_err(|error| map_recovery_catalog_provider_error(&error))?;
        Ok(RecoveryCatalogStatusSuccess {
            status: if outcome.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            outcome,
            receipt: RecoveryCatalogReceiptKind::ProviderResponse,
        })
    }
}

fn content_length_exceeds(headers: &HeaderMap, maximum: usize) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > maximum)
}
