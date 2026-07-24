use super::*;

pub(crate) async fn bootstrap_identity(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.bootstrap(&parts.headers, body).await {
        Ok(success) => bootstrap_success_response(success, request_id),
        Err(failure) => bootstrap_failure_response(failure, request_id),
    }
}

impl IdentityBootstrapState {
    pub(crate) fn committed_at(&self) -> Result<UtcMillis, ()> {
        UtcMillis::new(self.clock.now_utc_millis().map_err(|_| ())?).map_err(|_| ())
    }
}

pub(crate) async fn deployment_bootstrap_identity(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (mut parts, body) = request.into_parts();
    match state.deployment_bootstrap(&mut parts.headers, body).await {
        Ok(success) => bootstrap_success_response(success, request_id),
        Err(failure) => client_binding_failure_response(failure, request_id),
    }
}

pub(crate) async fn deployment_initial_device(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (mut parts, body) = request.into_parts();
    match state
        .deployment_initial_device(&mut parts.headers, body)
        .await
    {
        Ok(success) => initial_device_success_response(success, request_id),
        Err(failure) => client_binding_failure_response(failure, request_id),
    }
}

pub(crate) async fn get_identity_log_page(
    State(state): State<IdentityBootstrapState>,
    Path(route_identity_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .get_identity_log_page(&route_identity_id, parts.uri.query(), &parts.headers, body)
        .await
    {
        Ok(page) => identity_log_page_success_response(&page, request_id),
        Err(failure) => identity_log_page_failure_response(failure, request_id),
    }
}

pub(crate) async fn get_mls_v5_recovery_authorization(
    State(state): State<IdentityBootstrapState>,
    Path((route_identity_id, route_request_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .mls_v5_recovery_authorization(
            &route_identity_id,
            &route_request_id,
            parts.uri.query(),
            &parts.headers,
            body,
        )
        .await
    {
        Ok(projection) => match projection.exact_bytes() {
            Ok(bytes) => exact_cbor_response(
                StatusCode::OK,
                bytes,
                MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE,
                request_id,
            ),
            Err(_) => mls_v5_recovery_authorization_failure_response(
                MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable,
                request_id,
            ),
        },
        Err(failure) => mls_v5_recovery_authorization_failure_response(failure, request_id),
    }
}

pub(crate) async fn enroll_initial_device(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.enroll_initial_device(&parts.headers, body).await {
        Ok(success) => initial_device_success_response(success, request_id),
        Err(failure) => initial_device_failure_response(failure, request_id),
    }
}

impl IdentityBootstrapState {
    async fn mls_v5_recovery_authorization(
        &self,
        route_identity_id: &str,
        route_request_id: &str,
        raw_query: Option<&str>,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<MlsV5RecoveryAuthorizationProjection, MlsV5RecoveryAuthorizationFailure> {
        if !has_exact_header(
            headers,
            header::ACCEPT,
            MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE,
        ) || headers.contains_key(header::AUTHORIZATION)
            || headers.contains_key(header::CONTENT_TYPE)
            || headers.contains_key(header::CONTENT_ENCODING)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(IDEMPOTENCY_KEY_HEADER)
            || headers.contains_key(IDENTITY_ORIGIN_HEADER)
        {
            return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
        }
        let body = to_bytes(body, 1)
            .await
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::InvalidRequest)?;
        if !body.is_empty() {
            return Err(MlsV5RecoveryAuthorizationFailure::InvalidRequest);
        }
        let query = parse_mls_v5_recovery_authorization_query(
            route_identity_id,
            route_request_id,
            raw_query,
        )?;
        let now = self
            .committed_at()
            .map_err(|()| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
        let mut session = self
            .store
            .begin()
            .await
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
        let result =
            load_mls_v5_recovery_authorization_projection(session.connection(), query, now).await;
        session
            .rollback()
            .await
            .map_err(|_| MlsV5RecoveryAuthorizationFailure::TemporarilyUnavailable)?;
        result
    }

    async fn get_identity_log_page(
        &self,
        route_identity_id: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<IdentityLogPageV1, IdentityLogPageFailure> {
        if headers.contains_key(header::CONTENT_ENCODING) {
            return Err(IdentityLogPageFailure::InvalidRequest);
        }
        let body = to_bytes(body, 1)
            .await
            .map_err(|_| IdentityLogPageFailure::InvalidRequest)?;
        if !body.is_empty() {
            return Err(IdentityLogPageFailure::InvalidRequest);
        }
        let (identity_id, after_sequence, limit) =
            parse_identity_log_page_request(route_identity_id, query)?;
        match self
            .repository
            .read_page(&self.store, identity_id, after_sequence, limit)
            .await
        {
            Ok(IdentityLogPageReadOutcome::Page(page)) => Ok(page),
            Ok(IdentityLogPageReadOutcome::NotFound) => Err(IdentityLogPageFailure::NotFound),
            Ok(IdentityLogPageReadOutcome::Inactive) => Err(IdentityLogPageFailure::Inactive),
            Ok(IdentityLogPageReadOutcome::CursorAhead) => Err(IdentityLogPageFailure::CursorAhead),
            Err(error) => Err(map_identity_log_page_persistence_error(&error)),
        }
    }

    async fn bootstrap(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<BootstrapSuccess, BootstrapFailure> {
        if !has_exact_event_content_type(headers)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(BootstrapFailure::InvalidBootstrap);
        }
        let idempotency_key_hash = idempotency_key_hash(headers, HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| BootstrapFailure::InvalidBootstrap)?;
        if exact_event_bytes.is_empty() {
            return Err(BootstrapFailure::InvalidBootstrap);
        }

        let event = IdentityLogEventV1::decode_and_verify(&exact_event_bytes)
            .map_err(|_| BootstrapFailure::InvalidBootstrap)?;
        if event.wire() != IDENTITY_LOG_WIRE_VERSION
            || event.sequence().get() != 1
            || event.previous_event_hash().is_some()
            || !matches!(event.payload(), IdentityLogEventPayloadV1::Genesis { .. })
        {
            return Err(BootstrapFailure::InvalidBootstrap);
        }

        let command =
            IdentityAppendCommand::new(idempotency_key_hash, None, exact_event_bytes.to_vec())
                .map_err(|_| BootstrapFailure::InvalidBootstrap)?;
        let committed_at = UtcMillis::new(
            self.clock
                .now_utc_millis()
                .map_err(|_| BootstrapFailure::TemporarilyUnavailable)?,
        )
        .map_err(|_| BootstrapFailure::TemporarilyUnavailable)?;

        match self
            .repository
            .append_bootstrap(&self.store, &command, committed_at)
            .await
        {
            Ok(IdentityAppendOutcome::Committed(receipt)) => Ok(BootstrapSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Replayed(receipt)) => Ok(BootstrapSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(BootstrapFailure::IdentityConflict),
            Err(error) => Err(map_persistence_error(&error)),
        }
    }

    async fn deployment_bootstrap(
        &self,
        headers: &mut HeaderMap,
        body: Body,
    ) -> Result<BootstrapSuccess, ClientBindingFailure> {
        if !has_exact_event_content_type(headers)
            || headers.contains_key(header::IF_MATCH)
            || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(ClientBindingFailure::Invalid);
        }
        let binding_id = client_binding_id(headers)?;
        let authorization_digest = take_client_binding_authorization_digest(headers)?;
        let idem = idempotency_key_hash_binding(headers, HTTP_IDEMPOTENCY_KEY_HASH_DOMAIN)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| ClientBindingFailure::Invalid)?;
        if exact_event_bytes.is_empty() {
            return Err(ClientBindingFailure::Invalid);
        }
        let now = self
            .committed_at()
            .map_err(|()| ClientBindingFailure::Unavailable)?;
        match self
            .client_bindings
            .deployment_bootstrap(
                &self.store,
                binding_id,
                authorization_digest,
                idem,
                exact_event_bytes.to_vec(),
                now,
            )
            .await
        {
            Ok(IdentityAppendOutcome::Committed(receipt)) => Ok(BootstrapSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Replayed(receipt)) => Ok(BootstrapSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(ClientBindingFailure::Conflict),
            Err(error) => Err(map_client_binding_error(&error)),
        }
    }

    async fn deployment_initial_device(
        &self,
        headers: &mut HeaderMap,
        body: Body,
    ) -> Result<InitialDeviceSuccess, ClientBindingFailure> {
        if !has_exact_event_content_type(headers) || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(ClientBindingFailure::Invalid);
        }
        let binding_id = client_binding_id(headers)?;
        let authorization_digest = take_client_binding_authorization_digest(headers)?;
        let idem =
            idempotency_key_hash_binding(headers, HTTP_INITIAL_DEVICE_IDEMPOTENCY_KEY_HASH_DOMAIN)?;
        let expected = expected_genesis_hash(headers).map_err(|_| ClientBindingFailure::Invalid)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| ClientBindingFailure::Invalid)?;
        if exact_event_bytes.is_empty() {
            return Err(ClientBindingFailure::Invalid);
        }
        let now = self
            .committed_at()
            .map_err(|()| ClientBindingFailure::Unavailable)?;
        match self
            .client_bindings
            .initial_device(
                &self.store,
                binding_id,
                authorization_digest,
                idem,
                expected,
                exact_event_bytes.to_vec(),
                now,
            )
            .await
        {
            Ok(IdentityAppendOutcome::Committed(receipt)) => Ok(InitialDeviceSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Replayed(receipt)) => Ok(InitialDeviceSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(ClientBindingFailure::Conflict),
            Err(error) => Err(map_client_binding_error(&error)),
        }
    }

    async fn enroll_initial_device(
        &self,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<InitialDeviceSuccess, InitialDeviceFailure> {
        if !has_exact_event_content_type(headers) || headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(InitialDeviceFailure::InvalidInitialDevice);
        }
        let idempotency_key_hash =
            idempotency_key_hash(headers, HTTP_INITIAL_DEVICE_IDEMPOTENCY_KEY_HASH_DOMAIN)
                .map_err(|_| InitialDeviceFailure::InvalidInitialDevice)?;
        let expected_genesis_hash = expected_genesis_hash(headers)?;
        let exact_event_bytes = to_bytes(body, MAX_IDENTITY_BOOTSTRAP_EVENT_BYTES)
            .await
            .map_err(|_| InitialDeviceFailure::InvalidInitialDevice)?;
        if exact_event_bytes.is_empty() {
            return Err(InitialDeviceFailure::InvalidInitialDevice);
        }
        let committed_at = self
            .committed_at()
            .map_err(|()| InitialDeviceFailure::TemporarilyUnavailable)?;
        match self
            .repository
            .append_initial_device(
                &self.store,
                idempotency_key_hash,
                expected_genesis_hash,
                exact_event_bytes.to_vec(),
                committed_at,
            )
            .await
        {
            Ok(IdentityAppendOutcome::Committed(receipt)) => Ok(InitialDeviceSuccess {
                status: StatusCode::CREATED,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Replayed(receipt)) => Ok(InitialDeviceSuccess {
                status: StatusCode::OK,
                exact_receipt_bytes: receipt.exact_bytes().to_vec(),
            }),
            Ok(IdentityAppendOutcome::Forked { .. }) => Err(InitialDeviceFailure::IdentityConflict),
            Err(error) => Err(map_initial_device_persistence_error(&error)),
        }
    }
}
