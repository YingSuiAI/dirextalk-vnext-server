use super::{
    HISTORY_RECOVERY_COMPLETION_CONTENT_TYPE, HISTORY_RECOVERY_COMPLETION_RECEIPT_CONTENT_TYPE,
    IdentityBootstrapState, IntoResponse, Path, Request, Response, State, StatusCode,
    has_exact_content_type, header, idempotency_key_hash, parse_device_session_authorization,
    to_bytes,
};
use dtx_identity_persistence::{
    CompletionSignerMetadata, HistoryRecoveryCompletionCommand, is_canonical_https_origin,
};
use dtx_wire::Sha256Digest;

const IDEMPOTENCY_DOMAIN: &[u8] = b"dirextalk.history-recovery.completion-idempotency.v2\0";

pub(crate) async fn get_completion_key(State(state): State<IdentityBootstrapState>) -> Response {
    let Some(config) = state.completion_signer.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !is_canonical_https_origin(&state.public_origin) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let now = match state.committed_at() {
        Ok(now) => now,
        Err(()) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let metadata = CompletionSignerMetadata {
        key_id: config.key_id,
        epoch: config.epoch,
        rollback_floor_epoch: config.rollback_floor_epoch,
        issued_at: config.issued_at,
        expires_at: config.expires_at,
        previous_descriptor_digest: config.previous_descriptor_digest,
    };
    match state
        .completion
        .ensure_descriptor(
            &state.store,
            &state.public_origin,
            metadata,
            &config.signing_key,
            now,
        )
        .await
    {
        Ok(descriptor) => exact_descriptor_response(descriptor.exact_bytes),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

pub(crate) async fn get_historical_completion_key(
    State(state): State<IdentityBootstrapState>,
    Path(digest): Path<String>,
) -> Response {
    let Ok(raw) = hex_digest(&digest) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match reachable_descriptor(&state, raw).await {
        Ok(Some(descriptor)) => exact_descriptor_response(descriptor.exact_bytes),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn reachable_descriptor(
    state: &IdentityBootstrapState,
    target: Sha256Digest,
) -> Result<
    Option<dtx_identity_persistence::CompletionKeyDescriptor>,
    dtx_identity_persistence::IdentityPersistenceError,
> {
    let Some(mut current) = state.completion.current_descriptor(&state.store).await? else {
        return Ok(None);
    };
    for _ in 0..1024 {
        if current.digest == target {
            return Ok(Some(current));
        }
        let Some(previous) = current.previous_descriptor_digest else {
            return Ok(None);
        };
        let Some(next) = state
            .completion
            .historical_descriptor(&state.store, previous)
            .await?
        else {
            return Ok(None);
        };
        if next.epoch >= current.epoch || next.rollback_floor_epoch > current.rollback_floor_epoch {
            return Ok(None);
        }
        current = next;
    }
    Ok(None)
}

pub(crate) async fn complete_history_recovery(
    State(state): State<IdentityBootstrapState>,
    Path(completion_id): Path<String>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if !has_exact_content_type(&parts.headers, HISTORY_RECOVERY_COMPLETION_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
    {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let Ok(completion_id) = completion_id.parse::<uuid::Uuid>() else {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    };
    if completion_id.get_version_num() != 7 {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let Ok(credential) = parse_device_session_authorization(&parts.headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(idempotency) = idempotency_key_hash(&parts.headers, IDEMPOTENCY_DOMAIN) else {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    };
    let Ok(bytes) = to_bytes(body, 3_593_836).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let Ok(command) = HistoryRecoveryCompletionCommand::parse(bytes.to_vec(), idempotency) else {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    };
    if command.completion_id != completion_id {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let Some(config) = state.completion_signer.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !is_canonical_https_origin(&state.public_origin) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let now = match state.committed_at() {
        Ok(now) => now,
        Err(()) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let metadata = CompletionSignerMetadata {
        key_id: config.key_id,
        epoch: config.epoch,
        rollback_floor_epoch: config.rollback_floor_epoch,
        issued_at: config.issued_at,
        expires_at: config.expires_at,
        previous_descriptor_digest: config.previous_descriptor_digest,
    };
    let descriptor = match state
        .completion
        .ensure_descriptor(
            &state.store,
            &state.public_origin,
            metadata,
            &config.signing_key,
            now,
        )
        .await
    {
        Ok(v) => v,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    match state
        .completion
        .submit(
            &state.store,
            &command,
            &credential,
            &descriptor,
            &config.signing_key,
            now,
        )
        .await
    {
        Ok(outcome) => {
            let status = if outcome.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            exact_receipt_response(status, outcome.receipt_bytes)
        }
        Err(error) => map_completion_error(error),
    }
}

pub(crate) async fn get_history_recovery_completion(
    State(state): State<IdentityBootstrapState>,
    Path(completion_id): Path<String>,
    request: Request,
) -> Response {
    let (parts, _body) = request.into_parts();
    let Ok(completion_id) = completion_id.parse::<uuid::Uuid>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(credential) = parse_device_session_authorization(&parts.headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let now = match state.committed_at() {
        Ok(now) => now,
        Err(()) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    match state
        .completion
        .get_receipt(&state.store, &credential, completion_id, now)
        .await
    {
        Ok(Some(bytes)) => exact_receipt_response(StatusCode::OK, bytes),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn exact_descriptor_response(bytes: Vec<u8>) -> Response {
    let mut response = (StatusCode::OK, bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        super::HeaderValue::from_static(
            "application/vnd.dirextalk.history-recovery-completion-key-descriptor.v2+cbor",
        ),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        super::HeaderValue::from_static("no-store"),
    );
    response
}
fn exact_receipt_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = (status, bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        super::HeaderValue::from_static(HISTORY_RECOVERY_COMPLETION_RECEIPT_CONTENT_TYPE),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        super::HeaderValue::from_static("no-store"),
    );
    response
}
fn hex_digest(value: &str) -> Result<Sha256Digest, ()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(Sha256Digest::from_bytes(out))
}
fn map_completion_error(error: dtx_identity_persistence::IdentityPersistenceError) -> Response {
    match error {
        dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected
        | dtx_identity_persistence::IdentityPersistenceError::DeviceSessionRevoked => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        dtx_identity_persistence::IdentityPersistenceError::RecoveryCompletionExpired => {
            StatusCode::GONE.into_response()
        }
        dtx_identity_persistence::IdentityPersistenceError::IdempotencyConflict => {
            StatusCode::CONFLICT.into_response()
        }
        dtx_identity_persistence::IdentityPersistenceError::RecoveryCompletionInvalid => {
            StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
