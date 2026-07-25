pub fn mailbox_router(store: MailboxPgStore) -> Router {
    mailbox_router_with_state(MailboxNodeState::new(store))
}

/// Builds the mailbox router with explicit state for deterministic tests.
pub fn mailbox_router_with_state(state: MailboxNodeState) -> Router {
    Router::new()
        .route(MAILBOX_REGISTER_PATH_TEMPLATE, put(register_mailbox))
        .route(MAILBOX_ENQUEUE_PATH_TEMPLATE, put(enqueue_mailbox_envelope))
        .route(MAILBOX_PULL_PATH_TEMPLATE, post(pull_mailbox))
        .route(MAILBOX_ACK_PATH_TEMPLATE, post(acknowledge_mailbox))
        .route(
            IDENTITY_MAILBOX_PULL_V3_PATH,
            post(pull_identity_mailbox_v3),
        )
        .route(
            IDENTITY_MAILBOX_ACK_V2_PATH,
            post(acknowledge_identity_mailbox_v2),
        )
        .route(DEVICE_HISTORY_GRANT_V1_PATH, post(grant_device_history))
        .route(DEVICE_HISTORY_GRANT_V2_PATH, post(grant_device_history_v2))
        .route(DEVICE_HISTORY_GRANT_V5_PATH, post(grant_device_history_v5))
        .route(
            ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
            post(write_account_read_cursor),
        )
        .route(
            ACCOUNT_READ_CURSOR_QUERY_V1_PATH,
            post(query_account_read_cursor),
        )
        .merge(attachment::attachment_router())
        .with_state(state)
}

async fn register_mailbox(
    State(state): State<MailboxNodeState>,
    Path(mailbox_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.register(&mailbox_id, &parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn enqueue_mailbox_envelope(
    State(state): State<MailboxNodeState>,
    Path((mailbox_id, envelope_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state
        .enqueue(&mailbox_id, &envelope_id, &parts.headers, body)
        .await
    {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn pull_mailbox(
    State(state): State<MailboxNodeState>,
    Path(mailbox_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.pull(&mailbox_id, &parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn acknowledge_mailbox(
    State(state): State<MailboxNodeState>,
    Path(mailbox_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.acknowledge(&mailbox_id, &parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn pull_identity_mailbox_v3(
    State(state): State<MailboxNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    let result = state.pull_identity_v3(&parts.headers, body).await;
    match result {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn acknowledge_identity_mailbox_v2(
    State(state): State<MailboxNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.acknowledge_identity_v2(&parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn grant_device_history(State(state): State<MailboxNodeState>, request: Request) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.grant_device_history(&parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn grant_device_history_v2(
    State(state): State<MailboxNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.grant_device_history_v2(&parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn grant_device_history_v5(
    State(state): State<MailboxNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.grant_device_history_v5(&parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn write_account_read_cursor(
    State(state): State<MailboxNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.write_account_read_cursor(&parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}

async fn query_account_read_cursor(
    State(state): State<MailboxNodeState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    match state.query_account_read_cursor(&parts.headers, body).await {
        Ok(success) => mailbox_success_response(success, request_id),
        Err(failure) => mailbox_failure_response(failure, request_id),
    }
}
use axum::{
    Router,
    extract::{Path, Request, State},
    response::Response,
    routing::{post, put},
};
use dtx_domain::RequestId;
use dtx_mailbox::MailboxPgStore;

use super::{
    ACCOUNT_READ_CURSOR_QUERY_V1_PATH, ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
    DEVICE_HISTORY_GRANT_V1_PATH, DEVICE_HISTORY_GRANT_V2_PATH, DEVICE_HISTORY_GRANT_V5_PATH,
    IDENTITY_MAILBOX_ACK_V2_PATH, IDENTITY_MAILBOX_PULL_V3_PATH, MAILBOX_ACK_PATH_TEMPLATE,
    MAILBOX_ENQUEUE_PATH_TEMPLATE, MAILBOX_PULL_PATH_TEMPLATE, MAILBOX_REGISTER_PATH_TEMPLATE,
};
use super::{
    attachment,
    errors::{mailbox_failure_response, mailbox_success_response},
    state::MailboxNodeState,
};
