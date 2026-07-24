use super::{
    CONTACT_INVITE_CONTENT_TYPE, CONTACT_INVITE_RECEIPT_CONTENT_TYPE, CONTACT_INVITE_SECRET_HEADER,
    CONTACT_PENDING_CONTENT_TYPE, CONTACT_RECEIPT_CONTENT_TYPE, CONTACT_RECEIPT_SECRET_HEADER,
    CONTACT_REQUEST_CONTENT_TYPE, CONTACT_REVIEW_CONTENT_TYPE, ContactInviteV1, ContactRequestV1,
    ContactReviewV1, ContactStoreError, HeaderMap, IdentityBootstrapState, InviteCapabilityId,
    Path, Request, RequestId, Response, State, StatusCode, contact_failure, contact_secret,
    encode_pending, exact_cbor_response, has_exact_content_type, header, idempotency_key_hash,
    parse_device_session_authorization, to_bytes,
};

pub(crate) async fn create_contact_invite(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    if !has_exact_content_type(&parts.headers, CONTACT_INVITE_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
    {
        return contact_failure(ContactStoreError::Invalid, request_id);
    }
    let Ok(credential) = parse_device_session_authorization(&parts.headers) else {
        return contact_failure(ContactStoreError::Authentication, request_id);
    };
    let Ok(idempotency) =
        idempotency_key_hash(&parts.headers, b"dirextalk.contact-invite-http.v1\0")
    else {
        return contact_failure(ContactStoreError::Invalid, request_id);
    };
    let secret = match contact_secret(&parts.headers, CONTACT_INVITE_SECRET_HEADER) {
        Ok(v) => v,
        Err(e) => return contact_failure(e, request_id),
    };
    let Ok(bytes) = to_bytes(body, 65_536).await else {
        return contact_failure(ContactStoreError::Invalid, request_id);
    };
    let Ok(invite) = ContactInviteV1::decode(&bytes) else {
        return contact_failure(ContactStoreError::Invalid, request_id);
    };
    let Ok(now) = state.committed_at() else {
        return contact_failure(ContactStoreError::Unavailable, request_id);
    };
    match state
        .contacts
        .create_invite(
            &state.store,
            &credential,
            *idempotency.as_bytes(),
            &invite,
            &bytes,
            secret,
            now,
        )
        .await
    {
        Ok(receipt) => exact_cbor_response(
            StatusCode::CREATED,
            receipt,
            CONTACT_INVITE_RECEIPT_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
pub(crate) async fn revoke_contact_invite(
    State(state): State<IdentityBootstrapState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = RequestId::new();
    let Ok(invite_id) = id.parse::<InviteCapabilityId>() else {
        return contact_failure(ContactStoreError::Invalid, request_id);
    };
    let credential = match parse_device_session_authorization(&headers) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Authentication, request_id),
    };
    let idempotency = match idempotency_key_hash(&headers, b"dirextalk.contact-revoke-http.v1\0") {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, request_id),
    };
    match state
        .contacts
        .revoke_invite(
            &state.store,
            &credential,
            *idempotency.as_bytes(),
            invite_id,
            now,
        )
        .await
    {
        Ok(receipt) => exact_cbor_response(
            StatusCode::OK,
            receipt,
            CONTACT_INVITE_RECEIPT_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
pub(crate) async fn submit_contact_request(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    let (parts, body) = request.into_parts();
    if !has_exact_content_type(&parts.headers, CONTACT_REQUEST_CONTENT_TYPE)
        || parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
    {
        return contact_failure(ContactStoreError::Invalid, request_id);
    }
    let secret = match contact_secret(&parts.headers, CONTACT_INVITE_SECRET_HEADER) {
        Ok(v) => v,
        Err(e) => return contact_failure(e, request_id),
    };
    let bytes = match to_bytes(body, 150_000).await {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let command = match ContactRequestV1::decode(&bytes) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, request_id),
    };
    match state
        .contacts
        .submit_request(&state.store, &command, &bytes, secret, now)
        .await
    {
        Ok(receipt) => exact_cbor_response(
            StatusCode::CREATED,
            receipt.exact_bytes,
            CONTACT_RECEIPT_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
pub(crate) async fn pending_contact_requests(
    State(state): State<IdentityBootstrapState>,
    headers: HeaderMap,
) -> Response {
    let request_id = RequestId::new();
    let credential = match parse_device_session_authorization(&headers) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Authentication, request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, request_id),
    };
    match state
        .contacts
        .pending(&state.store, &credential, now)
        .await
        .and_then(|v| encode_pending(&v))
    {
        Ok(bytes) => exact_cbor_response(
            StatusCode::OK,
            bytes,
            CONTACT_PENDING_CONTENT_TYPE,
            request_id,
        ),
        Err(e) => contact_failure(e, request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
pub(crate) async fn review_contact_request(
    State(state): State<IdentityBootstrapState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let http_request_id = RequestId::new();
    let Ok(route_id) = id.parse::<RequestId>() else {
        return contact_failure(ContactStoreError::Invalid, http_request_id);
    };
    let (parts, body) = request.into_parts();
    if !has_exact_content_type(&parts.headers, CONTACT_REVIEW_CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
    {
        return contact_failure(ContactStoreError::Invalid, http_request_id);
    }
    let credential = match parse_device_session_authorization(&parts.headers) {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Authentication, http_request_id),
    };
    let idem = match idempotency_key_hash(&parts.headers, b"dirextalk.contact-review-http.v1\0") {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, http_request_id),
    };
    let bytes = match to_bytes(body, 300_000).await {
        Ok(v) => v,
        Err(_) => return contact_failure(ContactStoreError::Invalid, http_request_id),
    };
    let review = match ContactReviewV1::decode(&bytes) {
        Ok(v) if v.request_id() == route_id => v,
        _ => return contact_failure(ContactStoreError::Invalid, http_request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, http_request_id),
    };
    match state
        .contacts
        .review(
            &state.store,
            &credential,
            *idem.as_bytes(),
            &review,
            &bytes,
            now,
        )
        .await
    {
        Ok(v) => exact_cbor_response(
            StatusCode::OK,
            v.exact_bytes,
            CONTACT_RECEIPT_CONTENT_TYPE,
            http_request_id,
        ),
        Err(e) => contact_failure(e, http_request_id),
    }
}
#[allow(
    clippy::manual_let_else,
    reason = "explicit failure mapping keeps each HTTP boundary branch visible"
)]
pub(crate) async fn get_contact_receipt(
    State(state): State<IdentityBootstrapState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let http_request_id = RequestId::new();
    let Ok(id) = id.parse::<RequestId>() else {
        return contact_failure(ContactStoreError::Invalid, http_request_id);
    };
    let secret = match contact_secret(&headers, CONTACT_RECEIPT_SECRET_HEADER) {
        Ok(v) => v,
        Err(e) => return contact_failure(e, http_request_id),
    };
    let now = match state.committed_at() {
        Ok(v) => v,
        Err(()) => return contact_failure(ContactStoreError::Unavailable, http_request_id),
    };
    match state.contacts.receipt(&state.store, id, secret, now).await {
        Ok(v) => exact_cbor_response(
            StatusCode::OK,
            v.exact_bytes,
            CONTACT_RECEIPT_CONTENT_TYPE,
            http_request_id,
        ),
        Err(e) => contact_failure(e, http_request_id),
    }
}
