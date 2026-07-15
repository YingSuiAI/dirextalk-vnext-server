use axum::{
    Router,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, post, put},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::RequestId;
use dtx_mailbox::{
    AttachmentCapability, AttachmentCreate, AttachmentError, AttachmentManifest,
    AttachmentRepository, AttachmentStatus,
};
use dtx_wire::{CanonicalValue, Sha256Digest, encode_deterministic_cbor};
use uuid::Uuid;

use super::{
    HTTP_ENQUEUE_IDEMPOTENCY_HASH_DOMAIN, MailboxFailure, MailboxNodeState, cbor_field,
    exact_cbor_fields, has_exact_content_type, idempotency_key_hash, mailbox_failure_response,
    parse_cbor_bytes, parse_cbor_device_id, parse_cbor_identity_id, parse_cbor_utc_millis,
    parse_device_session_authorization, read_exact_body, require_cbor_version,
};

const CREATE_TYPE: &str = "application/vnd.dirextalk.attachment-create.v1+cbor";
const MANIFEST_TYPE: &str = "application/vnd.dirextalk.attachment-manifest.v1+octets";
const CHUNK_TYPE: &str = "application/vnd.dirextalk.attachment-chunk.v1+octets";
const CAPABILITY_SCHEME: &str = "DTX-Attachment-Capability";
const DIGEST_HEADER: &str = "dtx-ciphertext-sha256";
const UPLOAD_HEADER: HeaderName = HeaderName::from_static("dtx-attachment-upload-capability");
const READ_HEADER: HeaderName = HeaderName::from_static("dtx-attachment-read-capability");

pub(super) fn attachment_router() -> Router<MailboxNodeState> {
    Router::new()
        .route("/v1/attachments", post(create))
        .route("/v1/attachments/{object_id}", delete(cancel))
        .route(
            "/v1/attachments/{object_id}/manifest",
            put(finalize).get(read_manifest),
        )
        .route(
            "/v1/attachments/{object_id}/chunks/{index}",
            put(put_chunk).get(read_chunk),
        )
}

async fn create(State(state): State<MailboxNodeState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let result = async {
        if !has_exact_content_type(&parts.headers, CREATE_TYPE)
            || parts.headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let credential = parse_device_session_authorization(&parts.headers)?;
        let bytes = read_exact_body(body, 16_384).await?;
        let value = dtx_wire::decode_deterministic_cbor(&bytes)
            .map_err(|_| MailboxFailure::InvalidRequest)?;
        let fields = exact_cbor_fields(&value, 8)?;
        require_cbor_version(cbor_field(fields, 1)?)?;
        let object_id = parse_uuid(cbor_field(fields, 2)?)?;
        let owner_identity_id = parse_cbor_identity_id(cbor_field(fields, 3)?)?;
        let owner_device_id = parse_cbor_device_id(cbor_field(fields, 4)?)?;
        let manifest_digest =
            Sha256Digest::from_bytes(parse_cbor_bytes::<32>(cbor_field(fields, 5)?)?);
        let chunk_count = parse_u16(cbor_field(fields, 6)?)?;
        let ciphertext_bytes = parse_u64(cbor_field(fields, 7)?)?;
        let expires_at = parse_cbor_utc_millis(cbor_field(fields, 8)?)?;
        let upload = parse_secret_header(&parts.headers, &UPLOAD_HEADER)?;
        let read = parse_secret_header(&parts.headers, &READ_HEADER)?;
        if upload.iter().all(|byte| *byte == 0)
            || read.iter().all(|byte| *byte == 0)
            || upload == read
        {
            return Err(MailboxFailure::TemporarilyUnavailable);
        }
        let upload_capability = AttachmentCapability::new(upload);
        let read_capability = AttachmentCapability::new(read);
        let status = AttachmentRepository
            .create(
                &state.store,
                &credential,
                &AttachmentCreate {
                    object_id,
                    owner_identity_id,
                    owner_device_id,
                    manifest_digest,
                    chunk_count,
                    ciphertext_bytes,
                    expires_at,
                },
                &upload_capability,
                &read_capability,
                state.now()?,
            )
            .await
            .map_err(map_error)?;
        let receipt = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(object_id.to_string()),
            ),
        ]))
        .map_err(|_| MailboxFailure::TemporarilyUnavailable)?;
        let mut response = (
            if status == AttachmentStatus::Replay {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            receipt,
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(CREATE_TYPE));
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if status != AttachmentStatus::Replay {
            response
                .headers_mut()
                .insert(UPLOAD_HEADER, secret_header(&upload)?);
            response
                .headers_mut()
                .insert(READ_HEADER, secret_header(&read)?);
        }
        Ok(response)
    }
    .await;
    result.unwrap_or_else(|failure| mailbox_failure_response(failure, RequestId::new()))
}

async fn put_chunk(
    State(state): State<MailboxNodeState>,
    Path((object, index)): Path<(String, u16)>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let result = async {
        if !has_exact_content_type(&parts.headers, CHUNK_TYPE)
            || parts.headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let object_id = object
            .parse::<Uuid>()
            .map_err(|_| MailboxFailure::InvalidRequest)?;
        let capability = parse_capability(&parts.headers)?;
        let idempotency =
            idempotency_key_hash(&parts.headers, HTTP_ENQUEUE_IDEMPOTENCY_HASH_DOMAIN)?;
        let claimed = parse_digest_header(&parts.headers)?;
        let ciphertext = read_exact_body(body, 1_048_576).await?;
        let status = AttachmentRepository
            .put_chunk(
                &state.store,
                object_id,
                index,
                &capability,
                idempotency,
                claimed,
                &ciphertext,
                state.now()?,
            )
            .await
            .map_err(map_error)?;
        Ok((
            if status == AttachmentStatus::Replay {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response())
    }
    .await;
    result.unwrap_or_else(|failure| mailbox_failure_response(failure, RequestId::new()))
}

async fn finalize(
    State(state): State<MailboxNodeState>,
    Path(object): Path<String>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let result = async {
        if !has_exact_content_type(&parts.headers, MANIFEST_TYPE)
            || parts.headers.contains_key(header::CONTENT_ENCODING)
        {
            return Err(MailboxFailure::InvalidRequest);
        }
        let object_id = object
            .parse::<Uuid>()
            .map_err(|_| MailboxFailure::InvalidRequest)?;
        let capability = parse_capability(&parts.headers)?;
        let manifest = AttachmentManifest::parse(read_exact_body(body, 1_048_576).await?)
            .map_err(map_error)?;
        let status = AttachmentRepository
            .finalize(
                &state.store,
                object_id,
                &capability,
                &manifest,
                state.now()?,
            )
            .await
            .map_err(map_error)?;
        Ok((
            if status == AttachmentStatus::Replay {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            [(header::CACHE_CONTROL, "no-store")],
        )
            .into_response())
    }
    .await;
    result.unwrap_or_else(|failure| mailbox_failure_response(failure, RequestId::new()))
}

async fn read_manifest(
    State(state): State<MailboxNodeState>,
    Path(object): Path<String>,
    request: Request,
) -> Response {
    read_object(state, object, None, request.headers()).await
}

async fn read_chunk(
    State(state): State<MailboxNodeState>,
    Path((object, index)): Path<(String, u16)>,
    request: Request,
) -> Response {
    read_object(state, object, Some(index), request.headers()).await
}

async fn read_object(
    state: MailboxNodeState,
    object: String,
    index: Option<u16>,
    headers: &HeaderMap,
) -> Response {
    let result: Result<Response, MailboxFailure> = async {
        let object_id = object
            .parse::<Uuid>()
            .map_err(|_| MailboxFailure::InvalidRequest)?;
        let capability = parse_capability(headers)?;
        let now = state.now()?;
        if let Some(index) = index {
            let chunk = AttachmentRepository
                .read_chunk(&state.store, object_id, index, &capability, now)
                .await
                .map_err(map_error)?;
            let mut response = (StatusCode::OK, chunk.ciphertext).into_response();
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(CHUNK_TYPE));
            response.headers_mut().insert(
                HeaderName::from_static(DIGEST_HEADER),
                HeaderValue::from_str(&Base64UrlUnpadded::encode_string(chunk.digest.as_bytes()))
                    .map_err(|_| MailboxFailure::TemporarilyUnavailable)?,
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            Ok(response)
        } else {
            let manifest = AttachmentRepository
                .read_manifest(&state.store, object_id, &capability, now)
                .await
                .map_err(map_error)?;
            let mut response = (StatusCode::OK, manifest).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(MANIFEST_TYPE),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            Ok(response)
        }
    }
    .await;
    result.unwrap_or_else(|failure| mailbox_failure_response(failure, RequestId::new()))
}

async fn cancel(
    State(state): State<MailboxNodeState>,
    Path(object): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result: Result<Response, MailboxFailure> = async {
        let object_id = object
            .parse::<Uuid>()
            .map_err(|_| MailboxFailure::InvalidRequest)?;
        let credential = parse_device_session_authorization(&headers)?;
        AttachmentRepository
            .cancel(&state.store, &credential, object_id, state.now()?)
            .await
            .map_err(map_error)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    }
    .await;
    result.unwrap_or_else(|failure| mailbox_failure_response(failure, RequestId::new()))
}

fn parse_capability(headers: &HeaderMap) -> Result<AttachmentCapability, MailboxFailure> {
    let value = super::exact_authorization_value(headers, CAPABILITY_SCHEME)
        .map_err(|_| MailboxFailure::Unavailable)?;
    Ok(AttachmentCapability::new(
        super::decode_base64url_32(value).map_err(|()| MailboxFailure::Unavailable)?,
    ))
}
fn parse_digest_header(headers: &HeaderMap) -> Result<Sha256Digest, MailboxFailure> {
    let value = headers
        .get(DIGEST_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(MailboxFailure::InvalidRequest)?;
    Ok(Sha256Digest::from_bytes(
        super::decode_base64url_32(value).map_err(|()| MailboxFailure::InvalidRequest)?,
    ))
}
fn secret_header(bytes: &[u8; 32]) -> Result<HeaderValue, MailboxFailure> {
    let mut value = HeaderValue::from_str(&Base64UrlUnpadded::encode_string(bytes))
        .map_err(|_| MailboxFailure::TemporarilyUnavailable)?;
    value.set_sensitive(true);
    Ok(value)
}

fn parse_secret_header(headers: &HeaderMap, name: &HeaderName) -> Result<[u8; 32], MailboxFailure> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(MailboxFailure::InvalidRequest)?;
    if values.next().is_some() {
        return Err(MailboxFailure::InvalidRequest);
    }
    super::decode_base64url_32(value).map_err(|()| MailboxFailure::InvalidRequest)
}
fn parse_uuid(value: &CanonicalValue) -> Result<Uuid, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}
fn parse_u16(value: &CanonicalValue) -> Result<u16, MailboxFailure> {
    u16::try_from(parse_u64(value)?).map_err(|_| MailboxFailure::InvalidRequest)
}
fn parse_u64(value: &CanonicalValue) -> Result<u64, MailboxFailure> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    Ok(*value)
}
#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as Result::map_err adapter"
)]
fn map_error(error: AttachmentError) -> MailboxFailure {
    match error {
        AttachmentError::Invalid => MailboxFailure::InvalidRequest,
        AttachmentError::Conflict => MailboxFailure::Conflict,
        AttachmentError::Authentication => MailboxFailure::AuthenticationRejected,
        AttachmentError::Unavailable => MailboxFailure::Unavailable,
        AttachmentError::Database(_) => MailboxFailure::TemporarilyUnavailable,
    }
}
