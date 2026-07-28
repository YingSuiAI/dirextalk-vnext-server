use super::{
    Base64UrlUnpadded, Encoding, HeaderMap, HeaderValue, IdentityBootstrapState, IntoResponse,
    Path, Request, RequestId, Response, Sha256Digest, State, StatusCode, Zeroize, Zeroizing,
    header, to_bytes,
};
use dtx_identity_persistence::{
    CLIENT_BINDING_AUTHORIZATION_HASH_DOMAIN, CLIENT_BINDING_ISSUE_HASH_DOMAIN,
    ClientBindingIssueCommand, DEPLOYMENT_BINDING_CAPABILITY_HASH_DOMAIN,
    DEPLOYMENT_BINDING_CLIENT_AUTHORIZATION_DOMAIN, DEPLOYMENT_BINDING_STATUS_TOKEN_HASH_DOMAIN,
    DeploymentBindingTicketError, DeploymentBindingTicketState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_REDEEM_BYTES: usize = 512;
const STATUS_AUTHORIZATION_SCHEME: &str = "Dirextalk-Binding-Status";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemRequest {
    protocol_version: u8,
    ticket_id: String,
    capability: String,
}

impl Drop for RedeemRequest {
    fn drop(&mut self) {
        self.capability.zeroize();
    }
}

#[derive(Serialize)]
struct BindingImport {
    schema: &'static str,
    schema_version: u8,
    binding_id: Uuid,
    deployment_operation_id: Uuid,
    tenant_id: Uuid,
    server_origin: String,
    identity_tls_root_ca_pem: String,
    identity_tls_root_ca_sha256: String,
    expires_at_unix_ms: i64,
    authorization: String,
}

impl Drop for BindingImport {
    fn drop(&mut self) {
        self.identity_tls_root_ca_pem.zeroize();
        self.authorization.zeroize();
    }
}

#[derive(Serialize)]
struct StatusBody {
    ticket_id: Uuid,
    state: &'static str,
    ready: bool,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    request_id: String,
    retryable: bool,
}

pub(crate) async fn redeem_deployment_binding(
    State(state): State<IdentityBootstrapState>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    match redeem(&state, request).await {
        Ok(bytes) => json_response(StatusCode::OK, bytes, request_id),
        Err(error) => error_response(error, request_id),
    }
}

pub(crate) async fn get_deployment_binding_status(
    State(state): State<IdentityBootstrapState>,
    Path(ticket_id): Path<String>,
    request: Request,
) -> Response {
    let request_id = RequestId::new();
    match status(&state, &ticket_id, request).await {
        Ok(body) => match serde_json::to_vec(&body) {
            Ok(bytes) => json_response(StatusCode::OK, bytes, request_id),
            Err(_) => error_response(DeploymentBindingTicketError::Corrupt, request_id),
        },
        Err(error) => error_response(error, request_id),
    }
}

async fn redeem(
    state: &IdentityBootstrapState,
    request: Request,
) -> Result<Vec<u8>, DeploymentBindingTicketError> {
    let (parts, body) = request.into_parts();
    validate_redeem_headers(&parts.headers)?;
    let bytes = Zeroizing::new(
        to_bytes(body, MAX_REDEEM_BYTES)
            .await
            .map_err(|_| DeploymentBindingTicketError::Invalid)?
            .to_vec(),
    );
    let request: RedeemRequest =
        serde_json::from_slice(&bytes).map_err(|_| DeploymentBindingTicketError::Invalid)?;
    if request.protocol_version != 1
        || request.ticket_id.len() != 36
        || request.capability.len() != 43
    {
        return Err(DeploymentBindingTicketError::Invalid);
    }
    let ticket_id =
        Uuid::parse_str(&request.ticket_id).map_err(|_| DeploymentBindingTicketError::Invalid)?;
    if ticket_id.to_string() != request.ticket_id || ticket_id.get_version_num() != 7 {
        return Err(DeploymentBindingTicketError::Invalid);
    }
    let mut capability = Zeroizing::new([0_u8; 32]);
    Base64UrlUnpadded::decode(&request.capability, &mut *capability)
        .map_err(|_| DeploymentBindingTicketError::Invalid)?;
    let now = state
        .committed_at()
        .map_err(|()| DeploymentBindingTicketError::Corrupt)?
        .get();
    let capability_digest =
        Sha256Digest::hash_domain(DEPLOYMENT_BINDING_CAPABILITY_HASH_DOMAIN, &*capability);
    let ticket = state
        .deployment_bindings
        .authorize_redeem(&state.store, ticket_id, capability_digest, now)
        .await?;
    let authorization_raw =
        Sha256Digest::hash_domain(DEPLOYMENT_BINDING_CLIENT_AUTHORIZATION_DOMAIN, &*capability);
    let authorization = Base64UrlUnpadded::encode_string(authorization_raw.as_bytes());
    let output = BindingImport {
        schema: "dirextalk.client-binding",
        schema_version: 1,
        binding_id: ticket.binding_id,
        deployment_operation_id: ticket.deployment_operation_id,
        tenant_id: ticket.tenant_id,
        server_origin: ticket.server_origin.clone(),
        identity_tls_root_ca_pem: ticket.tls_root_ca_pem.clone(),
        identity_tls_root_ca_sha256: ticket.tls_root_ca_sha256.to_string(),
        expires_at_unix_ms: ticket.expires_at_ms,
        authorization,
    };
    let output_bytes = Zeroizing::new(
        serde_json::to_vec(&output).map_err(|_| DeploymentBindingTicketError::Corrupt)?,
    );
    let binding = ClientBindingIssueCommand {
        binding_id: ticket.binding_id,
        deployment_operation_id: ticket.deployment_operation_id,
        tenant_id: ticket.tenant_id,
        server_origin: ticket.server_origin,
        tls_root_ca_sha256: ticket.tls_root_ca_sha256,
        authorization_digest: Sha256Digest::hash_domain(
            CLIENT_BINDING_AUTHORIZATION_HASH_DOMAIN,
            authorization_raw.as_bytes(),
        ),
        artifact_digest: Sha256Digest::from_bytes(Sha256::digest(&output_bytes).into()),
        issue_request_digest: Sha256Digest::hash_domain(
            CLIENT_BINDING_ISSUE_HASH_DOMAIN,
            &output_bytes,
        ),
        issued_at_ms: ticket.issued_at_ms,
        expires_at_ms: ticket.expires_at_ms,
    };
    state
        .deployment_bindings
        .redeem(&state.store, ticket_id, capability_digest, &binding, now)
        .await?;
    Ok(output_bytes.to_vec())
}

async fn status(
    state: &IdentityBootstrapState,
    ticket_id: &str,
    request: Request,
) -> Result<StatusBody, DeploymentBindingTicketError> {
    let ticket_id_text = ticket_id;
    let ticket_id =
        Uuid::parse_str(ticket_id_text).map_err(|_| DeploymentBindingTicketError::Invalid)?;
    if ticket_id.to_string() != ticket_id_text || ticket_id.get_version_num() != 7 {
        return Err(DeploymentBindingTicketError::Invalid);
    }
    let (mut parts, body) = request.into_parts();
    if parts.headers.contains_key(header::CONTENT_TYPE)
        || parts.headers.contains_key(header::CONTENT_ENCODING)
        || parts.headers.contains_key("idempotency-key")
        || parts
            .headers
            .get(header::ACCEPT)
            .is_some_and(|value| value.as_bytes() != b"application/json")
    {
        return Err(DeploymentBindingTicketError::Invalid);
    }
    let body = to_bytes(body, 1)
        .await
        .map_err(|_| DeploymentBindingTicketError::Invalid)?;
    if !body.is_empty() {
        return Err(DeploymentBindingTicketError::Invalid);
    }
    let token = take_status_token(&mut parts.headers)?;
    let now = state
        .committed_at()
        .map_err(|()| DeploymentBindingTicketError::Corrupt)?
        .get();
    let state_value = state
        .deployment_bindings
        .status(
            &state.store,
            ticket_id,
            Sha256Digest::hash_domain(DEPLOYMENT_BINDING_STATUS_TOKEN_HASH_DOMAIN, &*token),
            now,
        )
        .await?;
    Ok(StatusBody {
        ticket_id,
        state: status_name(state_value),
        ready: state_value == DeploymentBindingTicketState::Consumed,
    })
}

fn validate_redeem_headers(headers: &HeaderMap) -> Result<(), DeploymentBindingTicketError> {
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(header::CONTENT_TYPE)
            .is_none_or(|value| value.as_bytes() != b"application/json")
        || headers.contains_key(header::CONTENT_ENCODING)
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key("idempotency-key")
        || headers
            .get(header::ACCEPT)
            .is_some_and(|value| value.as_bytes() != b"application/json")
    {
        return Err(DeploymentBindingTicketError::Invalid);
    }
    Ok(())
}

fn take_status_token(
    headers: &mut HeaderMap,
) -> Result<Zeroizing<[u8; 32]>, DeploymentBindingTicketError> {
    let values = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .map(|value| Zeroizing::new(value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    headers.remove(header::AUTHORIZATION);
    if values.len() != 1 {
        return Err(DeploymentBindingTicketError::Unauthorized);
    }
    let value =
        std::str::from_utf8(&values[0]).map_err(|_| DeploymentBindingTicketError::Unauthorized)?;
    let encoded = value
        .strip_prefix(STATUS_AUTHORIZATION_SCHEME)
        .and_then(|value| value.strip_prefix(' '))
        .ok_or(DeploymentBindingTicketError::Unauthorized)?;
    if encoded.len() != 43 {
        return Err(DeploymentBindingTicketError::Unauthorized);
    }
    let mut raw = Zeroizing::new([0_u8; 32]);
    Base64UrlUnpadded::decode(encoded, &mut *raw)
        .map_err(|_| DeploymentBindingTicketError::Unauthorized)?;
    Ok(raw)
}

const fn status_name(state: DeploymentBindingTicketState) -> &'static str {
    match state {
        DeploymentBindingTicketState::Issued => "issued",
        DeploymentBindingTicketState::Redeemed => "redeemed",
        DeploymentBindingTicketState::IdentityBound => "identity_bound",
        DeploymentBindingTicketState::Consumed => "consumed",
        DeploymentBindingTicketState::Expired => "expired",
        DeploymentBindingTicketState::Revoked => "revoked",
    }
}

fn json_response(status: StatusCode, body: Vec<u8>, request_id: RequestId) -> Response {
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert("dtx-request-id", value);
    }
    response
}

fn error_response(error: DeploymentBindingTicketError, request_id: RequestId) -> Response {
    let (status, code, retryable) = match error {
        DeploymentBindingTicketError::Invalid => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEPLOYMENT_BINDING_INVALID",
            false,
        ),
        DeploymentBindingTicketError::Unauthorized | DeploymentBindingTicketError::Expired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEPLOYMENT_BINDING_INVALID",
            false,
        ),
        DeploymentBindingTicketError::Conflict => {
            (StatusCode::CONFLICT, "DEPLOYMENT_BINDING_CONFLICT", false)
        }
        DeploymentBindingTicketError::Persistence(_) | DeploymentBindingTicketError::Corrupt => (
            StatusCode::SERVICE_UNAVAILABLE,
            "IDENTITY_SERVICE_UNAVAILABLE",
            true,
        ),
    };
    let body = serde_json::to_vec(&ErrorEnvelope {
        error: ErrorBody {
            code,
            request_id: request_id.to_string(),
            retryable,
        },
    })
    .unwrap_or_default();
    json_response(status, body, request_id)
}
