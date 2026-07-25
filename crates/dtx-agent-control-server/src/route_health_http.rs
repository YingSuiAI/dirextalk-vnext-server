//! Connector-mTLS Route Health HTTPS boundary and canonical signed contract.

use std::{collections::BTreeMap, fmt, str::FromStr};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use dtx_domain::{
    AgentDeviceId, AgentRouteBootstrapId, AgentRouteDeliveryId, BindingId, ConnectorId,
    ConversationId, InstallationId, LeaseId, RequestId, Revision, RouteHealthKeyId, TenantId,
};
use dtx_security::AuthenticatedConnectorPeer;
use dtx_storage::PgStore;
use dtx_wire::{
    CanonicalValue, Ed25519Signature, Sha256Digest, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sqlx::Row;
use uuid::Uuid;

pub const ROUTE_HEALTH_MEDIA_TYPE_V1: &str = "application/vnd.dirextalk.agent-route-health.v1+cbor";
pub const MAX_ROUTE_HEALTH_REQUEST_BYTES: usize = 64 * 1024;
pub const ROUTE_HEALTH_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.agent-route-health-request.v1\0";
pub const ROUTE_HEALTH_RECEIPT_DOMAIN: &[u8] = b"dirextalk.agent-route-health-receipt.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteHealthParseError {
    InvalidCbor,
    InvalidShape,
    InvalidSignature,
}
impl fmt::Display for RouteHealthParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid route health request")
    }
}
impl std::error::Error for RouteHealthParseError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteHealthRequest {
    pub version: u64,
    pub request_id: RequestId,
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_device_id: AgentDeviceId,
    pub bootstrap_id: AgentRouteBootstrapId,
    pub delivery_id: AgentRouteDeliveryId,
    pub route_id: ConversationId,
    pub connector_generation: u64,
    pub lease_id: LeaseId,
    pub lease_epoch: u64,
    pub route_fence: [u8; 32],
    pub health_key_id: RouteHealthKeyId,
    pub status_revision: Revision,
    pub mailbox_live: bool,
    pub mailbox_state_digest: [u8; 32],
    pub requested_at_ms: i64,
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: [u8; 32],
    pub signature: Ed25519Signature,
    signed_value: CanonicalValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteHealthReceipt {
    pub exact_cbor: Vec<u8>,
    pub replayed: bool,
    pub observation_revision: Revision,
}

#[derive(Clone)]
pub struct RouteHealthHttpState {
    pub store: PgStore,
    pub receipt_key_id: RouteHealthKeyId,
    pub receipt_seed: [u8; 32],
}

/// Validates and durably records one Route Health observation. All relation
/// checks, replay locking and head allocation occur in one tenant transaction;
/// no receipt is emitted before the commit succeeds.
pub async fn record_route_health(
    store: &PgStore,
    peer: AuthenticatedConnectorPeer,
    request: RouteHealthRequest,
    exact_request: &[u8],
    receipt_key_id: RouteHealthKeyId,
    receipt_seed: &[u8; 32],
    now_ms: i64,
) -> Result<RouteHealthReceipt, RouteHealthParseError> {
    if request.version != 1
        || request.tenant_id != peer.identity().tenant_id()
        || request.connector_id != peer.identity().connector_id()
        || request.expires_at_ms <= now_ms
        || request.observed_at_ms > now_ms + 60_000
        || request.requested_at_ms > now_ms + 60_000
        || request.expires_at_ms - now_ms > 10 * 60_000
    {
        return Err(RouteHealthParseError::InvalidShape);
    }
    let mut session = store
        .begin_tenant(request.tenant_id)
        .await
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
    let result = async {
        let request_digest = Sha256Digest::hash_domain(ROUTE_HEALTH_SIGNATURE_DOMAIN, exact_request);

        // Serialize first-time observations on a stable route-scoped fence.
        // This fence is independent of the immutable receipt ledger, so an
        // exact retry can safely observe the committed byte-identical row.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("{}:{}", request.tenant_id, request.route_id))
            .execute(session.connection())
            .await
            .map_err(|_| RouteHealthParseError::InvalidShape)?;

        // Durable replay is authenticated by the request signature and tenant
        // peer binding above. Resolve it before consulting mutable route,
        // bootstrap, lease or approval state so an exact committed receipt
        // remains replayable after those facts are later retired.
        let existing_nonce = sqlx::query(
            "SELECT request_digest, receipt_bytes, observation_revision
              FROM agent.agent_route_health_receipts
              WHERE tenant_id=$1 AND route_id=$2 AND nonce=$3",
        )
        .bind(Uuid::from(request.tenant_id))
        .bind(Uuid::from(request.route_id))
        .bind(request.nonce.to_vec())
        .fetch_optional(session.connection())
        .await
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
        if let Some(row) = existing_nonce {
            return replay_receipt(row, request_digest);
        }
        let existing_request_id = sqlx::query(
            "SELECT request_digest, receipt_bytes, observation_revision
              FROM agent.agent_route_health_receipts
              WHERE tenant_id=$1 AND request_id=$2",
        )
        .bind(Uuid::from(request.tenant_id))
        .bind(Uuid::from(request.request_id))
        .fetch_optional(session.connection())
        .await
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
        if let Some(row) = existing_request_id {
            return replay_receipt(row, request_digest);
        }

        let route = sqlx::query(
            "SELECT h.route_fence, h.bootstrap_id, h.expires_at_ms AS binding_expires_at_ms,
                    b.expires_at_ms AS bootstrap_expires_at_ms, b.state,
                    b.route_health_key_id, b.route_health_public_key, b.connector_id
               FROM agent.agent_route_binding_heads h
               JOIN agent.agent_route_bootstraps b
                 ON b.tenant_id=h.tenant_id AND b.bootstrap_id=h.bootstrap_id
              WHERE h.tenant_id=$1 AND h.route_id=$2 AND h.installation_id=$3
                AND h.binding_id=$4 AND h.agent_control_device_id=$5
                AND h.delivery_id=$6
              FOR UPDATE",
        )
        .bind(Uuid::from(request.tenant_id)).bind(Uuid::from(request.route_id)).bind(Uuid::from(request.installation_id))
        .bind(Uuid::from(request.binding_id)).bind(Uuid::from(request.agent_device_id)).bind(Uuid::from(request.delivery_id))
        .fetch_optional(session.connection()).await.map_err(|_| RouteHealthParseError::InvalidShape)?
        .ok_or(RouteHealthParseError::InvalidShape)?;
        let route_fence: Vec<u8> = route.try_get("route_fence").map_err(|_| RouteHealthParseError::InvalidShape)?;
        let stored_bootstrap: Uuid = route.try_get("bootstrap_id").map_err(|_| RouteHealthParseError::InvalidShape)?;
        let binding_expires_at_ms: i64 = route.try_get("binding_expires_at_ms").map_err(|_| RouteHealthParseError::InvalidShape)?;
        let bootstrap_expires_at_ms: i64 = route.try_get("bootstrap_expires_at_ms").map_err(|_| RouteHealthParseError::InvalidShape)?;
        let bootstrap_state: String = route.try_get("state").map_err(|_| RouteHealthParseError::InvalidShape)?;
        let route_connector: Uuid = route.try_get("connector_id").map_err(|_| RouteHealthParseError::InvalidShape)?;
        let stored_key: Uuid = route.try_get("route_health_key_id").map_err(|_| RouteHealthParseError::InvalidShape)?;
        let stored_public: Vec<u8> = route.try_get("route_health_public_key").map_err(|_| RouteHealthParseError::InvalidShape)?;

        // A concurrent first-time request may have committed while this
        // transaction waited for the route row. Recheck the immutable ledger
        // before evaluating mutable route/lease/approval state.
        let replay_nonce = sqlx::query(
            "SELECT request_digest, receipt_bytes, observation_revision
               FROM agent.agent_route_health_receipts
              WHERE tenant_id=$1 AND route_id=$2 AND nonce=$3",
        )
        .bind(Uuid::from(request.tenant_id))
        .bind(Uuid::from(request.route_id))
        .bind(request.nonce.to_vec())
        .fetch_optional(session.connection())
        .await
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
        if let Some(row) = replay_nonce {
            return replay_receipt(row, request_digest);
        }
        let replay_request_id = sqlx::query(
            "SELECT request_digest, receipt_bytes, observation_revision
               FROM agent.agent_route_health_receipts
              WHERE tenant_id=$1 AND request_id=$2",
        )
        .bind(Uuid::from(request.tenant_id))
        .bind(Uuid::from(request.request_id))
        .fetch_optional(session.connection())
        .await
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
        if let Some(row) = replay_request_id {
            return replay_receipt(row, request_digest);
        }

        if route_fence.as_slice() != request.route_fence
            || stored_bootstrap != Uuid::from(request.bootstrap_id)
            || binding_expires_at_ms <= now_ms
            || bootstrap_expires_at_ms <= now_ms
            || bootstrap_state != "installed"
            || route_connector != Uuid::from(request.connector_id)
            || stored_key != Uuid::from(request.health_key_id) || stored_public.len() != 32 { return Err(RouteHealthParseError::InvalidShape); }
        let active: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM agent.connector_leases l JOIN agent.connector_control_credentials c
             ON c.tenant_id=l.tenant_id AND c.connector_id=l.connector_id
             AND c.connector_generation=l.generation
             WHERE l.tenant_id=$1 AND l.connector_id=$2 AND l.lease_id=$3
               AND l.generation=$4 AND l.lease_epoch=$5 AND l.status='active'
               AND l.expires_at_ms > $6 AND c.certificate_fingerprint=$7
               AND c.not_before_ms <= $6 AND c.not_after_ms > $6")
            .bind(Uuid::from(request.tenant_id)).bind(Uuid::from(request.connector_id))
            .bind(Uuid::from(request.lease_id)).bind(i64::try_from(request.connector_generation).map_err(|_| RouteHealthParseError::InvalidShape)?)
            .bind(i64::try_from(request.lease_epoch).map_err(|_| RouteHealthParseError::InvalidShape)?)
            .bind(now_ms).bind(peer.certificate_fingerprint().as_bytes().to_vec())
            .fetch_optional(session.connection()).await.map_err(|_| RouteHealthParseError::InvalidShape)?;
        if active.is_none() { return Err(RouteHealthParseError::InvalidShape); }
        let approval_current: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM agent.agent_identity_approvals a
             JOIN agent.agent_devices d ON d.tenant_id=a.tenant_id
               AND d.installation_id=a.installation_id AND d.agent_device_id=a.agent_device_id
             JOIN identity.log_heads h ON h.identity_id=a.agent_identity_id
             AND h.head_sequence=a.identity_head_sequence AND h.head_hash=a.identity_head_hash
             WHERE a.tenant_id=$1 AND a.installation_id=$2 AND a.binding_id=$3
               AND a.agent_device_id=$4 AND a.credential_fingerprint=d.credential_fingerprint
               AND d.state='active')")
            .bind(Uuid::from(request.tenant_id)).bind(Uuid::from(request.installation_id))
            .bind(Uuid::from(request.binding_id)).bind(Uuid::from(request.agent_device_id))
            .fetch_one(session.connection()).await.map_err(|_| RouteHealthParseError::InvalidShape)?;
        let head: Option<(i64, i64)> = sqlx::query_as("SELECT observation_revision, status_revision FROM agent.agent_route_health_heads WHERE tenant_id=$1 AND route_id=$2 FOR UPDATE")
            .bind(Uuid::from(request.tenant_id)).bind(Uuid::from(request.route_id)).fetch_optional(session.connection()).await.map_err(|_| RouteHealthParseError::InvalidShape)?;
        if let Some((_, current_status)) = head {
            if i64::try_from(request.status_revision.get()).map_err(|_| RouteHealthParseError::InvalidShape)? <= current_status { return Err(RouteHealthParseError::InvalidShape); }
        }
        let next = head.map(|(revision, _)| revision).unwrap_or(0).checked_add(1).ok_or(RouteHealthParseError::InvalidShape)?;
        let receipt = sign_receipt(&request, request_digest, receipt_key_id, next, now_ms, approval_current, receipt_seed)?;
        let receipt_digest = Sha256Digest::hash_domain(ROUTE_HEALTH_RECEIPT_DOMAIN, &receipt);
        sqlx::query("INSERT INTO agent.agent_route_health_receipts (tenant_id,route_id,nonce,request_id,status_revision,request_digest,receipt_bytes,receipt_digest,observation_revision,observed_at_ms,expires_at_ms,created_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$10)")
            .bind(Uuid::from(request.tenant_id)).bind(Uuid::from(request.route_id)).bind(request.nonce.to_vec()).bind(Uuid::from(request.request_id)).bind(i64::try_from(request.status_revision.get()).map_err(|_| RouteHealthParseError::InvalidShape)?).bind(request_digest.as_bytes().to_vec()).bind(receipt.clone()).bind(receipt_digest.as_bytes().to_vec()).bind(next).bind(now_ms).bind(request.expires_at_ms).execute(session.connection()).await.map_err(|_| RouteHealthParseError::InvalidShape)?;
        sqlx::query("INSERT INTO agent.agent_route_health_heads (tenant_id,route_id,observation_revision,status_revision,updated_at_ms) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,route_id) DO UPDATE SET observation_revision=EXCLUDED.observation_revision,status_revision=EXCLUDED.status_revision,updated_at_ms=EXCLUDED.updated_at_ms")
            .bind(Uuid::from(request.tenant_id)).bind(Uuid::from(request.route_id)).bind(next).bind(i64::try_from(request.status_revision.get()).map_err(|_| RouteHealthParseError::InvalidShape)?).bind(now_ms).execute(session.connection()).await.map_err(|_| RouteHealthParseError::InvalidShape)?;
        Ok(RouteHealthReceipt { exact_cbor: receipt, replayed: false, observation_revision: Revision::new(u64::try_from(next).map_err(|_| RouteHealthParseError::InvalidShape)?).map_err(|_| RouteHealthParseError::InvalidShape)? })
    }.await;
    match result {
        Ok(value) => {
            session
                .commit()
                .await
                .map_err(|_| RouteHealthParseError::InvalidShape)?;
            Ok(value)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

fn replay_receipt(
    row: sqlx::postgres::PgRow,
    request_digest: Sha256Digest,
) -> Result<RouteHealthReceipt, RouteHealthParseError> {
    let digest: Vec<u8> = row
        .try_get("request_digest")
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
    if digest.as_slice() != request_digest.as_bytes() {
        return Err(RouteHealthParseError::InvalidShape);
    }
    let receipt_bytes: Vec<u8> = row
        .try_get("receipt_bytes")
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
    let revision: i64 = row
        .try_get("observation_revision")
        .map_err(|_| RouteHealthParseError::InvalidShape)?;
    Ok(RouteHealthReceipt {
        exact_cbor: receipt_bytes,
        replayed: true,
        observation_revision: Revision::new(
            u64::try_from(revision).map_err(|_| RouteHealthParseError::InvalidShape)?,
        )
        .map_err(|_| RouteHealthParseError::InvalidShape)?,
    })
}

fn sign_receipt(
    request: &RouteHealthRequest,
    request_digest: Sha256Digest,
    key_id: RouteHealthKeyId,
    revision: i64,
    now_ms: i64,
    approval_current: bool,
    seed: &[u8; 32],
) -> Result<Vec<u8>, RouteHealthParseError> {
    use ed25519_dalek::{Signer, SigningKey};
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(request.request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(request.nonce.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(request_digest.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(key_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bool(request.mailbox_live),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Bytes(request.mailbox_state_digest.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Unsigned(
                u64::try_from(revision).map_err(|_| RouteHealthParseError::InvalidShape)?,
            ),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Unsigned(
                u64::try_from(now_ms).map_err(|_| RouteHealthParseError::InvalidShape)?,
            ),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Unsigned(
                u64::try_from(request.expires_at_ms)
                    .map_err(|_| RouteHealthParseError::InvalidShape)?,
            ),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Bool(approval_current),
        ),
    ]);
    let bytes =
        encode_deterministic_cbor(&value).map_err(|_| RouteHealthParseError::InvalidShape)?;
    let signature = SigningKey::from_bytes(seed)
        .sign(Sha256Digest::hash_domain(ROUTE_HEALTH_RECEIPT_DOMAIN, &bytes).as_bytes());
    let mut map = match value {
        CanonicalValue::Map(map) => map,
        _ => unreachable!(),
    };
    map.push((
        CanonicalValue::Unsigned(12),
        CanonicalValue::Bytes(signature.to_bytes().to_vec()),
    ));
    encode_deterministic_cbor(&CanonicalValue::Map(map))
        .map_err(|_| RouteHealthParseError::InvalidShape)
}

impl RouteHealthRequest {
    pub fn parse(bytes: &[u8], verifying_key: &[u8; 32]) -> Result<Self, RouteHealthParseError> {
        let value =
            decode_deterministic_cbor(bytes).map_err(|_| RouteHealthParseError::InvalidCbor)?;
        let CanonicalValue::Map(entries) = value else {
            return Err(RouteHealthParseError::InvalidShape);
        };
        let mut fields = BTreeMap::new();
        for (key, value) in entries {
            let CanonicalValue::Unsigned(key) = key else {
                return Err(RouteHealthParseError::InvalidShape);
            };
            if fields.insert(key, value).is_some() {
                return Err(RouteHealthParseError::InvalidShape);
            }
        }
        if fields.len() != 23 || fields.keys().copied().ne(1..=23) {
            return Err(RouteHealthParseError::InvalidShape);
        }
        let mut signed_entries = Vec::with_capacity(22);
        let get = |key| fields.get(&key).ok_or(RouteHealthParseError::InvalidShape);
        let version = uint(get(1)?)?;
        let request_id = id(get(2)?)?;
        let tenant_id = id(get(3)?)?;
        let connector_id = id(get(4)?)?;
        let installation_id = id(get(5)?)?;
        let binding_id = id(get(6)?)?;
        let agent_device_id = id(get(7)?)?;
        let bootstrap_id = id(get(8)?)?;
        let delivery_id = id(get(9)?)?;
        let route_id = id(get(10)?)?;
        let connector_generation = uint(get(11)?)?;
        let lease_id = id(get(12)?)?;
        let lease_epoch = uint(get(13)?)?;
        let route_fence = bytes32(get(14)?)?;
        let health_key_id = id(get(15)?)?;
        let status_revision =
            Revision::new(uint(get(16)?)?).map_err(|_| RouteHealthParseError::InvalidShape)?;
        let mailbox_live = bool_value(get(17)?)?;
        let mailbox_state_digest = bytes32(get(18)?)?;
        let requested_at_ms =
            i64::try_from(uint(get(19)?)?).map_err(|_| RouteHealthParseError::InvalidShape)?;
        let observed_at_ms =
            i64::try_from(uint(get(20)?)?).map_err(|_| RouteHealthParseError::InvalidShape)?;
        let expires_at_ms =
            i64::try_from(uint(get(21)?)?).map_err(|_| RouteHealthParseError::InvalidShape)?;
        let nonce = bytes32(get(22)?)?;
        let signature_bytes = bytes64(get(23)?)?;
        for (key, value) in &fields {
            if *key != 23 {
                signed_entries.push((CanonicalValue::Unsigned(*key), value.clone()));
            }
        }
        let signed_value = CanonicalValue::Map(signed_entries);
        let signed = encode_deterministic_cbor(&signed_value)
            .map_err(|_| RouteHealthParseError::InvalidShape)?;
        let key = VerifyingKey::from_bytes(verifying_key)
            .map_err(|_| RouteHealthParseError::InvalidSignature)?;
        key.verify(
            &Sha256Digest::hash_domain(ROUTE_HEALTH_SIGNATURE_DOMAIN, &signed).as_bytes()[..],
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| RouteHealthParseError::InvalidSignature)?;
        Ok(Self {
            version,
            request_id,
            tenant_id,
            connector_id,
            installation_id,
            binding_id,
            agent_device_id,
            bootstrap_id,
            delivery_id,
            route_id,
            connector_generation,
            lease_id,
            lease_epoch,
            route_fence,
            health_key_id,
            status_revision,
            mailbox_live,
            mailbox_state_digest,
            requested_at_ms,
            observed_at_ms,
            expires_at_ms,
            nonce,
            signature: Ed25519Signature::from_bytes(signature_bytes),
            signed_value,
        })
    }

    pub fn request_digest(&self, bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::hash_domain(ROUTE_HEALTH_SIGNATURE_DOMAIN, bytes)
    }
    pub fn signed_cbor(&self) -> Result<Vec<u8>, RouteHealthParseError> {
        encode_deterministic_cbor(&self.signed_value)
            .map_err(|_| RouteHealthParseError::InvalidShape)
    }
}

fn uint(value: &CanonicalValue) -> Result<u64, RouteHealthParseError> {
    if let CanonicalValue::Unsigned(value) = value {
        Ok(*value)
    } else {
        Err(RouteHealthParseError::InvalidShape)
    }
}
fn bool_value(value: &CanonicalValue) -> Result<bool, RouteHealthParseError> {
    if let CanonicalValue::Bool(value) = value {
        Ok(*value)
    } else {
        Err(RouteHealthParseError::InvalidShape)
    }
}
fn bytes32(value: &CanonicalValue) -> Result<[u8; 32], RouteHealthParseError> {
    bytes(value)?
        .try_into()
        .map_err(|_| RouteHealthParseError::InvalidShape)
}
fn bytes64(value: &CanonicalValue) -> Result<[u8; 64], RouteHealthParseError> {
    bytes(value)?
        .try_into()
        .map_err(|_| RouteHealthParseError::InvalidShape)
}
fn bytes(value: &CanonicalValue) -> Result<Vec<u8>, RouteHealthParseError> {
    if let CanonicalValue::Bytes(value) = value {
        Ok(value.clone())
    } else {
        Err(RouteHealthParseError::InvalidShape)
    }
}
fn id<T: FromStr>(value: &CanonicalValue) -> Result<T, RouteHealthParseError> {
    match value {
        CanonicalValue::Text(value) => value
            .parse()
            .map_err(|_| RouteHealthParseError::InvalidShape),
        _ => Err(RouteHealthParseError::InvalidShape),
    }
}

pub fn route_health_router() -> Router {
    Router::new().route("/agent-route/health", post(route_health_unavailable))
}

pub fn route_health_router_with_state(state: RouteHealthHttpState) -> Router {
    Router::new()
        .route("/agent-route/health", post(route_health_handler))
        .with_state(state)
}

async fn route_health_handler(
    State(state): State<RouteHealthHttpState>,
    ConnectInfo(peer): ConnectInfo<crate::RouteHealthConnectInfo>,
    request: Request<Body>,
) -> Response {
    let bytes = match axum::body::to_bytes(request.into_body(), MAX_ROUTE_HEALTH_REQUEST_BYTES)
        .await
    {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request too large\n").into_response(),
    };
    let (tenant_id, route_id, bootstrap_id, health_key_id) = match route_health_hint(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid route health request\n").into_response();
        }
    };
    let mut session = match state.store.begin_tenant(tenant_id).await {
        Ok(session) => session,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "unavailable\n").into_response(),
    };
    let key = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT route_health_public_key
          FROM agent.agent_route_bootstraps
         WHERE tenant_id=$1 AND route_id=$2 AND bootstrap_id=$3
           AND route_health_key_id=$4 AND route_health_public_key IS NOT NULL",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(route_id))
    .bind(Uuid::from(bootstrap_id))
    .bind(Uuid::from(health_key_id))
    .fetch_optional(session.connection())
    .await
    .ok()
    .flatten();
    let key = match key {
        Some(key) => Some(key),
        None => sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT b.route_health_public_key
               FROM agent.agent_route_binding_heads h
               JOIN agent.agent_route_bootstraps b
                 ON b.tenant_id=h.tenant_id AND b.bootstrap_id=h.bootstrap_id
              WHERE h.tenant_id=$1 AND h.route_id=$2
                AND b.route_health_public_key IS NOT NULL",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(route_id))
        .fetch_optional(session.connection())
        .await
        .ok()
        .flatten(),
    };
    let _ = session.rollback().await;
    let Some(key) = key.and_then(|key| <[u8; 32]>::try_from(key).ok()) else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };
    let request = match RouteHealthRequest::parse(&bytes, &key) {
        Ok(request) => request,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "invalid route health request\n").into_response();
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| i64::try_from(value.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    match record_route_health(
        &state.store,
        peer.0,
        request,
        &bytes,
        state.receipt_key_id,
        &state.receipt_seed,
        now,
    )
    .await
    {
        Ok(receipt) => (
            if receipt.replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            [(axum::http::header::CONTENT_TYPE, ROUTE_HEALTH_MEDIA_TYPE_V1)],
            receipt.exact_cbor,
        )
            .into_response(),
        Err(_) => (StatusCode::CONFLICT, "route health rejected\n").into_response(),
    }
}

fn route_health_hint(
    bytes: &[u8],
) -> Result<
    (
        TenantId,
        ConversationId,
        AgentRouteBootstrapId,
        RouteHealthKeyId,
    ),
    RouteHealthParseError,
> {
    let CanonicalValue::Map(entries) =
        decode_deterministic_cbor(bytes).map_err(|_| RouteHealthParseError::InvalidCbor)?
    else {
        return Err(RouteHealthParseError::InvalidShape);
    };
    let mut tenant = None;
    let mut route = None;
    let mut bootstrap = None;
    let mut health_key = None;
    for (key, value) in entries {
        if let CanonicalValue::Unsigned(key) = key {
            if key == 3 {
                tenant = Some(id(&value)?);
            }
            if key == 10 {
                route = Some(id(&value)?);
            }
            if key == 8 {
                bootstrap = Some(id(&value)?);
            }
            if key == 15 {
                health_key = Some(id(&value)?);
            }
        }
    }
    tenant
        .zip(route)
        .zip(bootstrap)
        .zip(health_key)
        .map(|(((tenant, route), bootstrap), health_key)| (tenant, route, bootstrap, health_key))
        .ok_or(RouteHealthParseError::InvalidShape)
}

async fn route_health_unavailable(request: Request<Body>) -> Response {
    let bytes = match axum::body::to_bytes(request.into_body(), MAX_ROUTE_HEALTH_REQUEST_BYTES)
        .await
    {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request too large\n").into_response(),
    };
    if bytes.is_empty() {
        return (StatusCode::BAD_REQUEST, "invalid route health request\n").into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "route health application unavailable\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtx_wire::encode_deterministic_cbor;
    use ed25519_dalek::{Signer, SigningKey};
    use uuid::Uuid;

    #[test]
    fn canonical_request_signature_is_verified_and_tamper_is_rejected() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let values = (1..=22)
            .map(|key| {
                let value = match key {
                    1 | 11 | 13 | 16 | 19 | 20 | 21 => CanonicalValue::Unsigned(1),
                    17 => CanonicalValue::Bool(true),
                    14 | 18 | 22 => CanonicalValue::Bytes(vec![2; 32]),
                    _ => CanonicalValue::Text(Uuid::now_v7().to_string()),
                };
                (CanonicalValue::Unsigned(key), value)
            })
            .collect::<Vec<_>>();
        let signed =
            encode_deterministic_cbor(&CanonicalValue::Map(values.clone())).expect("signed cbor");
        let signature =
            key.sign(Sha256Digest::hash_domain(ROUTE_HEALTH_SIGNATURE_DOMAIN, &signed).as_bytes());
        let mut complete = values;
        complete.push((
            CanonicalValue::Unsigned(23),
            CanonicalValue::Bytes(signature.to_bytes().to_vec()),
        ));
        let bytes =
            encode_deterministic_cbor(&CanonicalValue::Map(complete)).expect("request cbor");
        let parsed = RouteHealthRequest::parse(&bytes, key.verifying_key().as_bytes())
            .expect("signature verifies");
        assert!(parsed.mailbox_live);
        let mut tampered = bytes.clone();
        *tampered.last_mut().expect("nonempty") ^= 1;
        assert!(RouteHealthRequest::parse(&tampered, key.verifying_key().as_bytes()).is_err());
    }

    #[test]
    fn receipt_is_signed_and_preserves_mailbox_observation() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let values = (1..=22)
            .map(|field| {
                let value = match field {
                    1 | 11 | 13 | 16 | 19 | 20 | 21 => CanonicalValue::Unsigned(1),
                    17 => CanonicalValue::Bool(true),
                    14 | 18 | 22 => CanonicalValue::Bytes(vec![4; 32]),
                    _ => CanonicalValue::Text(Uuid::now_v7().to_string()),
                };
                (CanonicalValue::Unsigned(field), value)
            })
            .collect::<Vec<_>>();
        let signed = encode_deterministic_cbor(&CanonicalValue::Map(values.clone())).unwrap();
        let signature =
            key.sign(Sha256Digest::hash_domain(ROUTE_HEALTH_SIGNATURE_DOMAIN, &signed).as_bytes());
        let mut complete = values;
        complete.push((
            CanonicalValue::Unsigned(23),
            CanonicalValue::Bytes(signature.to_bytes().to_vec()),
        ));
        let bytes = encode_deterministic_cbor(&CanonicalValue::Map(complete)).unwrap();
        let request = RouteHealthRequest::parse(&bytes, key.verifying_key().as_bytes()).unwrap();
        let receipt_key = SigningKey::from_bytes(&[11; 32]);
        let receipt = sign_receipt(
            &request,
            request.request_digest(&bytes),
            RouteHealthKeyId::new(),
            1,
            2,
            false,
            &receipt_key.to_bytes(),
        )
        .unwrap();
        let CanonicalValue::Map(fields) = decode_deterministic_cbor(&receipt).unwrap() else {
            panic!("receipt map")
        };
        assert!(fields.iter().any(|(k,v)| *k == CanonicalValue::Unsigned(6) && *v == CanonicalValue::Bool(true)));
        let signature = fields
            .iter()
            .find_map(|(k, v)| (*k == CanonicalValue::Unsigned(12)).then(|| v))
            .expect("receipt signature");
        assert!(matches!(signature, CanonicalValue::Bytes(value) if value.len() == 64));
    }

    #[test]
    fn malformed_and_oversize_payloads_fail_closed_before_application() {
        assert!(decode_deterministic_cbor(&[0xff]).is_err());
        assert!(decode_deterministic_cbor(&vec![0u8; MAX_ROUTE_HEALTH_REQUEST_BYTES + 1]).is_err());
    }
}
